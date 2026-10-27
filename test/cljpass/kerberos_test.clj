(ns cljpass.kerberos-test
  "Enrollment with Kerberos (SPNEGO) against a real test KDC (Apache
   Kerby), automatic approval and the server audit log."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.admin :as admin]
            [cljpass.audit :as audit]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.identity :as idn]
            [cljpass.kerberos :as krb]
            [cljpass.local :as local]
            [cljpass.negotiate :as negotiate]
            [cljpass.remote :as remote]
            [cljpass.server :as server]
            [cljpass.service :as svc]
            [cljpass.store :as store]
            [cljpass.vault :as v])
  (:import [java.io File]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.util.concurrent Callable]
           [javax.security.auth Subject]
           [javax.security.auth.callback CallbackHandler NameCallback PasswordCallback]
           [javax.security.auth.login AppConfigurationEntry AppConfigurationEntry$LoginModuleControlFlag
            Configuration LoginContext]
           [org.apache.kerby.kerberos.kerb.server SimpleKdcServer]
           [org.ietf.jgss GSSContext GSSManager GSSName Oid]))

(def realm "EXAMPLE.LOCAL")

(defn- free-port []
  (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(defn- msg-of [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defn- start-kdc! [^File dir]
  (let [kdc (doto (SimpleKdcServer.)
              (.setWorkDir dir) (.setKdcRealm realm) (.setKdcHost "localhost")
              (.setAllowUdp false) (.setKdcTcpPort (free-port)) (.init) (.start))]
    (.createPrincipal kdc (str "HTTP/localhost@" realm) (str (random-uuid)))
    (doseq [u ["alice" "bob"]] (.createPrincipal kdc (str u "@" realm) (str u "-pw")))
    (.exportPrincipal kdc (str "HTTP/localhost@" realm) (File. dir "http.keytab"))
    (System/setProperty "java.security.krb5.conf" (str (File. dir "krb5.conf")))
    kdc))

(defn- login
  "Like the Windows logon: Kerberos login of a domain user (password)."
  [user]
  (let [subject (Subject.)
        cfg (proxy [Configuration] []
              (getAppConfigurationEntry [_]
                (into-array AppConfigurationEntry
                            [(AppConfigurationEntry. "com.sun.security.auth.module.Krb5LoginModule"
                                                     AppConfigurationEntry$LoginModuleControlFlag/REQUIRED
                                                     {"refreshKrb5Config" "true"})])))
        handler (reify CallbackHandler
                  (handle [_ cbs]
                    (doseq [cb cbs]
                      (condp instance? cb
                        NameCallback (.setName ^NameCallback cb (str user "@" realm))
                        PasswordCallback (.setPassword ^PasswordCallback cb (.toCharArray (str user "-pw")))))))]
    (.login (LoginContext. "client" subject handler ^Configuration cfg))
    subject))

(defn- spnego-token
  "SPNEGO token for HTTP@localhost, as Windows sends it."
  ^bytes [^Subject subject]
  (Subject/callAs subject
                  (reify Callable
                    (call [_]
                      (let [m (GSSManager/getInstance)
                            ^GSSContext ctx (.createContext m (.createName m "HTTP@localhost" GSSName/NT_HOSTBASED_SERVICE)
                                                            (Oid. "1.3.6.1.5.5.2") nil GSSContext/DEFAULT_LIFETIME)]
                        (try (.initSecContext ctx (byte-array 0) 0 0)
                             (finally (.dispose ctx))))))))

(defn- post-with [header-fn]
  (fn [url ^String body]
    (let [r (.send (HttpClient/newHttpClient)
                   (-> (HttpRequest/newBuilder (URI/create url))
                       (.header "Content-Type" "application/json")
                       (.header "Authorization" (header-fn))
                       (.POST (HttpRequest$BodyPublishers/ofString body))
                       (.build))
                   (HttpResponse$BodyHandlers/ofString))]
      {:status (.statusCode r) :body (.body r)})))

(defn- as-windows-user
  "negotiate/*post* with the Kerberos ticket of `user`."
  [subject]
  (post-with #(str "Negotiate " (c/b64 (spnego-token subject)))))

(deftest principal-mapping
  (is (= "alice" (krb/user-of realm "Alice@EXAMPLE.LOCAL")))
  (is (nil? (krb/user-of realm "alice@OTHER.LOCAL")) "foreign realm")
  (is (nil? (krb/user-of realm "HTTP/pw.example.local@EXAMPLE.LOCAL")) "service principal")
  (is (nil? (krb/user-of realm "pc01$@EXAMPLE.LOCAL")) "machine account")
  (is (krb/ntlm-token? (.getBytes "NTLMSSP\u0000\u0001\u0000\u0000\u0000" "ISO-8859-1"))))

(deftest auto-approve-plan
  (let [roster {:users {"carol" {:status :disabled}}}
        pending [{:user "alice" :sign-pub "A"} {:user "bob" :sign-pub "B"} {:user "carol" :sign-pub "C"}
                 {:user "dave" :sign-pub "D"}]
        atts [{:user "alice" :sign-pub "A" :principal "alice@X"} {:user "bob" :sign-pub "OLD"}
              {:user "carol" :sign-pub "C"}]]
    (is (= {:approve [{:user "alice" :sign-pub "A" :principal "alice@X"}]
            :skipped [{:user "bob" :reason :other-key} {:user "carol" :reason :disabled}]}
           (admin/plan-auto-approve roster pending atts)))))

(deftest kerberos-enrollment-and-audit
  (let [dir (fs/create-temp-dir)
        kdc (start-kdc! (File. (str dir)))
        port (free-port)
        url (str "http://127.0.0.1:" port)
        db (str (fs/path dir "server.db"))
        stop (server/start! {:db db :port port :bind "127.0.0.1" :init-token "secret" :quiet-audit true
                             :keytab (str (fs/path dir "http.keytab")) :principal (str "HTTP/localhost@" realm)
                             :realm "example.local" :require-kerberos true})
        homes (into {} (for [u ["admin" "alice" "bob"]] [u (str (fs/create-temp-dir))]))
        admin-ident (idn/new-identity "admin")
        admin-s (svc/new-session {:idle-seconds 300})
        alice-s (svc/new-session {:idle-seconds 300})
        alice-krb (login "alice")]
    (try
      (let [{:keys [org-hash]} (admin/init-org! url "secret" "Example Ltd" admin-ident)
            approve! (fn []
                       (binding [local/*home* (homes "admin")]
                         (svc/sync-now admin-s)
                         (svc/with-ctx admin-s #(admin/auto-approve! % admin-ident (remote/attestations url admin-ident)))))]
        (binding [local/*home* (homes "admin")]
          (local/save-identity! admin-ident :file)
          (local/save-config! {:server url :org-hash org-hash :user "admin"})
          (svc/unlock! admin-s))

        (testing "without Kerberos, requests are refused (--require-kerberos)"
          (binding [local/*home* (homes "bob")]
            (is (= :core/server-kerberos-required
                   (msg-of #(svc/enroll! (svc/new-session {}) {:server url :org-hash org-hash :user "bob"
                                                               :protector :file :kerberos false}))))))

        (testing "no ticket, garbage, NTLM: rejected"
          (binding [local/*home* (str (fs/create-temp-dir))]
            (doseq [h ["" "Negotiate AAAA" (str "Negotiate " (c/b64 (.getBytes "NTLMSSP\u0000\u0001\u0000\u0000\u0000" "ISO-8859-1")))]]
              (binding [negotiate/*post* (post-with (constantly h))]
                (is (some? (msg-of #(svc/enroll! (svc/new-session {}) {:server url :org-hash org-hash :user "bob"
                                                                       :protector :file :kerberos true}))))))
            (is (not (local/identity-exists?)) "nothing is saved locally on failure")))

        (testing "logged on as alice, no request for bob"
          (binding [local/*home* (homes "bob")
                    negotiate/*post* (as-windows-user alice-krb)]
            (is (= :core/server-kerberos-other-user
                   (msg-of #(svc/enroll! (svc/new-session {}) {:server url :org-hash org-hash :user "bob"
                                                               :protector :file :kerberos true}))))))

        (testing "alice: enrollment without input, approval without fingerprint"
          (binding [local/*home* (homes "alice")
                    negotiate/*post* (as-windows-user alice-krb)]
            (let [r (svc/enroll! alice-s {:server url :org-hash org-hash :user "alice" :protector :file :kerberos true})]
              (is (:kerberos r))
              (is (= :pending (:state (svc/status alice-s))))
              (is (:kerberos (svc/status alice-s)))))
          (is (= [{:user "alice" :principal (str "alice@" realm)}]
                 (map #(select-keys % [:user :principal]) (remote/attestations url admin-ident))))
          (is (= ["alice"] (:approved (approve!))))
          (is (= [] (:approved (approve!))) "idempotent")
          (binding [local/*home* (homes "alice")]
            (is (= :active (:state (svc/status alice-s))))))

        (testing "attestations and audit log only for admins"
          (binding [local/*home* (homes "alice")]
            (let [ident (local/load-identity)]
              (is (= :core/server-admins-only (msg-of #(remote/audit-log url ident 0 100))))
              (is (= :core/server-admins-only (msg-of #(remote/attestations url ident)))))))

        (testing "audit log: events and hash chain"
          (let [{:keys [entries]} (remote/audit-log url admin-ident 0 1000)
                events (set (map :event entries))]
            (is (nil? (audit/verify-chain entries nil)))
            (is (= "server.start" (:event (first entries))))
            (is (every? events ["vault.init" "object.create" "enroll.denied" "kerberos.failed" "enroll.kerberos" "kerberos.list"]))
            (let [e (first (filter #(= "enroll.kerberos" (:event %)) entries))]
              (is (= "alice" (:user e)))
              (is (= "127.0.0.1" (:addr e)))
              (is (= (str "alice@" realm) (get-in e [:detail :principal]))))
            (is (some #(and (= "enroll.denied" (:event %)) (= "alice" (:user %)) (= "bob" (get-in % [:detail :requested])))
                      entries))
            (testing "a changed entry is detected"
              (store/sql-exec! (fs/absolutize db) ["UPDATE audit SET user = 'mallory' WHERE event = 'enroll.kerberos'"])
              (let [{:keys [entries]} (remote/audit-log url admin-ident 0 1000)]
                (is (= (:seq (first (filter #(= "enroll.kerberos" (:event %)) entries)))
                       (audit/verify-chain entries nil)))))
            (testing "a deleted entry is detected"
              (store/sql-exec! (fs/absolutize db) ["DELETE FROM audit WHERE seq = 3"])
              (is (= 4 (audit/verify-chain (:entries (remote/audit-log url admin-ident 0 1000)) nil)))))))
      (finally
        (stop)
        (.stop kdc)))))
