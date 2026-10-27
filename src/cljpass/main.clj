(ns cljpass.main
  "Entry point: without arguments the desktop UI starts (double-click on
   cljpass.exe). Server and admin functions are subcommands."
  (:gen-class)
  (:require [cljpass.cli :as cli]
            [clojure.string :as str]
            [cljpass.admin :as admin]
            [cljpass.audit :as audit]
            [cljpass.broker :as broker]
            [cljpass.codec :as codec]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.identity :as idn]
            [cljpass.json :as json]
            [cljpass.local :as local]
            [cljpass.ipc :as ipc]
            [cljpass.remote :as remote]
            [cljpass.rotate :as rotate]
            [cljpass.server :as server]
            [cljpass.service :as svc]
            [cljpass.store :as store]
            [cljpass.vault :as v]
            [cljpass.desktop :as desktop]))

(defn- usage [] (i18n/t :cli/usage))

(defn- die [& msg] (binding [*out* *err*] (println (apply str msg))) (System/exit 1))

(declare read-secret)

(defn- session []
  (let [s (svc/new-session {:idle-seconds 300})]
    (if (svc/standalone-mode?)
      (svc/open-file! s {:password (read-secret (i18n/t :cli/prompt-master-password))})
      (when (local/identity-exists?) (svc/unlock! s)))
    s))

(defn- admin-ident [s] (svc/with-ctx s :ident))

(defn- read-secret [prompt]
  (print prompt) (flush)
  (if-let [c (System/console)] (String. (.readPassword c)) (read-line)))

(defn- read-code []
  (print (i18n/t :cli/prompt-one-time-code)) (flush)
  (if-let [c (System/console)] (String. (.readPassword c)) (read-line)))

;; ================================================================ Commands

(defn cmd-gui [{:keys [opts]}]
  (if-let [ms (:smoke opts)]
    ;; Self-test (CI): local file in a throwaway directory, click through the dialogs
    (binding [local/*home* (fs/create-temp-dir)]
      (let [s (svc/new-session {})]
        (svc/open-file! s {:file (str (fs/path (fs/create-temp-dir) "selftest.kdbx")) :password "selftest" :create true
                           :kdf {:kdf :aes :rounds 1000}})
        (svc/save-entry s {:title "Example" :username "me" :password "secret" :folder "Test"})
        (svc/add-group! s "Test" "Empty")
        (svc/delete-entry s (svc/save-entry s {:title "Old" :password "old"}))
        (desktop/start! {:session s :on-start (fn [_] (desktop/smoke! ms))})))
    (desktop/start! {:idle-seconds (:idle opts)})))

(defn cmd-server [{:keys [opts]}]
  (when-not (:db opts) (die (i18n/t :cli/missing {:what "--db"})))
  (when (and (:keytab opts) (not (:realm opts))) (die (i18n/t :cli/missing {:what "--realm"})))
  (server/start! (select-keys opts [:db :port :bind :init-token :keytab :principal :realm :require-kerberos :trust-proxy]))
  (println (i18n/t :cli/server-listening {:address (str (or (:bind opts) "0.0.0.0") ":" (or (:port opts) 8080))})
           (if (:init-token opts) (i18n/t :cli/server-setup-allowed) "")
           (if (:keytab opts) (i18n/t :cli/server-kerberos-on {:realm (str/upper-case (:realm opts))}) ""))
  @(promise))

(defn cmd-enroll [{:keys [opts]}]
  (let [m (local/machine-config)
        r (svc/enroll! (svc/new-session {}) (cond-> {:server (or (:server opts) (:server m))
                                                     :org-hash (or (:org-hash opts) (:org-hash m))
                                                     :user (:user opts)}
                                              (contains? opts :kerberos) (assoc :kerberos (:kerberos opts))))]
    (println (i18n/t :cli/request-sent {:user (:user r)}))
    (if (:kerberos r)
      (println (i18n/t :cli/request-kerberos-confirmed))
      (println (i18n/t :cli/fingerprint-tell-admin {:fingerprint (:fingerprint r)})))))

(defn cmd-status [_]
  (let [st (svc/status (session))]
    (println (name (:state st)) (some-> (:mode st) name) (or (:file st) "") (or (:user st) "") (or (:fingerprint st) ""))
    (when-let [l (:link st)]
      (println (i18n/t :cli/server-connection-label) (name (:state l)) (:server l) (or (:fingerprint l) "")))
    (when-let [s (:sync st)] (println "Sync:" (if (:online s) "online" (str "offline - " (:reason s)))))))

(defn cmd-sync [_] (println (svc/sync-now (session))))

(defn cmd-list [_]
  (let [s (session)]
    ;; fetch the latest state; offline the local cache applies
    (try (svc/sync-now s) (catch clojure.lang.ExceptionInfo _ nil))
    (doseq [e (:entries (svc/list-entries s))]
      (println (format "%-36s  %-8s  %-30s  %s" (:id e) (:permission e) (:title e) (:username e))))))

(defn cmd-fingerprint [_] (println (idn/fingerprint (local/load-identity))))

(defn cmd-init [{:keys [opts]}]
  (doseq [k [:server :org :init-token :recovery-out]] (when-not (opts k) (die (i18n/t :cli/missing {:what (str "--" (name k))}))))
  (when (local/identity-exists?) (die (i18n/t :cli/identity-exists {:file (local/identity-file)})))
  (let [user (store/safe-name (or (:user opts) (local/default-user)))
        ident (idn/new-identity user)
        {:keys [org-hash recovery-priv]} (admin/init-org! (:server opts) (:init-token opts) (:org opts) ident)]
    (local/save-identity! ident (local/default-protector))
    (local/save-config! {:server (:server opts) :org-hash org-hash :user user})
    (spit (:recovery-out opts) (codec/->str {:format "cljpass-recovery-v1" :org-hash org-hash :recovery-priv recovery-priv}))
    (println (i18n/t :cli/vault-created {:user user}))
    (println)
    (println (i18n/t :cli/org-hash-distribute))
    (println "  " org-hash)
    (println)
    (println (i18n/t :cli/recovery-written {:file (:recovery-out opts)}))
    (println (i18n/t :cli/recovery-keep-offline))))

(defn- attestations-by-user
  "Kerberos confirmations of the server by user (empty if unavailable)."
  [s]
  (try (into {} (map (juxt :user identity)) (remote/attestations (:server (local/load-config!)) (admin-ident s)))
       (catch clojure.lang.ExceptionInfo _ {})))

(defn cmd-requests [_]
  (let [s (session)]
    (svc/sync-now s)
    (let [atts (attestations-by-user s)]
      (svc/with-ctx s (fn [ctx]
                        (let [rs (v/pending-requests (:store ctx) (:roster ctx))]
                          (when (empty? rs) (println (i18n/t :cli/no-requests)))
                          (doseq [r rs
                                  :let [a (atts (:user r))]]
                            (println (format "%-20s %s%s%s" (:user r) (:fingerprint r)
                                             (if (:known r) (str "  " (i18n/t :cli/new-device-or-key)) "")
                                             (if (and a (= (:sign-pub a) (:sign-pub r)))
                                               (str "  " (i18n/t :cli/kerberos-confirmed {:principal (:principal a)}))
                                               ""))))))))))

(defn- auto-approve-once! [s opts]
  (svc/sync-now s)
  (let [atts (remote/attestations (:server (local/load-config!)) (admin-ident s))
        {:keys [approved skipped]} (svc/with-ctx s #(admin/auto-approve! % (admin-ident s) atts))]
    (doseq [u approved] (println (i18n/t :cli/approved {:user u})))
    (doseq [{:keys [user reason]} skipped]
      (println (i18n/t (if (= :disabled reason) :cli/auto-approve-skipped-disabled :cli/auto-approve-skipped-key) {:user user})))
    (when (:ad-sync opts)
      (when (seq approved) (svc/sync-now s))
      (let [r (svc/with-ctx s #(admin/ad-sync! % (admin-ident s) (select-keys opts [:source :prefix])))]
        (when (:changed r) (println (i18n/t :cli/ad-sync-changed)))))))

(defn cmd-auto-approve
  "Approves requests confirmed by Kerberos. With --watch SECONDS as a
   service (scheduled task under the admin account), optionally with AD
   sync in the same run."
  [{:keys [opts]}]
  (let [s (session) watch (:watch opts)]
    (if-not watch
      (auto-approve-once! s opts)
      (loop []
        (try (auto-approve-once! s opts)
             (catch clojure.lang.ExceptionInfo e
               (binding [*out* *err*] (println (i18n/t :cli/error {:message (ex-message e)})))))
        (Thread/sleep (* 1000 (max 5 (long watch))))
        (recur)))))

(defn cmd-audit
  "Server audit log (admins only), with check of the hash chain."
  [{:keys [opts]}]
  (let [s (session)
        server (:server (local/load-config!))
        ident (admin-ident s)]
    (loop [since (or (:since opts) 0) prev nil]
      (let [{:keys [entries more]} (remote/audit-log server ident since 1000)
            broken (audit/verify-chain entries prev)]
        (doseq [e entries]
          (if (:json opts)
            (println (json/write-str e))
            (println (format "%6d  %s  %-20s %-14s %-15s %s %s" (:seq e) (:at e) (:event e) (or (:user e) "-")
                             (or (:addr e) "-") (or (:path e) "") (if (:detail e) (json/write-str (:detail e)) "")))))
        (when broken (die (i18n/t :cli/audit-chain-broken {:seq broken})))
        (when (and more (seq entries)) (recur (:seq (last entries)) (:hash (last entries))))))))

(defn cmd-approve [{:keys [opts]}]
  (let [user (or (:user opts) (die (i18n/t :cli/missing {:what "USER"})))
        _ (when-not (:fingerprint opts) (die (i18n/t :cli/fingerprint-missing)))
        s (session)]
    (svc/sync-now s)
    (svc/with-ctx s #(admin/approve! % (admin-ident s) user (select-keys opts [:fingerprint :display-name])))
    (println (i18n/t :cli/approved {:user user}))))

(defn cmd-disable [{:keys [opts]}]
  (let [s (session) user (or (:user opts) (die (i18n/t :cli/missing {:what "USER"})))]
    (svc/sync-now s)
    (svc/with-ctx s #(admin/disable-user! % (admin-ident s) user))
    (println (i18n/t :cli/disabled {:user user}))))

(defn cmd-group [{:keys [opts]}]
  (let [s (session) g (:group opts) members (:members opts)]
    (when-not g (die (i18n/t :cli/group-name-missing)))
    (svc/sync-now s)
    (svc/with-ctx s #(admin/set-group! % (admin-ident s) g members))
    (println (i18n/t :cli/group-set {:group g :members (str/join ", " members)}))))

(defn cmd-ad-sync [{:keys [opts]}]
  (let [s (session)]
    (svc/sync-now s)
    (println (svc/with-ctx s #(admin/ad-sync! % (admin-ident s) (select-keys opts [:source :prefix]))))))

(defn- write-transfer! [ident out]
  (let [{:keys [code file]} (admin/transfer-blob ident)]
    (spit out (codec/->str file))
    (println (i18n/t :cli/transfer-file {:file out}))
    (println (i18n/t :cli/transfer-code {:code code}))))

(defn cmd-export-device [{:keys [opts]}]
  (write-transfer! (local/load-identity) (or (:out opts) (die (i18n/t :cli/missing {:what "--out"})))))

(defn cmd-import-device [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        ident (admin/open-transfer (codec/parse (slurp f)) (read-code))
        m (merge (local/machine-config) (local/load-config) (select-keys opts [:server :org-hash]))]
    (when-not (and (:server m) (:org-hash m)) (die (i18n/t :cli/server-and-org-hash-required)))
    (local/save-identity! ident (local/default-protector))
    (local/save-config! {:server (:server m) :org-hash (:org-hash m) :user (:user ident)})
    (println (i18n/t :cli/identity-imported {:user (:user ident)}))))

(defn cmd-recover [{:keys [opts]}]
  (let [user (or (:user opts) (die (i18n/t :cli/missing {:what "USER"})))
        rk (codec/parse (slurp (or (:recovery-key opts) (die (i18n/t :cli/missing {:what "--recovery-key"})))))
        s (session)]
    (svc/sync-now s)
    (let [ident (svc/with-ctx s #(v/open-escrow (:store %) (:org %) user (:recovery-priv rk)))]
      (write-transfer! ident (or (:out opts) (die (i18n/t :cli/missing {:what "--out"})))))))

(defn cmd-open [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        new? (true? (:new opts))
        pw (read-secret (i18n/t (if new? :cli/prompt-new-master-password :cli/prompt-master-password)))
        _ (when (and new? (not= pw (read-secret (i18n/t :cli/prompt-repeat)))) (die (i18n/t :cli/passwords-mismatch)))
        {:keys [file]} (svc/open-file! (svc/new-session {}) {:file f :password pw :create new?
                                                              :keyfile (some-> (:keyfile opts) fs/read-bytes)})]
    (println (i18n/t :cli/local-mode {:file file}))))

(defn cmd-connect [{:keys [opts]}]
  (let [s (session)
        cfg (local/load-config!)
        _ (when-not (local/standalone? cfg) (die (i18n/t :cli/already-connected)))
        link (if (and (= :requested (get-in cfg [:link :state])) (not (:server opts)))
               (get (svc/status s) :link)
               (let [m (merge (local/machine-config) (:link cfg) (select-keys opts [:server :org-hash :user]))]
                 (when-not (and (:server m) (:org-hash m)) (die (i18n/t :cli/server-and-org-hash-required)))
                 (svc/connect-server! s (select-keys m [:server :org-hash :user]))))]
    (case (:state link)
      :ready (let [r (svc/finish-connect! s)]
               (println (i18n/t :cli/connected (select-keys r [:created :updated :copied :deleted]))))
      :pending (do (println (i18n/t :cli/approval-requested {:fingerprint (:fingerprint link)}))
                   (println (i18n/t :cli/connect-again)))
      (die (i18n/t :cli/server-connection-failed {:state (name (:state link)) :error (or (:error link) "")})))))

(defn cmd-disconnect [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        pw (read-secret (i18n/t :cli/prompt-master-password-new-file))
        _ (when (not= pw (read-secret (i18n/t :cli/prompt-repeat))) (die (i18n/t :cli/passwords-mismatch)))
        r (svc/disconnect! (session) {:file f :password pw :force (true? (:force opts))
                                      :keyfile (some-> (:keyfile opts) fs/read-bytes)})]
    (println (i18n/tn :cli/disconnected (:count r) {:file (:file r)}))))

(defn cmd-kdbx-import [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        pw (read-secret (i18n/t :cli/prompt-keepass-password))
        r (svc/import-kdbx (session) {:data (fs/read-bytes f)
                                      :password (not-empty pw)
                                      :keyfile (some-> (:keyfile opts) fs/read-bytes)
                                      :source (fs/file-name f)})]
    (println (i18n/tn :cli/kdbx-imported (:imported r) {:database (:database r)}))))

(defn cmd-kdbx-export [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        pw (read-secret (i18n/t :cli/prompt-new-keepass-password))
        _ (when (and (str/blank? pw) (not (:keyfile opts))) (die (i18n/t :cli/password-or-keyfile-required)))
        {:keys [data count]} (svc/export-kdbx (session) {:password (not-empty pw)
                                                         :keyfile (some-> (:keyfile opts) fs/read-bytes)
                                                         :database (:database opts)})]
    (fs/write-bytes f data)
    (println (i18n/tn :cli/exported count {:file f}))))

(defn- format-of [f opt allowed]
  (let [k (keyword (or opt (second (re-find #"\.([A-Za-z]+)$" (str f))) ""))]
    (or (allowed k) (die (i18n/t :cli/unknown-format {:formats (str/join ", " (map name allowed))})))))

(defn cmd-import [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        fmt (format-of f (:format opts) #{:kdbx :xml :csv})
        pw (when (= fmt :kdbx) (read-secret (i18n/t :cli/prompt-keepass-password)))
        r (svc/import-file (session) {:format fmt :data (fs/read-bytes f) :password (not-empty pw)
                                      :keyfile (some-> (:keyfile opts) fs/read-bytes) :source (fs/file-name f)})]
    (println (i18n/tn :cli/imported (:imported r)))))

(defn cmd-export [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        fmt (format-of f (:format opts) #{:xml :csv :html :xsl})
        {:keys [data count]} (svc/export-file (session) {:format fmt :passwords (true? (:passwords opts))
                                                         :xsl (:xsl opts)})]
    (fs/write-bytes f data)
    (when-not (local/windows?) (fs/set-owner-only! f))
    (println (i18n/tn :cli/exported-unencrypted count {:file f}))))

(defn cmd-kdbx-sync [{:keys [opts]}]
  (let [f (or (:file opts) (die (i18n/t :cli/missing {:what "FILE"})))
        s (session)
        pw (read-secret (i18n/t :cli/prompt-file-password {:file (fs/file-name f)}))
        r (svc/sync-file! s {:file f :password (not-empty pw) :keyfile (some-> (:keyfile opts) fs/read-bytes)})]
    (println (i18n/t :cli/synced (select-keys r [:added :updated :deleted])))))

(defn- rotate-list
  "What could be rotated here - the same picture a session gets
   (rotate/catalog): the plugins of this machine and the entries naming
   one."
  [s]
  (let [{:keys [plugins entries]} (rotate/catalog s)
        {:keys [dirs]} (local/load-changers)]
    (println (i18n/t :cli/rotate-plugins {:dirs (or (not-empty (str/join ", " dirs)) "-")
                                          :file (local/changers-file)}))
    (doseq [p plugins]
      (println (format "  %-24s %s" (:changer p)
                       (str/join " - " (remove str/blank? [(:title p) (:needs p)])))))
    (if (empty? entries)
      (println (i18n/t :cli/rotate-none {:field rotate/changer-field}))
      (doseq [e entries]
        (println (format "  %-32s %-24s %s" (:title e) (:changer e) (or (:host e) "?")))))))

(defn cmd-rotate [{:keys [opts args]}]
  (let [s (session)]
    (if (empty? args)
      (rotate-list s)
      (let [ctx {:session s
                 ;; typing the command is the confirmation; the code is not
                 :ask-code (fn [_] (or (:code opts) (read-code)))}
            results (doall
                     (for [ref args]
                       (let [r (rotate/rotate! ctx ref (select-keys opts [:probe :no-probe]))]
                         (when-let [log (not-empty (str/trim (str (:log r))))] (println log))
                         (println (rotate/summary r))
                         r)))]
        (when-not (every? #(= "ok" (:state %)) results) (System/exit 1))))))

;; ================================================================ agent (client of cljpass.broker)

(defn- agent-call [req]
  (let [{:keys [ok result error]} (broker/request req)]
    (if ok result (die error))))

(defn- field-map [xs]
  (into {} (for [x xs :let [[k v] (str/split (str x) #"=" 2)]] [k (or v "")])))

(defn- changes-of [opts]
  (cond-> (select-keys opts [:title :username :url :notes :folder :expires :tags :add-tags])
    (:field opts) (assoc :fields (field-map (:field opts)))
    (:remove-field opts) (assoc :remove-fields (vec (:remove-field opts)))))

(defn- flag-words
  "A flag directly before a word swallows it as its value (cli/parse):
   give the word back to the positional arguments."
  [opts ks args]
  (concat args (keep #(let [v (get opts %)] (when (string? v) v)) ks)))

(defn cmd-agent [{:keys [opts args]}]
  (let [[sub a b] args
        out #(println (json/write-str %))]
    (case sub
      "askpass" (let [r (broker/request {:op "askpass" :token (System/getenv "CLJPASS_ASKPASS") :prompt a})]
                  (if-let [ans (get-in r [:result :answer])]
                    (do (println ans) (flush))
                    (System/exit 1)))
      "status" (out (agent-call {:op "status"}))
      "find" (out (agent-call {:op "find" :query (str/join " " (flag-words opts [:history] (rest args)))
                               :history (boolean (:history opts))}))
      "show" (out (agent-call {:op "show" :ref a}))
      "history" (out (agent-call {:op "history" :ref a}))
      "set" (out (agent-call {:op "update" :ref a :changes (changes-of opts)}))
      "new" (out (agent-call {:op "create" :changes (cond-> (changes-of opts) (:generate opts) (assoc :generate true))}))
      "generate" (out (agent-call {:op "generate" :ref a :options (when (:length opts) {:length (:length opts)})}))
      "delete" (out (agent-call {:op "delete" :ref a}))
      "group" (out (agent-call {:op "group" :parent (if b a "") :name (or b a)}))
      ;; The changer cljpass started fetches "old" and "new" here: over the
      ;; socket of that one change, with its one-time token, once each.
      "secret" (let [{:keys [value error]} (ipc/secret a)]
                 (if value
                   (do (println value) (flush))
                   (do (binding [*out* *err*] (println error)) (System/exit 1))))
      "rotation" (out (agent-call {:op "rotation"}))
      "rotate" (out (agent-call {:op "rotate" :ref a :code (:code opts) :probe (boolean (:probe opts))}))
      "ssh" (out (agent-call {:op "ssh-open" :ref a :minutes (:minutes opts)}))
      "ssh-close" (out (agent-call {:op "ssh-close" :name a}))
      "channels" (out (agent-call {:op "channels"}))
      (println (i18n/t :cli/agent-usage)))))

(def table
  [{:cmds ["gui"] :fn cmd-gui :coerce {:idle :long :smoke :long}}
   {:cmds ["server"] :fn cmd-server :coerce {:port :long}}
   {:cmds ["enroll"] :fn cmd-enroll}
   {:cmds ["status"] :fn cmd-status}
   {:cmds ["sync"] :fn cmd-sync}
   {:cmds ["list"] :fn cmd-list}
   {:cmds ["fingerprint"] :fn cmd-fingerprint}
   {:cmds ["init"] :fn cmd-init}
   {:cmds ["requests"] :fn cmd-requests}
   {:cmds ["approve"] :fn cmd-approve :args->opts [:user]}
   {:cmds ["disable"] :fn cmd-disable :args->opts [:user]}
   {:cmds ["group"] :fn cmd-group :args->opts (cons :group (repeat :members)) :coerce {:members []}}
   {:cmds ["ad-sync"] :fn cmd-ad-sync}
   {:cmds ["auto-approve"] :fn cmd-auto-approve :coerce {:watch :long}}
   {:cmds ["audit"] :fn cmd-audit :coerce {:since :long}}
   {:cmds ["export-device"] :fn cmd-export-device}
   {:cmds ["import-device"] :fn cmd-import-device :args->opts [:file]}
   {:cmds ["recover"] :fn cmd-recover :args->opts [:user]}
   {:cmds ["open"] :fn cmd-open :args->opts [:file]}
   {:cmds ["connect"] :fn cmd-connect}
   {:cmds ["disconnect"] :fn cmd-disconnect :args->opts [:file]}
   {:cmds ["kdbx-import"] :fn cmd-kdbx-import :args->opts [:file]}
   {:cmds ["kdbx-sync"] :fn cmd-kdbx-sync :args->opts [:file]}
   {:cmds ["kdbx-export"] :fn cmd-kdbx-export :args->opts [:file]}
   {:cmds ["import"] :fn cmd-import :args->opts [:file]}
   {:cmds ["export"] :fn cmd-export :args->opts [:file]}
   {:cmds ["rotate"] :fn cmd-rotate}
   {:cmds ["agent"] :fn cmd-agent :coerce {:field [] :remove-field [] :minutes :long :length :long}}
   {:cmds ["help"] :fn (fn [_] (println (usage)))}
   {:cmds [] :fn (fn [m] (if (or (seq (:args m)) (seq (:opts m))) (println (usage)) (cmd-gui m)))}])

(defn- console-encoding!
  "Console output with non-ASCII characters: on Windows in the console's
   encoding, otherwise UTF-8 (the native binary does not detect the locale
   reliably)."
  []
  (let [cs (or (when (local/windows?) (some-> (System/console) (.charset)))
               java.nio.charset.StandardCharsets/UTF_8)
        w #(java.io.PrintWriter. (java.io.OutputStreamWriter. ^java.io.OutputStream % ^java.nio.charset.Charset cs) true)]
    (alter-var-root #'*out* (constantly (w System/out)))
    (alter-var-root #'*err* (constantly (w System/err)))))

(defn -main [& args]
  (console-encoding!)
  (i18n/set-lang! (local/preferred-lang))
  (try
    (cli/dispatch table args {:coerce {:port :long}})
    ;; background threads (agents/futures) must not delay the exit
    (shutdown-agents)
    (catch clojure.lang.ExceptionInfo e
      (if (:type (ex-data e))
        (die (i18n/t :cli/error {:message (ex-message e)}))
        (throw e)))
    (catch java.nio.file.NoSuchFileException e
      (die (i18n/t :cli/file-not-found {:file (ex-message e)})))))
