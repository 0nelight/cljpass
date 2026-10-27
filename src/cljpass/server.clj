(ns cljpass.server
  "HTTP object store (doc/FORMAT.md §9). The server
   - stores objects in SQLite,
   - only creates objects (except requests/ and escrow/),
   - checks every new object with the same rules as the clients,
   - never sees plaintext and has no keys,
   - optionally checks enrollments with Kerberos (§8.1),
   - writes an audit log (§9.2).

   Please terminate TLS at a reverse proxy (Caddy, nginx, IIS).

   Error bodies: {\"error\" text, \"type\" type}, plus \"msg\" (\"area/key\")
   and \"params\" when the text is an i18n key, so the client can show it
   in its own language."
  (:require [clojure.string :as str]
            [cljpass.audit :as audit]
            [cljpass.auth :as auth]
            [cljpass.crypto :as c]
            [cljpass.http :as http]
            [cljpass.i18n :as i18n]
            [cljpass.kerberos :as krb]
            [cljpass.json :as json]
            [cljpass.codec :as codec]
            [cljpass.store :as store]
            [cljpass.vault :as v]))

(defn- respond [status data]
  {:status status
   :headers {"Content-Type" "application/json; charset=utf-8"
             "Cache-Control" "no-store"}
   :body (json/write-str data)})

(defn- error
  "JSON error response. msg is an i18n key (translated here, sent along as
   \"msg\"/\"params\") or a plain text; for a plain text, data may be the
   ex-data of the exception, whose :msg/:params are sent along."
  ([status type msg] (error status type msg nil))
  ([status type msg data]
   (let [[text k params] (if (keyword? msg)
                           [(i18n/t msg data) msg data]
                           [msg (:msg data) (:params data)])]
     (respond status (cond-> {:error text :type (name type)}
                       (keyword? k) (assoc :msg (str (namespace k) "/" (name k))
                                           :params (or params {})))))))

(defn- client-addr
  "Address of the client; behind a reverse proxy (--trust-proxy) the last
   entry of X-Forwarded-For."
  [{:keys [trust-proxy]} req]
  (or (when trust-proxy
        (some-> (get-in req [:headers "x-forwarded-for"]) (str/split #",") last str/trim not-empty))
      (:remote-addr req)))

(defn- audit!
  "Audit entry for a request. m: {:event :user :path :detail}."
  [{:keys [db] :as srv} req m]
  (when db (audit/log! db (assoc m :addr (client-addr srv req)) {:quiet (:quiet-audit srv)})))

(defn- claimed-user
  "User name from the Authorization header (not verified) - for the audit
   log of failed logins."
  [req]
  (:u (auth/parse-header (get-in req [:headers "authorization"]))))

(defn- error-detail [e] {:msg (some-> (:msg (ex-data e)) str) :error (ex-message e)})

(defn- body-bytes ^bytes [req]
  (if-let [b (:body req)] (.readAllBytes ^java.io.InputStream b) (byte-array 0)))

(defn- key-of
  "Public key for authentication: active users in the roster and the
   admins from org.json (for the very first roster)."
  [st]
  (fn [u]
    (try
      (let [org (v/load-org st nil)
            roster (v/latest-roster (v/load-rosters st org))]
        (or (:sign-pub (v/active-user roster u))
            (get-in org [:admins u :sign-pub])))
      (catch Exception _ nil))))

(defn- path-with-query [req]
  (str (:uri req) (when-let [q (:query-string req)] (str "?" q))))

(defn- authenticate [{:keys [nonces]} req body key-fn]
  (auth/verify nonces key-fn (get-in req [:headers "authorization"])
               (:request-method req) (path-with-query req) body))

(defn- admin-key-of
  "Like key-of, but only for the admins from org.json."
  [st]
  (fn [u]
    (try (get-in (v/load-org st nil) [:admins u :sign-pub])
         (catch Exception _ nil))))

(defn- object-path [uri]
  (let [p (subs uri (count "/v1/objects/"))]
    (when (and (seq p) (not (str/includes? p "..")) (not (str/starts-with? p "/"))
               (re-matches #"[a-z0-9._/-]+" p))
      p)))

(defn- store-object!
  "Checks and stores an object. Returns :ok or throws ex-info."
  [st path text]
  (v/validate-new-object st path text)
  (if (store/overwritable? path)
    (store/put-obj! st path text)
    (store/create-obj! st path text))
  :ok)

(defn- object-error
  "Response for a rejected object (and audit entry)."
  [srv req user path e]
  (let [t (:type (ex-data e))]
    (audit! srv req {:event (case t :conflict "object.conflict" :invalid "object.rejected" "object.error")
                     :user user :path path :detail (error-detail e)})
    (case t
      :conflict (error 409 :conflict (ex-message e) (ex-data e))
      :invalid (error 422 :invalid (ex-message e) (ex-data e))
      (error 500 :error (ex-message e) (ex-data e)))))

(defn- handle-put [{:keys [st write-lock init-token require-kerberos] :as srv} req]
  (let [path (object-path (:uri req))
        body (body-bytes req)
        text (String. body "UTF-8")
        doc (try (codec/parse text) (catch Exception _ nil))]
    (cond
      (nil? path) (error 400 :bad-path :core/server-bad-path)
      (nil? doc) (error 400 :bad-json :core/server-not-json)

      ;; setup: org.json only with the init token and only once
      (= path v/org-path)
      (if (and init-token (= init-token (get-in req [:headers "x-init-token"])))
        (locking write-lock
          (try (v/validate-new-object st path text)
               (store/create-obj! st path text)
               (audit! srv req {:event "vault.init" :user (:signer doc) :path path
                                :detail {:name (get-in doc [:body :name])}})
               (respond 201 {:ok true})
               (catch clojure.lang.ExceptionInfo e
                 (audit! srv req {:event "vault.init-rejected" :user (:signer doc) :detail (error-detail e)})
                 (if (= :conflict (:type (ex-data e)))
                   (error 409 :conflict :core/server-vault-exists)
                   (error 422 :invalid (ex-message e) (ex-data e))))))
        (do (audit! srv req {:event "vault.init-denied" :path path})
            (error 403 :forbidden :core/server-init-token-invalid)))

      ;; with Kerberos required, requests only come via /v1/enroll
      (and require-kerberos (str/starts-with? path "requests/"))
      (do (audit! srv req {:event "enroll.denied" :user (:signer doc) :path path :detail {:reason "kerberos required"}})
          (error 403 :forbidden :core/server-kerberos-required))

      :else
      (let [signer (:signer doc)
            ;; requests/escrow: authentication with the key from the request itself
            key-fn (cond
                     (str/starts-with? path "requests/")
                     (fn [u] (when (= u signer) (get-in doc [:body :sign-pub])))
                     (str/starts-with? path "escrow/")
                     (fn [u] (when (= u signer)
                               (or (some-> (store/read-doc st (v/request-path u)) (v/valid-request u) :sign-pub)
                                   ((key-of st) u))))
                     :else (key-of st))
            user (authenticate srv req body key-fn)]
        (cond
          (nil? user) (do (audit! srv req {:event "auth.failed" :user (claimed-user req) :path path})
                          (error 401 :unauthorized :core/server-auth-invalid))
          (not= user signer) (do (audit! srv req {:event "auth.forbidden" :user user :path path
                                                  :detail {:signer signer}})
                                 (error 403 :forbidden :core/server-own-name-only))
          :else
          (locking write-lock
            (try
              (store-object! st path text)
              (audit! srv req {:event (cond (str/starts-with? path "requests/") "enroll.request"
                                            (store/overwritable? path) "object.put"
                                            :else "object.create")
                               :user user :path path
                               :detail (when (str/starts-with? path "requests/")
                                         {:fingerprint (c/fingerprint (get-in doc [:body :sign-pub]))})})
              (respond 201 {:ok true})
              (catch clojure.lang.ExceptionInfo e
                (object-error srv req user path e)))))))))

;; ---------------------------------------------------------------- Kerberos enrollment (§8.1)

(defn- attestation-row [{:keys [user sign_pub principal at]}]
  {:user user :sign-pub sign_pub :principal principal :at at})

(defn attestations
  "Kerberos confirmations: {user {:sign-pub :principal :at}}."
  [db]
  (into {} (for [r (store/sql-query db ["SELECT user, sign_pub, principal, at FROM kerberos ORDER BY user"])]
             [(:user r) (attestation-row r)])))

(defn- negotiate-challenge [status type msg & [params]]
  (-> (error status type msg params)
      (assoc-in [:headers "WWW-Authenticate"] "Negotiate")))

(defn- handle-enroll
  "POST /v1/enroll with \"Authorization: Negotiate ...\" and the body
   {\"request\": \"<doc>\", \"escrow\": \"<doc>\"}: stores request and escrow
   and notes that the request really comes from this domain user."
  [{:keys [st db write-lock kerberos] :as srv} req]
  (let [token (krb/negotiate-token (get-in req [:headers "authorization"]))]
    (cond
      (nil? kerberos) (error 404 :not-found :core/server-kerberos-off)
      (nil? token) (negotiate-challenge 401 :unauthorized :core/server-kerberos-missing)
      :else
      (let [k (try (krb/accept kerberos token)
                   (catch clojure.lang.ExceptionInfo e
                     (audit! srv req {:event "kerberos.failed" :detail {:reason (:reason (ex-data e))}})
                     nil))
            body (try (json/read-str (String. (body-bytes req) "UTF-8")) (catch Exception _ nil))
            req-text (:request body)
            esc-text (:escrow body)
            rdoc (try (codec/parse req-text) (catch Exception _ nil))
            user (get-in rdoc [:body :user])]
        (cond
          (nil? k) (negotiate-challenge 401 :unauthorized :core/server-kerberos-invalid)
          (nil? (:user k))
          (do (audit! srv req {:event "kerberos.failed" :detail {:principal (:principal k) :reason "foreign realm or name"}})
              (error 403 :forbidden :core/server-kerberos-principal {:principal (:principal k)}))
          (not (and (string? req-text) (string? esc-text) rdoc))
          (error 400 :bad-json :core/server-not-json)
          (not= user (:user k))
          (do (audit! srv req {:event "enroll.denied" :user (:user k)
                               :detail {:principal (:principal k) :requested user :reason "other user"}})
              (error 403 :forbidden :core/server-kerberos-other-user {:principal (:principal k)}))
          :else
          (locking write-lock
            (try
              (let [rpath (v/request-path user)]
                (store-object! st rpath req-text)
                (store-object! st (v/escrow-path user) esc-text)
                (store/sql-exec! db ["REPLACE INTO kerberos(user, sign_pub, principal, at) VALUES (?, ?, ?, ?)"
                                     user (get-in rdoc [:body :sign-pub]) (:principal k) (store/now)])
                (audit! srv req {:event "enroll.kerberos" :user user :path rpath
                                 :detail {:principal (:principal k)
                                          :fingerprint (c/fingerprint (get-in rdoc [:body :sign-pub]))}})
                (cond-> (respond 201 {:ok true :user user :principal (:principal k)})
                  (:out k) (assoc-in [:headers "WWW-Authenticate"] (str "Negotiate " (c/b64 (:out k))))))
              (catch clojure.lang.ExceptionInfo e
                (object-error srv req user (v/request-path user) e)))))))))

;; ---------------------------------------------------------------- Admin reads

(defn- query-params [req]
  (into {} (for [kv (str/split (or (:query-string req) "") #"&")
                 :let [[k val] (str/split kv #"=" 2)] :when (seq k)]
             [k val])))

(defn- with-admin
  "(f admin) if the request is signed by an admin from org.json."
  [{:keys [st] :as srv} req event f]
  (if-let [admin (authenticate srv req (byte-array 0) (admin-key-of st))]
    (do (audit! srv req {:event event :user admin}) (f admin))
    (do (audit! srv req {:event "auth.failed" :user (claimed-user req) :path (:uri req)})
        (error 401 :unauthorized :core/server-admins-only))))

(defn- handle-attestations [{:keys [db] :as srv} req]
  (with-admin srv req "kerberos.list"
    (fn [_] (respond 200 {:attestations (vec (vals (attestations db)))}))))

(defn- handle-audit [{:keys [db] :as srv} req]
  (with-admin srv req "audit.read"
    (fn [_]
      (let [params (query-params req)
            since (or (some-> (params "since") parse-long) 0)
            limit (min 5000 (or (some-> (params "limit") parse-long) 1000))
            es (audit/entries db since limit)]
        (respond 200 {:entries es :more (= limit (count es))})))))

(defn- handle-changes [{:keys [st] :as srv} req]
  (if-not (authenticate srv req (byte-array 0) (key-of st))
    ;; not in the audit log: pending clients poll here until approval
    (error 401 :unauthorized :core/server-auth-invalid-or-not-enabled)
    (let [params (query-params req)
          since (or (some-> (params "since") parse-long) 0)
          limit (min 5000 (or (some-> (params "limit") parse-long) 1000))
          objs (store/since st since limit)]
      (respond 200 {:objects objs :more (= limit (count objs))}))))

(defn handler [srv]
  (fn [req]
    (try
      (let [m (:request-method req) uri (:uri req)]
        (cond
          (and (= :get m) (= uri "/v1/health")) (respond 200 {:ok true})
          ;; org.json is public (enrollment needs recovery_pub; the client checks the pin)
          (and (= :get m) (= uri "/v1/org"))
          (if-let [o (store/get-obj (:st srv) v/org-path)]
            {:status 200 :headers {"Content-Type" "application/json"} :body o}
            (error 404 :not-found :core/server-no-vault))
          (and (= :get m) (= uri "/v1/changes")) (handle-changes srv req)
          (and (= :put m) (str/starts-with? uri "/v1/objects/")) (handle-put srv req)
          (and (= :post m) (= uri "/v1/enroll")) (handle-enroll srv req)
          (and (= :get m) (= uri "/v1/kerberos")) (handle-attestations srv req)
          (and (= :get m) (= uri "/v1/audit")) (handle-audit srv req)
          :else (error 404 :not-found :core/server-unknown)))
      (catch Exception e
        (error 500 :error (ex-message e) (ex-data e))))))

(defn start!
  "opts: {:db \"server.db\" :port 8080 :bind \"0.0.0.0\" :init-token \"...\"
          :keytab \"http.keytab\" :principal \"HTTP/pw.example.local@EXAMPLE.LOCAL\" :realm \"EXAMPLE.LOCAL\"
          :require-kerberos bool :trust-proxy bool :quiet-audit bool}
   Kerberos is on as soon as :keytab is given. Returns a stop function."
  [{:keys [db port bind init-token keytab principal realm require-kerberos trust-proxy quiet-audit]
    :or {port 8080 bind "0.0.0.0"}}]
  (when (and require-kerberos (not keytab))
    (throw (i18n/error :core/kerberos-config-incomplete nil {:type :usage})))
  (let [st (store/sqlite-store db)
        srv {:st st
             :db (:db st)
             :nonces (auth/make-nonce-cache)
             :write-lock (Object.)
             :init-token init-token
             :kerberos (when keytab (krb/acceptor {:keytab keytab :principal principal :realm realm}))
             :require-kerberos (boolean require-kerberos)
             :trust-proxy (boolean trust-proxy)
             :quiet-audit (boolean quiet-audit)}]
    (audit/init! (:db srv))
    (store/sql-exec! (:db srv) ["CREATE TABLE IF NOT EXISTS kerberos (
                                   user TEXT PRIMARY KEY,
                                   sign_pub TEXT NOT NULL,
                                   principal TEXT NOT NULL,
                                   at TEXT NOT NULL)"])
    (audit/log! (:db srv) {:event "server.start"
                           :detail {:kerberos (if keytab (str/upper-case realm) "off")
                                    :require_kerberos (boolean require-kerberos)
                                    :init (boolean init-token)}}
                {:quiet quiet-audit})
    (http/run-server (handler srv) {:port port :ip bind :max-body (* 4 1024 1024)})))
