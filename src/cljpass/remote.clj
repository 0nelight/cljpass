(ns cljpass.remote
  "The client's HTTP access to the object store server (JDK HttpClient).

   Error bodies with \"msg\" (an i18n key \"area/key\") and \"params\" are
   rethrown with that key, so the text appears in the client's language."
  (:require [clojure.string :as str]
            [cljpass.auth :as auth]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.json :as json]
            [cljpass.negotiate :as negotiate])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest HttpRequest$BodyPublishers
            HttpResponse HttpResponse$BodyHandlers]
           [java.time Duration]))

(def timeout-ms 8000)

(defonce ^:private client
  (delay (-> (HttpClient/newBuilder)
             (.connectTimeout (Duration/ofMillis timeout-ms))
             (.followRedirects HttpClient$Redirect/NEVER)
             (.build))))

(defn- offline! [e]
  (throw (ex-info (i18n/t :core/server-unreachable {:detail (ex-message e)})
                  {:type :offline :msg :core/server-unreachable :params {:detail (ex-message e)}}
                  e)))

(defn- request
  "{:method :get|:put :uri :headers {} :body bytes} -> {:status :body}"
  [{:keys [method uri headers ^bytes body]}]
  (try
    (let [b (reduce (fn [^java.net.http.HttpRequest$Builder b [k v]] (.header b k v))
                    (-> (HttpRequest/newBuilder (URI/create uri))
                        (.timeout (Duration/ofMillis timeout-ms))
                        (.method (str/upper-case (name method))
                                 (if body
                                   (HttpRequest$BodyPublishers/ofByteArray body)
                                   (HttpRequest$BodyPublishers/noBody))))
                    headers)
          ^HttpResponse r (.send ^HttpClient @client (.build ^java.net.http.HttpRequest$Builder b)
                                 (HttpResponse$BodyHandlers/ofString))]
      {:status (.statusCode r) :body (.body r)})
    ;; connection errors and timeouts are IOExceptions (possibly wrapped)
    (catch Exception e
      (if (some #(instance? java.io.IOException %) (take-while some? (iterate ex-cause e)))
        (offline! e)
        (throw e)))))

(defn- base [server] (str/replace server #"/+$" ""))

(defn- parse-error
  "{:status :type :message}, plus :server-msg (keyword) and :server-params
   when the error body carries an i18n key."
  [{:keys [status body]}]
  (let [m (try (json/read-str body) (catch Exception _ nil))
        k (when (and (string? (:msg m)) (seq (:msg m))) (keyword (:msg m)))]
    (cond-> {:status status :type (keyword (or (:type m) "error")) :message (or (:error m) (str "HTTP " status))}
      k (assoc :server-msg k :server-params (when (map? (:params m)) (:params m))))))

(defn- server-error
  "Exception for an error response: with the server's i18n key if it sent
   one, otherwise with the local key k and params."
  [e k params data]
  (let [data (dissoc data :server-msg :server-params)]
    (if-let [sk (:server-msg e)]
      (i18n/error sk (:server-params e) data)
      (i18n/error k params data))))

(defn fetch-org
  "org.json from the server (public). The caller checks the pin."
  [server]
  (let [r (request {:method :get :uri (str (base server) "/v1/org")})]
    (if (= 200 (:status r))
      (:body r)
      (let [e (parse-error r)]
        (throw (server-error e :core/vault-fetch-failed {:detail (:message e)} e))))))

(defn changes
  "Objects with seq > since. Returns {:objects [...] :more bool}."
  [server ident since]
  (let [path (str "/v1/changes?since=" since "&limit=1000")
        r (request {:method :get :uri (str (base server) path)
                    :headers {"Authorization" (auth/header ident :get path nil)}})]
    (case (:status r)
      200 (json/read-str (:body r))
      401 (throw (i18n/error :core/not-enabled nil {:type :unauthorized}))
      (let [e (parse-error r)]
        (throw (if (:server-msg e)
                 (server-error e nil nil e)
                 (ex-info (:message e) e)))))))

(defn put-object!
  "Returns :ok, :conflict or throws {:type :rejected}/{:type :offline}."
  [server ident path ^String body & [{:keys [init-token]}]]
  (let [bytes (c/utf8 body)
        upath (str "/v1/objects/" path)
        r (request {:method :put :uri (str (base server) upath)
                    :headers (cond-> {"Content-Type" "application/json"
                                      "Authorization" (auth/header ident :put upath bytes)}
                               init-token (assoc "X-Init-Token" init-token))
                    :body bytes})]
    (case (:status r)
      (200 201) :ok
      409 :conflict
      (let [e (parse-error r)]
        (throw (server-error e :core/server-rejected {:detail (:message e)}
                             (assoc e :type :rejected :server-type (:type e))))))))

(defn enroll-kerberos!
  "Enrollment with the Windows logon (§8.1): request + escrow in one POST,
   authenticated by Kerberos. Returns {:user :principal}."
  [server {:keys [request escrow]}]
  (let [r (negotiate/post (str (base server) "/v1/enroll") (json/write-str {:request request :escrow escrow}))]
    (if (= 201 (:status r))
      (select-keys (json/read-str (:body r)) [:user :principal])
      (let [e (parse-error r)]
        (throw (server-error e :core/server-rejected {:detail (:message e)}
                             (assoc e :type (if (= 401 (:status r)) :kerberos :rejected) :server-type (:type e))))))))

(defn- admin-get
  "GET for admins (signed). Returns the parsed body."
  [server ident path]
  (let [r (request {:method :get :uri (str (base server) path)
                    :headers {"Authorization" (auth/header ident :get path nil)}})]
    (if (= 200 (:status r))
      (json/read-str (:body r))
      (let [e (parse-error r)]
        (throw (server-error e :core/server-rejected {:detail (:message e)} (assoc e :type :rejected)))))))

(defn attestations
  "Kerberos confirmations of the server: [{:user :sign-pub :principal :at}]."
  [server ident]
  (:attestations (admin-get server ident "/v1/kerberos")))

(defn audit-log
  "Audit entries with seq > since: {:entries [...] :more bool}."
  [server ident since limit]
  (admin-get server ident (str "/v1/audit?since=" since "&limit=" limit)))
