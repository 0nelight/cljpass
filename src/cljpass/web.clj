(ns cljpass.web
  "Local web UI. Runs only on 127.0.0.1 with a random port.

   The client no longer uses it (desktop UI: cljpass.desktop). It is kept
   as the basis for a Firefox add-on and is still tested. To try it:
   clojure -M:web

   Protections:
   - Access token (256 bits) only in the start URL; after that an HttpOnly
     cookie with SameSite=Strict.
   - The Host header must be 127.0.0.1:<port> (against DNS rebinding).
   - API only via POST with Origin = own address and header X-CljPass
     (foreign pages fail at the CORS preflight).
   - Strict Content-Security-Policy, no inline script, no framing.
   - Private keys never leave the process. On Windows passwords go
     straight to the clipboard, not to the browser.

   Language: header X-CljPass-Lang, else the user's setting."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [cljpass.clipboard :as clip]
            [cljpass.crypto :as c]
            [cljpass.http :as http]
            [cljpass.i18n :as i18n]
            [cljpass.json :as json]
            [cljpass.local :as local]
            [cljpass.proc :as proc]
            [cljpass.service :as svc]))

(def ^:private security-headers
  {"Content-Security-Policy" (str "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                  "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
   "X-Frame-Options" "DENY"
   "X-Content-Type-Options" "nosniff"
   "Referrer-Policy" "no-referrer"
   "Cache-Control" "no-store"})

(defn- json-resp [status data]
  {:status status
   :headers (assoc security-headers "Content-Type" "application/json; charset=utf-8")
   :body (json/write-str data)})

(def ^:private assets
  {"/" ["ui/index.html" "text/html; charset=utf-8"]
   "/app.js" ["ui/app.js" "text/javascript; charset=utf-8"]
   "/app.css" ["ui/app.css" "text/css; charset=utf-8"]})

(defn- asset [path]
  (when-let [[res ctype] (assets path)]
    {:status 200
     :headers (assoc security-headers "Content-Type" ctype)
     :body (slurp (io/resource res))}))

(defn- cookie [req]
  (some->> (get-in req [:headers "cookie"])
           (re-find #"(?:^|;\s*)av=([A-Za-z0-9_-]+)")
           second))

(defn- token= [a b] (and a b (c/bytes= (c/utf8 a) (c/utf8 b))))

;; ================================================================ API

(defn- opts-of [m] (into {} (for [[k v] m] [(keyword k) v])))

(defn- api [session op p]
  (case op
    ;; texts of the web UI in the requested language
    "i18n" (let [l i18n/*lang*]
             {:lang l :languages i18n/languages :auto (nil? (:lang (local/load-prefs)))
              :messages (i18n/ui-catalog l)})
    ;; language choice: "en", "de" or "auto" (operating system)
    "set-lang" (do (local/update-prefs! #(if-let [l (i18n/normalize (:lang p))] (assoc % :lang l) (dissoc % :lang)))
                   {:lang (local/preferred-lang)})
    "status" (svc/status session)
    "enroll" (svc/enroll! session (select-keys p [:server :org-hash :user]))
    "unlock" (do (svc/unlock! session) (svc/status session))
    ;; local mode (KeePass file) and switching between file and server
    "open-file" (do (svc/open-file! session {:file (:file p) :password (:password p)
                                            :keyfile (some-> (:keyfile p) not-empty c/unb64)
                                            :create (true? (:create p))})
                    (svc/status session))
    "pick-file" (cond
                  (true? (:probe p)) {:supported (local/windows?)}
                  :else (let [r (local/pick-file {:save (true? (:save p)) :file (:file p)})]
                          (if (= :unsupported r) {:supported false} {:supported true :file r})))
    "sync-file" (svc/sync-file! session {:file (:file p) :password (:password p)
                                         :keyfile (some-> (:keyfile p) not-empty c/unb64)})
    "connect" (svc/connect-server! session (select-keys p [:server :org-hash :user]))
    "connect-finish" (svc/finish-connect! session)
    "connect-cancel" (svc/cancel-connect! session)
    "disconnect" (svc/disconnect! session {:file (:file p) :password (:password p)
                                           :keyfile (some-> (:keyfile p) not-empty c/unb64)
                                           :overwrite (true? (:overwrite p)) :force (true? (:force p))})
    "lock" (do (svc/lock! session) {:state :locked})
    "sync" (svc/sync-now session)
    "entries" (assoc (svc/list-entries session)
                     :pending (svc/pending-count session)
                     :conflicts (count (svc/conflicts session)))
    "entry" (svc/get-entry session (:id p))
    "save" (svc/save-entry session p)
    "duplicate" (svc/duplicate-entry session (:id p))
    "delete" (svc/delete-entry session (:id p))
    "copy" (let [v (svc/get-field session (:id p) (:field p))]
             (if (clip/native?)
               (do (clip/copy! v) {:copied true :clear-after clip/clear-seconds})
               {:copied false :value v :clear-after clip/clear-seconds}))
    "reveal" {:value (svc/get-field session (:id p) (:field p))}
    "principals" (svc/principals session)
    "acl" (svc/get-acl session (:id p))
    "set-acl" (svc/set-acl session (:id p) (:acl p))
    "history" (svc/history session (:id p))
    "conflicts" (svc/conflicts session)
    "resolve" (svc/resolve-conflict session (:id p) (keyword (:action p)))
    "generate" (let [pw (svc/generate-password (opts-of p))]
                 {:password pw :quality (svc/password-quality pw)})
    "quality" {:quality (svc/password-quality (str (:password p)))}
    "kdbx-import" (svc/import-kdbx session {:data (c/unb64 (str (:data p)))
                                            :password (:password p)
                                            :keyfile (some-> (:keyfile p) not-empty c/unb64)
                                            :source (:name p)})
    "kdbx-export" (let [{:keys [data count]} (svc/export-kdbx session {:password (:password p)
                                                                        :keyfile (some-> (:keyfile p) not-empty c/unb64)})]
                    {:data (c/b64 data) :count count})
    (throw (i18n/error :ui/unknown-action {:op op} {:type :not-found}))))

(defn- error-status [t]
  (case t
    :locked 423 :not-enrolled 409 :forbidden 403 :not-found 404
    (:conflict :group-not-ready :exists :pending-changes :pending :standalone) 409
    :offline 503
    :kdbx-bad-key 422
    400))

(defn handler [{:keys [session token port]}]
  (let [origin (str "http://127.0.0.1:" port)
        host (str "127.0.0.1:" port)]
    (fn [req]
      (let [uri (:uri req) m (:request-method req)]
        ;; language per request: X-CljPass-Lang, else the user's setting
        (binding [i18n/*lang* (or (i18n/normalize (get-in req [:headers "x-cljpass-lang"]))
                                  (local/preferred-lang))]
          (cond
            (not= host (get-in req [:headers "host"]))
            {:status 421 :body (i18n/t :ui/wrong-host)}

            ;; entry with token -> set cookie
            (and (= :get m) (= "/" uri) (token= token (second (re-find #"(?:^|&)t=([A-Za-z0-9_-]+)" (str (:query-string req))))))
            {:status 303
             :headers (assoc security-headers
                             "Location" "/"
                             "Set-Cookie" (str "av=" token "; HttpOnly; SameSite=Strict; Path=/"))}

            (not (token= token (cookie req)))
            {:status 401 :headers (assoc security-headers "Content-Type" "text/plain; charset=utf-8")
             :body (i18n/t :ui/open-from-start-menu)}

            (= :get m) (or (asset uri) {:status 404 :body (i18n/t :ui/not-found)})

            (and (= :post m) (str/starts-with? uri "/api/"))
            (if-not (and (= origin (get-in req [:headers "origin"]))
                         (= "1" (get-in req [:headers "x-cljpass"])))
              (json-resp 403 {:error (i18n/t :ui/request-rejected)})
              (try
                (let [p (json/read-str (slurp (:body req) :encoding "UTF-8"))]
                  (svc/check-idle! session)
                  (binding [svc/*background* (true? (:background p))]
                    (try
                      (json-resp 200 {:ok true :result (api session (subs uri 5) p)})
                      (catch clojure.lang.ExceptionInfo e
                        (let [t (:type (ex-data e))]
                          (json-resp (error-status t) {:error (i18n/message e) :type (some-> t name)})))
                      (catch Exception e
                        (json-resp 500 {:error (i18n/t :core/internal-error {:detail (ex-message e)})})))))
                (catch Exception e
                  (json-resp 500 {:error (i18n/t :core/internal-error {:detail (ex-message e)})}))))

            :else {:status 405 :body (i18n/t :ui/not-allowed)}))))))

(defn- random-token [] (str/replace (c/b64 (c/random-bytes 32)) #"[+/=]" {"+" "-" "/" "_" "=" ""}))

(defn start!
  "Starts the UI. Returns {:url .. :stop fn}."
  [session {:keys [port] :or {port 0}}]
  (let [port (if (pos? port) port (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))
        token (random-token)
        stop (http/run-server (handler {:session session :token token :port port})
                              ;; large enough for the KDBX import (Base64)
                              {:ip "127.0.0.1" :port port :max-body (* 64 1024 1024)})]
    {:url (str "http://127.0.0.1:" port "/?t=" token) :port port :token token :stop stop}))

(defn -main
  "Development only (basis for a Firefox add-on): clojure -M:web"
  [& _]
  (let [s (svc/new-session {:idle-seconds 300})
        _ (when (and (local/identity-exists?) (local/load-config) (not (svc/standalone-mode?))) (svc/unlock! s))
        {:keys [url]} (start! s {})]
    (println (i18n/t :ui/web-ui-url {:url url}))
    (loop [] (Thread/sleep 15000) (svc/check-idle! s) (recur))))

(defn open-browser! [url]
  (try
    (cond
      (local/windows?) (proc/spawn! ["rundll32" "url.dll,FileProtocolHandler" url])
      :else (proc/spawn! ["xdg-open" url]))
    (catch Exception _ nil)))
