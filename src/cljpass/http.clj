(ns cljpass.http
  "Small HTTP server on com.sun.net.httpserver (in the JDK, also works with
   native-image). Handlers as in Ring:
     request   {:request-method :get :uri \"/..\" :query-string \"..\"
                :headers {\"host\" \"..\"} :body InputStream}
     response  {:status 200 :headers {\"..\" \"..\"} :body String|bytes|nil}"
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io ByteArrayInputStream InputStream]
           [java.net InetAddress InetSocketAddress]
           [java.util.concurrent Executors ExecutorService]))

(defn- read-body
  "Reads at most max-body bytes; nil if there are more."
  [^InputStream in max-body]
  (let [b (.readNBytes in (int (inc max-body)))]
    (when (<= (alength b) max-body) b)))

(defn- request [^HttpExchange ex body]
  (let [uri (.getRequestURI ex)]
    {:request-method (keyword (str/lower-case (.getRequestMethod ex)))
     :uri (.getRawPath uri)
     :query-string (.getRawQuery uri)
     :headers (into {} (for [[k vs] (.getRequestHeaders ex)]
                         [(str/lower-case k) (str/join "," vs)]))
     :remote-addr (some-> (.getRemoteAddress ex) .getAddress .getHostAddress)
     :body (ByteArrayInputStream. body)}))

(defn- send! [^HttpExchange ex {:keys [status headers body]}]
  (let [^bytes b (cond (nil? body) nil
                       (bytes? body) body
                       :else (.getBytes (str body) "UTF-8"))
        hs (.getResponseHeaders ex)]
    (doseq [[k v] headers] (.set hs (str k) (str v)))
    (.sendResponseHeaders ex (int (or status 200)) (if (and b (pos? (alength b))) (alength b) -1))
    (when (and b (pos? (alength b)))
      (with-open [out (.getResponseBody ex)] (.write out b)))
    (.close ex)))

(defn run-server
  "Starts the server and returns a stop function.
   opts: {:ip \"127.0.0.1\" :port 8080 :max-body bytes :threads 16}"
  [handler {:keys [ip port max-body threads] :or {ip "0.0.0.0" max-body (* 1024 1024) threads 16}}]
  (let [server (HttpServer/create (InetSocketAddress. (InetAddress/getByName ip) (int port)) 64)
        ^ExecutorService pool (Executors/newFixedThreadPool (int threads))]
    (.createContext server "/"
                    (reify HttpHandler
                      (handle [_ ex]
                        (try
                          (if-let [body (read-body (.getRequestBody ex) max-body)]
                            (send! ex (handler (request ex body)))
                            (send! ex {:status 413 :headers {"Content-Type" "text/plain; charset=utf-8"}
                                       :body (i18n/t :core/http-request-too-large)}))
                          (catch Throwable t
                            (try (send! ex {:status 500 :body (i18n/t :core/http-internal-error)}) (catch Throwable _ nil))
                            (when-not (instance? java.io.IOException t)
                              (binding [*out* *err*] (println "HTTP error:" (ex-message t)))))))))
    (.setExecutor server pool)
    (.start server)
    (fn stop []
      (.stop server 0)
      (.shutdownNow pool))))
