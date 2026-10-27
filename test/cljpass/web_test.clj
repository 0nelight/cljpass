(ns cljpass.web-test
  "Protection of the local UI: host check, token/cookie, origin, CSP; UI texts per language."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [cljpass.fs :as fs]
            [cljpass.json :as json]
            [cljpass.local :as local]
            [cljpass.service :as svc]
            [cljpass.web :as web]))

(defn- raw
  "HTTP/1.1 request over a raw socket (so that wrong Host headers can be
   sent as well). Returns {:status :headers :body}."
  [port method path headers & [body]]
  (with-open [s (java.net.Socket. "127.0.0.1" (int port))]
    (let [out (.getOutputStream s)
          b (.getBytes (or body "") "UTF-8")
          req (str method " " path " HTTP/1.1\r\n"
                   (apply str (for [[k v] (merge {"Host" (str "127.0.0.1:" port) "Connection" "close"
                                                  "Content-Length" (str (alength b))} headers)]
                                (str k ": " v "\r\n")))
                   "\r\n")]
      (.write out (.getBytes req "UTF-8"))
      (.write out b)
      (.flush out)
      (let [resp (slurp (.getInputStream s))
            [head body] (str/split resp #"\r\n\r\n" 2)
            [status-line & hs] (str/split-lines head)]
        {:status (parse-long (second (str/split status-line #" ")))
         :headers (into {} (for [h hs :let [[k v] (str/split h #":\s*" 2)]] [(str/lower-case k) v]))
         :body body}))))

(deftest local-web-protection
  ;; with-redefs: the server answers on its own threads, a binding would not reach them
  (with-redefs [local/*home* (str (fs/create-temp-dir))]
    (let [session (svc/new-session {})
          {:keys [port token stop]} (web/start! session {})
          api (fn [headers] (raw port "POST" "/api/status" headers "{}"))
          good {"Cookie" (str "av=" token) "Origin" (str "http://127.0.0.1:" port) "X-CljPass" "1"
                "Content-Type" "application/json"}]
      (try
        (testing "foreign Host header (DNS rebinding) is rejected"
          (is (= 421 (:status (raw port "GET" "/" {"Host" "evil.example:80" "Cookie" (str "av=" token)})))))
        (testing "no access without token/cookie"
          (is (= 401 (:status (raw port "GET" "/" {}))))
          (is (= 401 (:status (raw port "GET" "/?t=falsch" {}))))
          (is (= 401 (:status (api (dissoc good "Cookie"))))))
        (testing "token in the start URL sets an HttpOnly/SameSite cookie"
          (let [r (raw port "GET" (str "/?t=" token) {})]
            (is (= 303 (:status r)))
            (is (str/includes? (get-in r [:headers "set-cookie"]) "HttpOnly"))
            (is (str/includes? (get-in r [:headers "set-cookie"]) "SameSite=Strict"))))
        (testing "page with cookie, strict CSP"
          (let [r (raw port "GET" "/" {"Cookie" (str "av=" token)})]
            (is (= 200 (:status r)))
            (is (str/includes? (get-in r [:headers "content-security-policy"]) "script-src 'self'"))
            (is (= "DENY" (get-in r [:headers "x-frame-options"])))))
        (testing "API only with own origin and X-CljPass header"
          (is (= 403 (:status (api (assoc good "Origin" "https://evil.example")))))
          (is (= 403 (:status (api (dissoc good "X-CljPass")))))
          (let [r (api good)]
            (is (= 200 (:status r)))
            (is (str/includes? (:body r) "not-enrolled"))))
        (testing "UI texts in the language of the X-CljPass-Lang header"
          (let [texts (fn [lang] (let [r (raw port "POST" "/api/i18n" (assoc good "X-CljPass-Lang" lang) "{}")]
                                   (is (= 200 (:status r)))
                                   (get-in (json/read-str (:body r)) [:result :messages])))
                de (texts "de")
                en (texts "en")]
            ;; cljpass.json reads keys as keywords: "ui/cancel" -> :ui/cancel
            (is (= "Abbrechen" (get de :ui/cancel)))
            (is (= "Eintrag löschen" (get de :ui/entry-delete)))
            (is (= "Cancel" (get en :ui/cancel)))
            (is (= "Delete entry" (get en :ui/entry-delete)))))
        (testing "error texts in the requested language"
          (let [r (raw port "POST" "/api/no-such-op" (assoc good "X-CljPass-Lang" "de") "{}")]
            (is (= 404 (:status r)))
            (is (str/includes? (:body r) "Unbekannte Aktion"))))
        (finally (stop))))))
