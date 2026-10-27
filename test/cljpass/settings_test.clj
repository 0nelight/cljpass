(ns cljpass.settings-test
  "KeePass parity stage 2.6: expiry with time of day, recently opened files,
   adjustable lock."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.fs :as fs]
            [cljpass.kdbx :as k]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.service :as svc]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- tmp-file [n] (str (fs/path (fs/create-temp-dir) n)))

(defn- times-of [file title]
  (let [xml (:xml (k/read-kdbx (fs/read-bytes file) {:password "m"}))
        e (first (for [g (tree-seq #(= :Group (:tag %)) #(k/children % :Group) (k/child (k/child xml :Root) :Group))
                       e (k/children g :Entry)
                       :when (= title (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value)) (k/children e :String)))]
                   e))]
    [(k/child-text (k/child e :Times) :Expires) (k/child-text (k/child e :Times) :ExpiryTime)
     (count (k/children (k/child e :History) :Entry))]))

(defn- sa-payload [s id] ((requiring-resolve 'cljpass.standalone/payload) (:file @s) id))

(deftest expiry-with-time
  (testing "normal form"
    (is (= "" (kp/norm-expires "")))
    (is (= "2030-06-01" (kp/norm-expires "2030-06-01")))
    (is (= "2030-06-01" (kp/norm-expires "2030-06-01T00:00:00Z")))
    (is (= "2030-06-01T14:30:00Z" (kp/norm-expires "2030-06-01T14:30:00.123Z")))
    (is (nil? (kp/norm-expires "bald"))))
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "ablauf.kdbx")]
      (svc/open-file! s {:file file :password "m" :create true :kdf fast})
      (let [id (svc/save-entry s {:title "Zert" :password "x" :expires "2030-06-01T14:30:00Z"})]
        (testing "date and time in the file like KeePass"
          (is (= ["True" "2030-06-01T14:30:00Z" 0] (times-of file "Zert")))
          (is (= "2030-06-01T14:30:00Z" (:expires (svc/get-entry s id)))))
        (testing "older state with a plain date: time stays, no history item"
          (let [p (assoc (sa-payload s id) :expires "2030-06-01")
                out (:xml (kp/export-doc [{:payload p :id id}] {}))
                e (first (filter #(= :Entry (:tag %)) (tree-seq #(#{:KeePassFile :Root :Group} (:tag %)) :content out)))]
            (is (= "2030-06-01T14:30:00Z" (k/child-text (k/child e :Times) :ExpiryTime)))
            (is (empty? (k/children (k/child e :History) :Entry)))
            (is (kp/unchanged-since? (kp/core-hash p) (sa-payload s id))
                "marker from before the time of day (date only): counts as unchanged")
            (is (not (kp/unchanged-since? (kp/core-hash (sa-payload s id))
                                          (assoc (sa-payload s id) :expires "2030-06-01T15:00:00Z")))
                "only the time changed: detected")))
        (testing "changing the time is a change (with history)"
          (svc/save-entry s (assoc (svc/get-entry s id) :expires "2030-06-01T18:00:00Z"))
          (is (= ["True" "2030-06-01T18:00:00Z" 1] (times-of file "Zert"))))
        (testing "plain date: midnight UTC"
          (svc/save-entry s (assoc (svc/get-entry s id) :expires "2031-01-02"))
          (is (= ["True" "2031-01-02T00:00:00Z" 2] (times-of file "Zert")))
          (is (= "2031-01-02" (:expires (svc/get-entry s id)))))
        (testing "no expiry"
          (svc/save-entry s (assoc (svc/get-entry s id) :expires ""))
          (is (= "False" (first (times-of file "Zert")))))))))

(deftest recent-files-and-idle
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          a (tmp-file "a.kdbx") b (tmp-file "b.kdbx")]
      (svc/open-file! s {:file a :password "m" :create true :kdf fast})
      (svc/lock! s)
      (svc/open-file! s {:file b :password "m" :create true :kdf fast})
      (svc/lock! s)
      (svc/open-file! s {:file a :password "m"})
      (is (= [(fs/absolutize a) (fs/absolutize b)] (svc/recent-files)) "newest first, without duplicates")
      (testing "lock after idle time is adjustable"
        (svc/set-idle! s 0)
        (swap! s assoc :last-activity 0)
        (is (nil? (svc/check-idle! s)) "0 = never lock")
        (svc/set-idle! s 1)
        (swap! s assoc :last-activity 0)
        (is (true? (svc/check-idle! s))))
      (testing "passwords for the list only on request"
        (svc/open-file! s {:file a :password "m"})
        (let [id (svc/save-entry s {:title "X" :password "pw"})]
          (is (= {id "pw"} (svc/passwords s [id]))))))))

(defn- free-port [] (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(deftest expiry-time-survives-server-roundtrip
  (let [port (free-port)
        url (str "http://127.0.0.1:" port)
        stop ((requiring-resolve 'cljpass.server/start!) {:db (str (fs/path (fs/create-temp-dir) "server.db")) :port port :bind "127.0.0.1" :init-token "t"})
        s (svc/new-session {})
        ident ((requiring-resolve 'cljpass.identity/new-identity) "admin")]
    (try
      (binding [local/*home* (str (fs/create-temp-dir))]
        (let [{:keys [org-hash]} ((requiring-resolve 'cljpass.admin/init-org!) url "t" "Example" ident)
              by-title (fn [t] (first (filter #(= t (:title %)) (:entries (svc/list-entries s)))))]
          (local/save-identity! ident :file)
          (local/save-config! {:server url :org-hash org-hash :user "admin"})
          (svc/unlock! s)
          (svc/save-entry s {:title "Zert" :password "x" :expires "2030-06-01T14:30:00Z"})
          (svc/save-entry s {:title "Old" :password "y" :expires "2030-06-01"})
          (svc/disconnect! s {:file (tmp-file "getrennt.kdbx") :password "m" :kdf fast})
          (testing "change only the time while disconnected"
            (svc/save-entry s (assoc (svc/get-entry s (:id (by-title "Zert"))) :expires "2030-06-01T18:00:00Z")))
          (svc/connect-server! s {:server url :org-hash org-hash :user "admin"})
          (let [r (svc/finish-connect! s)]
            (is (= {:updated 1 :copied 0 :created 0} (select-keys r [:updated :copied :created]))
                "the time goes into the vault, the entry with a plain date stays unchanged"))
          (is (= "2030-06-01T18:00:00Z" (:expires (by-title "Zert"))))
          (is (= "2030-06-01" (:expires (by-title "Old"))))))
      (finally (stop)))))
