(ns cljpass.service-test
  "End to end: real HTTP server with SQLite, several clients with their own
   local cache, offline mode and conflicts."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.fs :as fs]
            [cljpass.admin :as admin]
            [cljpass.identity :as idn]
            [cljpass.local :as local]
            [cljpass.server :as server]
            [cljpass.service :as svc]
            [cljpass.vault :as v]))

(defn- free-port []
  (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(defn- msg-of
  "Message key (:msg of ex-data) of the exception thrown by (f), or nil."
  [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defmacro as [homes user & body]
  `(binding [local/*home* (get ~homes ~user)] ~@body))

(deftest end-to-end
  (let [port (free-port)
        url (str "http://127.0.0.1:" port)
        db (str (fs/path (fs/create-temp-dir) "server.db"))
        stop (atom (server/start! {:db db :port port :bind "127.0.0.1" :init-token "secret"}))
        homes (into {} (for [u ["admin" "alice" "bob"]] [u (str (fs/create-temp-dir))]))
        sessions (into {} (for [u (keys homes)] [u (svc/new-session {:idle-seconds 300})]))
        S #(get sessions %)
        admin-ident (idn/new-identity "admin")]
    (try
      ;; ---------------------------------------------------------- Setup
      (let [{:keys [org-hash recovery-priv]} (admin/init-org! url "secret" "Example Ltd" admin-ident)]
        (is (string? recovery-priv))
        (as homes "admin"
            (local/save-identity! admin-ident :file)
            (local/save-config! {:server url :org-hash org-hash :user "admin"})
            (svc/unlock! (S "admin"))
            (is (= :active (:state (svc/status (S "admin"))))))

        (testing "wrong init token is rejected"
          (is (= :core/server-init-token-invalid
                 (msg-of #(admin/init-org! url "falsch" "X" (idn/new-identity "evil"))))))

        (testing "Enrollment: pending until approval by fingerprint"
          (doseq [u ["alice" "bob"]]
            (as homes u
                (let [{:keys [fingerprint]} (svc/enroll! (S u) {:server url :org-hash org-hash :user u :protector :file})]
                  (is (= :pending (:state (svc/status (S u)))))
                  (as homes "admin"
                      (svc/sync-now (S "admin"))
                      (is (= :app/fingerprint-mismatch
                             (msg-of #(svc/with-ctx (S "admin") (fn [ctx] (admin/approve! ctx admin-ident u {:fingerprint "0000"}))))))
                      (svc/with-ctx (S "admin") #(admin/approve! % admin-ident u {:fingerprint fingerprint}))))
                (is (= :active (:state (svc/status (S u))))))))

        (testing "wrong pin is detected"
          (is (= :core/org-pin-mismatch
                 (msg-of #(as homes "alice"
                              (binding [local/*home* (str (fs/create-temp-dir))]
                                (svc/enroll! (svc/new-session {}) {:server url :org-hash "falsch" :user "eve" :protector :file})))))))

        ;; ---------------------------------------------------------- Sharing
        (let [id (as homes "alice" (svc/save-entry (S "alice") {:title "Firewall" :username "root"
                                                                :password "pw1" :folder "Netzwerk"}))]
          (as homes "alice"
              (svc/set-acl (S "alice") id [{:principal "u:alice" :permission "owner"}
                                           {:principal "u:bob" :permission "read"}]))
          (testing "bob sees the entry after sync and can read the password"
            (as homes "bob"
                (svc/sync-now (S "bob"))
                (is (= ["Firewall"] (map :title (:entries (svc/list-entries (S "bob"))))))
                (is (= "pw1" (svc/get-field (S "bob") id "password")))
                (is (= "read" (:permission (svc/get-entry (S "bob") id))))))

          (testing "bob (read only) cannot save - rejected locally and on the server"
            (as homes "bob"
                (is (= :core/entry-no-permission
                       (msg-of #(svc/save-entry (S "bob") {:id id :title "Firewall" :password "boese"}))))))

          (testing "sharing dialog: principals and ACL"
            (as homes "alice"
                (is (= #{"u:admin" "u:alice" "u:bob"} (set (map :principal (svc/principals (S "alice"))))))
                (is (= {"u:alice" "owner" "u:bob" "read"}
                       (into {} (map (juxt :principal :permission) (:acl (svc/get-acl (S "alice") id))))))))

          ;; ---------------------------------------------------------- offline
          (testing "server offline: reading works, writing goes into the queue"
            (@stop)
            (as homes "bob" (is (= "pw1" (svc/get-field (S "bob") id "password"))))
            (as homes "alice"
                (svc/save-entry (S "alice") {:id id :title "Firewall" :username "root" :password "pw2" :folder "Netzwerk"})
                (is (= 1 (svc/pending-count (S "alice"))))
                (is (= "pw2" (svc/get-field (S "alice") id "password")) "own change visible at once"))
            (reset! stop (server/start! {:db db :port port :bind "127.0.0.1"}))
            (as homes "alice"
                (let [r (svc/sync-now (S "alice"))]
                  (is (= 1 (get-in r [:push :pushed])))
                  (is (zero? (svc/pending-count (S "alice"))))))
            (as homes "bob"
                (svc/sync-now (S "bob"))
                (is (= "pw2" (svc/get-field (S "bob") id "password")))))

          (testing "conflict: two owners change the same entry offline"
            (as homes "alice"
                (svc/set-acl (S "alice") id [{:principal "u:alice" :permission "owner"}
                                             {:principal "u:bob" :permission "update"}]))
            (as homes "bob" (svc/sync-now (S "bob")))
            (@stop)
            (as homes "alice" (svc/save-entry (S "alice") {:id id :title "Firewall" :password "from-alice"}))
            (as homes "bob" (svc/save-entry (S "bob") {:id id :title "Firewall" :password "from-bob"}))
            (reset! stop (server/start! {:db db :port port :bind "127.0.0.1"}))
            (as homes "alice" (svc/sync-now (S "alice")))
            (as homes "bob"
                (svc/sync-now (S "bob"))
                (let [[c] (svc/conflicts (S "bob"))]
                  (is (= "conflict" (:status c)))
                  (is (= "from-alice" (svc/get-field (S "bob") id "password")) "server state wins at first")
                  (svc/resolve-conflict (S "bob") (:id c) :retry)
                  (is (empty? (svc/conflicts (S "bob"))))
                  (is (= "from-bob" (svc/get-field (S "bob") id "password")) "bob's version taken over deliberately"))))

          (testing "groups via the server"
            (as homes "admin"
                (svc/sync-now (S "admin"))
                (svc/with-ctx (S "admin") #(admin/set-group! % admin-ident "it" ["alice" "bob"])))
            (as homes "bob" (is (seq (:log (svc/sync-now (S "bob"))))))
            (as homes "alice"
                (svc/sync-now (S "alice"))
                (let [id2 (svc/save-entry (S "alice") {:title "Switch" :password "sw"})]
                  (svc/set-acl (S "alice") id2 [{:principal "u:alice" :permission "owner"}
                                                {:principal "g:it" :permission "read"}])
                  (as homes "bob"
                      (svc/sync-now (S "bob"))
                      (is (= "sw" (svc/get-field (S "bob") id2 "password")))))))

          (testing "lock removes the identity from memory"
            (as homes "alice"
                (svc/lock! (S "alice"))
                (is (= :app/locked (msg-of #(svc/list-entries (S "alice")))))
                (svc/unlock! (S "alice"))
                (is (seq (:entries (svc/list-entries (S "alice")))))))))
      (finally (@stop)))))

(deftest password-generator
  (let [pw (svc/generate-password {:length 24 :upper true :lower true :digits true :special true})]
    (is (= 24 (count pw)))
    (is (re-find #"[A-Z]" pw)) (is (re-find #"[a-z]" pw)) (is (re-find #"[0-9]" pw)) (is (re-find #"[^A-Za-z0-9]" pw))
    (is (< 100 (svc/password-quality pw)))
    (is (not (re-find #"[O0Il1|]" (svc/generate-password {:length 200 :upper true :lower true :digits true
                                                          :exclude-look-alike true}))))))
