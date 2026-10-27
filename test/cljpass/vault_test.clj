(ns cljpass.vault-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.identity :as ident]
            [cljpass.store :as store]
            [cljpass.vault :as v]))

(defn- msg-key
  "i18n key (:msg) of the exception thrown by f, nil if nothing is thrown."
  [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defn setup
  "Org with admin + alice, bob, carol, dave; group it = {bob carol}."
  []
  (let [st (store/mem-store)
        ids (into {} (for [u ["admin" "alice" "bob" "carol" "dave"]] [u (ident/new-identity u)]))
        {:keys [org-hash recovery-priv]} (v/create-org! st "Test GmbH" (ids "admin"))
        org (v/load-org st org-hash)]
    (doseq [u ["alice" "bob" "carol" "dave"]] (v/submit-request! st org (ids u)))
    (v/write-roster! st org (ids "admin")
                     (fn [r] (-> (reduce v/add-user
                                         (v/add-user r (ident/public-part (ids "admin")))
                                         (v/pending-requests st (v/latest-roster {})))
                                 (v/set-group-members "it" #{"bob" "carol"}))))
    {:st st :ids ids :org org :org-hash org-hash :recovery-priv recovery-priv}))

(defn ctx [{:keys [st org-hash ids]} user & [state]]
  (v/open-ctx st org-hash (ids user) state))

(defn read-as [env user id]
  (let [cx (ctx env user)]
    (v/maintain-groups! cx)
    (v/decrypt-entry cx (:head (v/load-entry cx id)))))

(defn admin! [env f] (v/write-roster! (:st env) (:org env) ((:ids env) "admin") f))

(deftest canonical-json
  (is (= "{\"a_b\":1,\"prev\":null,\"z\":[\"x\",true]}" (codec/->str {:z ["x" true] :a-b 1 :prev nil :gone nil})))
  (is (= "\"\\u0001\\n\\\"ä\"" (codec/->str "\u0001\n\"ä")))
  (is (thrown? Exception (codec/->str 1.5)))
  (let [x {:acl [{:principal "u:bob" :perm "read"}] :n 3}]
    (is (= x (codec/parse (codec/->str x))))))

(deftest enrollment-and-roster
  (let [env (setup)]
    (is (empty? (v/pending-requests (:st env) (:roster (ctx env "alice")))) "all activated")
    (is (= #{"admin" "alice" "bob" "carol" "dave"} (set (keys (:users (:roster (ctx env "alice")))))))
    (testing "non-admin cannot change the roster"
      (is (= :core/roster-admins-only
             (msg-key #(v/write-roster! (:st env) (:org env) ((:ids env) "alice") identity)))))
    (testing "wrong pin is detected"
      (is (= :core/org-pin-mismatch (msg-key #(v/load-org (:st env) "abc"))))
      (is (thrown-with-msg? Exception #"pinned hash" (v/load-org (:st env) "abc"))))
    (testing "wire format is JSON with raw keys"
      (let [body (:body (store/read-doc (:st env) "roster/00000001.json"))]
        (is (vector? (:users body)))
        (is (= 32 (count (c/unb64 (:sign-pub (first (:users body)))))))))))

(deftest create-read-share-revoke
  (let [env (setup)
        id (:entry-id (v/create-entry! (ctx env "alice") {:title "DB" :password "secret"}))]
    (is (= "secret" (:password (read-as env "alice" id))))
    (is (nil? (read-as env "bob" id)) "bob has no access yet")

    (testing "sharing with bob (read)"
      (v/share! (ctx env "alice") id "u:bob" :read)
      (is (= "secret" (:password (read-as env "bob" id))))
      (is (thrown-with-msg? Exception #"no permission update"
                            (v/update-entry! (ctx env "bob") id {:title "DB" :password "boese"}))))

    (testing "bob must not reshare"
      (is (= :core/entry-no-permission (msg-key #(v/share! (ctx env "bob") id "u:dave" :read))))
      (is (thrown-with-msg? Exception #"no permission owner" (v/share! (ctx env "bob") id "u:dave" :read))))

    (testing "update permission"
      (v/share! (ctx env "alice") id "u:bob" :update)
      (v/update-entry! (ctx env "bob") id {:title "DB" :password "new"})
      (is (= "new" (:password (read-as env "alice" id)))))

    (testing "revoking: future versions no longer readable"
      (v/share! (ctx env "alice") id "u:bob" nil)
      (is (nil? (read-as env "bob" id))))

    (testing "history"
      (is (= [5 4 3 2 1] (map :version (v/entry-history (ctx env "alice") id)))))))

(deftest group-sharing-and-rotation
  (let [env (setup)
        id (:entry-id (v/create-entry! (ctx env "alice") {:title "Router" :password "r1"}))]
    (testing "group without a key is not ready yet"
      (is (= :core/group-not-ready (msg-key #(v/share! (ctx env "alice") id "g:it" :read)))))
    ;; carol starts first -> she creates epoch 1 and provides bob with the key
    (is (seq (v/maintain-groups! (ctx env "carol"))))
    (v/share! (ctx env "alice") id "g:it" :read)
    (is (= "r1" (:password (read-as env "bob" id))))
    (is (= "r1" (:password (read-as env "carol" id))))
    (is (nil? (read-as env "dave" id)))

    (testing "dave joins: only the group key is distributed"
      (admin! env #(v/set-group-members % "it" #{"bob" "carol" "dave"}))
      (v/maintain-groups! (ctx env "bob"))
      (is (= "r1" (:password (read-as env "dave" id)))))

    (testing "carol (creator of epoch 1) is removed"
      (admin! env #(v/set-group-members % "it" #{"bob" "dave"}))
      (is (= 2 (get-in (ctx env "bob") [:roster :groups "it" :epoch])))
      (testing "old entries stay readable for the remaining members"
        (let [cx (ctx env "bob")]
          (is (= "r1" (:password (v/decrypt-entry cx (:head (v/load-entry cx id)))))))))

    (testing "new version after rotation is not readable for carol"
      (v/maintain-groups! (ctx env "bob"))
      (v/update-entry! (ctx env "alice") id {:title "Router" :password "r2"})
      (is (= "r2" (:password (read-as env "dave" id))))
      (is (nil? (read-as env "carol" id))))

    (testing "admin has no access"
      (is (nil? (read-as env "admin" id))))))

(defn- forge!
  "bob writes a version he is not allowed to write."
  [env id]
  (let [l (v/load-entry (ctx env "alice") id)
        bob ((:ids env) "bob")
        n (inc (:max-number l))
        body (-> (:head l)
                 (assoc :version n :prev (:hash l) :author "bob"
                        :acl (assoc (get-in l [:head :acl]) "u:bob" :owner))
                 v/entry->wire)
        path (str "entries/" id "/" (store/pad n) ".json")]
    (store/create-obj! (:st env) path (codec/->str (codec/sign-doc :entry body "bob" (get-in bob [:sign :priv]))))
    path))

(deftest tamper-skip-and-rollback
  (let [env (setup)
        id (:entry-id (v/create-entry! (ctx env "alice") {:title "X" :password "p1"}))]
    (v/share! (ctx env "alice") id "u:bob" :read)

    (testing "forged version is skipped and reported, entry stays usable"
      (forge! env id)
      (let [{:keys [head warnings]} (v/load-entry (ctx env "alice") id)]
        (is (= 2 (:version head)))
        (is (some #(re-find #"by bob.*no permission owner" %) warnings)))
      (testing "next valid version gets number 4 and links to v2"
        (v/update-entry! (ctx env "alice") id {:title "X" :password "p2"})
        (is (= 4 (:version (:head (v/load-entry (ctx env "alice") id)))))
        (is (= "p2" (:password (read-as env "bob" id))))))

    (testing "rollback is detected"
      (is (= :core/entry-rollback (msg-key #(v/load-entry (ctx env "alice" {:entries {id 9}}) id))))
      (is (= :core/roster-rollback (msg-key #(ctx env "alice" {:roster-version 99}))))
      (is (thrown-with-msg? Exception #"Rollback" (ctx env "alice" {:roster-version 99}))))))

(deftest disabled-user-and-escrow
  (let [env (setup)
        id (:entry-id (v/create-entry! (ctx env "alice") {:title "Y" :password "p"}))]
    (v/share! (ctx env "alice") id "u:bob" :update)
    (admin! env #(v/disable-user % "bob"))
    (testing "disabled user can no longer write, a warning appears"
      (is (thrown? Exception (v/update-entry! (ctx env "bob") id {:title "Y" :password "x"})))
      (is (some #(re-find #"disabled users" %) (:warnings (v/load-entry (ctx env "alice") id)))))
    (testing "recovery escrow can be opened with the org recovery key"
      (is (= ((:ids env) "alice") (v/open-escrow (:st env) (:org env) "alice" (:recovery-priv env)))))))

(deftest server-validation
  (let [env (setup)
        st (:st env)
        id (:entry-id (v/create-entry! (ctx env "alice") {:title "Z" :password "p"}))
        valid? (fn [path body] (try (v/validate-new-object st path body) (catch Exception e (ex-message e))))]
    (testing "valid version is accepted (checked against a copy)"
      (let [shadow (store/mem-store)]
        (doseq [{:keys [path body]} (store/since st 0 10000)] (store/create-obj! shadow path body))
        (let [env2 (assoc env :st shadow)
              cx (ctx env2 "alice")
              _ (v/update-entry! cx id {:title "Z" :password "q"})
              path (str "entries/" id "/00000002.json")]
          (is (true? (valid? path (store/get-obj shadow path)))))))
    (testing "forgery is rejected"
      (let [path (forge! env id)
            body (store/get-obj st path)
            shadow (store/mem-store)]
        (doseq [{:keys [path body]} (store/since st 0 10000) :when (not (str/ends-with? path "00000002.json"))]
          (store/create-obj! shadow path body))
        (is (re-find #"no permission" (str (try (v/validate-new-object shadow path body) (catch Exception e (ex-message e))))))
        (is (= :core/entry-no-permission (msg-key #(v/validate-new-object shadow path body))))))
    (testing "roster only from admins"
      (let [doc (codec/sign-doc :roster {:version 2} "alice" (get-in (:ids env) ["alice" :sign :priv]))]
        (is (string? (valid? "roster/00000002.json" (codec/->str doc))))))
    (testing "unknown paths"
      (is (re-find #"Unknown path" (valid? "../../etc/passwd" "{}")))
      (is (= :core/unknown-path (msg-key #(v/validate-new-object st "../../etc/passwd" "{}")))))))
