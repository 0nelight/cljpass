(ns cljpass.standalone-test
  "Local mode with a KeePass file and switching between file and server in
   both directions (doc/FORMAT.md §13)."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.admin :as admin]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.identity :as idn]
            [cljpass.kdbx :as k]
            [cljpass.kdbx-test]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.server :as server]
            [cljpass.service :as svc]
            [cljpass.standalone :as sa]))

;; Fast KDF parameters for tests
(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- tmp-file [n] (str (fs/path (fs/create-temp-dir) n)))

(defn- titles [s] (set (map :title (:entries (svc/list-entries s)))))

(defn- by-title [s t] (first (filter #(= t (:title %)) (:entries (svc/list-entries s)))))

(defn- msg-of
  "Message key (:msg of ex-data) of the exception thrown by (f), or nil."
  [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defn- file-entries
  "Entries read directly from the file (as KeePass sees them): {title entry-element}."
  [file password]
  (let [doc (k/read-kdbx (fs/read-bytes file) {:password password})]
    (into {} (for [g (tree-seq #(= :Group (:tag %)) #(k/children % :Group) (k/child (k/child (:xml doc) :Root) :Group))
                   e (k/children g :Entry)]
               [(some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value)) (k/children e :String)) e]))))

(deftest file-mode
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "privat.kdbx")]
      (testing "not set up: choice between file and server"
        (is (= :not-enrolled (:state (svc/status s)))))

      (testing "create a new file"
        (is (= :app/kdbx-extension-required (msg-of #(svc/open-file! s {:file "x.txt" :password "pw" :create true}))))
        (is (= :app/master-key-required (msg-of #(svc/open-file! s {:file file :password "" :create true}))))
        (svc/open-file! s {:file file :password "master" :create true :kdf fast})
        (is (fs/exists? file))
        (is (= {:state :active :mode :standalone} (select-keys (svc/status s) [:state :mode]))))

      (let [id (svc/save-entry s {:title "Bank" :username "me" :password "secret1" :folder "Personal/Finance"
                                  :custom-fields [{:name "PIN" :value "1234" :protected true}]})]
        (testing "entry is in the file at once - KeePass can read it"
          (let [e (get (file-entries file "master") "Bank")]
            (is e)
            (is (= id (kp/uuid->id (k/child-text e :UUID))) "entry ID = KeePass UUID")))

        (testing "reading, fields, permissions"
          (is (= "secret1" (svc/get-field s id "password")))
          (is (= "owner" (:permission (svc/get-entry s id))))
          (is (= [{:name "PIN" :value "1234" :protected true}] (:custom-fields (svc/get-entry s id))))
          (is (= #{"Bank"} (titles s)) "the database record is not shown")
          (is (= [] (svc/principals s)))
          (is (= :app/no-sharing-in-standalone (msg-of #(svc/set-acl s id [{:principal "u:x" :permission "read"}])))))

        (testing "changing: old state in the KeePass history, ID stays"
          (svc/save-entry s {:id id :title "Bank" :username "me" :password "secret2" :folder "Personal/Finance"})
          (is (= "secret2" (svc/get-field s id "password")))
          (is (= 2 (count (svc/history s id))))
          (is (= 1 (count (k/children (k/child (get (file-entries file "master") "Bank") :History) :Entry)))))

        (testing "duplicating and deleting (recycle bin, then DeletedObjects like KeePass)"
          (let [dup (svc/duplicate-entry s id)]
            (is (= #{"Bank" "Bank - Copy"} (titles s)))
            (is (not= (kp/entry-uuid (sa/payload (:file @s) dup) dup) (kp/entry-uuid (sa/payload (:file @s) id) id)))
            (is (= :recycled (svc/delete-entry s dup)))
            (is (= (i18n/t :kp/recycle-bin) (:folder (by-title s "Bank - Copy"))))
            (is (:recycled (by-title s "Bank - Copy")))
            (is (= 0 (count (kp/deleted-objects (sa/db-record (:file @s))))))
            (is (= :deleted (svc/delete-entry s dup)))
            (is (= #{"Bank"} (titles s)))
            (is (= 1 (count (kp/deleted-objects (sa/db-record (:file @s))))))))

        (testing "locking discards everything, unlocking needs the master password"
          (svc/lock! s)
          (is (= {:state :locked :mode :standalone :file (fs/absolutize file) :exists true} (svc/status s)))
          (is (= :app/locked (msg-of #(svc/list-entries s))))
          (is (= :kp/kdbx-bad-key (msg-of #(svc/open-file! s {:password "falsch"}))))
          (svc/open-file! s {:password "master"})
          (is (= "secret2" (svc/get-field s id "password"))))

        (testing "file was changed externally (KeePass, another device): reloaded first"
          (let [other (sa/open file {:password "master"})
                other (sa/save! (sa/put other (str (random-uuid)) {:title "From KeePass" :password "x"}))]
            (is (sa/changed-on-disk? (:file @s)))
            (svc/save-entry s {:title "New here" :password "y"})
            (is (= #{"Bank" "From KeePass" "New here"} (titles s)))
            (is (= #{"Bank" "From KeePass" "New here"} (set (keys (file-entries file "master")))))
            (is (sa/changed-on-disk? other) "the other state is outdated now")))

        (testing "settings of the file are kept when saving (KDF)"
          (is (= fast (select-keys (k/kdf-opts (:kdf (k/read-kdbx (fs/read-bytes file) {:password "master"}))) (keys fast))))))

      (testing "server enrollment is blocked in local mode"
        (is (= :app/enroll-in-standalone (msg-of #(svc/enroll! s {:server "http://x" :org-hash "y"}))))))))

(defn- free-port []
  (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(defmacro as [homes user & body]
  `(binding [local/*home* (get ~homes ~user)] ~@body))

(deftest switch-between-file-and-server
  (let [port (free-port)
        url (str "http://127.0.0.1:" port)
        stop (server/start! {:db (tmp-file "server.db") :port port :bind "127.0.0.1" :init-token "secret"})
        homes (into {} (for [u ["admin" "alice" "bob"]] [u (str (fs/create-temp-dir))]))
        S (into {} (for [u (keys homes)] [u (svc/new-session {})]))
        admin-ident (idn/new-identity "admin")
        file (tmp-file "alice.kdbx")
        approve! (fn [u fp] (as homes "admin"
                                (svc/sync-now (S "admin"))
                                (svc/with-ctx (S "admin") #(admin/approve! % admin-ident u {:fingerprint fp}))))]
    (try
      (let [{:keys [org-hash]} (admin/init-org! url "secret" "Example" admin-ident)]
        (as homes "admin"
            (local/save-identity! admin-ident :file)
            (local/save-config! {:server url :org-hash org-hash :user "admin"})
            (svc/unlock! (S "admin")))
        (as homes "bob"
            (approve! "bob" (:fingerprint (svc/enroll! (S "bob") {:server url :org-hash org-hash :user "bob" :protector :file}))))

        ;; ------------------------------------------------ alice starts locally
        (as homes "alice"
            (svc/open-file! (S "alice") {:file file :password "m1" :create true :kdf fast})
            (svc/save-entry (S "alice") {:title "A" :password "a1"})
            (svc/save-entry (S "alice") {:title "B" :password "b1" :folder "Folder"}))

        (testing "file -> server: request, keep working, take over after approval"
          (as homes "alice"
              (let [{:keys [state fingerprint]} (svc/connect-server! (S "alice") {:server url :org-hash org-hash :user "alice" :protector :file})]
                (is (= :pending state))
                (is (= :pending (get-in (svc/status (S "alice")) [:link :state])))
                (is (= "a1" (svc/get-field (S "alice") (:id (by-title (S "alice") "A")) "password")) "local keeps working")
                ;; the server answers 401 until approval: reported as unreachable with the reason
                (let [d (try (svc/finish-connect! (S "alice")) nil (catch clojure.lang.ExceptionInfo e (ex-data e)))]
                  (is (= :app/server-unreachable (:msg d)))
                  (is (= (i18n/t :core/not-enabled) (get-in d [:params :reason]))))
                (approve! "alice" fingerprint)))
          (as homes "alice"
              (is (= :ready (get-in (svc/status (S "alice")) [:link :state])))
              (let [r (svc/finish-connect! (S "alice"))]
                (is (= 2 (:created r)))
                (is (= {:state :active :mode :server} (select-keys (svc/status (S "alice")) [:state :mode]))))
              (is (= #{"A" "B"} (disj (titles (S "alice")) (kp/db-title "alice"))))
              (is (= "Folder" (:folder (by-title (S "alice") "B"))))
              (is (fs/exists? file) "the file stays as a backup")))

        ;; ------------------------------------------------ share D with bob
        (as homes "alice"
            (let [d (svc/save-entry (S "alice") {:title "D" :password "d1"})]
              (svc/set-acl (S "alice") d [{:principal "u:alice" :permission "owner"}
                                          {:principal "u:bob" :permission "update"}])
              (svc/save-entry (S "alice") {:title "Server only" :password "s"})))

        (testing "server -> file: all readable entries, afterwards without a server"
          (as homes "alice"
              (is (= :app/file-exists
                     (msg-of #(svc/disconnect! (S "alice") {:file file :password "m2" :kdf fast}))))
              (let [f2 (tmp-file "getrennt.kdbx")
                    r (svc/disconnect! (S "alice") {:file f2 :password "m2" :kdf fast})]
                (is (= 4 (:count r)) "A, B, D, Server only")
                (is (= {:state :active :mode :standalone} (select-keys (svc/status (S "alice")) [:state :mode])))
                (is (= #{"A" "B" "D" "Server only"} (titles (S "alice"))))
                (is (local/identity-exists?) "identity stays for later"))))

        (testing "working disconnected while bob changes things on the server"
          (as homes "bob"
              (svc/sync-now (S "bob"))
              (svc/save-entry (S "bob") {:id (:id (by-title (S "bob") "D")) :title "D" :password "d-bob"}))
          (as homes "alice"
              (let [s (S "alice")]
                (svc/save-entry s {:id (:id (by-title s "A")) :title "A" :password "a2"})
                (svc/delete-entry s (:id (by-title s "B")))
                (svc/save-entry s {:title "C" :password "c1"})
                (svc/save-entry s {:id (:id (by-title s "D")) :title "D" :password "d-alice"}))))

        (testing "reconnecting: reconciled without duplicates, nothing gets lost"
          (as homes "alice"
              (let [s (S "alice")]
                (is (= :ready (:state (svc/connect-server! s {:server url :org-hash org-hash :user "alice"})))
                    "already approved - no admin needed")
                (let [r (svc/finish-connect! s)]
                  (is (= {:created 1 :updated 1 :copied 1 :deleted 1} (select-keys r [:created :updated :copied :deleted]))))
                (let [ts (disj (titles s) (kp/db-title "alice"))]
                  (is (= #{"A" "C" "D" "D (local change)" "Server only"} ts)))
                (is (= "a2" (svc/get-field s (:id (by-title s "A")) "password")))
                (is (= "d-bob" (svc/get-field s (:id (by-title s "D")) "password")) "server state stays")
                (is (= "d-alice" (svc/get-field s (:id (by-title s "D (local change)")) "password")))))
          (as homes "bob"
              (svc/sync-now (S "bob"))
              (is (= "d-bob" (svc/get-field (S "bob") (:id (by-title (S "bob") "D")) "password")))))

        (testing "there and back without changes: no duplicates"
          (as homes "alice"
              (let [s (S "alice")
                    before (count (:entries (svc/list-entries s)))]
                (svc/disconnect! s {:file (tmp-file "nochmal.kdbx") :password "m3" :kdf fast})
                (svc/connect-server! s {:server url :org-hash org-hash :user "alice"})
                (let [r (svc/finish-connect! s)]
                  (is (= 0 (+ (:created r) (:updated r) (:copied r) (:deleted r)))))
                (is (= before (count (:entries (svc/list-entries s)))))))))
      (finally (stop)))))

;; ---------------------------------------------------------------- KeePass <-> cljpass

(def ^:private aes {:kdf :aes :rounds 1000})

(defn- entry-by-title [xml title]
  (first (for [g (tree-seq #(= :Group (:tag %)) #(k/children % :Group) (k/child (k/child xml :Root) :Group))
               e (k/children g :Entry)
               :when (= title (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value)) (k/children e :String)))]
           e)))

(deftest keepass-roundtrip
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [file (tmp-file "aus-keepass.kdbx")
          original (k/parse-xml-str @#'cljpass.kdbx-test/sample-xml)
          bins @#'cljpass.kdbx-test/sample-binaries
          _ (fs/write-bytes file (k/write-kdbx {:xml original :binaries bins} (assoc aes :password "kp")))
          s (svc/new-session {})]
      (svc/open-file! s {:file file :password "kp"})
      (is (= #{"DB prod" "Router" "Geloescht"} (titles s)))
      (svc/save-entry s {:id (:id (by-title s "Router")) :title "Router" :password "r2" :folder "Server"})
      (let [back (k/read-kdbx (fs/read-bytes file) {:password "kp"})
            xml (:xml back)]
        (testing "unchanged entries, meta and plugin data stay exactly as in KeePass"
          (is (= (entry-by-title original "DB prod") (entry-by-title xml "DB prod")))
          (is (= (k/child original :Meta) (k/child xml :Meta)))
          (is (= (k/child (k/child original :Root) :DeletedObjects) (k/child (k/child xml :Root) :DeletedObjects))))
        (testing "changed entry: new value, old one in the history, same UUID"
          (let [e (entry-by-title xml "Router")]
            (is (= "r2" (some #(when (= "Password" (k/child-text % :Key)) (k/child-text % :Value)) (k/children e :String))))
            (is (= "RW50cnkyMDAwMDAwMDAwMA==" (k/child-text e :UUID)))
            (is (= 1 (count (k/children (k/child e :History) :Entry))))))
        (testing "key derivation as set in KeePass"
          (is (= aes (k/kdf-opts (:kdf back)))))
        (testing "changed and saved in KeePass again -> cljpass reads it"
          (let [xml2 (update xml :content
                             (fn [cs] (mapv #(if (= :Meta (:tag %))
                                               (update % :content (fn [ms] (mapv (fn [m] (if (= :DatabaseName (:tag m)) (assoc m :content ["New"]) m)) ms)))
                                               %)
                                            cs)))]
            (fs/write-bytes file (k/write-kdbx {:xml xml2 :binaries (mapv #(get (:binaries back) (str %)) (range (count (:binaries back))))}
                                               (assoc aes :password "kp")))
            (svc/sync-now s)
            (is (= "New" (:org (svc/list-entries s))))))))))

(deftest sync-two-files
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [a (tmp-file "a.kdbx")
          b (tmp-file "b.kdbx")
          s (svc/new-session {})
          title-set #(set (keys (file-entries % %2)))]
      (svc/open-file! s {:file a :password "pa" :create true :kdf fast})
      ;; deleting without recycle bin (the recycle bin has its own test)
      (svc/set-db-settings! s {:recycle-bin false})
      (doseq [t ["X" "Y" "Z" "D1" "D2"]] (svc/save-entry s {:title t :password (str t "0")}))
      ;; b is a copy with its own password (e.g. on the laptop)
      (sa/write-copy! (:file @s) b {:password "pb"} fast)
      (Thread/sleep 1100)
      ;; over there (b): change Y and Z, create a new one, delete D2
      (let [ob (sa/open b {:password "pb"})
            id-of (fn [db t] (some (fn [[id p]] (when (= t (:title p)) id)) (sa/entries db)))
            ob (sa/put ob (id-of ob "Y") (assoc (sa/payload ob (id-of ob "Y")) :password "Y-b"))
            ob (sa/put ob (id-of ob "Z") (assoc (sa/payload ob (id-of ob "Z")) :password "Z-b"))
            ob (sa/put ob (str (random-uuid)) {:title "only-b" :password "b"})
            ob (sa/delete ob (id-of ob "D2"))]
        (sa/save! ob))
      (Thread/sleep 1100)
      ;; here (a): change X, change Z later (wins), create a new one, delete D1
      (svc/save-entry s {:id (:id (by-title s "X")) :title "X" :password "X-a"})
      (svc/save-entry s {:id (:id (by-title s "Z")) :title "Z" :password "Z-a"})
      (svc/save-entry s {:title "only-a" :password "a"})
      (svc/delete-entry s (:id (by-title s "D1")))
      (let [r (svc/sync-file! s {:file b :password "pb"})]
        (is (= {:added 1 :updated 1 :deleted 1} (select-keys r [:added :updated :deleted]))))
      (testing "both files have the same state afterwards"
        (is (= #{"X" "Y" "Z" "only-a" "only-b"} (titles s)))
        (is (= #{"X" "Y" "Z" "only-a" "only-b"} (title-set a "pa") (title-set b "pb"))))
      (testing "the newer change wins, the older one is in the history"
        (is (= "X-a" (svc/get-field s (:id (by-title s "X")) "password")))
        (is (= "Y-b" (svc/get-field s (:id (by-title s "Y")) "password")))
        (is (= "Z-a" (svc/get-field s (:id (by-title s "Z")) "password")))
        (let [z (get (file-entries b "pb") "Z")
              old (set (for [h (k/children (k/child z :History) :Entry)
                             st (k/children h :String) :when (= "Password" (k/child-text st :Key))]
                         (k/child-text st :Value)))]
          (is (contains? old "Z-b") "state of b in the history")))
      (testing "second synchronization changes nothing"
        (is (= {:added 0 :updated 0 :deleted 0} (select-keys (svc/sync-file! s {:file b :password "pb"}) [:added :updated :deleted]))))
      (testing "the opened file itself is not allowed"
        (is (= :app/sync-with-self (msg-of #(svc/sync-file! s {:file a :password "pa"}))))))))
