(ns cljpass.offline-test
  "Offline copy of a KeePass file on a network share (doc/FORMAT.md §13.1).
   The share is a temporary folder; unreachable means moved away or a FIFO
   that blocks on reading like a hanging mount."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.fs :as fs]
            [cljpass.local :as local]
            [cljpass.offline :as offline]
            [cljpass.proc :as proc]
            [cljpass.service :as svc]
            [cljpass.standalone :as sa]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- titles [s] (set (map :title (:entries (svc/list-entries s)))))

(defn- file-titles
  "Titles in the shared file itself, as another device sees them."
  [file]
  (set (map (comp :title second) (sa/entries (sa/open file {:password "master"})))))

(defn- other-device!
  "Another device (KeePass) changes the shared file."
  [file title]
  (let [db (sa/open file {:password "master"})]
    (sa/save! (sa/put db (str (random-uuid)) {:title title :password "x"}))))

(defn- msg-of [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(deftest offline-copy
  (binding [local/*home* (str (fs/create-temp-dir))
            offline/*timeout-ms* 1000]
    (let [share (fs/create-temp-dir)
          file (str (fs/path share "passwords.kdbx"))
          away (str file ".away")
          copy (offline/copy-file file)
          s (svc/new-session {})]
      (sa/create! file {:password "master"} fast)
      ;; a temporary folder is not a network share: switch it on for this file
      (local/save-config! {:mode :standalone :file file :offline-copies {file true}})

      (testing "opening creates the copy"
        (svc/open-file! s {:file file :password "master"})
        (is (fs/exists? copy))
        (is (= {:enabled true :state :synced :pending false} (:offline-copy (svc/status s)))))

      (testing "online a change goes to the copy and to the share at once"
        (svc/save-entry s {:title "Bank" :password "1"})
        (is (= #{"Bank"} (file-titles file)))
        (is (false? (offline/pending? file))))

      (testing "share unreachable: working with the copy"
        (fs/move file away)
        (svc/lock! s)
        (svc/open-file! s {:file file :password "master"})
        (is (= #{"Bank"} (titles s)))
        (svc/save-entry s {:title "Offline" :password "2"})
        (is (= #{"Bank" "Offline"} (titles s)))
        (is (= {:enabled true :state :offline :pending true :reason :missing}
               (:offline-copy (svc/status s))))
        (is (not (fs/exists? file)) "a missing shared file is never re-created"))

      (testing "share back: the change is written"
        (fs/move away file)
        (let [r (svc/sync-now s)]
          (is (:online r))
          (is (= {:enabled true :state :synced :pending false} (:offline-copy r))))
        (is (= #{"Bank" "Offline"} (file-titles file))))

      (testing "only the share changed: taken over"
        (other-device! file "Laptop")
        (is (:reloaded (svc/sync-now s)))
        (is (= #{"Bank" "Offline" "Laptop"} (titles s))))

      (testing "both changed while offline: merged, nothing lost"
        (fs/move file away)
        (svc/save-entry s {:title "Travelling" :password "3"})
        (fs/move away file)
        (other-device! file "Office")
        (let [r (svc/sync-now s)]
          (is (= {:added 1 :updated 0 :deleted 0} (get-in r [:offline-copy :merged])))
          (is (false? (get-in r [:offline-copy :pending]))))
        (is (= #{"Bank" "Offline" "Laptop" "Travelling" "Office"} (titles s) (file-titles file))))

      (testing "deleted on the other device while we were offline"
        (let [db (sa/open file {:password "master"})
              [id] (first (filter #(= "Laptop" (:title (second %))) (sa/entries db)))]
          (sa/save! (sa/delete db id)))
        (svc/sync-now s)
        (is (not (contains? (titles s) "Laptop"))))

      (testing "hanging share: timeout instead of blocking"
        (fs/move file away)
        (proc/run ["mkfifo" file] nil {})
        (let [t0 (System/currentTimeMillis)
              r (svc/sync-now s)]
          (is (< (- (System/currentTimeMillis) t0) 3000))
          (is (= :offline (get-in r [:offline-copy :state])))
          (is (= :timeout (get-in r [:offline-copy :reason]))))
        (testing "changing the master key needs the share"
          (is (= :app/offline-master-key (msg-of #(svc/change-master-key! s {:password "new"})))))
        (testing "switching off needs the share"
          (svc/save-entry s {:title "Pending" :password "4"})
          (is (= :app/offline-copy-pending (msg-of #(svc/set-offline-copy! s false)))))
        (fs/delete-if-exists file)
        (fs/move away file)
        (svc/sync-now s)
        (is (contains? (file-titles file) "Pending")))

      (testing "switching off removes the copy, the file is used directly"
        (is (= {:enabled false} (svc/set-offline-copy! s false)))
        (is (not (fs/exists? copy)))
        (svc/save-entry s {:title "Direkt" :password "5"})
        (is (contains? (file-titles file) "Direkt"))
        (is (false? (get-in (local/load-config) [:offline-copies file]))))

      (testing "switching on again"
        (is (:enabled (svc/set-offline-copy! s true)))
        (is (fs/exists? copy))
        (svc/lock! s)
        (fs/move file away)
        (svc/open-file! s {:file file :password "master"})
        (is (contains? (titles s) "Direkt"))
        (fs/move away file))

      (testing "wrong master key on the share (changed elsewhere): copy untouched, error shown"
        (let [db (sa/open file {:password "master"})]
          (sa/save! (sa/set-creds db {:password "anders"})))
        (let [r (svc/sync-now s)]
          (is (= :error (get-in r [:offline-copy :state])))
          (is (contains? (titles s) "Direkt")))))))

(deftest without-copy-unreachable
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [file (str (fs/path (fs/create-temp-dir) "weg" "passwords.kdbx"))]
      (local/save-config! {:mode :standalone :file file :offline-copies {file true}})
      (is (= :app/file-not-found (msg-of #(svc/open-file! (svc/new-session {}) {:file file :password "master"}))))
      (is (not (fs/exists? (fs/parent file))) "no folder is created for an unmounted share"))))

(deftest network-detection
  (testing "a setting per file wins"
    (is (true? (offline/enabled? {:offline-copies {"/tmp/a.kdbx" true}} "/tmp/a.kdbx")))
    (is (false? (offline/enabled? {:offline-copies {"/tmp/a.kdbx" false}} "/tmp/a.kdbx"))))
  (when-not (local/windows?)
    (testing "local folders are no network share"
      (is (false? (offline/network-path? (str (fs/path (fs/create-temp-dir) "x.kdbx"))))))))
