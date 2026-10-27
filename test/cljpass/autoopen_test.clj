(ns cljpass.autoopen-test
  "AutoOpen like KeeAutoExec/KeePassXC: rules (pure) and opening further
   files in their own sessions (tabs)."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cljpass.autoopen :as ao]
            [cljpass.fs :as fs]
            [cljpass.local :as local]
            [cljpass.service :as svc])
  (:import [java.time Instant]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- sep [s] (str/replace s "/" java.io.File/separator))

(defn- cf [m] (vec (for [[k v] m] {:name k :value v :protected false})))

(deftest group-and-fields
  (is (ao/auto-open-folder? "AutoOpen"))
  (is (ao/auto-open-folder? "Personal/autoopen/Sub"))
  (is (not (ao/auto-open-folder? "AutoOpenX")))
  (is (not (ao/auto-open-folder? "")))
  (let [p {:title "T" :username "u" :url "x" :custom-fields (cf {"IfDevice" "pc1"})}]
    (is (= "u" (ao/raw-field p "UserName")))
    (is (= "pc1" (ao/raw-field p "IfDevice")))
    (is (= "" (ao/raw-field p "Nope")))))

(deftest placeholders
  (let [ctx {:payload {:title "Team" :password "pw" :custom-fields (cf {"Sub" "abc"})}
             :db-file (sep "/data/main.kdbx")
             :env {"HOME" "/home/x" "SystemDrive" "C:"}}]
    (is (= (sep "/data/team.kdbx") (ao/compile-str "{DB_DIR}/team.kdbx" (assoc ctx :db-file (sep "/data/main.kdbx")))))
    (is (= "main|kdbx|main.kdbx" (ao/compile-str "{db_basename}|{DB_EXT}|{DB_NAME}" ctx)))
    (is (= "Team-abc-pw" (ao/compile-str "{TITLE}-{S:Sub}-{PASSWORD}" ctx)))
    (is (= "/home/x/a C:" (ao/compile-str "%HOME%/a %systemdrive%" ctx)))
    (is (= "{UNKNOWN} %NOPE%" (ao/compile-str "{UNKNOWN} %NOPE%" ctx)))
    (testing "values are not expanded again"
      (is (= "{TITLE}" (ao/compile-str "{PASSWORD}" (assoc-in ctx [:payload :password] "{TITLE}")))))))

(deftest paths
  (let [base (sep "/data/dbs")]
    (is (= (sep "/data/dbs/team.kdbx") (ao/resolve-path "team.kdbx" base)))
    (is (= (sep "/data/team.kdbx") (ao/resolve-path "../team.kdbx" base)))
    (is (= (sep "/data/dbs/a b.kdbx") (ao/resolve-path "\"a b.kdbx\" --ignored" base)))
    (is (= (sep "/data/dbs/x.kdbx") (ao/resolve-path "kdbx://x.kdbx" base)))
    (is (nil? (ao/resolve-path "  " base)))
    (when-not (local/windows?)
      (is (= "/srv/a b.kdbx" (ao/resolve-path "file:///srv/a%20b.kdbx" base)))
      (is (= "/srv/abs.kdbx" (ao/resolve-path "/srv/abs.kdbx" base)))
      (is (= "/data/dbs/sub/team.kdbx" (ao/resolve-path "sub\\team.kdbx" base)) "path written on Windows")
      (is (= "/data/team.kdbx" (ao/resolve-path (ao/compile-str "{DB_DIR}\\..\\team.kdbx" {:db-file "/data/dbs/main.kdbx"}) base))))))

(deftest if-device
  (let [me #{"pc1" "pc1.example.local"}]
    (is (ao/device-enabled? "" me))
    (is (ao/device-enabled? "PC1" me) "names are case-insensitive")
    (is (not (ao/device-enabled? "pc2" me)) "only named devices")
    (is (ao/device-enabled? "pc2, pc1" me))
    (is (not (ao/device-enabled? "!pc1" me)))
    (is (ao/device-enabled? "!pc2" me) "an exclusion list allows all others")
    (is (ao/device-enabled? "\"pc1\"" me) "quoted like CSV")
    (is (ao/device-enabled? "pc2" #{}) "unknown device name: open")))

(deftest item-rules
  (let [now (Instant/parse "2026-06-01T00:00:00Z")
        e (fn [id folder url & {:as more}]
            {:id id :payload (merge {:title id :folder folder :url url} more)})
        xs (ao/items [(e "a" "AutoOpen" "a.kdbx" :custom-fields (cf {"Priority" "5"}))
                      (e "b" "AutoOpen" "b.kdbx")
                      (e "c" "Other" "c.kdbx")
                      (e "d" "AutoOpen" "")
                      (e "e" "AutoOpen/Sub" "e.kdbx" :expires "2026-01-01")
                      (e "f" "AutoOpen" "f.kdbx" :expires "2026-01-01" :custom-fields (cf {"Enabled" "true"}))
                      (e "g" "AutoOpen" "g.kdbx" :custom-fields (cf {"Enabled" "False" "Visible" "false" "IfDevice" "!pc1"}))
                      (e "h" "Papierkorb/AutoOpen" "h.kdbx")]
                     {:db-file (sep "/data/main.kdbx") :devices #{"pc1"} :now now :exclude-folder "Papierkorb"})
        by-id (into {} (map (juxt :id identity)) xs)]
    (is (= ["b" "e" "f" "g" "a"] (map :id xs)) "without URL, outside AutoOpen and in the recycle bin: ignored; sorted by Priority")
    (is (= (sep "/data/b.kdbx") (:file (by-id "b"))))
    (is (false? (:enabled (by-id "e"))) "expired = disabled")
    (is (true? (:enabled (by-id "f"))) "Enabled overrides the expiry")
    (is (= [false false] ((juxt :enabled :device) (by-id "g"))))
    (is (every? #(not (contains? % :password)) xs) "no secrets in the list")))

(deftest target-rules
  (let [t (ao/target {:url "{DB_DIR}/x.kdbx" :username "keys/x.key" :password " pw "
                      :custom-fields (cf {"SkipIfNotExists" "True" "Focus" "restore"})}
                     {:db-file (sep "/data/main.kdbx")})]
    (is (= (sep "/data/x.kdbx") (:file t)))
    (is (= (sep "/data/keys/x.key") (:keyfile t)))
    (is (= " pw " (:password t)) "password unchanged")
    (is (:skip-if-missing t))
    (is (:restore-focus t)))
  (is (nil? (ao/target {:url ""} {:db-file "/x.kdbx"}))))

;; ================================================================ Service: tabs and AutoOpen

(defn- msg-of [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(deftest open-files-in-tabs
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [dir (fs/create-temp-dir)
          main-file (str (fs/path dir "main.kdbx"))
          team-file (str (fs/path dir "team" "team.kdbx"))
          key-file (str (fs/path dir "team" "team.key"))
          main (svc/new-session {})
          team (svc/new-session {})]
      (fs/create-dirs (fs/path dir "team"))
      (fs/write-bytes key-file (.getBytes "my key file content"))
      ;; the team file with password + key file
      (svc/open-extra-file! team {:file team-file :password "team-pw" :keyfile (fs/read-bytes key-file) :create true :kdf fast})
      (svc/save-entry team {:title "Team entry" :password "x"})
      (svc/lock! team)
      (svc/open-file! main {:file main-file :password "master" :create true :kdf fast})

      (testing "a further file does not change the mode or the main file"
        (is (= {:state :locked :mode :standalone :extra true :file team-file :exists true} (svc/status team)))
        (is (= main-file (:file (local/load-config))))
        (is (= :app/main-tab-only (msg-of #(svc/connect-server! team {:server "https://x" :org-hash "y"}))))
        (is (= :app/main-tab-only (msg-of #(svc/open-file! team {:file team-file :password "team-pw"})))))

      (let [id (svc/save-entry main {:title "Team" :folder "AutoOpen" :url "team/team.kdbx"
                                     :username "{DB_DIR}/team/team.key" :password "team-pw"})
            _ (svc/save-entry main {:title "Gone" :folder "AutoOpen" :url "missing.kdbx" :password "x"
                                    :custom-fields [{:name "SkipIfNotExists" :value "True"}]})
            _ (svc/save-entry main {:title "Broken" :folder "AutoOpen" :url "missing2.kdbx" :password "x"
                                    :custom-fields [{:name "Priority" :value "99"}]})
            items (svc/auto-open-items main)]
        (testing "items"
          (is (= ["Team" "Gone" "Broken"] (map :title items)))
          (is (every? :auto items))
          (is (= team-file (:file (first items)))))

        (testing "target with key file, skipping and errors"
          (let [t (svc/auto-open-target main id)]
            (is (= team-file (:file t)))
            (is (= "my key file content" (String. ^bytes (:keyfile t)))))
          (is (false? (:prompt (svc/auto-open-target main id))))
          (is (= {:skip true} (svc/auto-open-target main (:id (second items)))))
          (is (= :app/file-not-found (msg-of #(svc/auto-open-target main (:id (last items)))))))

        (testing "open in its own session, unlock again after locking"
          (let [t (svc/auto-open-target main id)]
            (svc/open-extra-file! team (assoc (select-keys t [:password :keyfile]) :file (:file t)))
            (is (= #{"Team entry"} (set (map :title (:entries (svc/list-entries team))))))
            (is (= :active (:state (svc/status team))))
            (is (= team-file (svc/session-file team)))
            (svc/lock! team)
            (is (= :kp/kdbx-bad-key (msg-of #(svc/open-extra-file! team {:password "wrong" :keyfile (:keyfile t)}))))
            (is (= team-file (svc/session-file team)) "the locked tab keeps its file")
            (svc/open-extra-file! team {:password "team-pw" :keyfile (:keyfile t)})
            (is (= :active (:state (svc/status team))))))

        (testing "the main file is untouched by the tab"
          (is (= #{"Team" "Gone" "Broken"} (set (map :title (:entries (svc/list-entries main))))))
          (is (= main-file (:file (local/load-config))))
          (is (= [team-file main-file] (take 2 (svc/recent-files)))))

        (testing "without a stored key: ask for it (KeeAutoExec), not skip"
          (let [ask (svc/save-entry main {:title "Ask" :folder "AutoOpen" :url "team/team.kdbx"})]
            (is (:auto (some #(when (= ask (:id %)) %) (svc/auto-open-items main))))
            (is (= {:file team-file :prompt true :password nil :keyfile nil :restore-focus false}
                   (svc/auto-open-target main ask)))))))))
