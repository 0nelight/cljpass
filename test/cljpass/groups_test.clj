(ns cljpass.groups-test
  "KeePass parity stage 2: managing groups and the recycle bin - checked via
   the written file, the way KeePass reads it."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
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

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- tmp-file [n] (str (fs/path (fs/create-temp-dir) n)))

(defn- bin
  "Name of the recycle bin group (created in the current language), or
   bin/sub for a path below it."
  ([] (i18n/t :kp/recycle-bin))
  ([sub] (str (bin) "/" sub)))

(defn- msg-of
  "Message key (:msg of ex-data) of the exception thrown by (f), or nil."
  [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defn- file-tree
  "Group tree of the file: {path {:uuid :entries #{title} :group el}} and meta."
  [file password]
  (let [xml (:xml (k/read-kdbx (fs/read-bytes file) {:password password}))
        root (k/child (k/child xml :Root) :Group)
        out (atom {})]
    ((fn visit [g path]
       (swap! out assoc path {:uuid (k/child-text g :UUID) :group g
                              :entries (set (for [e (k/children g :Entry)]
                                              (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value))
                                                    (k/children e :String))))})
       (doseq [sub (k/children g :Group)]
         (visit sub (str/join "/" (remove str/blank? [path (k/child-text sub :Name)])))))
     root "")
    {:groups @out :meta (k/child xml :Meta) :deleted (set (map #(k/child-text % :UUID)
                                                              (k/children (k/child (k/child xml :Root) :DeletedObjects) :DeletedObject)))}))

(defn- by-title [s t] (first (filter #(= t (:title %)) (:entries (svc/list-entries s)))))

(deftest groups-in-file
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "groups.kdbx")
          tree #(file-tree file "m")]
      (svc/open-file! s {:file file :password "m" :create true :kdf fast})

      (testing "create empty groups - KeePass sees them"
        (is (= "Server" (svc/add-group! s "" "Server")))
        (is (= "Server/Linux" (svc/add-group! s "Server" "Linux")))
        (is (= "Personal" (svc/add-group! s "" " Personal ")))
        (is (= ["Server" "Server/Linux" "Personal"] (:groups (svc/list-entries s))))
        (is (contains? (:groups (tree)) "Server/Linux"))
        (is (= :kp/group-exists (msg-of #(svc/add-group! s "" "Server"))))
        (is (= :kp/group-name-slash (msg-of #(svc/add-group! s "" "a/b"))))
        (is (= :kp/group-not-found (msg-of #(svc/add-group! s "Does/Not/Exist" "x")))))

      (let [web (svc/save-entry s {:title "Web" :password "w" :folder "Server/Linux"})
            _ (svc/save-entry s {:title "Mail" :password "m" :folder "Personal"})
            linux-uuid (get-in (tree) [:groups "Server/Linux" :uuid])]
        (is (= #{"Web"} (get-in (tree) [:groups "Server/Linux" :entries])) "entry in the created group")

        (testing "renaming: entries move along, UUID stays"
          (is (= {:path "Server/Debian"} (svc/rename-group! s "Server/Linux" "Debian")))
          (is (= "Server/Debian" (:folder (by-title s "Web"))))
          (is (= linux-uuid (get-in (tree) [:groups "Server/Debian" :uuid])))
          (is (= #{"Web"} (get-in (tree) [:groups "Server/Debian" :entries])))
          (is (not (contains? (:groups (tree)) "Server/Linux")))
          (is (= :kp/group-rename-root (msg-of #(svc/rename-group! s "" "x")))))

        (testing "moving: with its entries, not into itself"
          (is (= {:path "Personal/Debian"} (svc/move-group! s "Server/Debian" "Personal")))
          (is (= "Personal/Debian" (:folder (by-title s "Web"))))
          (is (= linux-uuid (get-in (tree) [:groups "Personal/Debian" :uuid])))
          (is (= :kp/group-move-into-itself (msg-of #(svc/move-group! s "Personal" "Personal/Debian"))))
          (svc/move-group! s "Personal/Debian" "")
          (is (= "Debian" (:folder (by-title s "Web")))))

        (testing "deleting an entry: into the recycle bin, as KeePass knows it"
          (is (= :recycled (svc/delete-entry s web)))
          (let [{:keys [groups meta]} (tree)
                bin (get groups (bin))]
            (is (= (:uuid bin) (k/child-text meta :RecycleBinUUID)))
            (is (= "43" (k/child-text (:group bin) :IconID)))
            (is (= "false" (k/child-text (:group bin) :EnableSearching)))
            (is (= #{"Web"} (:entries bin))))
          (let [l (svc/list-entries s)]
            (is (= (bin) (:recycle-bin l)))
            (is (:recycled (by-title s "Web")))
            (is (not (:recycled (by-title s "Mail")))))
          (testing "password report skips the recycle bin"
            (svc/save-entry s {:title "Web2" :password "w"})
            (is (empty? (:duplicates (svc/password-report s))))))

        (testing "deleting a group: with its content into the recycle bin"
          (is (= {:recycled true :deleted 0 :path (bin "Personal")} (svc/delete-group! s "Personal")))
          (is (= (bin "Personal") (:folder (by-title s "Mail"))))
          (is (= #{"Mail"} (get-in (tree) [:groups (bin "Personal") :entries]))))

        (testing "same name in the recycle bin: with a counter"
          (svc/add-group! s "" "Personal")
          (is (= (bin "Personal (2)") (:path (svc/delete-group! s "Personal")))))

        (testing "from the recycle bin: permanently, with DeletedObjects"
          (let [personal-uuid (get-in (tree) [:groups (bin "Personal") :uuid])
                mail-uuid (kp/entry-uuid (sa/payload (:file @s) (:id (by-title s "Mail"))) nil)]
            (is (= {:recycled false :deleted 1} (svc/delete-group! s (bin "Personal"))))
            (is (nil? (by-title s "Mail")))
            (is (every? (:deleted (tree)) [personal-uuid mail-uuid]))))

        (testing "empty the recycle bin"
          (is (= 1 (svc/empty-recycle-bin! s)))
          (is (nil? (by-title s "Web")))
          (is (= #{(bin)} (set (filter #(str/starts-with? % (bin)) (keys (:groups (tree))))))))

        (testing "without a recycle bin entries are deleted at once"
          (svc/set-db-settings! s {:recycle-bin false})
          (is (false? (:recycle-bin (svc/db-settings s))))
          (is (= "False" (k/child-text (:meta (tree)) :RecycleBinEnabled)))
          (is (= :deleted (svc/delete-entry s (:id (by-title s "Web2")))))
          (is (nil? (by-title s "Web2")))
          (is (= {:recycled false :deleted 0} (svc/delete-group! s "Server"))))

        (testing "reopening the file: everything still there"
          (svc/lock! s)
          (svc/open-file! s {:file file :password "m"})
          (is (= ["Debian" (bin)] (:groups (svc/list-entries s)))))))))

(deftest several-entries-in-file
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "mehrere.kdbx")
          _ (svc/open-file! s {:file file :password "m" :create true :kdf fast})
          [a b c] (mapv #(svc/save-entry s {:title % :password % :tags "old"}) ["A" "B" "C"])]
      (testing "moving (dragging into the group tree)"
        (is (= {:updated 2 :skipped 0} (svc/move-entries! s [a b] "New/Target")))
        (is (= {:updated 0 :skipped 0} (svc/move-entries! s [a] " New / Target ")) "already there")
        (is (= #{"A" "B"} (get-in (file-tree file "m") [:groups "New/Target" :entries]))))
      (testing "setting and removing tags"
        (is (= {:updated 3 :skipped 0} (svc/tag-entries! s [a b c] {:add "new" :remove "old"})))
        (is (= "new" (:tags (svc/get-entry s c))))
        (is (= {:updated 0 :skipped 0} (svc/tag-entries! s [a] {:add "new"}))))
      (testing "deleting: first recycle bin, then permanently"
        (is (= {:recycled 2 :deleted 0 :skipped 0} (svc/delete-entries! s [a b])))
        (is (= {:recycled 1 :deleted 1 :skipped 0} (svc/delete-entries! s [a c])))
        (is (= #{"B" "C"} (get-in (file-tree file "m") [:groups (bin) :entries])))))))

(defn- entry-el [file password title]
  (let [xml (:xml (k/read-kdbx (fs/read-bytes file) {:password password}))]
    (first (for [g (tree-seq #(= :Group (:tag %)) #(k/children % :Group) (k/child (k/child xml :Root) :Group))
                 e (k/children g :Entry)
                 :when (= title (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value)) (k/children e :String)))]
             e))))

(deftest icons-and-colors
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "symbole.kdbx")
          el #(entry-el file "m" %)]
      (svc/open-file! s {:file file :password "m" :create true :kdf fast})
      (let [id (svc/save-entry s {:title "Bank" :password "x" :look {:icon-id 37 :fg "#ff0000" :bg ""}})]
        (testing "new entry with icon and color - the way KeePass saves it"
          (is (= "37" (k/child-text (el "Bank") :IconID)))
          (is (= "#FF0000" (k/child-text (el "Bank") :ForegroundColor)))
          (is (= {:id 37 :name "Homebanking"} (:icon (by-title s "Bank"))))
          (is (= {:fg "#FF0000" :bg ""} (:colors (svc/get-entry s id))))
          (is (= 1 (count (svc/history s id)))))
        (testing "changing only the icon: one history item like in KeePass"
          (svc/save-entry s (assoc (svc/get-entry s id) :look {:icon-id 1}))
          (is (= "1" (k/child-text (el "Bank") :IconID)))
          (is (= "#FF0000" (k/child-text (el "Bank") :ForegroundColor)) "color stays")
          (is (= 2 (count (svc/history s id)))))
        (testing "saving without :look changes nothing about it"
          (svc/save-entry s (assoc (svc/get-entry s id) :password "y"))
          (is (= "1" (k/child-text (el "Bank") :IconID)))
          (is (= 3 (count (svc/history s id))))
          (svc/save-entry s (svc/get-entry s id))
          (is (= 3 (count (svc/history s id))) "saved unchanged: no history item"))
        (testing "color back to default"
          (svc/save-entry s (assoc (svc/get-entry s id) :look {:fg ""}))
          (is (= "" (str (k/child-text (el "Bank") :ForegroundColor))))))
      (testing "group icon"
        (svc/add-group! s "" "Server")
        (svc/set-group-icon! s "Server" 38)
        (is (= {:id 38 :name "DriveWindows"} (some #(when (= "Server" (:folder %)) (:icon %)) (:folder-icons (svc/list-entries s)))))))))

(deftest keepass-icons-kept
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [file (tmp-file "aus-keepass.kdbx")
          _ (fs/write-bytes file (k/write-kdbx {:xml (k/parse-xml-str @#'cljpass.kdbx-test/sample-xml)
                                               :binaries @#'cljpass.kdbx-test/sample-binaries}
                                              {:kdf :aes :rounds 1000 :password "kp"}))
          s (svc/new-session {})
          el #(entry-el file "kp" "DB prod")]
      (svc/open-file! s {:file file :password "kp"})
      (let [id (:id (by-title s "DB prod"))]
        (is (= {:fg "#FF0000" :bg ""} (:colors (by-title s "DB prod"))))
        (is (= "SWNvbklEMDAwMDAwMDAwMA==" (get-in (by-title s "DB prod") [:icon :custom :uuid] (k/child-text (el) :CustomIconUUID))))
        (testing "saving without changes keeps the custom icon and color"
          (svc/save-entry s (assoc (svc/get-entry s id) :password "new"))
          (is (= "SWNvbklEMDAwMDAwMDAwMA==" (k/child-text (el) :CustomIconUUID)))
          (is (= "#FF0000" (k/child-text (el) :ForegroundColor))))
        (testing "choosing a standard icon replaces the custom one"
          (svc/save-entry s (assoc (svc/get-entry s id) :look {:icon-id 12}))
          (is (nil? (k/child (el) :CustomIconUUID)))
          (is (= "12" (k/child-text (el) :IconID)))
          (is (some #(= "SWNvbklEMDAwMDAwMDAwMA==" (k/child-text % :CustomIconUUID))
                    (k/children (k/child (el) :History) :Entry))
              "the old icon is in the history"))))))

(defn- free-port [] (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(deftest groups-on-server
  (let [port (free-port)
        url (str "http://127.0.0.1:" port)
        stop (server/start! {:db (str (fs/path (fs/create-temp-dir) "server.db")) :port port :bind "127.0.0.1" :init-token "t"})
        s (svc/new-session {})
        ident (idn/new-identity "admin")]
    (try
      (binding [local/*home* (str (fs/create-temp-dir))]
        (let [{:keys [org-hash]} (admin/init-org! url "t" "Example" ident)]
          (local/save-identity! ident :file)
          (local/save-config! {:server url :org-hash org-hash :user "admin"})
          (svc/unlock! s))
        (svc/save-entry s {:title "A" :password "a" :folder "Net/Router"})
        (svc/save-entry s {:title "B" :password "b" :folder "Net"})
        (svc/save-entry s {:title "C" :password "c" :folder "Netzwerk"})
        (testing "renaming changes the folder of all entries below"
          (is (= {:path "LAN" :updated 2 :skipped 0} (svc/rename-group! s "Net" "LAN")))
          (is (= "LAN/Router" (:folder (by-title s "A"))))
          (is (= "LAN" (:folder (by-title s "B"))))
          (is (= "Netzwerk" (:folder (by-title s "C"))) "same beginning, different group"))
        (testing "moving"
          (is (= {:path "Netzwerk/Router" :updated 1 :skipped 0} (svc/move-group! s "LAN/Router" "Netzwerk")))
          (is (= "Netzwerk/Router" (:folder (by-title s "A")))))
        (testing "icon and color in the vault, in the export for KeePass"
          (let [id (svc/save-entry s {:title "Symbol" :password "s" :look {:icon-id 19 :bg "#00ff00"}})
                f (tmp-file "export.kdbx")]
            (is (= 19 (get-in (svc/get-entry s id) [:icon :id])))
            (fs/write-bytes f (:data (svc/export-kdbx s {:password "x" :kdf :aes :rounds 1000})))
            (is (= "19" (k/child-text (entry-el f "x" "Symbol") :IconID)))
            (is (= "#00FF00" (k/child-text (entry-el f "x" "Symbol") :BackgroundColor)))
            (svc/delete-entry s id)))
        (testing "several entries"
          (let [ids (map :id (:entries (svc/list-entries s)))]
            (is (= {:updated 3 :skipped 0} (svc/tag-entries! s ids {:add "x"})))
            (is (= {:updated 2 :skipped 0} (svc/move-entries! s ids "Netzwerk")))
            (is (= {:recycled 0 :deleted 3 :skipped 0} (svc/delete-entries! s ids)))
            (is (empty? (:entries (svc/list-entries s))))))
        (testing "empty groups and the recycle bin exist only in the file"
          (is (= :app/server-no-empty-groups (msg-of #(svc/add-group! s "" "X"))))
          (is (= :app/server-no-group-delete (msg-of #(svc/delete-group! s "LAN"))))))
      (finally (stop)))))
