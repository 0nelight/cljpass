(ns cljpass.standalone
  "Local mode without a server - like KeePass (doc/FORMAT.md §13).

   The vault is an ordinary KeePass file (KDBX 4), protected with a master
   password and/or key file. There is no identity, no server and no
   sharing. The file can be opened with KeePass or KeePassXC at any time.

   In RAM the master key and every entry are kept only encrypted
   (cljpass.secmem). Locking discards everything; unlocking needs the
   master password again.

   The file is saved after every change (atomically via a temporary file).
   If someone changed the file in the meantime (KeePass, another device via
   a file share), it is reloaded first and the change is applied on top.

   With an offline copy (cljpass.offline) all reads and writes go to the
   local copy (:copy); :file stays the shared file the user opened.

   For switching to the server, merge-into-vault! reconciles the content with
   the vault - without duplicates, even when switching back and forth
   several times."
  (:require [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.kdbx :as kdbx]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.secmem :as sm]
            [cljpass.vault :as v])
  (:import [java.time Instant]))

;; ================================================================ Helpers

(defn- protect-map [m] (sm/protect (codec/->bytes m)))
(defn- reveal-map [p] (sm/with-plain p #(codec/parse (c/utf8-str %))))

(defn- creds-of
  "Protected -> {:password :keyfile bytes} for cljpass.kdbx."
  [p]
  (let [{:keys [password keyfile]} (reveal-map p)]
    {:password password :keyfile (some-> keyfile c/unb64)}))

(defn- protect-creds [{:keys [password ^bytes keyfile]}]
  (when (and (str/blank? password) (nil? keyfile))
    (throw (i18n/error :app/master-key-required nil {:type :kdbx-bad-key})))
  (protect-map {:password (not-empty password) :keyfile (some-> keyfile c/b64)}))

(defn stamp
  "Content stamp of a file's bytes (SHA-256)."
  [^bytes b]
  (c/hex (c/sha256 b)))

(defn- work-file
  "The file actually read and written: the offline copy, if there is one."
  [db]
  (or (:copy db) (:file db)))

(defn check-path
  "Only .kdbx files; returns the absolute path."
  [file]
  (let [f (str/trim (str file))]
    (when-not (re-find #"(?i)\.kdbx$" f)
      (throw (i18n/error :app/kdbx-extension-required nil {:type :invalid-path})))
    (fs/absolutize f)))

(defn write-file!
  "Writes atomically: first a temporary file in the same folder, then replace."
  [file ^bytes data]
  (fs/create-dirs (fs/parent file))
  (let [tmp (str file ".tmp")]
    (fs/write-bytes tmp data)
    (fs/move tmp file true)
    (when-not (local/windows?) (fs/set-owner-only! file))
    file))

;; ================================================================ Database in memory

(defn- from-doc
  "Read/exported document -> state. Entry IDs are derived from the KeePass
   UUIDs and so stay stable across saves."
  [{:keys [file copy creds kdf db-id]} doc file-stamp]
  (let [{:keys [db entries]} (kp/import-doc doc {:source (fs/file-name file)
                                                 :db-id (or (kp/db-marker (:xml doc)) db-id)})
        ids (reduce (fn [acc p]
                      (let [id (kp/uuid->id (kp/entry-uuid p nil))
                            id (if (or (nil? id) (contains? (:seen acc) id)) (str (random-uuid)) id)]
                        (-> acc (update :seen conj id) (update :pairs conj [id p]))))
                    {:seen #{} :pairs []}
                    entries)]
    {:file file
     :copy copy
     :creds creds
     :kdf kdf
     :db-id (get-in db [:kdbx-db :id])
     ;; the database record's title is stored data with a localized prefix
     ;; (cljpass.keepass/db-title); db-title-name strips it in any language
     :name (let [n (kp/db-title-name (:title db))]
             (if (str/blank? n) (fs/file-name file) n))
     :db (protect-map db)
     :entries (into {} (for [[id p] (:pairs ids)] [id (protect-map p)]))
     :times (into {} (for [[id p] (:pairs ids)] [id (kp/entry-times p)]))
     :stamp file-stamp}))

(defn open
  "Opens a KeePass file. creds: {:password :keyfile bytes}.
   copy: path of an offline copy (cljpass.offline); read from it unless
   data (the file's bytes, already read) is given."
  [file creds & [{:keys [copy data]}]]
  (let [file (check-path file)
        src (or copy file)
        _ (when-not (or data (fs/exists? src))
            (throw (i18n/error :app/file-not-found {:file file} {:type :not-found})))
        data (or data (fs/read-bytes src))
        doc (kdbx/read-kdbx data creds)]
    (from-doc {:file file :copy copy :creds (protect-creds creds) :kdf (kdbx/kdf-opts (:kdf doc))} doc (stamp data))))

(defn create!
  "Creates a new, empty KeePass file (KDBX 4, AES-256, Argon2id) and opens it.
   kdf: options for cljpass.kdbx/write-kdbx (tests: fast)."
  [file creds & [kdf]]
  (let [file (check-path file)
        _ (when (fs/exists? file)
            (throw (i18n/error :app/file-exists {:file file} {:type :exists})))
        _ (protect-creds creds)
        doc (kp/empty-doc (str/replace (fs/file-name file) #"(?i)\.kdbx$" ""))]
    (write-file! file (kdbx/write-kdbx {:xml (:xml doc) :binaries []} (merge kdf creds)))
    (open file creds)))

(defn payload [db id]
  (some-> (get-in db [:entries id]) reveal-map))

(defn db-record [db] (reveal-map (:db db)))

(defn entries
  "[[id payload times] ...]"
  [db]
  (for [[id p] (:entries db)] [id (reveal-map p) (get-in db [:times id])]))

(defn put
  "Sets an entry. The modification time (for the KeePass history) is now."
  [db id payload]
  (-> db
      (assoc-in [:entries id] (protect-map payload))
      (assoc-in [:times id :modified] (kdbx/now-iso))))

(defn delete
  "Removes an entry and records it in <DeletedObjects> like KeePass."
  [db id]
  (let [p (or (payload db id) (throw (i18n/error :app/entry-not-found nil {:type :not-found})))
        uuid (kp/entry-uuid p id)]
    (-> db
        (update :entries dissoc id)
        (update :times dissoc id)
        (assoc :db (protect-map (kp/add-deleted (db-record db) uuid (str (.truncatedTo (Instant/now) java.time.temporal.ChronoUnit/SECONDS))))))))

(defn export-items
  "All entries + database record for cljpass.keepass/export-doc."
  [db]
  (cons {:payload (db-record db)}
        (for [[id p t] (entries db)] {:id id :payload p :modified (:modified t)})))

(defn- export-bytes [db creds kdf]
  (let [doc (kp/export-doc (export-items db) {:database (:db-id db)})]
    [doc (kdbx/write-kdbx doc (merge kdf creds))]))

(defn save!
  "Writes to the file and rebuilds the state from what was written (so memory
   always matches the file, including the KeePass history)."
  [db]
  (let [[doc data] (export-bytes db (creds-of (:creds db)) (:kdf db))]
    (write-file! (work-file db) data)
    (from-doc db (assoc doc :binaries (into {} (map-indexed (fn [i b] [(str i) b]) (:binaries doc)))
                        :version [4])
              (stamp data))))

(defn update-db-record
  "Changes the database record (meta, group tree, deleted objects)."
  [db f]
  (assoc db :db (protect-map (f (db-record db)))))

(defn set-creds
  "New master key (KeePass: File > Change Master Key). Takes effect with the
   next save!."
  [db creds]
  (-> db
      (assoc :creds (protect-creds creds))
      (update-db-record #(kp/touch-master-key % (kdbx/now-iso)))))

(defn changed-on-disk?
  "Was the file changed externally since it was loaded/saved?"
  [db]
  (and (fs/exists? (work-file db))
       (not= (:stamp db) (stamp (fs/read-bytes (work-file db))))))

(defn read-doc
  "Decrypts KeePass file bytes with the remembered master key."
  [db ^bytes data]
  (kdbx/read-kdbx data (creds-of (:creds db))))

(defn from-bytes
  "State from KeePass file bytes, read with the remembered master key."
  [db ^bytes data]
  (let [doc (read-doc db data)]
    (from-doc (assoc db :kdf (kdbx/kdf-opts (:kdf doc))) doc (stamp data))))

(defn reload
  "Reloads the file with the remembered master key."
  [db]
  (from-bytes db (fs/read-bytes (work-file db))))

(defn export-kdbx
  "Copy with a different master key (Save As / export)."
  [db creds]
  (let [[doc data] (export-bytes db creds {})]
    {:data data :count (count (:entries db)) :doc doc}))

;; ================================================================ Synchronize with another file

(defn sync-with
  "Synchronizes with another KeePass file (like File > Synchronize in
   KeePass). other-doc: result of cljpass.kdbx/read-kdbx.
   Matching by KeePass UUID:
   - in both: the newer state (LastModificationTime) wins, the other one
     goes into the history
   - only over there: is taken over, unless it was deleted here after its
     last change
   - only here: is deleted if it was deleted over there after its last
     change
   - deleted objects of both sides are united.
   Returns [db' {:added :updated :deleted}]."
  [db other-doc]
  (let [{odb :db oentries :entries} (kp/import-doc other-doc {})
        ours (into {} (for [[id p] (entries db)] [(kp/entry-uuid p id) [id p]]))
        theirs (into {} (for [p oentries] [(kp/entry-uuid p nil) (assoc-in p [:kdbx :db] (:db-id db))]))
        our-del (into {} (map (juxt :uuid :time)) (kp/deleted-objects (db-record db)))
        their-del (into {} (map (juxt :uuid :time)) (kp/deleted-objects odb))
        newer? (fn [a b] (pos? (compare (str a) (str b))))
        stats (atom {:added 0 :updated 0 :deleted 0})
        bump! #(swap! stats update % inc)
        db (reduce (fn [db [u tp]]
                     (if-let [[id op] (ours u)]
                       (let [om (kp/entry-modified op) tm (kp/entry-modified tp)]
                         (cond
                           (and (= om tm) (= (kp/core-hash op) (kp/core-hash tp))) db
                           (newer? tm om) (do (bump! :updated) (put db id (kp/merge-entry tp op)))
                           :else (put db id (kp/merge-entry op tp))))
                       (let [dt (our-del u)]
                         (if (and dt (not (newer? (kp/entry-modified tp) dt)))
                           db
                           (let [id (kp/uuid->id u)
                                 [id tp] (if (and id (not (payload db id))) [id tp]
                                             (let [n (str (random-uuid))] [n (kp/fresh-copy tp n)]))]
                             (bump! :added)
                             (put db id tp))))))
                   db theirs)
        db (reduce (fn [db [u [id op]]]
                     (let [dt (their-del u)]
                       (if (and (not (theirs u)) dt (not (newer? (kp/entry-modified op) dt)))
                         (do (bump! :deleted) (delete db id))
                         db)))
                   db ours)]
    [(assoc db :db (protect-map (kp/merge-deleted (db-record db) (kp/deleted-objects odb))))
     @stats]))

(defn write-copy!
  "Writes the current state with a different key to another file."
  [db file creds kdf]
  (write-file! file (second (export-bytes db creds kdf))))

;; ================================================================ Switching to the server (§13)

(defn- instant ^Instant [s] (try (Instant/parse (str s)) (catch Exception _ nil)))

(defn merge-into-vault!
  "Takes the file content into the vault. Matching by the origin marker
   (:kdbx-source, written when disconnecting) or the KeePass UUID:
   - unknown                          -> new entry (owner: me)
   - equal / changed only in the vault -> stays as it is in the vault
   - changed only locally, permitted  -> new version in the vault
   - both changed or no permission    -> copy \"(local change)\" (localized
                                         title suffix), nothing gets lost
   - deleted locally, I am the owner and unchanged in the vault
     since then                       -> deleted in the vault
   - in the file's recycle bin        -> counts as deleted (as above), never
                                         enters the vault anew
   Returns counters per case."
  [ctx db]
  (let [readable (:entries (v/list-entries ctx))
        by-id (into {} (map (juxt :id identity)) readable)
        by-uuid (reduce (fn [m e] (let [u (kp/entry-uuid (:payload e) (:id e))]
                                    (if (or (nil? u) (contains? m u)) m (assoc m u e))))
                        {} readable)
        dbp (db-record db)
        db-id (get-in dbp [:kdbx-db :id])
        vault-db (some #(when (= db-id (get-in % [:payload :kdbx-db :id])) %) readable)
        can? (fn [e perm] (v/perm>= (:my-perm e) perm))
        report (atom {:created 0 :updated 0 :unchanged 0 :copied 0 :deleted 0})
        bump! #(swap! report update % inc)
        clean (fn [p] (cond-> (dissoc p :kdbx-source)
                        (:kdbx p) (assoc-in [:kdbx :db] db-id)))
        bin (kp/recycle-bin dbp)
        [binned local] ((juxt filter remove) (fn [[_ p]] (kp/in-folder? (:folder p) bin)) (entries db))
        owner-unchanged? (fn [target ^Instant since]
                           ;; KeePass stores timestamps to the second: compare in seconds
                           (let [changed-at (some-> (instant (get-in target [:head :created-at]))
                                                    (.truncatedTo java.time.temporal.ChronoUnit/SECONDS))]
                             (and (can? target :owner) since changed-at (not (.isAfter ^Instant changed-at since)))))]
    ;; Structure and settings of the database
    (cond
      (nil? vault-db) (v/create-entry! ctx dbp)
      (= (get-in vault-db [:payload :kdbx-db :skeleton]) (get-in dbp [:kdbx-db :skeleton])) nil
      (can? vault-db :update) (v/update-entry! ctx (:id vault-db) (merge (:payload vault-db) dbp)))
    (doseq [[_ p] local
            :let [src (:kdbx-source p)
                  target (or (by-id (:id src)) (by-uuid (kp/entry-uuid p nil)))
                  new (clean p)]]
      (if-not target
        (do (v/create-entry! ctx new) (bump! :created))
        (let [tp (:payload target)
              h (kp/core-hash new)
              local-changed? (or (nil? src) (not (kp/unchanged-since? (:hash src) new)))
              vault-changed? (or (nil? src) (not= (:version src) (get-in target [:head :version])))]
          (cond
            (or (= h (kp/core-hash tp)) (not local-changed?)) (bump! :unchanged)
            (and (not vault-changed?) (can? target :update))
            (do (v/update-entry! ctx (:id target) (merge tp new)) (bump! :updated))
            :else
            (do (v/create-entry! ctx (kp/fresh-copy (update new :title #(i18n/t :app/local-change-title {:title %}))
                                                    (str (random-uuid))))
                (bump! :copied))))))
    (let [present (set (map (fn [[id p]] (kp/entry-uuid p id)) local))]
      (doseq [{:keys [uuid time]} (kp/deleted-objects dbp)
              :let [target (by-uuid uuid)]
              :when (and target (not (present uuid)) (owner-unchanged? target (instant time)))]
        (v/delete-entry! ctx (:id target))
        (bump! :deleted)))
    ;; Recycle bin: state at disconnect (marker) unchanged in the vault -> delete
    (doseq [[id p] binned
            :let [src (:kdbx-source p)
                  target (or (by-id (:id src)) (by-uuid (kp/entry-uuid p id)))]
            :when (and target (= (:version src) (get-in target [:head :version]))
                       (owner-unchanged? target (Instant/now)))]
      (v/delete-entry! ctx (:id target))
      (bump! :deleted))
    @report))
