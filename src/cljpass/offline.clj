(ns cljpass.offline
  "Offline copy of a KeePass file on a network share (doc/FORMAT.md §13.1).

   In local mode cljpass can work with a local copy of the file
   (<home>/offline) and synchronize it with the shared file whenever the
   share is reachable:
   - only the shared file changed -> the copy takes it over unchanged
   - only the copy changed        -> the copy is written to the share
   - both changed                 -> merged like File > Synchronize
                                     (cljpass.standalone/sync-with), the
                                     result goes to both
   While the share is unreachable (NAS off, no VPN, not mounted, file
   missing) reading and changing work on the copy; the changes are written
   back with the next synchronization. A missing shared file is never
   re-created.

   Every access to the share runs in a daemon thread with a timeout, so a
   hanging network mount cannot block the UI.

   What was synchronized last is kept as content stamps in a meta file next
   to the copy: {:file F :remote <stamp of the shared file> :local <stamp of
   the copy>}. Pending changes are derived from it, so a crash between
   writing the copy and the share loses nothing."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.local :as local]
            [cljpass.standalone :as sa]))

;; ================================================================ When

(def ^:private network-fs
  #{"cifs" "smb3" "smbfs" "nfs" "nfs4" "afs" "ceph" "glusterfs" "9p" "davfs"
    "fuse.sshfs" "fuse.rclone" "fuse.davfs2" "fuse.gvfsd-fuse"})

(defn- unescape-mount
  "/proc/mounts writes space, tab, newline and backslash as \\ooo."
  [s]
  (str/replace s #"\\([0-7]{3})" (fn [[_ o]] (str (char (Integer/parseInt o 8))))))

(defn- mount-type
  "File system type of the mount that contains path (Linux), or nil."
  [path]
  (when (fs/exists? "/proc/mounts")
    ;; slurp fails on procfs (available() is not supported there)
    (->> (str/split-lines (c/utf8-str (fs/read-bytes "/proc/mounts")))
         (keep (fn [l]
                 (let [[_ dir type] (str/split l #" ")
                       dir (some-> dir unescape-mount)]
                   (when (and type (or (= dir "/") (= path dir) (str/starts-with? path (str dir "/"))))
                     [dir type]))))
         (sort-by (comp count first))
         last
         second)))

(defn network-path?
  "Is the file on a network share? Windows: UNC path (\\\\server\\share),
   Linux: the mount is SMB/CIFS, NFS, SSHFS, WebDAV, ... Reads only the
   mount table, never the share itself."
  [file]
  (let [f (fs/absolutize file)]
    (if (local/windows?)
      (str/starts-with? f "\\\\")
      (boolean (network-fs (mount-type f))))))

(defn enabled?
  "Offline copy for this file? Set per file in config.edn
   (:offline-copies {file true|false}); without a setting for files on a
   network share."
  [cfg file]
  (let [v (get (:offline-copies cfg) file)]
    (if (some? v) (boolean v) (network-path? file))))

;; ================================================================ Copy and meta file

(defn- dir [] (str (fs/path (local/home) "offline")))

(defn copy-file
  "Path of the offline copy of file."
  [file]
  (str (fs/path (dir) (str (subs (c/hex (c/sha256 (c/utf8 (str file)))) 0 16) "-" (fs/file-name file)))))

(defn- meta-file [file] (str (copy-file file) ".edn"))

(defn- load-meta [file]
  (let [f (meta-file file)]
    (when (fs/exists? f)
      (try (edn/read-string (slurp f)) (catch Exception _ nil)))))

(defn- save-meta! [file stamps]
  (sa/write-file! (meta-file file) (c/utf8 (pr-str (assoc stamps :file file)))))

(defn forget!
  "Removes the offline copy of file (without looking at it)."
  [file]
  (fs/delete-if-exists (copy-file file))
  (fs/delete-if-exists (meta-file file))
  nil)

(defn pending?
  "Does the copy hold changes that are not in the shared file yet?"
  [file]
  (let [copy (copy-file file)]
    (and (fs/exists? copy)
         (not= (:local (load-meta file)) (sa/stamp (fs/read-bytes copy))))))

;; ================================================================ Share access

(def ^:dynamic *timeout-ms* "Longest wait for the share." 5000)

(defn- on-share
  "(f) in a daemon thread: {:ok value}, {:error exception} or ::timeout.
   After a timeout the thread is left alone; it ends when the mount gives up."
  [f]
  (let [p (promise)]
    (doto (Thread. ^Runnable (fn [] (deliver p (try {:ok (f)} (catch Throwable e {:error e}))))
                   "cljpass-share")
      (.setDaemon true)
      (.start))
    (deref p *timeout-ms* ::timeout)))

(defn- unreachable [r]
  (if (= ::timeout r)
    {:unreachable :timeout}
    {:unreachable :error :error (ex-message (:error r))}))

(defn- fetch
  "Content of the shared file: {:data bytes} or {:unreachable reason}."
  [file]
  (let [r (on-share #(when (fs/exists? file) (fs/read-bytes file)))]
    (cond (or (= ::timeout r) (:error r)) (unreachable r)
          (nil? (:ok r)) {:unreachable :missing}
          :else {:data (:ok r)})))

(defn- push!
  "Writes data to the shared file if it still has the stamp expected.
   Atomically via a temporary file, without creating folders (an unmounted
   share must not turn into a local folder). Returns :written, :changed or
   {:unreachable reason}."
  [file expected ^bytes data]
  (let [r (on-share #(cond
                       (not (fs/exists? file)) :missing
                       (not= expected (sa/stamp (fs/read-bytes file))) :changed
                       :else (let [tmp (str file ".tmp")]
                               (fs/write-bytes tmp data)
                               (fs/move tmp file true)
                               :written)))]
    (cond (or (= ::timeout r) (:error r)) (unreachable r)
          (= :missing (:ok r)) {:unreachable :missing}
          :else (:ok r))))

;; ================================================================ Synchronize

(defn synchronize
  "Synchronizes the offline copy of db with the shared file.
   remote: the shared file as fetched already (optional).
   Returns [db' status], status:
     {:state :synced | :offline | :error
      :pending  true when the copy has changes the share does not have yet
      :pulled   the shared file was taken over
      :pushed   the copy was written to the share
      :merged   {:added :updated :deleted} when both had changed
      :reason   :timeout | :missing | :error (offline), :error message}"
  ([db] (synchronize db nil))
  ([db remote] (synchronize db remote 3))
  ([db remote attempts]
   (let [{:keys [file copy]} db
         db (if (sa/changed-on-disk? db) (sa/reload db) db)
         stamps (load-meta file)
         dirty? (not= (:stamp db) (:local stamps))
         remote (or remote (fetch file))]
     (if-let [why (:unreachable remote)]
       [db (cond-> {:state :offline :reason why :pending dirty?}
             (:error remote) (assoc :error (:error remote)))]
       (let [data ^bytes (:data remote)
             rs (sa/stamp data)
             changed? (not= rs (:remote stamps))]
         (try
           (cond
             (and (not dirty?) (not changed?))
             [db {:state :synced :pending false}]

             ;; decrypt first: a different master key must not touch the copy
             (not dirty?)
             (let [db (sa/from-bytes db data)]
               (sa/write-file! copy data)
               (save-meta! file {:remote rs :local rs})
               [db {:state :synced :pending false :pulled true}])

             :else
             (let [[db merged] (if changed?
                                 (let [[db stats] (sa/sync-with db (sa/read-doc db data))]
                                   [(sa/save! db) stats])
                                 [db nil])
                   out (fs/read-bytes copy)
                   r (push! file rs out)]
               (cond
                 (= :written r)
                 (do (save-meta! file {:remote (sa/stamp out) :local (sa/stamp out)})
                     [db (cond-> {:state :synced :pending false :pushed true} merged (assoc :merged merged))])

                 ;; someone saved in between: once more with their state
                 (and (= :changed r) (pos? attempts))
                 (let [[db st] (synchronize db nil (dec attempts))]
                   [db (cond-> st (and merged (not (:merged st))) (assoc :merged merged))])

                 (= :changed r)
                 [db {:state :error :pending true :error (i18n/t :app/offline-copy-busy {:file file})}]

                 :else
                 [db (assoc r :state :offline :pending true)])))
           (catch clojure.lang.ExceptionInfo e
             [db {:state :error :pending dirty? :error (i18n/message e)}])))))))

(defn open
  "Opens file through its offline copy and synchronizes. creds as for
   cljpass.standalone/open. Returns [db status].
   Without a copy the share has to be reachable."
  [file creds]
  (let [file (sa/check-path file)
        copy (copy-file file)
        remote (fetch file)
        has-copy? (fs/exists? copy)]
    (cond
      (and (not has-copy?) (= :missing (:unreachable remote)))
      (throw (i18n/error :app/file-not-found {:file file} {:type :not-found}))

      (and (not has-copy?) (:unreachable remote))
      (throw (i18n/error :app/file-unreachable {:file file} {:type :offline}))

      ;; nothing pending in the copy: start from the shared file
      (and (:data remote) (not (pending? file)))
      (let [data (:data remote)
            db (sa/open file creds {:copy copy :data data})]
        (sa/write-file! copy data)
        (save-meta! file {:remote (:stamp db) :local (:stamp db)})
        [db {:state :synced :pending false}])

      :else
      (synchronize (sa/open file creds {:copy copy}) remote))))

(defn attach
  "Starts an offline copy for the open db (the share has to be reachable).
   Returns [db' status]."
  [db]
  (let [{:keys [file]} db
        remote (fetch file)
        _ (when (:unreachable remote)
            (throw (i18n/error :app/file-unreachable {:file file} {:type :offline})))
        copy (copy-file file)
        data (:data remote)
        db (if (= (sa/stamp data) (:stamp db))
             (assoc db :copy copy)
             (sa/from-bytes (assoc db :copy copy) data))]
    (sa/write-file! copy data)
    (save-meta! file {:remote (:stamp db) :local (:stamp db)})
    [db {:state :synced :pending false}]))

(defn detach
  "Ends the offline copy of db: synchronizes and removes it. Refuses while
   changes could not be written to the share yet. Returns db'."
  [db]
  (let [[db st] (synchronize db)]
    (when-not (= :synced (:state st))
      (throw (i18n/error :app/offline-copy-pending {:file (:file db)} {:type :offline})))
    (forget! (:file db))
    (assoc db :copy nil)))
