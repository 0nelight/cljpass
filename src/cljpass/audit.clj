(ns cljpass.audit
  "Audit log of the server (doc/FORMAT.md §9.2): who wrote what, failed
   logins, Kerberos enrollments, rejected objects.

   Every entry is chained to its predecessor by a hash, so that deleting or
   changing single entries in the database is detectable (not a rewrite of
   the whole chain - for that, ship the log elsewhere: each entry also goes
   to stdout as one JSON line, e.g. for journald/syslog).

   Entry: {seq at event user addr path detail prev hash}, hash =
   SHA-256 hex over canonical JSON of all other fields."
  (:require [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.json :as json]
            [cljpass.store :as store]))

(def genesis "0000000000000000000000000000000000000000000000000000000000000000")

(defn init!
  "Creates the table in the server database."
  [db]
  (store/sql-exec! db ["CREATE TABLE IF NOT EXISTS audit (
                          seq INTEGER PRIMARY KEY,
                          at TEXT NOT NULL,
                          event TEXT NOT NULL,
                          user TEXT,
                          addr TEXT,
                          path TEXT,
                          detail TEXT,
                          prev TEXT NOT NULL,
                          hash TEXT NOT NULL)"]))

(defn entry-hash
  "Hash of an entry (without :hash)."
  [e]
  (c/hex (c/sha256 (codec/->bytes (into (sorted-map) (dissoc e :hash))))))

(defn- row->entry [r]
  (cond-> (select-keys r [:seq :at :event :prev :hash])
    (:user r) (assoc :user (:user r))
    (:addr r) (assoc :addr (:addr r))
    (:path r) (assoc :path (:path r))
    (:detail r) (assoc :detail (json/read-str (:detail r)))))

(defn- last-entry [db]
  (first (store/sql-query db ["SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"])))

(def ^:private lock (Object.))

(defn log!
  "Appends an event. m: {:event \"object.create\" :user :addr :path :detail {}}.
   Empty values are left out. Returns the entry."
  [db m & [{:keys [quiet]}]]
  (locking lock
    (let [{:keys [seq hash]} (last-entry db)
          ;; as it will be read back (keys/values as JSON), so that the hash stays reproducible
          m (update m :detail #(some-> % json/write-str json/read-str))
          e (into {:seq (inc (or seq 0)) :at (store/now) :event (name (:event m)) :prev (or hash genesis)}
                  (for [k [:user :addr :path :detail]
                        :let [v (get m k)]
                        :when (and (some? v) (not= "" v) (not= {} v))]
                    [k v]))
          e (assoc e :hash (entry-hash e))]
      (store/sql-exec! db ["INSERT INTO audit(seq, at, event, user, addr, path, detail, prev, hash) VALUES (?,?,?,?,?,?,?,?,?)"
                           (:seq e) (:at e) (:event e) (:user e) (:addr e) (:path e)
                           (some-> (:detail e) json/write-str) (:prev e) (:hash e)])
      (when-not quiet
        (locking *out* (println (str "AUDIT " (json/write-str e)))))
      e)))

(defn entries
  "Entries with seq > since, oldest first."
  [db since limit]
  (mapv row->entry (store/sql-query db ["SELECT * FROM audit WHERE seq > ? ORDER BY seq LIMIT ?" since limit])))

(defn verify-chain
  "Checks consecutive entries: each hash is correct and each prev is the
   hash of the entry before. prev-hash: hash before the first entry (nil =
   not known, e.g. when reading from the middle). Returns nil or the seq of
   the first broken entry."
  [entries prev-hash]
  (loop [[e & more] entries prev prev-hash]
    (cond
      (nil? e) nil
      (not= (:hash e) (entry-hash e)) (:seq e)
      (and prev (not= prev (:prev e))) (:seq e)
      (and (nil? prev) (= 1 (:seq e)) (not= genesis (:prev e))) (:seq e)
      :else (recur more (:hash e)))))
