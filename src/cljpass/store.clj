(ns cljpass.store
  "Object store (doc/FORMAT.md §9). A store only knows paths and JSON
   texts - no permissions, no keys. It is considered NOT trustworthy:
   clients check everything themselves.

   Implementations:
   - MemStore     for tests
   - SqliteStore  local cache in the client and the server's database
   - (cljpass.remote) HTTP client to the server"
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n])
  (:import [java.sql Connection DriverManager PreparedStatement ResultSet]))

(defprotocol ObjectStore
  (get-obj [s path] "JSON text or nil")
  (list-paths [s prefix] "sorted paths with this prefix")
  (create-obj! [s path body] "create only; throws {:type :conflict} if it exists")
  (put-obj! [s path body] "create or overwrite (only requests/, escrow/)")
  (since [s seq-no limit] "changes with seq > seq-no: [{:seq :path :body}]"))

(defn conflict! [path]
  (throw (i18n/error :core/conflict {:path path} {:type :conflict :path path})))

(def overwritable-prefixes ["requests/" "escrow/"])

(defn overwritable? [path] (some #(str/starts-with? path %) overwritable-prefixes))

;; ================================================================ Helpers

(defn read-doc [s path] (some-> (get-obj s path) codec/parse))

(defn write-doc! [s path doc] (create-obj! s path (codec/->str doc)))

(defn pad [n] (format "%08d" n))

(defn numbered
  "[[number path] ...] of all <prefix>NNNNNNNN.json, ascending."
  [s prefix]
  (->> (list-paths s prefix)
       (keep (fn [p] (when-let [[_ n] (re-matches #"(\d{8})\.json" (subs p (count prefix)))]
                       [(parse-long n) p])))
       (sort-by first)))

(defn children
  "Direct children of a prefix (directory-like)."
  [s prefix]
  (->> (list-paths s prefix)
       (map #(first (str/split (subs % (count prefix)) #"/" 2)))
       distinct sort))

(def name-re #"[a-z0-9][a-z0-9._-]{0,63}")

(defn safe-name
  "Strictly checks names that end up in paths (§3.1)."
  [s]
  (when-not (and (string? s) (re-matches name-re s) (not (str/includes? s "..")))
    (throw (i18n/error :core/invalid-name {:name (pr-str s)} {:type :invalid-name})))
  s)

(defn now [] (str (java.time.Instant/now)))

;; ================================================================ MemStore

(defrecord MemStore [state]
  ObjectStore
  (get-obj [_ path] (:body (get-in @state [:objects path])))
  (list-paths [_ prefix] (sort (filter #(str/starts-with? % prefix) (keys (:objects @state)))))
  (create-obj! [_ path body]
    (let [ok (atom false)]
      (swap! state (fn [st]
                     (if (contains? (:objects st) path)
                       (do (reset! ok false) st)
                       (let [n (inc (:seq st 0))]
                         (reset! ok true)
                         (-> st (assoc :seq n) (assoc-in [:objects path] {:seq n :body body}))))))
      (when-not @ok (conflict! path))
      path))
  (put-obj! [_ path body]
    (swap! state (fn [st] (let [n (inc (:seq st 0))]
                            (-> st (assoc :seq n) (assoc-in [:objects path] {:seq n :body body})))))
    path)
  (since [_ seq-no limit]
    (->> (:objects @state)
         (map (fn [[p {:keys [seq body]}]] {:seq seq :path p :body body}))
         (filter #(> (:seq %) seq-no))
         (sort-by :seq) (take limit) vec)))

(defn mem-store [] (->MemStore (atom {:seq 0 :objects {}})))

;; ================================================================ SQLite (JDBC)

;; One connection per database file; all accesses run one after another
;; (SQLite serializes writes anyway).
(defonce ^:private connections (atom {}))

(defn- connection ^Connection [db]
  (or (@connections db)
      (locking connections
        (or (@connections db)
            (let [c (DriverManager/getConnection (str "jdbc:sqlite:" db))]
              (swap! connections assoc db c)
              c)))))

(defn- prepare ^PreparedStatement [^Connection c [sql & params]]
  (let [ps (.prepareStatement c ^String sql)]
    (doseq [[i v] (map-indexed vector params)]
      (.setObject ps (int (inc i)) v))
    ps))

(defn sql-exec! [db sql-params]
  (let [c (connection db)]
    (locking c
      (with-open [ps (prepare c sql-params)]
        (.execute ps)
        nil))))

(defn sql-query
  "Rows as maps with column names as keywords."
  [db sql-params]
  (let [c (connection db)]
    (locking c
      (with-open [ps (prepare c sql-params)
                  ^ResultSet rs (.executeQuery ps)]
        (let [md (.getMetaData rs)
              cols (mapv #(keyword (.getColumnLabel md (int %))) (range 1 (inc (.getColumnCount md))))]
          (loop [rows (transient [])]
            (if (.next rs)
              (recur (conj! rows (into {} (map-indexed (fn [i k] [k (.getObject rs (int (inc i)))]) cols))))
              (persistent! rows))))))))

(defn close-sqlite!
  "Closes the connection to a database (tests)."
  [db]
  (when-let [^Connection c (@connections db)]
    (swap! connections dissoc db)
    (.close c)))

(defn- unique-violation? [e] (str/includes? (str (ex-message e)) "UNIQUE constraint failed"))

(defrecord SqliteStore [db]
  ObjectStore
  (get-obj [_ path] (:body (first (sql-query db ["SELECT body FROM objects WHERE path = ?" path]))))
  (list-paths [_ prefix]
    (mapv :path (sql-query db ["SELECT path FROM objects WHERE substr(path, 1, ?) = ? ORDER BY path"
                               (count prefix) prefix])))
  (create-obj! [_ path body]
    (try (sql-exec! db ["INSERT INTO objects(path, body, created_at) VALUES (?, ?, ?)" path body (now)])
         path
         (catch Exception e (if (unique-violation? e) (conflict! path) (throw e)))))
  (put-obj! [_ path body]
    ;; REPLACE assigns a new seq, so that sync sees the change
    (sql-exec! db ["REPLACE INTO objects(path, body, created_at) VALUES (?, ?, ?)" path body (now)])
    path)
  (since [_ seq-no limit]
    (vec (sql-query db ["SELECT seq, path, body FROM objects WHERE seq > ? ORDER BY seq LIMIT ?" seq-no limit]))))

(defn sqlite-store
  "Opens/creates an SQLite database with the object schema."
  [db-file]
  (fs/create-dirs (fs/parent (fs/absolutize db-file)))
  (let [db (fs/absolutize db-file)]
    (sql-exec! db ["PRAGMA journal_mode=WAL"])
    (sql-exec! db ["CREATE TABLE IF NOT EXISTS objects (
                      seq INTEGER PRIMARY KEY AUTOINCREMENT,
                      path TEXT UNIQUE NOT NULL,
                      body TEXT NOT NULL,
                      created_at TEXT NOT NULL)"])
    (sql-exec! db ["CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)"])
    (->SqliteStore db)))

(defn meta-get
  "Local metadata (client/server internal only, hence EDN)."
  [{:keys [db]} k]
  (some-> (first (sql-query db ["SELECT v FROM meta WHERE k = ?" (name k)])) :v edn/read-string))

(defn meta-put! [{:keys [db]} k v]
  (binding [*print-length* nil *print-level* nil]
    (sql-exec! db ["REPLACE INTO meta(k, v) VALUES (?, ?)" (name k) (pr-str v)])))
