(ns cljpass.sync
  "Client store: always reads from the local SQLite cache (works offline),
   writes to the server. If the server is unreachable, the change goes into
   the queue (outbox) and is pushed on the next sync. Conflicts are never
   lost silently (doc/FORMAT.md §9)."
  (:require [cljpass.i18n :as i18n]
            [cljpass.remote :as remote]
            [cljpass.store :as store]))

(defn- init-outbox! [db]
  (store/sql-exec! db ["CREATE TABLE IF NOT EXISTS outbox (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          path TEXT NOT NULL,
                          body TEXT NOT NULL,
                          kind TEXT NOT NULL,          -- create | put
                          status TEXT NOT NULL,        -- pending | conflict | rejected
                          error TEXT,
                          created_at TEXT NOT NULL)"]))

(defn- delete-local! [db path] (store/sql-exec! db ["DELETE FROM objects WHERE path = ?" path]))

(defn- enqueue! [db path body kind]
  (store/sql-exec! db ["INSERT INTO outbox(path, body, kind, status, created_at) VALUES (?, ?, ?, 'pending', ?)"
                       path body kind (store/now)]))

(defn outbox [{:keys [cache]}]
  (vec (store/sql-query (:db cache) ["SELECT id, path, body, kind, status, error, created_at FROM outbox ORDER BY id"])))

(defn drop-outbox! [{:keys [cache]} id]
  (store/sql-exec! (:db cache) ["DELETE FROM outbox WHERE id = ?" id]))

(defn- pending-paths [db]
  (set (map :path (store/sql-query db ["SELECT path FROM outbox WHERE status = 'pending'"]))))

(declare pull!)

(defrecord ClientStore [cache server ident-fn]
  store/ObjectStore
  (get-obj [_ path] (store/get-obj cache path))
  (list-paths [_ prefix] (store/list-paths cache prefix))
  (since [_ n limit] (store/since cache n limit))
  (create-obj! [this path body]
    (when (store/get-obj cache path) (store/conflict! path))
    (let [r (try (remote/put-object! server (ident-fn) path body)
                 (catch clojure.lang.ExceptionInfo e
                   (if (= :offline (:type (ex-data e))) :offline (throw e))))]
      (case r
        :ok (store/create-obj! cache path body)
        :conflict (do (try (pull! this) (catch Exception _ nil))
                      (store/conflict! path))
        :offline (do (store/create-obj! cache path body)
                     (enqueue! (:db cache) path body "create")
                     path))))
  (put-obj! [_ path body]
    (let [r (try (remote/put-object! server (ident-fn) path body)
                 (catch clojure.lang.ExceptionInfo e
                   (if (= :offline (:type (ex-data e))) :offline (throw e))))]
      (store/put-obj! cache path body)
      (when (= :offline r) (enqueue! (:db cache) path body "put"))
      path)))

(defn pull!
  "Fetches new objects from the server into the cache."
  [{:keys [cache server ident-fn]}]
    (let [db (:db cache)
          pending (pending-paths db)]
      (loop [since (or (store/meta-get cache :remote-seq) 0) n 0 anomalies []]
        (let [{:keys [objects more]} (remote/changes server (ident-fn) since)
              anomalies
              (reduce
               (fn [acc {:keys [seq path body]}]
                 (let [local (store/get-obj cache path)]
                   (cond
                     (nil? local) (do (store/create-obj! cache path body) acc)
                     (= local body) acc
                     (store/overwritable? path) (do (store/put-obj! cache path body) acc)
                     ;; our own version, not yet uploaded, collides: the server wins,
                     ;; our version is kept in the outbox as a conflict
                     (contains? pending path)
                     (do (delete-local! db path)
                         (store/create-obj! cache path body)
                         (store/sql-exec! db ["UPDATE outbox SET status = 'conflict', error = ? WHERE path = ? AND status = 'pending'"
                                              (i18n/t :core/sync-changed-by-someone-else) path])
                         acc)
                     :else (conj acc path))))
               anomalies objects)
              last-seq (or (:seq (last objects)) since)]
          (store/meta-put! cache :remote-seq last-seq)
          (if (and more (< n 1000))
            (recur last-seq (inc n) anomalies)
            {:received (+ (* n 1000) (count objects)) :anomalies anomalies})))))

(defn push!
  "Pushes the queue."
  [{:keys [cache server ident-fn]}]
    (let [db (:db cache)]
      (reduce
       (fn [acc {:keys [id path body]}]
         (if (:offline acc)
           acc
           (try
             (case (remote/put-object! server (ident-fn) path body)
               :ok (do (drop-outbox! {:cache cache} id) (update acc :pushed inc))
               :conflict (do (delete-local! db path)
                             (store/sql-exec! db ["UPDATE outbox SET status = 'conflict', error = ? WHERE id = ?"
                                                  (i18n/t :core/sync-changed-by-someone-else) id])
                             (update acc :conflicts inc)))
             (catch clojure.lang.ExceptionInfo e
               (case (:type (ex-data e))
                 :offline (assoc acc :offline true)
                 :rejected (do (delete-local! db path)
                               (store/sql-exec! db ["UPDATE outbox SET status = 'rejected', error = ? WHERE id = ?"
                                                    (ex-message e) id])
                               (update acc :rejected inc))
                 (throw e))))))
       {:pushed 0 :conflicts 0 :rejected 0 :offline false}
       (store/sql-query db ["SELECT id, path, body FROM outbox WHERE status = 'pending' ORDER BY id"]))))

(defn client-store
  "cache-file: local SQLite file; ident-fn: returns the unlocked identity."
  [cache-file server ident-fn]
  (let [cache (store/sqlite-store cache-file)]
    (init-outbox! (:db cache))
    (->ClientStore cache server ident-fn)))

(defn sync!
  "Pull, push, pull. Being offline is not an error."
  [cs]
  (try
    (let [pull1 (pull! cs)
          push (push! cs)
          pull2 (if (pos? (:pushed push)) (pull! cs) {:received 0 :anomalies []})]
      {:online true :received (+ (:received pull1) (:received pull2)) :push push
       :anomalies (into (:anomalies pull1) (:anomalies pull2))})
    (catch clojure.lang.ExceptionInfo e
      (if (#{:offline :unauthorized} (:type (ex-data e)))
        {:online false :reason (ex-message e) :type (:type (ex-data e))}
        (throw e)))))
