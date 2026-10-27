(ns cljpass.service
  "Application logic for the web UI and the CLI.

   Two modes (doc/FORMAT.md §13), the same UI:
   - Server: identity (DPAPI), vault with permissions per entry, sync.
   - Local (standalone): a KeePass file with a master password, without a
     server (cljpass.standalone). Switching in both directions at any time.

   The identity or the opened file is kept in RAM only encrypted
   (cljpass.secmem) and is discarded after idle time (lock). The UI never
   gets private keys, and passwords only on explicit request."
  (:require [clojure.string :as str]
            [cljpass.autoopen :as ao]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.csv :as csv]
            [cljpass.export :as ex]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.identity :as idn]
            [cljpass.kdbx :as kdbx]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.offline :as offline]
            [cljpass.otp :as otp]
            [cljpass.pwgen :as pwgen]
            [cljpass.remote :as remote]
            [cljpass.secmem :as sm]
            [cljpass.standalone :as sa]
            [cljpass.store :as store]
            [cljpass.sync :as sync]
            [cljpass.vault :as v]))

;; ================================================================ Session

(defn new-session
  "idle-seconds: automatic lock (KeePass: 'Lock workspace after ...')."
  [{:keys [idle-seconds] :or {idle-seconds 300}}]
  (atom {:identity nil :file nil :cs nil :idle-ms (* 1000 idle-seconds) :last-activity (System/currentTimeMillis)}))

(defn locked?
  "Neither identity (server) nor file (local) unlocked."
  [session]
  (and (nil? (:identity @session)) (nil? (:file @session))))

(defn lock! [session] (swap! session assoc :identity nil :file nil) nil)

(defn standalone-mode? [] (local/standalone? (local/load-config)))

(defn extra?
  "A session for a further KeePass file in its own tab (open-extra-file!,
   AutoOpen) - beside the main database, which may be the server."
  [session]
  (some? (:extra @session)))

(defn- standalone?
  "Does the session work on a KeePass file (local mode or a further tab)?"
  [session]
  (or (extra? session) (standalone-mode?)))

(defn- main-only!
  "Server connection and setup only exist in the main tab."
  [session]
  (when (extra? session)
    (throw (i18n/error :app/main-tab-only nil {:type :conflict}))))

(defn- server-cfg
  "Server settings: in server mode the configuration, in local mode the
   requested connection (:link)."
  [cfg]
  (if (local/standalone? cfg)
    (or (some-> (:link cfg) (select-keys [:server :org-hash :user]) not-empty)
        (throw (i18n/error :app/no-server-in-standalone nil {:type :standalone})))
    cfg))

(defn- current-ident [session]
  (let [p (or (:identity @session) (throw (i18n/error :app/locked nil {:type :locked})))]
    (sm/with-plain p #(codec/parse (c/utf8-str %)))))

(defn- client-store [session cfg]
  (let [cs (:cs @session)]
    (if (and cs (= (:server cs) (:server cfg)))
      cs
      (let [cs (sync/client-store (local/cache-file) (:server cfg) #(current-ident session))]
        (swap! session assoc :cs cs)
        cs))))

(defn- load-identity! [session]
  (swap! session assoc :identity (sm/protect (local/load-identity-bytes))))

(defn unlock!
  "Loads the identity via DPAPI and keeps it in RAM only encrypted."
  [session]
  (load-identity! session)
  (swap! session assoc :last-activity (System/currentTimeMillis))
  nil)

(defn set-idle!
  "Sets the lock after idle time (seconds, 0 = never)."
  [session seconds]
  (swap! session assoc :idle-ms (* 1000 (max 0 (long seconds)))))

(defn check-idle!
  [session]
  (let [{:keys [idle-ms last-activity]} @session]
    (when (and (not (locked? session)) (pos? idle-ms) (> (- (System/currentTimeMillis) last-activity) idle-ms))
      (lock! session)
      true)))

(def ^:dynamic *background*
  "true for automatic requests (polling, background sync): they don't count
   as activity, otherwise the automatic lock would never happen."
  false)

(defn touch! [session]
  (when-not *background* (swap! session assoc :last-activity (System/currentTimeMillis))))

(defn with-ctx
  "(f ctx) with the unlocked identity; saves the anti-rollback state."
  [session f]
  (check-idle! session)
  (when (locked? session) (throw (i18n/error :app/locked nil {:type :locked})))
  (touch! session)
  (let [cfg (server-cfg (local/load-config!))
        cs (client-store session cfg)
        ctx (v/open-ctx cs (:org-hash cfg) (current-ident session) (store/meta-get (:cache cs) :seen))
        result (f ctx)]
    (store/meta-put! (:cache cs) :seen @(:seen ctx))
    result))

;; Fetch the latest state before writing (roster, head versions).
;; Being offline is not an error - then the local state applies.
(defn- refresh! [session]
  (when-not (locked? session)
    (let [cs (client-store session (server-cfg (local/load-config!)))]
      (try (sync/pull! cs) (catch clojure.lang.ExceptionInfo _ nil)))))

(defn with-fresh-ctx [session f]
  (refresh! session)
  (with-ctx session f))

;; ================================================================ Enrollment

(defn- verified-org
  "Fetches org.json from the server and checks it against the pin."
  [server org-hash]
  (let [tmp (store/mem-store)]
    (store/create-obj! tmp v/org-path (remote/fetch-org server))
    (v/load-org tmp org-hash)))

(defn kerberos?
  "Enrollment with the Windows logon? From org.edn {:kerberos true}
   (distributed by IT), overridable per call."
  [opts]
  (if (contains? opts :kerberos) (boolean (:kerberos opts)) (true? (:kerberos (local/machine-config)))))

(defn- submit!
  "Sends request + escrow: with Kerberos in one authenticated POST,
   otherwise as signed objects."
  [session server org ident kerberos]
  (if kerberos
    (remote/enroll-kerberos! server (v/request-docs org ident))
    (v/submit-request! (client-store session {:server server}) org ident)))

(defn enroll!
  "First start: creates the identity (DPAPI), uploads request + escrow.
   Server and org hash usually come via GPO (local/machine-config).
   With Kerberos (org.edn {:kerberos true}) the server confirms the
   Windows user, so that an admin (or `auto-approve`) can approve without
   a fingerprint; the local state is only written once the server has
   accepted the request."
  [session {:keys [server org-hash user protector] :as opts}]
  (main-only! session)
  (when (local/standalone? (local/load-config))
    (throw (i18n/error :app/enroll-in-standalone nil {:type :standalone})))
  (let [kerberos (kerberos? opts)
        user (store/safe-name (or (not-empty user) (local/default-user)))
        org (verified-org server org-hash)
        ident (if (local/identity-exists?) (local/load-identity) (idn/new-identity user))
        _ (when (not= user (:user ident)) (throw (i18n/error :app/identity-other-user nil {})))
        _ (when kerberos (submit! session server org ident true))
        _ (local/save-identity! ident (or protector (local/default-protector)))
        _ (local/save-config! (cond-> {:mode :server :server server :org-hash org-hash :user user}
                                kerberos (assoc :kerberos true)))
        _ (unlock! session)]
    (when-not kerberos (submit! session server org ident false))
    {:user user :fingerprint (idn/fingerprint ident) :kerberos kerberos}))

(defn auto-enroll-config
  "Settings for enrollment without any input, or nil: org.edn has server,
   org hash and {:kerberos true}, and the device is not set up yet."
  []
  (let [m (local/machine-config)]
    (when (and (nil? (local/load-config)) (:server m) (:org-hash m) (true? (:kerberos m))
               (not (false? (:auto-enroll m))))
      (select-keys m [:server :org-hash]))))

;; ================================================================ Local mode (KeePass file)

(defn- current-file [session]
  (check-idle! session)
  (or (:file @session) (throw (i18n/error :app/locked nil {:type :locked}))))

(defn- with-file [session f]
  (let [db (current-file session)]
    (touch! session)
    (f db)))

(def ^:private offline-retry-ms
  "While the share is unreachable, changes try it at most this often (each
   try can take the full timeout)."
  30000)

(defn- sync-copy!
  "Synchronizes the offline copy with the shared file (cljpass.offline) and
   remembers the result as :copy-state. Without force a recently
   unreachable share is not tried again."
  [session db force]
  (let [{:keys [state at]} (:copy-state @session)
        now (System/currentTimeMillis)]
    (if (and (not force) (= :offline state) at (< (- now at) offline-retry-ms))
      (do (swap! session assoc-in [:copy-state :pending] (offline/pending? (:file db)))
          db)
      (let [[db st] (offline/synchronize db)]
        (swap! session assoc :copy-state (assoc st :at now))
        db))))

(defn- change-file!
  "(f db) -> [db' result]. Reloads first if the file was changed externally
   (KeePass, another device), saves right afterwards. With an offline copy
   the shared file is synchronized before and after."
  [session f]
  (locking session
    (let [db (current-file session)
          _ (touch! session)
          db (cond (:copy db) (sync-copy! session db false)
                   (sa/changed-on-disk? db) (sa/reload db)
                   :else db)
          [db result] (f db)
          db (sa/save! db)
          db (if (:copy db) (sync-copy! session db false) db)]
      (swap! session assoc :file db)
      result)))

(defn- open-db
  "Opens or creates a KeePass file, through its offline copy where that is
   switched on (cljpass.offline/enabled?). Returns [db copy-state]."
  [cfg file creds create kdf]
  (let [copy? (offline/enabled? cfg file)]
    (cond
      create (let [db (sa/create! file creds kdf)]
               (if copy? (do (offline/forget! file) (offline/attach db)) [db nil]))
      copy? (offline/open file creds)
      :else [(sa/open file creds) nil])))

(defn- copy-status
  "Offline copy for the UI: {:enabled :state :pending :reason :error :merged}."
  [session db]
  (if (:copy db)
    (assoc (select-keys (:copy-state @session) [:state :pending :reason :error :merged]) :enabled true)
    {:enabled false}))

(defn- file-payload [db id]
  (or (sa/payload db id) (throw (i18n/error :app/entry-not-found nil {:type :not-found}))))

(defn- link-status
  "State of a requested server connection in local mode:
   :ready (approved), :pending, :offline or :error."
  [session cfg]
  (try
    (when-not (:identity @session) (load-identity! session))
    (let [lcfg (server-cfg cfg)
          r (sync/sync! (client-store session lcfg))
          active? (try (with-ctx session #(boolean (v/active-user (:roster %) (:user lcfg))))
                       (catch Exception _ false))]
      ;; 401 means: server reachable, but not approved yet
      {:state (cond active? :ready (or (:online r) (= :unauthorized (:type r))) :pending :else :offline)
       :server (:server lcfg)
       :user (:user lcfg)
       :fingerprint (idn/fingerprint (current-ident session))})
    (catch clojure.lang.ExceptionInfo e
      {:state :error :error (i18n/message e)})))

(defn open-file!
  "Starts or unlocks local mode: opens a KeePass file, with create = true
   creates a new one. opts: {:file :password :keyfile bytes :create :kdf}."
  [session {:keys [file password keyfile create kdf]}]
  (main-only! session)
  (let [cfg (local/load-config)
        _ (when (and cfg (not (local/standalone? cfg)))
            (throw (i18n/error :app/connected-to-server nil {:type :conflict})))
        _ (when-not (or (local/standalone? cfg) (local/standalone-allowed?))
            (throw (i18n/error :app/standalone-disabled nil {:type :forbidden})))
        file (sa/check-path (or (not-empty (str/trim (str file))) (:file cfg)
                                (throw (i18n/error :app/no-file nil {:type :invalid-path}))))
        [db st] (open-db cfg file {:password (not-empty password) :keyfile keyfile} create kdf)]
    (local/save-config! (assoc (or cfg {}) :mode :standalone :file (:file db)))
    (local/update-prefs! (fn [m] (update m :recent-files #(vec (take 10 (distinct (cons (:file db) %)))))))
    (swap! session assoc :file db :copy-state (some-> st (assoc :at (System/currentTimeMillis)))
           :last-activity (System/currentTimeMillis))
    (when (and (= :requested (get-in cfg [:link :state])) (local/identity-exists?))
      (load-identity! session))
    {:file (:file db) :name (:name db) :offline-copy (copy-status session db)}))

(defn set-offline-copy!
  "Local mode: switches the offline copy of the open file on or off and
   remembers that for this file. Switching off needs the share, so that no
   change stays behind in the copy."
  [session on]
  (when-not (standalone? session)
    (throw (i18n/error :app/offline-copy-file-only nil {:type :standalone})))
  (locking session
    (let [db (current-file session)
          db (cond
               (and on (not (:copy db))) (let [[db st] (offline/attach db)]
                                           (swap! session assoc :copy-state (assoc st :at (System/currentTimeMillis)))
                                           db)
               (and (not on) (:copy db)) (let [db (offline/detach db)]
                                           (swap! session assoc :copy-state nil)
                                           db)
               :else db)]
      (swap! session assoc :file db)
      (local/save-config! (assoc-in (local/load-config!) [:offline-copies (:file db)] (boolean on)))
      (copy-status session db))))

;; ================================================================ Further files (tabs) and AutoOpen

(defn open-extra-file!
  "Opens a further KeePass file in this (new) session - for a tab beside the
   main database, which may also be the server. Changes neither the
   configuration nor the mode, only the list of recent files. The session
   remembers the file, so that it can be unlocked again after locking.
   opts: {:file :password :keyfile bytes :create :kdf}."
  [session {:keys [file password keyfile create kdf]}]
  (when-not (or (local/standalone? (local/load-config)) (local/standalone-allowed?))
    (throw (i18n/error :app/standalone-disabled nil {:type :forbidden})))
  (let [file (sa/check-path (or (not-empty (str/trim (str file))) (:extra @session)
                                (throw (i18n/error :app/no-file nil {:type :invalid-path}))))
        _ (swap! session assoc :extra file)
        [db st] (open-db (local/load-config) file {:password (not-empty password) :keyfile keyfile} create kdf)]
    (local/update-prefs! (fn [m] (update m :recent-files #(vec (take 10 (distinct (cons (:file db) %)))))))
    (swap! session assoc :extra (:file db) :file db :copy-state (some-> st (assoc :at (System/currentTimeMillis)))
           :last-activity (System/currentTimeMillis))
    {:file (:file db) :name (:name db) :offline-copy (copy-status session db)}))

(defn session-file
  "Path of the KeePass file of the session (open or locked), nil for the server."
  [session]
  (or (some-> (:file @session) :file) (:extra @session)
      (when (standalone-mode?) (:file (local/load-config)))))

(defn- entry-order
  "Order like in the KeePass file: group, then position in it."
  [{:keys [payload]}]
  [(str (:folder payload)) (get-in payload [:kdbx :pos] Long/MAX_VALUE) (str (:title payload))])

(defn- auto-open-source
  "Entries of the session's database for AutoOpen: {:entries [{:id :payload
   :trusted}] :db-file :exclude-folder}. In server mode only own entries are
   trusted: an entry shared by someone else must not make this computer open
   files (e.g. from a foreign network share) without being asked."
  [session]
  (if (standalone? session)
    (with-file session
      (fn [db] {:db-file (:file db)
                :exclude-folder (kp/recycle-bin (sa/db-record db))
                :entries (vec (sort-by entry-order (for [[id p] (sa/entries db)] {:id id :payload p :trusted true})))}))
    (with-ctx session
      (fn [ctx] {:db-file nil
                 :entries (vec (sort-by entry-order
                                         (for [{:keys [id payload my-perm]} (:entries (v/list-entries ctx))
                                               :when (ao/auto-open-folder? (:folder payload))]
                                           {:id id :payload payload :trusted (= "owner" (some-> my-perm name))})))}))))

(defn- auto-open-opts [{:keys [db-file exclude-folder]}]
  {:db-file db-file
   ;; server mode: relative paths count from the home folder
   :base-dir (when-not db-file (System/getProperty "user.home"))
   :env (into {} (System/getenv))
   :exclude-folder exclude-folder})

(defn auto-open-items
  "AutoOpen entries of the session's database (cljpass.autoopen/items),
   without secrets. :auto = to be opened automatically on unlocking
   (enabled, this device, trusted)."
  [session]
  (let [src (auto-open-source session)
        trusted (into {} (map (juxt :id :trusted)) (:entries src))]
    (mapv #(assoc % :auto (boolean (and (:enabled %) (:device %) (trusted (:id %)))))
          (ao/items (:entries src) (auto-open-opts src)))))

(defn auto-open-target
  "File and master key for one AutoOpen entry: {:file :password :keyfile
   bytes :prompt :restore-focus}, or {:skip true} if it is to be skipped
   silently (SkipIfNotExists, SkipIfKeyFileNotExists). :prompt = no key
   stored, ask for it like KeeAutoExec."
  [session id]
  (let [src (auto-open-source session)
        payload (or (some #(when (= id (:id %)) (:payload %)) (:entries src))
                    (throw (i18n/error :app/entry-not-found nil {:type :not-found})))
        {:keys [file keyfile keyfile-attachment skip-if-missing skip-if-key-missing] :as t}
        (or (ao/target payload (auto-open-opts src))
            (throw (i18n/error :app/no-file nil {:type :invalid-path})))]
    (cond
      (and (not (fs/exists? file)) skip-if-missing) {:skip true}
      (not (fs/exists? file)) (throw (i18n/error :app/file-not-found {:file file} {:type :not-found}))
      (and keyfile (not (fs/exists? keyfile)) skip-if-key-missing) {:skip true}
      (and keyfile (not (fs/exists? keyfile)))
      (throw (i18n/error :app/auto-open-keyfile-missing {:file keyfile} {:type :not-found}))
      :else {:file file
             :prompt (and (nil? (:password t)) (nil? keyfile) (not keyfile-attachment))
             :password (:password t)
             :keyfile (cond keyfile (fs/read-bytes keyfile)
                            keyfile-attachment (kp/attachment-data payload ao/keyfile-attachment))
             :restore-focus (:restore-focus t)})))

(defn connect-server!
  "Local mode -> server, step 1: creates the identity (or takes the existing
   one) and requests approval. Until the admin approves, work continues
   with the file; then finish-connect! takes it over."
  [session {:keys [server org-hash user protector] :as opts}]
  (main-only! session)
  (let [cfg (local/load-config!)
        _ (when-not (local/standalone? cfg) (throw (i18n/error :app/already-connected nil {:type :conflict})))
        kerberos (kerberos? opts)
        _ (current-file session)
        user (store/safe-name (str/lower-case (or (not-empty (str/trim (str user))) (local/default-user))))
        org (verified-org server org-hash)
        ident (if (local/identity-exists?) (local/load-identity) (idn/new-identity user))
        _ (when (not= user (:user ident))
            (throw (i18n/error :app/identity-exists-for {:user (:user ident)} {:type :conflict})))
        _ (when-not (local/identity-exists?) (local/save-identity! ident (or protector (local/default-protector))))
        link (cond-> {:server server :org-hash org-hash :user user :state :requested}
               kerberos (assoc :kerberos true))]
    (local/save-config! (assoc cfg :link link))
    (load-identity! session)
    (submit! session server org ident kerberos)
    (link-status session (local/load-config))))

(defn cancel-connect!
  "Withdraws the requested connection (the identity stays)."
  [session]
  (main-only! session)
  (let [cfg (local/load-config!)]
    (when (= :requested (get-in cfg [:link :state]))
      (local/save-config! (assoc-in cfg [:link :state] :cancelled)))
    true))

(defn finish-connect!
  "Local mode -> server, step 2 (after approval): takes the file into the
   vault (reconciled, no duplicates) and switches to server mode. The file
   itself stays unchanged."
  [session]
  (main-only! session)
  (let [cfg (local/load-config!)
        link (:link cfg)
        _ (when-not (and (local/standalone? cfg) (= :requested (:state link)))
            (throw (i18n/error :app/no-connect-requested nil {:type :conflict})))
        db (current-file session)
        db (cond (:copy db) (sync-copy! session db true)
                 (sa/changed-on-disk? db) (sa/reload db)
                 :else db)
        _ (when-not (:identity @session) (load-identity! session))
        r (sync/sync! (client-store session (server-cfg cfg)))
        _ (when-not (:online r)
            (throw (i18n/error :app/server-unreachable {:reason (:reason r)} {:type :offline})))
        report (with-ctx session
                 (fn [ctx]
                   (when-not (v/active-user (:roster ctx) (:user link))
                     (throw (i18n/error :app/not-approved-yet nil {:type :pending})))
                   (sa/merge-into-vault! ctx db)))]
    (local/save-config! (-> (select-keys link [:server :org-hash :user :kerberos])
                            (assoc :mode :server :file (:file db))))
    (swap! session assoc :file nil)
    (assoc report :file (:file db) :log (with-ctx session v/maintain-groups!))))

(declare sync-now pending-count)

(defn disconnect!
  "Server -> local mode: writes all readable entries as a KeePass file and
   works with it from now on. Identity and cache stay, so that reconnecting
   later can reconcile the changes.
   opts: {:file :password :keyfile bytes :overwrite :force :kdf}."
  [session {:keys [file password keyfile overwrite force kdf]}]
  (main-only! session)
  (let [cfg (local/load-config!)
        _ (when (local/standalone? cfg) (throw (i18n/error :app/already-standalone nil {:type :conflict})))
        _ (when-not (local/standalone-allowed?)
            (throw (i18n/error :app/standalone-disabled nil {:type :forbidden})))
        file (sa/check-path file)
        _ (when (and (fs/exists? file) (not overwrite))
            (throw (i18n/error :app/file-exists {:file file} {:type :exists})))
        _ (when (and (str/blank? password) (nil? keyfile))
            (throw (i18n/error :app/master-key-required nil {:type :kdbx-bad-key})))
        _ (sync-now session)
        pending (pending-count session)
        _ (when (and (pos? pending) (not force))
            (throw (ex-info (i18n/tn :app/pending-changes pending)
                            {:type :pending-changes :msg :app/pending-changes :params {:n pending}})))
        items (with-ctx session
                (fn [ctx]
                  (mapv (fn [{:keys [id head payload]}]
                          {:id id :version (:version head) :payload payload :modified (:created-at head)})
                        (:entries (v/list-entries ctx)))))
        doc (kp/export-doc items {:markers true})]
    (when (fs/exists? file) (fs/move file (str file ".bak") true))
    ;; a new file: an old offline copy of the same path must not be merged into it
    (offline/forget! file)
    (sa/write-file! file (kdbx/write-kdbx doc (merge kdf {:password (not-empty password) :keyfile keyfile})))
    (local/save-config! {:mode :standalone :file file
                         :link (assoc (select-keys cfg [:server :org-hash :user]) :state :disconnected)})
    (swap! session assoc :identity nil)
    (open-file! session {:file file :password password :keyfile keyfile})
    {:file file :count (:count doc)}))

;; ================================================================ Status

(defn status
  "State for the start page: :not-enrolled | :locked | :pending | :active.
   :mode is :server or :standalone."
  [session]
  (let [cfg (local/load-config)]
    (cond
      (extra? session)
      (if-let [db (:file @session)]
        {:state :active :mode :standalone :extra true :file (:file db) :name (:name db)
         :offline-copy (copy-status session db)}
        {:state :locked :mode :standalone :extra true :file (:extra @session)
         :exists (or (fs/exists? (offline/copy-file (:extra @session))) (fs/exists? (:extra @session)))})

      (nil? cfg) {:state :not-enrolled :defaults (local/machine-config) :user (local/default-user)
                  :file (local/default-kdbx-file) :standalone-allowed (local/standalone-allowed?)}

      (local/standalone? cfg)
      (if-let [db (:file @session)]
        (cond-> {:state :active :mode :standalone :file (:file db) :name (:name db)
                 :offline-copy (copy-status session db)
                 :defaults (merge (local/machine-config) (select-keys (:link cfg) [:server :org-hash :user]))
                 :user (or (get-in cfg [:link :user]) (local/default-user))}
          (= :requested (get-in cfg [:link :state])) (assoc :link (link-status session cfg)))
        {:state :locked :mode :standalone :file (:file cfg)
         :exists (or (fs/exists? (offline/copy-file (:file cfg))) (fs/exists? (:file cfg)))})

      (locked? session) {:state :locked :mode :server :user (:user cfg)}
      :else
      (let [cs (client-store session cfg)
            r (sync/sync! cs)
            ident (current-ident session)
            active? (try (with-ctx session #(boolean (v/active-user (:roster %) (:user cfg))))
                         (catch Exception _ false))]
        (if active?
          {:state :active :mode :server :user (:user cfg) :sync r
           :file (or (:file cfg) (local/default-kdbx-file))
           :standalone-allowed (local/standalone-allowed?)
           :log (with-ctx session v/maintain-groups!)}
          {:state :pending :mode :server :user (:user cfg) :sync r
           :fingerprint (idn/fingerprint ident) :kerberos (true? (:kerberos cfg))})))))

(defn sync-now
  "Server: fetch and apply. Local: reload the file if it was changed
   externally; with an offline copy synchronize it with the shared file."
  [session]
  (if (standalone? session)
    (let [db (current-file session)]
      (if (:copy db)
        (locking session
          (let [db (sync-copy! session (current-file session) true)
                st (:copy-state @session)]
            (swap! session assoc :file db)
            {:online (= :synced (:state st)) :standalone true :reloaded (boolean (:pulled st))
             :offline-copy (copy-status session db) :log []}))
        (let [changed? (sa/changed-on-disk? db)]
          (when changed? (swap! session assoc :file (sa/reload db)))
          {:online true :standalone true :reloaded changed? :log []})))
    (let [cs (client-store session (local/load-config!))
          r (sync/sync! cs)]
      (assoc r :log (with-ctx session v/maintain-groups!)))))

;; ================================================================ Display helpers

(defn- principal-label [roster pr]
  (let [[kind nm] (str/split pr #":" 2)]
    (case kind
      "u" {:principal pr :kind "user" :name nm
           :display (or (get-in roster [:users nm :display-name]) nm)
           :active (boolean (v/active-user roster nm))}
      "g" {:principal pr :kind "group" :name nm :display nm
           :members (count (get-in roster [:groups nm :members]))
           :active (not (get-in roster [:groups nm :deleted]))})))

(def ^:private payload-keys [:title :username :password :url :notes :folder :expires :tags])

(defn- payload-row [id payload]
  {:id id
   :title (str (:title payload))
   :username (str (:username payload))
   :url (str (:url payload))
   :notes (str (:notes payload))
   :folder (str (:folder payload))
   :expires (str (:expires payload))
   :tags (kp/tag-list (kp/payload-tags payload))
   ;; for searching like in KeePass: custom fields without protection (protected ones never)
   :fields (vec (for [{:keys [name value protected]} (:custom-fields payload) :when (not protected)]
                  (str name ": " value)))
   :otp (otp/configured? (:custom-fields payload))
   :attachments (kp/attachment-count payload)
   :icon (kp/entry-icon payload)
   :colors (kp/entry-colors payload)
   :kdbx-database (boolean (:kdbx-db payload))})

(defn- entry-row [{:keys [id head payload my-perm warnings]}]
  (assoc (payload-row id payload)
         :modified (:created-at head)
         :modified-by (:author head)
         :version (:version head)
         :permission (name (or my-perm :read))
         :shared (> (count (:acl head)) 1)
         :warnings warnings))

(defn- file-row [[id payload {:keys [modified history]}]]
  (assoc (payload-row id payload)
         :modified modified :modified-by nil :version (inc (or history 0))
         :permission "owner" :shared false :warnings []))

(defn- no-sharing! []
  (throw (i18n/error :app/no-sharing-in-standalone nil {:type :standalone})))

;; ================================================================ Entries

(defn list-entries [session]
  (if (standalone? session)
    (with-file session
      (fn [db]
        {:user nil :display-name nil :org (:name db) :mode :standalone :file (:file db)
         :offline-copy (copy-status session db)
         :default-username (:default-username (kp/db-settings (sa/db-record db)))
         :entries (let [bin (kp/recycle-bin (sa/db-record db))]
                    (vec (sort-by #(str/lower-case (:title %))
                                  (map #(assoc (file-row %) :recycled (kp/in-folder? (:folder (second %)) bin))
                                       (sa/entries db)))))
         :folder-icons (kp/folder-icons [(:kdbx-db (sa/db-record db))])
         :groups (kp/group-paths (sa/db-record db))
         :recycle-bin (kp/recycle-bin (sa/db-record db))
         :recycle-bin-enabled (kp/recycle-bin-enabled? (sa/db-record db))
         :errors []}))
    (with-ctx session
      (fn [ctx]
        (let [{:keys [entries errors]} (v/list-entries ctx)]
          {:user (v/me ctx)
           :mode :server
           :display-name (get-in ctx [:roster :users (v/me ctx) :display-name])
           :org (get-in ctx [:org :name])
           :entries (mapv entry-row entries)
           ;; folder icons from imported KeePass databases
           :folder-icons (kp/folder-icons (keep #(get-in % [:payload :kdbx-db]) entries))
           :errors (mapv #(select-keys % [:id :error]) errors)})))))

(defn- payload-of [ctx id]
  (let [{:keys [head warnings]} (v/load-entry ctx id)
        payload (or (v/decrypt-entry ctx head)
                    (throw (i18n/error :app/no-access nil {:type :forbidden})))]
    [head payload warnings]))

(defn get-field
  "A single field, e.g. the password for copying."
  [session id field]
  (if (standalone? session)
    (with-file session #(str (get (file-payload % id) (keyword field) "")))
    (with-ctx session (fn [ctx] (str (get (second (payload-of ctx id)) (keyword field) ""))))))

(defn- entry-view [payload]
  (merge (zipmap payload-keys (repeat ""))
         (select-keys payload payload-keys)
         {:tags (kp/payload-tags payload)
          :custom-fields (vec (:custom-fields payload))
          :attachments (kp/attachments payload)
          :otp (otp/configured? (:custom-fields payload))
          :icon (kp/entry-icon payload)
          :colors (kp/entry-colors payload)}))

(defn get-entry [session id]
  (if (standalone? session)
    (with-file session
      (fn [db]
        (let [{:keys [modified history]} (get-in db [:times id])]
          (assoc (entry-view (file-payload db id))
                 :id id :permission "owner" :version (inc (or history 0))
                 :modified modified :modified-by nil :warnings []))))
    (with-ctx session
      (fn [ctx]
        (let [[head payload warnings] (payload-of ctx id)]
          (assoc (entry-view payload)
                 :id id
                 :permission (name (or (v/permission (:roster ctx) (:acl head) (v/me ctx)) :read))
                 :version (:version head)
                 :modified (:created-at head)
                 :modified-by (:author head)
                 :warnings warnings))))))

(defn- fields-of
  "Fields from the UI. Tags only if sent along - older UIs (web) don't know
   them and must not delete them."
  [e]
  (cond-> (assoc (into {} (for [k payload-keys :when (not= k :tags)] [k (str (get e k ""))]))
                 :custom-fields (vec (for [{:keys [name value protected]} (:custom-fields e)
                                           :when (seq (str name))]
                                       {:name (str name) :value (str value) :protected (boolean protected)})))
    (contains? e :tags) (assoc :tags (kp/norm-tags (:tags e)))))

(defn save-entry
  "Creates (without :id) or changes an entry. Unknown payload fields are kept.
   Attachments like in KeePass: :attach [{:name :data bytes}] (same name
   replaces), :detach [name ...]. Icon and colors: :look {:icon-id :fg :bg}."
  [session {:keys [id] :as e}]
  (let [fields (fields-of e)
        ops (select-keys e [:attach :detach])
        attach (fn [p pid new?] (kp/edit-attachments (kp/set-look p (:look e)) pid ops (not new?) (kdbx/now-iso)))]
    (if (standalone? session)
      (change-file! session
                    (fn [db]
                      (if (str/blank? id)
                        (let [nid (str (random-uuid))] [(sa/put db nid (attach fields nid true)) nid])
                        [(sa/put db id (attach (merge (file-payload db id) fields) id false)) id])))
      (with-fresh-ctx session
        (fn [ctx]
          (:entry-id
           (if (str/blank? id)
             (v/create-entry! ctx (attach fields nil true))
             (let [[_ old] (payload-of ctx id)]
               (v/update-entry! ctx id (attach (merge old fields) id false))))))))))

(defn recent-files
  "Recently opened KeePass files (newest first), like KeePass."
  []
  (vec (:recent-files (local/load-prefs))))

(defn passwords
  "Passwords of several entries {id pw} - only for \"show passwords in the
   list\" (explicit request)."
  [session ids]
  (let [ids (set ids)]
    (if (standalone? session)
      (with-file session (fn [db] (into {} (for [[id p] (sa/entries db) :when (ids id)] [id (str (:password p))]))))
      (with-ctx session (fn [ctx] (into {} (for [{:keys [id payload]} (:entries (v/list-entries ctx)) :when (ids id)]
                                             [id (str (:password payload))])))))))

(defn attachment-data
  "Content of an attachment (bytes), e.g. for Save As."
  [session id name]
  (let [p (if (standalone? session)
            (with-file session #(file-payload % id))
            (with-ctx session #(second (payload-of % id))))]
    (or (kp/attachment-data p name)
        (throw (i18n/error :app/attachment-not-found {:name name} {:type :not-found})))))

(defn otp
  "Current TOTP code of an entry: {:code :remaining :period}.
   The secret never leaves the service."
  [session id]
  (let [fields (:custom-fields (if (standalone? session)
                                 (with-file session #(file-payload % id))
                                 (with-ctx session #(second (payload-of % id)))))]
    (if-let [cfg (otp/config fields)]
      (otp/current cfg)
      (throw (i18n/error :app/no-totp nil {:type :not-found})))))

(defn- copy-of [payload new-id]
  (kp/fresh-copy (update payload :title #(i18n/t :app/copy-title {:title %})) new-id))

(defn duplicate-entry [session id]
  (let [nid (str (random-uuid))]
    (if (standalone? session)
      (change-file! session (fn [db] [(sa/put db nid (copy-of (file-payload db id) nid)) nid]))
      (with-fresh-ctx session
        (fn [ctx]
          (let [[_ payload] (payload-of ctx id)]
            (:entry-id (v/create-entry! ctx (copy-of payload nid)))))))))

(defn- recycle
  "Local, like KeePass: moves to the recycle bin (creates it if needed).
   If the entry is already in it or the recycle bin is disabled, it is
   deleted permanently. Returns [db' :recycled|:deleted]."
  [db id]
  (let [p (file-payload db id)
        dbp (sa/db-record db)]
    (if (and (kp/recycle-bin-enabled? dbp) (not (kp/in-folder? (:folder p) (kp/recycle-bin dbp))))
      (let [[dbp bin] (kp/ensure-recycle-bin dbp (kdbx/now-iso))]
        [(-> db (sa/update-db-record (constantly dbp)) (sa/put id (assoc p :folder bin))) :recycled])
      [(sa/delete db id) :deleted])))

(defn delete-entry
  "Server: delete. Local: into the recycle bin, from the recycle bin
   permanently. Returns :recycled or :deleted."
  [session id]
  (if (standalone? session)
    (change-file! session #(recycle % id))
    (with-fresh-ctx session (fn [ctx] (v/delete-entry! ctx id) :deleted))))

;; ================================================================ Several entries (multi-selection)

(defn- bulk!
  "(f payload) -> new payload or nil (unchanged) for every entry.
   In the vault only where I have the permission perm; the rest counts as
   :skipped. Returns {:updated n :skipped n}."
  [session ids f]
  (let [ids (distinct ids)]
    (if (standalone? session)
      (change-file! session
                    (fn [db] (reduce (fn [[db r] id]
                                       (if-let [p (f (file-payload db id))]
                                         [(sa/put db id p) (update r :updated inc)]
                                         [db r]))
                                     [db {:updated 0 :skipped 0}] ids)))
      (with-fresh-ctx session
        (fn [ctx]
          (reduce (fn [r id]
                    (let [[head payload] (payload-of ctx id)]
                      (if-let [p (f payload)]
                        (if (v/perm>= (v/permission (:roster ctx) (:acl head) (v/me ctx)) :update)
                          (do (v/update-entry! ctx id p) (update r :updated inc))
                          (update r :skipped inc))
                        r)))
                  {:updated 0 :skipped 0} ids))))))

(defn move-entries!
  "Moves entries into a group (KeePass: drag into the group tree)."
  [session ids folder]
  (let [folder (str/join "/" (kp/folder-segments folder))]
    (bulk! session ids #(when (not= folder (str/join "/" (kp/folder-segments (:folder %))))
                          (assoc % :folder folder)))))

(defn tag-entries!
  "Adds/removes tags on several entries. tags: {:add \"a;b\" :remove \"c\"}."
  [session ids {:keys [add remove]}]
  (let [add (kp/tag-list add) gone (set (kp/tag-list remove))]
    (bulk! session ids (fn [p] (let [old (kp/tag-list (kp/payload-tags p))
                                     new (vec (distinct (concat (clojure.core/remove gone old) add)))]
                                 (when (not= old new) (assoc p :tags (str/join ";" new))))))))

(defn delete-entries!
  "Deletes several entries (local: recycle bin like delete-entry).
   Returns {:recycled n :deleted n :skipped n}."
  [session ids]
  (let [ids (distinct ids)
        zero {:recycled 0 :deleted 0 :skipped 0}]
    (if (standalone? session)
      (change-file! session (fn [db] (reduce (fn [[db r] id] (let [[db k] (recycle db id)] [db (update r k inc)]))
                                             [db zero] ids)))
      (with-fresh-ctx session
        (fn [ctx]
          (reduce (fn [r id]
                    (let [{:keys [head]} (v/load-entry ctx id)]
                      (if (v/perm>= (v/permission (:roster ctx) (:acl head) (v/me ctx)) :owner)
                        (do (v/delete-entry! ctx id) (update r :deleted inc))
                        (update r :skipped inc))))
                  zero ids))))))

;; ================================================================ Groups (KeePass: add/edit/delete group)

(defn- rebase-entries
  "Local: moves the folder of all entries under old to new."
  [db old new]
  (reduce (fn [db [id p]]
            (if-let [f (kp/rebase-folder (:folder p) old new)]
              (sa/put db id (assoc p :folder f))
              db))
          db (sa/entries db)))

(defn- set-db-record [db dbp] (sa/update-db-record db (constantly dbp)))

(defn- rebase-server!
  "Server mode: the folder is a field of each entry. Renaming and moving
   changes all entries below it that I may change."
  [session old new]
  (with-fresh-ctx session
    (fn [ctx]
      (reduce (fn [r {:keys [id payload my-perm]}]
                (if-let [f (when-not (:kdbx-db payload) (kp/rebase-folder (:folder payload) old new))]
                  (if (v/perm>= my-perm :update)
                    (do (v/update-entry! ctx id (assoc payload :folder f)) (update r :updated inc))
                    (update r :skipped inc))
                  r))
              {:path new :updated 0 :skipped 0}
              (:entries (v/list-entries ctx))))))

(defn- server-groups!
  "Group features that exist only in a KeePass file; k is the message key."
  [k]
  (throw (i18n/error k nil {:type :standalone})))

(defn add-group!
  "New, empty group (local only). Returns the folder path."
  [session parent name]
  (when-not (standalone? session) (server-groups! :app/server-no-empty-groups))
  (change-file! session (fn [db] (let [[dbp path] (kp/add-group (sa/db-record db) parent name (kdbx/now-iso))]
                                   [(set-db-record db dbp) path]))))

(defn rename-group!
  "Renames a group. Returns {:path new-path :updated n :skipped n}."
  [session path name]
  (if (standalone? session)
    (change-file! session
                  (fn [db]
                    (let [[dbp new] (kp/rename-group (sa/db-record db) path name (kdbx/now-iso))]
                      [(-> db (set-db-record dbp) (rebase-entries path new)) {:path new}])))
    (let [segs (kp/folder-segments path)
          nm (str/trim (str name))]
      (when (or (empty? segs) (str/blank? nm) (str/includes? nm "/"))
        (throw (i18n/error :app/invalid-group-name nil {:type :invalid})))
      (rebase-server! session path (str/join "/" (conj (pop segs) nm))))))

(defn move-group!
  "Moves a group with everything in it under target (empty = top level).
   Returns {:path new-path ...}."
  [session path target]
  (if (standalone? session)
    (change-file! session
                  (fn [db]
                    (let [[dbp new] (kp/move-group (sa/db-record db) path target (kdbx/now-iso))]
                      [(-> db (set-db-record dbp) (rebase-entries path new)) {:path new}])))
    (let [segs (kp/folder-segments path)]
      (when (or (empty? segs) (kp/in-folder? target path))
        (throw (i18n/error :app/group-into-itself nil {:type :invalid})))
      (rebase-server! session path (str/join "/" (conj (kp/folder-segments target) (peek segs)))))))

(defn delete-group!
  "Local, like KeePass: group with its content into the recycle bin; from the
   recycle bin (or without one) permanently. Returns {:recycled bool :deleted n}."
  [session path]
  (when-not (standalone? session) (server-groups! :app/server-no-group-delete))
  (change-file! session
                (fn [db]
                  (let [now (kdbx/now-iso)
                        dbp (sa/db-record db)]
                    (if (and (kp/recycle-bin-enabled? dbp) (not (kp/in-folder? path (kp/recycle-bin dbp))))
                      (let [[dbp bin] (kp/ensure-recycle-bin dbp now)
                            [dbp new] (kp/move-group dbp path bin now true)]
                        [(-> db (set-db-record dbp) (rebase-entries path new)) {:recycled true :deleted 0 :path new}])
                      (let [victims (for [[id p] (sa/entries db) :when (kp/in-folder? (:folder p) path)] id)
                            db (reduce sa/delete db victims)]
                        [(sa/update-db-record db #(kp/remove-group % path now)) {:recycled false :deleted (count victims)}]))))))

(defn set-group-icon!
  "Icon of a group (local only: server mode has no group tree)."
  [session path icon-id]
  (when-not (standalone? session) (server-groups! :app/server-no-group-icons))
  (change-file! session (fn [db] [(sa/update-db-record db #(kp/set-group-icon % path icon-id (kdbx/now-iso))) true])))

(defn empty-recycle-bin!
  "Empties the recycle bin: deletes everything in it permanently. Returns the number of entries."
  [session]
  (when-not (standalone? session) (server-groups! :app/server-no-recycle-bin))
  (change-file! session
                (fn [db]
                  (let [now (kdbx/now-iso)
                        dbp (sa/db-record db)
                        bin (kp/recycle-bin dbp)]
                    (if-not bin
                      [db 0]
                      (let [victims (for [[id p] (sa/entries db) :when (kp/in-folder? (:folder p) bin)] id)
                            db (reduce sa/delete db victims)
                            subs (filter #(= bin (str/join "/" (pop (kp/folder-segments %)))) (kp/group-paths (sa/db-record db)))]
                        [(sa/update-db-record db #(reduce (fn [p g] (kp/remove-group p g now)) % subs))
                         (count victims)]))))))

(defn principals [session]
  (if (standalone? session)
    []
    (with-fresh-ctx session
      (fn [ctx]
        (let [r (:roster ctx)]
          (vec (concat
                (for [[g {:keys [deleted]}] (sort-by key (:groups r)) :when (not deleted)]
                  (principal-label r (str "g:" g)))
                (for [[u _] (sort-by key (:users r)) :when (v/active-user r u)]
                  (principal-label r (str "u:" u))))))))))

(defn get-acl [session id]
  (if (standalone? session)
    (with-file session (fn [db] (file-payload db id) {:id id :my-permission "owner" :acl []}))
    (with-ctx session
      (fn [ctx]
        (let [{:keys [head]} (v/load-entry ctx id)]
          {:id id
           :my-permission (name (or (v/permission (:roster ctx) (:acl head) (v/me ctx)) :read))
           :acl (vec (for [[pr perm] (sort-by key (:acl head))]
                       (assoc (principal-label (:roster ctx) pr) :permission (name perm))))})))))

(defn set-acl
  "acl: [{:principal \"u:bob\" :permission \"read\"} ...]"
  [session id acl]
  (when (standalone? session) (no-sharing!))
  (with-fresh-ctx session
    (fn [ctx]
      (v/set-acl! ctx id (into {} (for [{:keys [principal permission]} acl]
                                    [principal (keyword permission)])))
      true)))

(defn history
  "Server: versions in the vault. Local: history like in KeePass."
  [session id]
  (if (standalone? session)
    (with-file session
      (fn [db]
        (let [old (kp/entry-history (file-payload db id))
              cur {:version (inc (count old)) :date (get-in db [:times id :modified]) :valid true :deleted false}]
          (vec (cons cur (reverse (map-indexed (fn [i h] {:version (inc i) :date (:date h) :valid true :deleted false})
                                               old)))))))
    (with-ctx session #(v/entry-history % id))))

(def ^:private restorable [:title :username :password :url :notes :folder :expires :tags :custom-fields])

(defn history-entry
  "An older version for display (number as in history)."
  [session id version]
  (if (standalone? session)
    (with-file session
      (fn [db]
        (or (kp/history-version (file-payload db id) (dec version))
            (throw (i18n/error :app/version-not-found nil {:type :not-found})))))
    (with-ctx session
      (fn [ctx]
        (let [p (or (v/version-payload ctx id version)
                    (throw (i18n/error :app/version-unreadable nil {:type :forbidden})))]
          (assoc (entry-view p) :date (some #(when (= version (:version %)) (:date %)) (v/entry-history ctx id))))))))

(defn restore-history
  "Restores an older version (KeePass: History > Restore).
   The current state stays in the history. In server mode a new version is
   created with the fields of the old one (permissions stay as they are)."
  [session id version]
  (if (standalone? session)
    (change-file! session (fn [db] [(sa/put db id (kp/restore-history (file-payload db id) (dec version) (kdbx/now-iso))) id]))
    (with-fresh-ctx session
      (fn [ctx]
        (let [old (or (v/version-payload ctx id version)
                      (throw (i18n/error :app/version-unreadable nil {:type :forbidden})))
              [_ cur] (payload-of ctx id)]
          (v/update-entry! ctx id (merge cur (select-keys (merge (fields-of {}) old) restorable)))
          id)))))

(defn delete-history
  "Deletes a history item (local mode only - the vault is immutable)."
  [session id version]
  (when-not (standalone? session)
    (throw (i18n/error :app/history-immutable nil {:type :standalone})))
  (change-file! session (fn [db] [(sa/put db id (kp/delete-history (file-payload db id) (dec version))) true])))

;; ================================================================ KeePass (KDBX)

(defn- ensure-unlocked! [session]
  (check-idle! session)
  (when (locked? session) (throw (i18n/error :app/locked nil {:type :locked}))))

(defn import-kdbx
  "Imports a KeePass file (KDBX 3.1/4.x). opts: {:data bytes :password
   :keyfile bytes :source file-name}. Server: every KeePass entry becomes an
   entry of its own (owner: me), plus a record with structure and settings
   of the database. Nothing gets lost (cljpass.keepass).
   Local: the entries go into the opened file (like importing in KeePass)."
  [session {:keys [data password keyfile source format]}]
  (ensure-unlocked! session)
  (let [doc (if (= :xml format) (kdbx/read-xml data) (kdbx/read-kdbx data {:password password :keyfile keyfile}))
        {:keys [db entries]} (kp/import-doc doc {:source source})]
    (if (standalone? session)
      (change-file! session
                    (fn [db0]
                      [(reduce (fn [acc p]
                                 (let [id (kp/uuid->id (kp/entry-uuid p nil))]
                                   (if (and id (not (sa/payload acc id)))
                                     (sa/put acc id (dissoc p :kdbx-source))
                                     (let [nid (str (random-uuid))] (sa/put acc nid (kp/fresh-copy p nid))))))
                               db0 entries)
                       {:database nil :imported (count entries)}]))
      (with-fresh-ctx session
        (fn [ctx]
          (let [db-entry (:entry-id (v/create-entry! ctx db))
                ids (mapv #(:entry-id (v/create-entry! ctx %)) entries)]
            {:database (get-in db [:kdbx-db :id])
             :database-entry db-entry
             :imported (count ids)}))))))

(defn import-csv
  "CSV from KeePass, KeePassXC, Bitwarden, browsers ... Every row becomes a
   new entry (local: in the file, server: owner me)."
  [session {:keys [data]}]
  (ensure-unlocked! session)
  (let [entries (csv/import-rows (c/utf8-str data))]
    (if (standalone? session)
      (change-file! session (fn [db] [(reduce #(sa/put %1 (str (random-uuid)) %2) db entries) {:imported (count entries)}]))
      (with-fresh-ctx session (fn [ctx] (doseq [p entries] (v/create-entry! ctx p)) {:imported (count entries)})))))

(defn import-file
  "Import by format: :kdbx, :xml (KeePass XML 2.x) or :csv."
  [session {:keys [format] :as opts}]
  (case format
    :csv (import-csv session opts)
    (import-kdbx session opts)))

(declare export-items)

(defn export-file
  "Unencrypted export like KeePass: {:format :xml|:csv|:html|:xsl
   :xsl path of the template :passwords bool (HTML)}. Returns {:data bytes :count n}."
  [session {:keys [format xsl passwords]}]
  (ensure-unlocked! session)
  (let [{:keys [items root bin]} (export-items session)
        doc (kp/export-doc items {})
        visible (for [{:keys [payload]} items
                      :when (and (not (:kdbx-db payload)) (not (kp/in-folder? (:folder payload) bin)))]
                  payload)
        visible (sort-by (juxt #(str/lower-case (str (:folder %))) #(str/lower-case (str (:title %)))) visible)]
    {:count (:count doc)
     :data (case format
             :xml (kdbx/write-xml doc)
             :xsl (ex/transform (kdbx/write-xml doc) (or xsl (throw (i18n/error :app/no-xsl-template nil {:type :invalid}))))
             :csv (c/utf8 (csv/export-rows visible root #(otp/uri (:title %) (:custom-fields %))))
             :html (c/utf8 (ex/html root visible {:passwords passwords})))}))

(defn export-kdbx
  "All entries I can read as KDBX 4. opts: {:password :keyfile
   bytes :database (id of an import) :kdf ...}. Returns {:data bytes :count n}."
  [session opts]
  (ensure-unlocked! session)
  (if (standalone? session)
    (with-file session #(select-keys (sa/export-kdbx % (select-keys opts [:password :keyfile])) [:data :count]))
    (let [items (with-fresh-ctx session
                  (fn [ctx]
                    (mapv (fn [{:keys [head payload]}] {:payload payload :modified (:created-at head)})
                          (:entries (v/list-entries ctx)))))
          doc (kp/export-doc items (select-keys opts [:database]))]
      {:data (kdbx/write-kdbx doc (select-keys opts [:password :keyfile :kdf :memory-kib :iterations :parallelism :rounds]))
       :count (:count doc)})))

(defn- export-items
  "All readable entries for an export: {:items :root :bin}."
  [session]
  (if (standalone? session)
    (with-file session (fn [db] {:items (vec (sa/export-items db)) :root (:name db)
                                 :bin (kp/recycle-bin (sa/db-record db))}))
    (with-fresh-ctx session
      (fn [ctx] {:items (mapv (fn [{:keys [head payload]}] {:payload payload :modified (:created-at head)})
                              (:entries (v/list-entries ctx)))
                 :root (get-in ctx [:org :name])
                 :bin nil}))))

(defn sync-file!
  "Local mode: synchronizes with another KeePass file (like in KeePass).
   Afterwards the result is in both files; the other one keeps its master
   password and its key derivation.
   opts: {:file :password :keyfile bytes}."
  [session {:keys [file password keyfile]}]
  (when-not (standalone? session)
    (throw (i18n/error :app/sync-file-standalone-only nil {:type :standalone})))
  (let [file (sa/check-path file)
        _ (when (= file (:file (current-file session)))
            (throw (i18n/error :app/sync-with-self nil {:type :invalid-path})))
        _ (when-not (fs/exists? file) (throw (i18n/error :app/file-not-found {:file file} {:type :not-found})))
        creds {:password (not-empty password) :keyfile keyfile}
        other (kdbx/read-kdbx (fs/read-bytes file) creds)
        stats (change-file! session #(sa/sync-with % other))]
    (sa/write-copy! (:file @session) file creds (kdbx/kdf-opts (:kdf other)))
    (assoc stats :file file)))

(defn- file-only!
  "Features of local mode with a KeePass file; k is the message key."
  [session k]
  (when-not (standalone? session)
    (throw (i18n/error k nil {:type :standalone}))))

(defn change-master-key!
  "Local mode: changes the master key (password and/or key file).
   opts: {:password :keyfile bytes}."
  [session {:keys [password keyfile]}]
  (file-only! session :app/master-key-file-only)
  (change-file! session (fn [db]
                          ;; the copy and the shared file must not end up with different keys
                          (when (and (:copy db) (not= :synced (get-in @session [:copy-state :state])))
                            (throw (i18n/error :app/offline-master-key {:file (:file db)} {:type :offline})))
                          [(sa/set-creds db {:password (not-empty password) :keyfile keyfile}) true])))

(defn db-settings
  "Local mode: {:name :description :default-username :history-max-items :recycle-bin :master-key-changed}."
  [session]
  (file-only! session :app/db-settings-file-only)
  (with-file session #(kp/db-settings (sa/db-record %))))

(defn set-db-settings!
  [session settings]
  (file-only! session :app/db-settings-file-only)
  (let [s (cond-> (select-keys settings [:name :description :default-username :history-max-items :recycle-bin])
            (contains? settings :history-max-items)
            (update :history-max-items #(let [n (if (number? %) (long %) (parse-long (str/trim (str %))))]
                                          (if (and n (>= n -1)) n
                                              (throw (i18n/error :app/invalid-history-max-items nil {:type :invalid}))))))]
    (change-file! session (fn [db] [(sa/update-db-record db #(kp/set-db-settings % s (kdbx/now-iso))) true]))))

;; ================================================================ Queue / conflicts

(defn conflicts [session]
  (if (standalone? session)
    []
    (let [cs (client-store session (local/load-config!))]
      (vec (for [{:keys [id path status error created_at]} (sync/outbox cs)
                 :when (not= "pending" status)]
             {:id id :path path :status status :error error :date created_at})))))

(defn pending-count [session]
  (if (standalone? session)
    0
    (let [cs (client-store session (local/load-config!))]
      (count (filter #(= "pending" (:status %)) (sync/outbox cs))))))

(defn resolve-conflict
  "action :retry = apply my content again on top of the current state,
   :discard = discard it."
  [session outbox-id action]
  (when (standalone? session) (throw (i18n/error :app/no-conflicts-in-standalone nil {:type :standalone})))
  (let [cs (client-store session (local/load-config!))
        row (first (filter #(= outbox-id (:id %)) (sync/outbox cs)))]
    (when-not row (throw (i18n/error :app/not-found nil {:type :not-found})))
    (when (= action :retry)
      (with-ctx session
        (fn [ctx]
          (let [doc (codec/parse (:body row))
                mine (v/entry-from-wire (:body doc))
                payload (or (v/decrypt-entry ctx mine) (throw (i18n/error :app/own-change-unreadable nil {})))]
            (if (:deleted mine)
              (v/delete-entry! ctx (:entry-id mine))
              (v/update-entry! ctx (:entry-id mine) payload))))))
    (sync/drop-outbox! cs outbox-id)
    true))


;; ================================================================ Password generator (like KeePass)

(def charsets pwgen/charsets)

(defn generate-password
  "Character sets or pattern, see cljpass.pwgen/generate."
  [opts]
  (pwgen/generate opts))

(defn password-quality
  "Estimated strength in bits with pattern detection (cljpass.pwgen/quality)."
  [pw]
  (pwgen/quality pw))

(defn generator-profiles
  "Built-in and custom profiles of the generator (custom: local preferences)."
  []
  (vec (concat pwgen/builtin-profiles (:generator-profiles (local/load-prefs)))))

(defn save-generator-profile!
  "Saves a custom profile (same name replaces). Built-in ones stay unchanged."
  [profile]
  (let [p (select-keys profile pwgen/profile-keys)
        nm (str/trim (str (:name p)))]
    (when (str/blank? nm) (throw (i18n/error :app/profile-name-required nil {:type :invalid})))
    (when (some #(= nm (:name %)) pwgen/builtin-profiles)
      (throw (i18n/error :app/profile-name-builtin nil {:type :exists})))
    (when-not (str/blank? (str (:pattern p))) (pwgen/parse-pattern (:pattern p)))
    (local/update-prefs! (fn [m] (update m :generator-profiles
                                         #(conj (vec (remove (fn [x] (= nm (:name x))) %)) (assoc p :name nm)))))
    (generator-profiles)))

(defn delete-generator-profile! [nm]
  (local/update-prefs! (fn [m] (update m :generator-profiles #(vec (remove (fn [x] (= nm (:name x))) %)))))
  (generator-profiles))

(def weak-bits
  "Below this estimated strength a password counts as weak."
  64)

(defn password-report
  "Like KeePass (Edit > Show Entries > Duplicate/Weak Passwords):
   {:duplicates [[id ...] ...] :weak [id ...]}. The UI only gets IDs."
  [session]
  (let [pairs (if (standalone? session)
                (with-file session (fn [db] (let [bin (kp/recycle-bin (sa/db-record db))]
                                              (vec (for [[id p] (sa/entries db) :when (not (kp/in-folder? (:folder p) bin))]
                                                     [id (str (:password p))])))))
                (with-ctx session (fn [ctx] (vec (for [{:keys [id payload]} (:entries (v/list-entries ctx))
                                                       :when (not (:kdbx-db payload))]
                                                   [id (str (:password payload))])))))
        pairs (remove (comp str/blank? second) pairs)]
    {:duplicates (->> pairs (group-by second) vals (filter #(> (count %) 1)) (mapv #(vec (sort (map first %)))))
     :weak (vec (sort (for [[id pw] pairs :when (< (password-quality pw) weak-bits)] id)))}))
