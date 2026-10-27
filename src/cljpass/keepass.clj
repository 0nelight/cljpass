(ns cljpass.keepass
  "Lossless mapping between KDBX documents (cljpass.kdbx) and vault
   payloads (doc/FORMAT.md §6.3).

   Import: every KeePass entry becomes a vault entry.
   - Title, user name, password, URL, notes, folder and expiry date end up
     in the regular fields, all other fields (e.g. PIN, otp) in
     :custom-fields - that is how they are shown and edited in the app.
   - In addition the complete <Entry> element is kept (history,
     attachments, icons, plugin data in CustomData, auto-type, tags,
     colors, timestamps, even elements nobody knows) under :kdbx.
   - Everything that does not belong to an entry (Meta with settings,
     plugin data and icons, group tree with empty groups, deleted objects,
     public header data) becomes a record of its own, :kdbx-db.

   Export: the fields from the vault win. If something changed, the old
   state moves into the KeePass history (like editing in KeePass). Vault
   fields KeePass does not know go into CustomData \"cljpass/payload\"
   and come back on the next import.

   For switching between local mode (file) and server (§13) the export can
   write origin markers: CustomData \"cljpass/source\" per entry (vault
   ID, version, checksum of the fields) and \"cljpass/database\" in Meta.
   On import they end up in :kdbx-source or determine the ID of the
   database record.

   All structures are chosen so that they survive the canonical JSON (§3)
   unchanged: lists instead of maps with arbitrary keys."
  (:require [clojure.data.xml :as xml]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.kdbx :as k])
  (:import [java.nio ByteBuffer]
           [java.time Instant LocalDate LocalDateTime ZoneOffset]
           [java.time.temporal ChronoUnit]
           [java.util UUID]))

(def ^:private core-fields
  [["Title" :title] ["UserName" :username] ["Password" :password] ["URL" :url] ["Notes" :notes]])

(def ^:private core-keys (set (map first core-fields)))

(def ^:private known-keys
  #{:title :username :password :url :notes :folder :expires :tags :custom-fields :kdbx :kdbx-db :kdbx-source})

(def ^:private extra-key "cljpass/payload")
(def ^:private source-key "cljpass/source")
(def ^:private db-key "cljpass/database")
(def ^:private zero-uuid "AAAAAAAAAAAAAAAAAAAAAA==")

;; ================================================================ XML helpers

(defn- el [tag & content] (xml/element* tag {} (remove nil? content)))

(defn- elements [e] (filter k/element? (tree-seq k/element? :content e)))

(defn- tag? [tag x] (and (k/element? x) (= tag (:tag x))))

(defn- remove-children [e pred] (update e :content #(vec (remove pred %))))

(defn- set-child
  "Replaces the first child with the tag of `c`, or appends `c`."
  [e c]
  (let [cs (vec (:content e))
        i (first (keep-indexed #(when (tag? (:tag c) %2) %1) cs))]
    (assoc e :content (if i (assoc cs i c) (conj cs c)))))

(defn- set-text [e tag v] (set-child e (el tag v)))

(defn- postwalk-el [f e]
  (if (k/element? e) (f (update e :content #(mapv (partial postwalk-el f) %))) e))

(defn- new-uuid [] (c/b64 (c/random-bytes 16)))

(defn uuid->id
  "KeePass UUID (16 bytes, Base64) -> entry ID in vault format; nil if it
   is not 16 bytes."
  [b64]
  (try (let [b (c/unb64 (str b64))]
         (when (= 16 (alength b))
           (let [bb (ByteBuffer/wrap b)] (str (UUID. (.getLong bb) (.getLong bb))))))
       (catch Exception _ nil)))

(defn id->uuid
  "Entry ID -> KeePass UUID. This way an entry gets the same UUID on every
   export (important for syncing and for KeePass itself)."
  [id]
  (try (let [u (UUID/fromString (str id))]
         (c/b64 (.array (doto (ByteBuffer/allocate 16)
                          (.putLong (.getMostSignificantBits u))
                          (.putLong (.getLeastSignificantBits u))))))
       (catch Exception _ nil)))

(defn- times-el [t]
  (el :Times (el :CreationTime t) (el :LastModificationTime t) (el :LastAccessTime t)
      (el :ExpiryTime t) (el :Expires "False") (el :UsageCount "0") (el :LocationChanged t)))

(defn- iso-sec
  "Time value -> ISO-8601 in UTC, truncated to seconds; nil if unreadable.
   Accepts an instant, date+time and a date (all UTC)."
  [s]
  (let [s (str/trim (str s))]
    (when-not (str/blank? s)
      (when-let [^Instant t (or (try (Instant/parse s) (catch Exception _ nil))
                                (try (.toInstant (.atOffset (LocalDateTime/parse s) ZoneOffset/UTC)) (catch Exception _ nil))
                                (try (.toInstant (.atStartOfDay (LocalDate/parse s) ZoneOffset/UTC)) (catch Exception _ nil)))]
        (str (.truncatedTo t ChronoUnit/SECONDS))))))


(defn norm-expires
  "Expiry like KeePass (date and time): \"\", \"YYYY-MM-DD\" (date only, also
   for midnight UTC) or \"YYYY-MM-DDThh:mm:ssZ\"; nil if unreadable."
  [s]
  (if (str/blank? (str s))
    ""
    (when-let [t (iso-sec s)]
      (if (or (re-matches #"\d{4}-\d{2}-\d{2}" (str/trim (str s))) (str/ends-with? t "T00:00:00Z"))
        (subs t 0 10)
        t))))

(defn- same-expiry?
  "A plain date (older payloads, input without a time) matches every
   instant on that day (UTC) - so the time from the file is kept."
  [cur want]
  (let [cur (str cur) want (str want)]
    (or (= cur want) (and (= 10 (count want)) (str/starts-with? cur want)))))

(defn norm-tags
  "Tags like KeePass: separated by ; or , - normalized to \"a;b\"."
  [s]
  (str/join ";" (distinct (remove str/blank? (map str/trim (str/split (str s) #"[;,]"))))))

(defn tag-list [s] (vec (remove str/blank? (str/split (norm-tags s) #";"))))

;; ================================================================ Icon and colors (KeePass: icon, foreground/background color)

(defn norm-color
  "KeePass color \"#RRGGBB\" (upper case) or \"\" for the default."
  [c]
  (let [c (str/trim (str c))]
    (if (re-matches #"#[0-9A-Fa-f]{6}" c) (str/upper-case c) "")))

(defn- look-of-entry
  "Icon and colors as they are in the <Entry> (or <Group>)."
  [e]
  {:icon (cond-> {:id (or (parse-long (str/trim (str (k/child-text e :IconID)))) 0)}
           (not-empty (k/child-text e :CustomIconUUID)) (assoc :custom (k/child-text e :CustomIconUUID)))
   :colors {:fg (norm-color (k/child-text e :ForegroundColor))
            :bg (norm-color (k/child-text e :BackgroundColor))}})

(defn- set-after
  "Sets child c; if missing, inserts it right after the first child with tag after."
  [e c after]
  (if (k/child e (:tag c))
    (set-child e c)
    (let [cs (vec (:content e))
          i (first (keep-indexed #(when (tag? after %2) %1) cs))]
      (assoc e :content (if i (vec (concat (subvec cs 0 (inc i)) [c] (subvec cs (inc i)))) (conj cs c))))))

(defn- apply-look
  "Writes icon/colors from the payload (:kdbx :icon, :kdbx :colors) into the
   element - only what differs, so unchanged parts stay exactly as they are.
   Payloads without these keys change nothing."
  [e payload]
  (let [kd (:kdbx payload)
        cur (look-of-entry e)
        {:keys [id custom]} (:icon kd)
        custom (not-empty (str custom))
        {:keys [fg bg]} (:colors kd)]
    (cond-> e
      (and (contains? kd :icon) (not= (long (or id 0)) (get-in cur [:icon :id])))
      (set-text :IconID (str (or id 0)))
      (and (contains? kd :icon) (not= custom (get-in cur [:icon :custom])))
      (as-> x (if custom
                (set-after x (el :CustomIconUUID custom) :IconID)
                (remove-children x #(tag? :CustomIconUUID %))))
      (and (contains? kd :colors) (not= (norm-color fg) (get-in cur [:colors :fg])))
      (set-after (el :ForegroundColor (norm-color fg)) :IconID)
      (and (contains? kd :colors) (not= (norm-color bg) (get-in cur [:colors :bg])))
      (set-after (el :BackgroundColor (norm-color bg)) :ForegroundColor))))

(defn set-look
  "Sets icon/colors of a payload. look: {:icon-id n :fg \"#..\" :bg \"#..\"},
   each optional. A standard icon replaces a custom icon."
  [payload {:keys [icon-id] :as look}]
  (cond-> payload
    (some? icon-id) (update :kdbx #(assoc (or % {:v 1}) :icon {:id (long icon-id)}))
    (contains? look :fg) (update :kdbx #(assoc-in (or % {:v 1}) [:colors :fg] (norm-color (:fg look))))
    (contains? look :bg) (update :kdbx #(assoc-in (or % {:v 1}) [:colors :bg] (norm-color (:bg look))))))

(defn entry-colors
  "{:fg :bg} of a payload for display (\"\" = default)."
  [payload]
  (merge {:fg "" :bg ""} (get-in payload [:kdbx :colors])))

;; ================================================================ Reading entries

(defn- strings
  "[[key value protected?] ...] in document order."
  [entry]
  (for [s (k/children entry :String)
        :let [v (k/child s :Value)]]
    [(k/child-text s :Key) (or (some-> v k/text) "") (= "True" (get-in v [:attrs :Protected]))]))

(defn- core-of-entry
  "The fields the vault shows, as they are in the <Entry>."
  [e]
  (let [ss (strings e)
        m (into {} (map (juxt first second) ss))
        times (k/child e :Times)]
    (into {:expires (or (when (= "True" (k/child-text times :Expires)) (norm-expires (k/child-text times :ExpiryTime))) "")
           :tags (norm-tags (k/child-text e :Tags))
           :custom-fields (vec (for [[key v p] ss :when (not (core-keys key))]
                                 {:name key :value v :protected p}))}
          (for [[key kw] core-fields] [kw (get m key "")]))))

(defn- binary-refs [entry]
  (distinct (keep #(when (tag? :Binary %) (get-in (k/child % :Value) [:attrs :Ref])) (elements entry))))

(defn- icon-refs [entry]
  (distinct (keep #(when (tag? :CustomIconUUID %) (k/text %)) (elements entry))))

(defn- take-item
  "Removes a CustomData item written by cljpass and returns
   [entry value-as-map]."
  [entry key]
  (let [cd (k/child entry :CustomData)
        item (some #(when (= key (k/child-text % :Key)) %) (k/children cd :Item))]
    (if-not item
      [entry nil]
      (let [cd' (remove-children cd #(identical? % item))
            entry' (if (some k/element? (:content cd'))
                     (set-child entry cd')
                     (remove-children entry #(identical? % cd)))
            v (try (codec/parse (k/child-text item :Value)) (catch Exception _ nil))]
        [entry' (when (map? v) v)]))))

(defn- set-item
  "Sets (or removes, for nil) a CustomData item with a JSON value."
  [e key v]
  (let [cd (or (k/child e :CustomData) (el :CustomData))
        cd (remove-children cd #(and (tag? :Item %) (= key (k/child-text % :Key))))]
    (cond
      (some? v) (set-child e (update cd :content #(conj (vec %) (el :Item (el :Key key) (el :Value (codec/->str v))))))
      (some k/element? (:content cd)) (set-child e cd)
      :else (remove-children e #(tag? :CustomData %)))))

;; ================================================================ Import

(defn- entry-payload [e chain pos db-id binaries icons]
  (let [[e extra] (take-item e extra-key)
        [e source] (take-item e source-key)
        core (core-of-entry e)
        ;; expiry date KeePass could not represent (see set-extra)
        core (cond-> core
               (and (str/blank? (:expires core)) (string? (:expires extra))) (assoc :expires (:expires extra)))]
    (merge (apply dissoc extra known-keys)
           core
           (when source {:kdbx-source source})
           {:folder (str/join "/" (map second (rest chain)))
            :kdbx {:v 1
                   :db db-id
                   :pos pos
                   :icon (:icon (look-of-entry e))
                   :colors (:colors (look-of-entry e))
                   :groups (mapv vec chain)
                   :entry (k/xml-str e)
                   :binaries (vec (for [r (binary-refs e)
                                        :let [b (get binaries r)]
                                        :when b]
                                    {:ref r :protected (boolean (:protected b)) :data (c/b64 (:data b))}))
                   :icons (vec (for [u (icon-refs e)
                                     :let [i (get icons u)]
                                     :when i]
                                 {:uuid u :xml (k/xml-str i)}))}})))

(defn- strip-entries [g]
  (update g :content (fn [cs] (vec (keep #(cond (tag? :Entry %) nil
                                                (tag? :Group %) (strip-entries %)
                                                :else %)
                                         cs)))))

(defn db-marker
  "ID of the database record the file was exported from (or nil)."
  [xml]
  (some #(when (= db-key (k/child-text % :Key)) (some-> (k/child-text % :Value) str/trim not-empty))
        (k/children (k/child (k/child xml :Meta) :CustomData) :Item)))

(defn db-title
  "Title of the database record in the current language, e.g.
   \"KeePass database: Team\"."
  [db-name]
  (i18n/t :kp/db-title {:name db-name}))

(defn db-title-name
  "Database name from a database record title (inverse of db-title). The
   title is stored data, written in whatever language was active at the
   time, so the prefix of every language is recognized. Returns the title
   unchanged if no prefix matches."
  [title]
  (let [title (str title)]
    (or (some (fn [lang]
                (let [prefix (i18n/tr lang :kp/db-title {:name ""})]
                  (when (and (seq prefix) (str/starts-with? title prefix))
                    (subs title (count prefix)))))
              i18n/languages)
        title)))

(defn import-doc
  "KDBX file that was read (cljpass.kdbx/read-kdbx) -> {:db payload :entries [payload ...]}.
   :db is the record with everything that does not belong to single entries.
   opts: {:source file name :db-id ID of the record (random otherwise)}.
   Title and notes of :db are written in the current language (i18n/*lang*)."
  [{:keys [xml binaries public-custom-data version]} {:keys [source db-id]}]
  (let [db-id (or db-id (str (random-uuid)))
        meta (k/child xml :Meta)
        icons (into {} (for [i (k/children (k/child meta :CustomIcons) :Icon)] [(k/child-text i :UUID) i]))
        root (k/child (k/child xml :Root) :Group)
        entries (atom [])]
    (when root
      ((fn visit [g chain]
         (let [chain (conj chain [(or (k/child-text g :UUID) "") (or (k/child-text g :Name) "")])]
           (doseq [[i e] (map-indexed vector (k/children g :Entry))]
             (swap! entries conj (entry-payload e chain i db-id binaries icons)))
           (doseq [sub (k/children g :Group)] (visit sub chain))))
       root []))
    {:db {:title (db-title (or (not-empty (k/child-text meta :DatabaseName)) source (i18n/t :kp/db-title-fallback)))
          :username "" :password "" :url "" :folder "" :expires ""
          :notes (if source
                   (i18n/t :kp/db-notes-source {:source source})
                   (i18n/t :kp/db-notes))
          :kdbx-db {:v 1
                    :id db-id
                    :skeleton (k/xml-str (update xml :content
                                                 (fn [cs] (mapv #(if (tag? :Root %)
                                                                   (update % :content (fn [rs] (mapv (fn [x] (if (tag? :Group x) (strip-entries x) x)) rs)))
                                                                   %)
                                                                cs))))
                    :public-custom-data (some-> public-custom-data c/b64)
                    :version (str/join "." version)
                    :source source
                    :imported-at (k/now-iso)}}
     :entries @entries}))

;; ================================================================ Icons for display

(def standard-icons
  "The 69 built-in KeePass icons (IconID 0-68), names as in KeePass (PwIcon).
   The user interface maps them to its own graphics."
  ["Key" "World" "Warning" "NetworkServer" "MarkedDirectory" "UserCommunication" "Parts"
   "Notepad" "WorldSocket" "Identity" "PaperReady" "Digicam" "IRCommunication" "MultiKeys"
   "Energy" "Scanner" "WorldStar" "CDRom" "Monitor" "EMail" "Configuration" "ClipboardReady"
   "PaperNew" "Screen" "EnergyCareful" "EMailBox" "Disk" "Drive" "PaperQ" "TerminalEncrypted"
   "Console" "Printer" "ProgramIcons" "Run" "Settings" "WorldComputer" "Archive" "Homebanking"
   "DriveWindows" "Clock" "EMailSearch" "PaperFlag" "Memory" "TrashBin" "Note" "Expired" "Info"
   "Package" "Folder" "FolderOpen" "FolderPackage" "LockOpen" "PaperLocked" "Checked" "Pen"
   "Thumbnail" "Book" "List" "UserKey" "Tool" "Home" "Star" "Tux" "Feather" "Apple" "Wiki"
   "Money" "Certificate" "BlackBerry"])

(defn- starts-with-bytes? [^bytes b & xs]
  (and (>= (alength b) (count xs))
       (every? true? (map-indexed #(= (bit-and (aget b (int %1)) 0xff) %2) xs))))

(defn- image-mime
  "Raster formats only: SVG could contain scripts and is not displayed."
  [^bytes b]
  (cond
    (starts-with-bytes? b 0x89 0x50 0x4E 0x47) "image/png"
    (starts-with-bytes? b 0xFF 0xD8 0xFF) "image/jpeg"
    (starts-with-bytes? b 0x47 0x49 0x46 0x38) "image/gif"
    (starts-with-bytes? b 0x00 0x00 0x01 0x00) "image/x-icon"
    (starts-with-bytes? b 0x42 0x4D) "image/bmp"
    (and (starts-with-bytes? b 0x52 0x49 0x46 0x46) (> (alength b) 12)
         (= "WEBP" (String. b 8 4 "ISO-8859-1"))) "image/webp"
    :else nil))

(defn- icon-display
  "{:id n :name \"Key\"} plus :custom {:uuid :name :data-url} if a custom
   icon is set and readable as an image."
  [id custom-uuid icon-el]
  (let [id (if (and id (< -1 id (count standard-icons))) id 0)
        data (some-> icon-el (k/child-text :Data) str/trim not-empty
                     (#(try (c/unb64 %) (catch Exception _ nil))))
        mime (some-> data image-mime)]
    (cond-> {:id id :name (standard-icons id)}
      (and custom-uuid mime) (assoc :custom {:uuid custom-uuid
                                             :name (k/child-text icon-el :Name)
                                             :data-url (str "data:" mime ";base64," (c/b64 data))}))))

(defn entry-icon
  "Icon of a vault entry for display."
  [payload]
  (let [{:keys [id custom]} (get-in payload [:kdbx :icon])
        icon-xml (when custom (some #(when (= custom (:uuid %)) (:xml %)) (get-in payload [:kdbx :icons])))]
    (icon-display id custom (some-> icon-xml k/parse-xml-str))))

(defn folder-icons
  "Folder icons from the database records: [{:folder \"Server/Linux\" :icon ..}].
   For the same path from several imports the first one wins."
  [db-payloads]
  (let [acc (reduce
             (fn [acc {:keys [skeleton]}]
               (let [doc (k/parse-xml-str skeleton)
                     icons (into {} (for [i (k/children (k/child (k/child doc :Meta) :CustomIcons) :Icon)]
                                      [(k/child-text i :UUID) i]))
                     root (k/child (k/child doc :Root) :Group)
                     out (atom acc)]
                 (when root
                   ((fn visit [g path]
                      (let [custom (k/child-text g :CustomIconUUID)]
                        (swap! out #(if (contains? % path) %
                                        (assoc % path (icon-display (parse-long (str (k/child-text g :IconID)))
                                                                    custom (get icons custom))))))
                      (doseq [sub (k/children g :Group)]
                        (visit sub (str/join "/" (remove str/blank? [path (or (k/child-text sub :Name) "")])))))
                    root ""))
                 @out))
             {}
             db-payloads)]
    (vec (for [[f icon] (sort-by key acc)] {:folder f :icon icon}))))

;; ================================================================ Export: groups

(defn- new-group-el [uuid name t]
  (el :Group (el :UUID uuid) (el :Name name) (el :Notes) (el :IconID "48") (times-el t)
      (el :IsExpanded "True") (el :DefaultAutoTypeSequence) (el :EnableAutoType "null")
      (el :EnableSearching "null") (el :LastTopVisibleEntry zero-uuid)))

(defn- fresh-doc [t]
  (el :KeePassFile
      (el :Meta (el :Generator "cljpass") (el :DatabaseName "cljpass") (el :DatabaseNameChanged t)
          (el :DatabaseDescription) (el :DatabaseDescriptionChanged t)
          (el :DefaultUserName) (el :DefaultUserNameChanged t)
          (el :MaintenanceHistoryDays "365") (el :Color) (el :MasterKeyChanged t)
          (el :MasterKeyChangeRec "-1") (el :MasterKeyChangeForce "-1")
          (el :MemoryProtection (el :ProtectTitle "False") (el :ProtectUserName "False")
              (el :ProtectPassword "True") (el :ProtectURL "False") (el :ProtectNotes "False"))
          (el :CustomIcons) (el :RecycleBinEnabled "True") (el :RecycleBinUUID zero-uuid)
          (el :RecycleBinChanged t) (el :EntryTemplatesGroup zero-uuid) (el :EntryTemplatesGroupChanged t)
          (el :LastSelectedGroup zero-uuid) (el :LastTopVisibleGroup zero-uuid)
          (el :HistoryMaxItems "10") (el :HistoryMaxSize "6291456") (el :SettingsChanged t))
      (el :Root (new-group-el (new-uuid) "cljpass" t) (el :DeletedObjects))))

(defn- index-groups
  "Group tree -> {uuid {:el properties without children, :parent, :name, :children [uuid]}}"
  [root]
  (let [idx (atom {})]
    ((fn visit [g parent]
       (let [u (k/child-text g :UUID)
             subs (k/children g :Group)]
         (swap! idx assoc u {:el (remove-children g #(or (tag? :Group %) (tag? :Entry %)))
                             :parent parent
                             :name (or (k/child-text g :Name) "")
                             :children (mapv #(k/child-text % :UUID) subs)})
         (doseq [s subs] (visit s u))))
     root nil)
    @idx))

(defn- folder-of [idx u]
  (->> (iterate #(get-in idx [% :parent]) u) (take-while some?) reverse rest
       (map #(get-in idx [% :name])) (str/join "/")))

(defn- place
  "Target group for an entry: the original group if the folder is unchanged
   in the vault, otherwise the folder path (groups are created as needed).
   Returns [idx uuid]."
  [idx root payload t]
  (let [folder (str/join "/" (remove str/blank? (map str/trim (str/split (str (:folder payload)) #"/"))))
        chain (get-in payload [:kdbx :groups])
        u (first (peek chain))]
    (if (and u (idx u) (= folder (folder-of idx u)))
      [idx u]
      (let [segs (if (and (seq chain) (= folder (str/join "/" (map second (rest chain)))))
                   (rest chain)
                   (map (fn [n] [nil n]) (remove str/blank? (str/split folder #"/"))))]
        (reduce (fn [[idx parent] [id name]]
                  (let [kids (get-in idx [parent :children])
                        hit (or (when (and id (some #{id} kids)) id)
                                (first (filter #(= name (get-in idx [% :name])) kids)))]
                    (if hit
                      [idx hit]
                      (let [nu (if (and id (not (idx id))) id (new-uuid))]
                        [(-> idx
                             (assoc nu {:el (new-group-el nu name t) :parent parent :name name :children []})
                             (update-in [parent :children] conj nu))
                         nu]))))
                [idx root]
                segs)))))

(defn- build-group [idx u entries-by-group]
  (let [{:keys [el children]} (idx u)]
    (update el :content #(vec (concat % (map second (sort-by first (entries-by-group u)))
                                      (map (fn [ch] (build-group idx ch entries-by-group)) children))))))

;; ================================================================ Export: entries

(defn- fresh-entry [t uuid]
  (el :Entry (el :UUID (or uuid (new-uuid))) (el :IconID "0") (el :ForegroundColor) (el :BackgroundColor)
      (el :OverrideURL) (el :Tags) (times-el t)
      (el :AutoType (el :Enabled "True") (el :DataTransferObfuscation "0"))
      (el :History)))

(defn payload-tags
  "Tags of a payload. Payloads from before :tags was introduced only have
   them in the stored <Entry> - then those apply (otherwise they would be
   lost on the next export)."
  [p]
  (norm-tags (if (contains? p :tags)
               (:tags p)
               (some-> (get-in p [:kdbx :entry]) k/parse-xml-str (k/child-text :Tags)))))

(defn- core-of-payload [p]
  (into {:expires (or (norm-expires (:expires p)) "")
         :tags (payload-tags p)
         :custom-fields (vec (for [{:keys [name value protected]} (:custom-fields p)
                                   :when (seq (str name))]
                               {:name (str name) :value (str value) :protected (boolean protected)}))}
        (for [[_ kw] core-fields] [kw (str (get p kw ""))])))

(def ^:dynamic *history-max*
  "Maximum number of history items per entry (KeePass: HistoryMaxItems,
   -1 = unlimited). export-doc sets it from the database settings."
  10)

(defn- trim-history
  "Removes the oldest history items until *history-max* is met."
  [hist]
  (let [n (- (count (filter #(tag? :Entry %) (:content hist))) *history-max*)]
    (if (and (>= *history-max* 0) (pos? n))
      (update hist :content
              (fn [cs] (second (reduce (fn [[left acc] x]
                                         (if (and (pos? left) (tag? :Entry x)) [(dec left) acc] [left (conj acc x)]))
                                       [n []] cs))))
      hist)))

(defn- touch-modified [e t]
  (set-child e (set-text (or (k/child e :Times) (times-el t)) :LastModificationTime t)))

(defn- push-history [e t]
  (let [snapshot (remove-children e #(tag? :History %))
        hist (or (k/child e :History) (el :History))]
    (-> e
        (set-child (trim-history (update hist :content #(conj (vec %) snapshot))))
        (touch-modified t))))

(defn- string-el [key value protected]
  (el :String (el :Key key) (xml/element :Value (if protected {:Protected "True"} {}) value)))

(defn- set-strings
  "Sets all String fields to the state of the vault. Existing elements keep
   their position and attributes; removed custom fields disappear."
  [e {:keys [custom-fields] :as core} fresh?]
  (let [wanted (into (array-map)
                     (concat (for [[key kw] core-fields] [key [(get core kw) (= kw :password)]])
                             (for [{:keys [name value protected]} custom-fields] [name [value protected]])))
        cs (vec (:content e))
        seen (atom #{})
        cs (vec (keep (fn [x]
                        (if-not (tag? :String x)
                          x
                          (let [key (k/child-text x :Key)]
                            (if-let [[v p] (get wanted key)]
                              (do (swap! seen conj key)
                                  (let [attrs (:attrs (k/child x :Value))
                                        attrs (cond
                                                (core-keys key) attrs
                                                (= (boolean p) (= "True" (:Protected attrs))) attrs
                                                p (assoc attrs :Protected "True")
                                                :else (dissoc attrs :Protected))]
                                    (set-child x (xml/element :Value attrs v))))
                              nil))))
                      cs))
        missing (for [[key [v p]] wanted
                      :when (and (not (@seen key)) (or fresh? (seq v) (not (core-keys key))))]
                  (string-el key v p))
        last-s (last (keep-indexed #(when (tag? :String %2) %1) cs))
        before (first (keep-indexed #(when (some (fn [t] (tag? t %2)) [:Binary :AutoType :History]) %1) cs))
        at (cond last-s (inc last-s) before before :else (count cs))]
    (assoc e :content (vec (concat (subvec cs 0 at) missing (subvec cs at))))))

(defn- set-expiry [e core]
  (let [times (k/child e :Times)
        cur (when (= "True" (k/child-text times :Expires)) (norm-expires (k/child-text times :ExpiryTime)))
        want (not-empty (:expires core))]
    (cond
      (and cur want (same-expiry? cur want)) e
      (= cur want) e
      want (set-child e (-> (or times (times-el (k/now-iso)))
                            (set-text :Expires "True") (set-text :ExpiryTime (iso-sec want))))
      :else (set-child e (set-text times :Expires "False")))))

(defn- set-tags [e core]
  (if (= (norm-tags (k/child-text e :Tags)) (:tags core))
    e
    (set-text e :Tags (:tags core))))

(defn- set-extra
  "Stores vault fields without a KeePass counterpart in CustomData."
  [e p]
  (let [extra (cond-> (apply dissoc p known-keys)
                ;; expiry that cannot be read as a date
                (and (not (str/blank? (str (:expires p)))) (nil? (norm-expires (:expires p))))
                (assoc :expires (str (:expires p))))]
    (set-item e extra-key (not-empty extra))))

(defn- norm-folder [f] (str/join "/" (remove str/blank? (map str/trim (str/split (str f) #"/")))))

(defn- core-hash* [p date-only?]
  (codec/hash-of (cond-> (-> (core-of-payload p)
                             (update :custom-fields #(vec (sort-by :name %)))
                             (assoc :folder (norm-folder (:folder p))))
                   date-only? (update :expires #(if (> (count %) 10) (subs % 0 10) %))
                   ;; without tags, as before they were introduced (markers stay valid)
                   (str/blank? (payload-tags p)) (dissoc :tags))))

(defn core-hash
  "Checksum over everything that is seen and changed in the app (fields and
   folder) - to detect changes when syncing."
  [p]
  (core-hash* p false))

(defn unchanged-since?
  "Does the checksum of an origin marker still match the payload? Markers
   from before expiry times were computed with the date only; they stay
   valid as long as nothing else changed."
  [marker-hash p]
  (or (= marker-hash (core-hash p)) (= marker-hash (core-hash* p true))))

(defn- entry-core-for
  "Fields of the <Entry> for comparison with core (plain date = same day)."
  [e core]
  (let [c (core-of-entry e)]
    (if (same-expiry? (:expires c) (:expires core)) (assoc c :expires (:expires core)) c)))

(defn- build-entry
  "Vault entry -> <Entry>. source: origin marker or nil."
  [{:keys [payload modified id]} source now]
  (let [t (or (iso-sec modified) now)
        stored (get-in payload [:kdbx :entry])
        base (if stored (k/parse-xml-str stored) (fresh-entry t (id->uuid id)))
        core (core-of-payload payload)
        base (if (and stored (or (not= (entry-core-for base core) core)
                                 (not= (look-of-entry base) (look-of-entry (apply-look base payload)))))
               (push-history base t)
               base)]
    (-> base
        (set-strings core (nil? stored))
        (set-expiry core)
        (set-tags core)
        (apply-look payload)
        (set-extra payload)
        (set-item source-key source))))

(defn- remap-binaries
  "Sets the attachment refs of an entry to indexes into the shared
   attachment list (identical contents are stored only once)."
  [e local state]
  (let [local (into {} (map (juxt :ref identity)) local)]
    (postwalk-el
     (fn [x]
       (if-not (tag? :Binary x)
         x
         (let [v (k/child x :Value)
               ref (get-in v [:attrs :Ref])]
           (cond
             (nil? ref) x
             (get local ref)
             (let [{:keys [protected data]} (get local ref)
                   key [(boolean protected) data]
                   idx (or (get-in @state [:index key])
                           (let [n (count (:list @state))]
                             (swap! state #(-> % (assoc-in [:index key] n)
                                               (update :list conj {:protected (boolean protected) :data (c/unb64 data)})))
                             n))]
               (set-child x (assoc-in v [:attrs :Ref] (str idx))))
             ;; attachment missing (damaged import): don't leave a dangling reference
             :else (el :Dropped)))))
     e)))

(defn- drop-dropped [e] (postwalk-el #(remove-children % (fn [x] (tag? :Dropped x))) e))

(defn- choose-db [dbs entries database]
  (cond
    database (or (first (filter #(= database (:id %)) dbs))
                 (throw (i18n/error :kp/db-not-found {:id database} {:type :not-found})))
    (empty? dbs) nil
    :else (let [freq (frequencies (keep #(get-in % [:payload :kdbx :db]) entries))]
            (apply max-key #(get freq (:id %) 0) (reverse dbs)))))

(defn- set-db-marker [meta id]
  (let [cd (or (k/child meta :CustomData) (el :CustomData))
        cd (remove-children cd #(and (tag? :Item %) (= db-key (k/child-text % :Key))))]
    (set-child meta (update cd :content #(conj (vec %) (el :Item (el :Key db-key) (el :Value id)))))))

(defn- source-marker
  "Marker for syncing after returning to the server (§13)."
  [{:keys [id version payload]}]
  (if (and id version)
    {:id id :version version :hash (core-hash payload)}
    (:kdbx-source payload)))

(defn- export-doc* [doc db entries now markers]
  (let [doc (if (k/child (k/child doc :Root) :Group)
              doc
              (set-child doc (set-child (or (k/child doc :Root) (el :Root)) (new-group-el (new-uuid) "cljpass" now))))
        root-el (k/child (k/child doc :Root) :Group)
        root (k/child-text root-el :UUID)
        bins (atom {:index {} :list []})
        used (atom #{})
        [idx placed] (reduce (fn [[idx acc] [n item]]
                               (let [p (:payload item)
                                     [idx u] (place idx root p now)
                                     e (-> (build-entry item (if markers (source-marker item) (:kdbx-source p)) now)
                                           (remap-binaries (get-in p [:kdbx :binaries]) bins)
                                           drop-dropped)
                                     uuid (k/child-text e :UUID)
                                     e (if (or (str/blank? uuid) (@used uuid)) (set-text e :UUID (new-uuid)) e)
                                     pos (get-in p [:kdbx :pos] Long/MAX_VALUE)]
                                 (swap! used conj (k/child-text e :UUID))
                                 [idx (update acc u (fnil conj []) [[pos n] e])]))
                             [(index-groups root-el) {}]
                             (map-indexed vector entries))
        tree (build-group idx root placed)
        known-icons (set (map #(k/child-text % :UUID) (k/children (k/child (k/child doc :Meta) :CustomIcons) :Icon)))
        new-icons (->> entries
                       (mapcat #(get-in % [:payload :kdbx :icons]))
                       (remove #(known-icons (:uuid %)))
                       (map (juxt :uuid :xml))
                       (into (sorted-map))
                       vals
                       (map k/parse-xml-str))
        meta (let [m (or (k/child doc :Meta) (k/child (fresh-doc now) :Meta))]
               (cond-> m
                 (seq new-icons) (set-child (update (or (k/child m :CustomIcons) (el :CustomIcons))
                                                    :content #(vec (concat % new-icons))))
                 (and markers db) (set-db-marker (:id db))))
        doc (-> doc
                (set-child meta)
                (set-child (set-child (k/child doc :Root) tree)))]
    {:xml doc
     :binaries (:list @bins)
     :public-custom-data (some-> (:public-custom-data db) c/unb64)
     :count (count entries)}))

(defn export-doc
  "items: [{:payload :modified :id :version}] - all readable entries
   including the database records (:id/:version optional). opts:
   {:database id} chooses whose Meta and group tree the file gets
   (otherwise the one with the most entries); {:markers true} writes the
   origin markers (disconnecting from the server). Existing :kdbx-source
   is always kept. Returns {:xml :binaries :public-custom-data :count}."
  [items {:keys [database markers]}]
  (let [now (k/now-iso)
        dbs (keep #(get-in % [:payload :kdbx-db]) items)
        entries (remove #(get-in % [:payload :kdbx-db]) items)
        db (choose-db dbs entries database)
        doc (if db (k/parse-xml-str (:skeleton db)) (fresh-doc now))]
    (binding [*history-max* (or (some-> (k/child-text (k/child doc :Meta) :HistoryMaxItems) str/trim parse-long) 10)]
      (export-doc* doc db entries now markers))))

;; ================================================================ Helpers for file mode and syncing (§13)

(defn entry-uuid
  "KeePass UUID an entry carries in an exported file."
  [payload id]
  (or (some-> (get-in payload [:kdbx :entry]) k/parse-xml-str (k/child-text :UUID))
      (id->uuid id)))

(defn entry-times
  "{:created :modified} from the stored <Entry> (ISO-8601) or {}."
  [payload]
  (if-let [e (some-> (get-in payload [:kdbx :entry]) k/parse-xml-str)]
    (let [t (k/child e :Times)]
      {:created (iso-sec (k/child-text t :CreationTime))
       :modified (iso-sec (k/child-text t :LastModificationTime))
       :history (count (k/children (k/child e :History) :Entry))})
    {}))

(defn entry-history
  "History like in KeePass (oldest first): [{:date :title}]."
  [payload]
  (when-let [e (some-> (get-in payload [:kdbx :entry]) k/parse-xml-str)]
    (vec (for [old (k/children (k/child e :History) :Entry)]
           {:date (iso-sec (k/child-text (k/child old :Times) :LastModificationTime))
            :title (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value))
                         (k/children old :String))}))))

(defn fresh-copy
  "Payload for a copy with a new ID: its own UUID, without history and
   origin marker (like Duplicate in KeePass)."
  [payload new-id]
  (cond-> (dissoc payload :kdbx-source)
    (get-in payload [:kdbx :entry])
    (update-in [:kdbx :entry]
               #(k/xml-str (-> (k/parse-xml-str %)
                               (set-text :UUID (id->uuid new-id))
                               (remove-children (fn [x] (tag? :History x)))
                               (set-child (el :History)))))))

(defn deleted-objects
  "[{:uuid :time}] from <DeletedObjects> of a database record."
  [db-payload]
  (when-let [sk (get-in db-payload [:kdbx-db :skeleton])]
    (vec (for [d (k/children (k/child (k/child (k/parse-xml-str sk) :Root) :DeletedObjects) :DeletedObject)]
           {:uuid (k/child-text d :UUID) :time (iso-sec (k/child-text d :DeletionTime))}))))

(defn add-deleted
  "Records a deletion in <DeletedObjects> like KeePass (for syncing and
   KeePass synchronization)."
  [db-payload uuid t]
  (update-in db-payload [:kdbx-db :skeleton]
             (fn [sk]
               (let [doc (k/parse-xml-str sk)
                     root (or (k/child doc :Root) (el :Root))
                     dos (or (k/child root :DeletedObjects) (el :DeletedObjects))
                     dos (update dos :content #(conj (vec %) (el :DeletedObject (el :UUID uuid) (el :DeletionTime t))))]
                 (k/xml-str (set-child doc (set-child root dos)))))))

(defn empty-doc
  "New, empty KeePass database {:xml :binaries} (file mode)."
  [db-name]
  (let [t (k/now-iso)
        doc (fresh-doc t)
        doc (set-child doc (set-text (k/child doc :Meta) :DatabaseName db-name))
        root (k/child doc :Root)
        doc (set-child doc (set-child root (set-text (k/child root :Group) :Name db-name)))]
    {:xml doc :binaries {}}))

;; ================================================================ Synchronizing like KeePass

(defn- mod-time [e] (or (iso-sec (k/child-text (k/child e :Times) :LastModificationTime)) ""))

(defn entry-modified
  "LastModificationTime (ISO, seconds) of a payload, \"\" if unknown."
  [payload]
  (or (some-> (get-in payload [:kdbx :entry]) k/parse-xml-str mod-time) ""))

(defn merge-entry
  "Merges both states of an entry (KeePass: Synchronize). The newer one
   wins; the older one and its history go into the history (unless already
   there). Attachments and icons are carried over."
  [win lose]
  (let [we (k/parse-xml-str (get-in win [:kdbx :entry]))
        le (k/parse-xml-str (get-in lose [:kdbx :entry]))
        hist (or (k/child we :History) (el :History))
        have (into #{(mod-time we)} (map mod-time (k/children hist :Entry)))
        cands (cons (remove-children le #(tag? :History %)) (k/children (k/child le :History) :Entry))
        new (->> cands (remove #(have (mod-time %))) (group-by mod-time) vals (map first))
        ;; rename the attachment refs of the other state so they don't collide
        rename (fn [e] (postwalk-el (fn [x] (if (and (tag? :Binary x) (get-in (k/child x :Value) [:attrs :Ref]))
                                              (set-child x (update-in (k/child x :Value) [:attrs :Ref] #(str "s:" %)))
                                              x))
                                    e))
        new (map rename new)
        used (set (for [e new b (elements e) :when (tag? :Binary b)] (get-in (k/child b :Value) [:attrs :Ref])))
        hist (update hist :content #(vec (sort-by mod-time (concat (filter k/element? %) new))))]
    (if (empty? new)
      win
      (-> win
          (assoc-in [:kdbx :entry] (k/xml-str (set-child we hist)))
          (update-in [:kdbx :binaries] #(vec (concat % (for [b (get-in lose [:kdbx :binaries])
                                                             :let [r (str "s:" (:ref b))]
                                                             :when (used r)]
                                                         (assoc b :ref r)))))
          (update-in [:kdbx :icons] #(let [known (set (map :uuid %))]
                                       (vec (concat % (remove (comp known :uuid) (get-in lose [:kdbx :icons]))))))))))

(defn merge-deleted
  "Takes over the DeletedObjects of another record (union)."
  [db-payload others]
  (let [have (set (map :uuid (deleted-objects db-payload)))]
    (reduce (fn [p {:keys [uuid time]}] (add-deleted p uuid time))
            db-payload
            (remove #(have (:uuid %)) others))))

;; ================================================================ Attachments, history, settings (like KeePass)

(defn- stored-entry [payload] (some-> (get-in payload [:kdbx :entry]) k/parse-xml-str))

(defn- apply-core
  "Writes the fields of the payload into an <Entry> (like the export)."
  [e payload fresh?]
  (let [core (core-of-payload payload)]
    (-> e (set-strings core fresh?) (set-expiry core) (set-tags core) (apply-look payload))))

(defn ensure-entry-xml
  "Entries created in cljpass have no stored <Entry> yet. Attachments and
   history need one: create it with the current fields."
  [payload id now]
  (if (get-in payload [:kdbx :entry])
    payload
    (update payload :kdbx #(merge {:v 1 :binaries [] :icons []} %
                                  {:entry (k/xml-str (apply-core (fresh-entry now (id->uuid id)) payload true))}))))

(defn- bin-ref [b] (get-in (k/child b :Value) [:attrs :Ref]))

(defn- prune-binaries
  "Removes attachment data referenced neither by the entry nor its history."
  [payload]
  (let [used (set (some-> (stored-entry payload) binary-refs))]
    (update-in payload [:kdbx :binaries] #(vec (filter (comp used :ref) %)))))

(defn attachment-count
  "Number of attachments, without decoding data (for the list)."
  [payload]
  (if (seq (get-in payload [:kdbx :binaries]))
    (count (k/children (stored-entry payload) :Binary))
    0))

(defn attachments
  "Attachments of the current state: [{:name :size}]."
  [payload]
  (if-let [e (stored-entry payload)]
    (let [bins (into {} (map (juxt :ref identity)) (get-in payload [:kdbx :binaries]))]
      (vec (for [b (k/children e :Binary)
                 :let [d (get bins (bin-ref b))]
                 :when d]
             {:name (str (k/child-text b :Key)) :size (alength (c/unb64 (:data d)))})))
    []))

(defn attachment-data
  "Content of an attachment (bytes) or nil."
  [payload name]
  (when-let [e (stored-entry payload)]
    (let [bins (into {} (map (juxt :ref identity)) (get-in payload [:kdbx :binaries]))]
      (some #(when (= name (k/child-text % :Key)) (some-> (get bins (bin-ref %)) :data c/unb64))
            (k/children e :Binary)))))

(defn edit-attachments
  "Changes attachments. ops: {:detach [name ...] :attach [{:name :data bytes}]},
   an attachment with the same name is replaced. history?: old state goes
   into the history (like every change in KeePass). The fields of the
   payload are copied into the <Entry> as well, so the export does not
   create another history item."
  [payload id {:keys [attach detach]} history? now]
  (if (and (empty? attach) (empty? detach))
    payload
    (let [p (ensure-entry-xml payload id now)
          e (stored-entry p)
          e (-> (if history? (push-history e now) (touch-modified e now))
                (apply-core p false))
          names (into (set detach) (map :name attach))
          e (remove-children e #(and (tag? :Binary %) (names (k/child-text % :Key))))
          new (for [{:keys [name data]} attach] [(str "a:" (c/hex (c/random-bytes 8))) name data])
          cs (vec (:content e))
          after (last (keep-indexed #(when (or (tag? :Binary %2) (tag? :String %2)) %1) cs))
          at (if after (inc after) (count cs))
          e (assoc e :content (vec (concat (subvec cs 0 at)
                                           (for [[ref name _] new] (el :Binary (el :Key name) (xml/element :Value {:Ref ref})))
                                           (subvec cs at))))]
      (-> p
          (assoc-in [:kdbx :entry] (k/xml-str e))
          (update-in [:kdbx :binaries] #(vec (concat % (for [[ref _ data] new] {:ref ref :protected false :data (c/b64 data)}))))
          prune-binaries))))

(defn- history-entries [e] (vec (k/children (k/child e :History) :Entry)))

(defn history-version
  "History item i (0 = oldest) for display: fields, date, attachments."
  [payload i]
  (when-let [old (some-> (stored-entry payload) history-entries (get i))]
    (let [p (assoc-in payload [:kdbx :entry] (k/xml-str old))]
      (assoc (core-of-entry old)
             :date (mod-time old)
             :attachments (attachments p)))))

(defn restore-history
  "Restores history item i (KeePass: Restore). The current state goes into
   the history."
  [payload i now]
  (let [e (stored-entry payload)
        old (get (some-> e history-entries) i)
        _ (when-not old (throw (i18n/error :kp/history-not-found nil {:type :not-found})))
        cur (push-history e now)
        times (-> (or (k/child old :Times) (times-el now))
                  (set-text :CreationTime (or (k/child-text (k/child cur :Times) :CreationTime) now))
                  (set-text :LastModificationTime now))
        restored (-> old
                     (remove-children #(tag? :History %))
                     (set-child times)
                     (set-child (k/child cur :History)))]
    (merge payload
           (core-of-entry restored)
           {:kdbx (merge (:kdbx payload) (look-of-entry restored) {:entry (k/xml-str restored)})})))

(defn delete-history
  "Deletes history item i (KeePass: History > Delete)."
  [payload i]
  (let [e (stored-entry payload)
        hist (k/child e :History)
        olds (history-entries e)]
    (when-not (get olds i) (throw (i18n/error :kp/history-not-found nil {:type :not-found})))
    (let [victim (get olds i)
          hist (update hist :content (fn [cs] (vec (remove #(identical? % victim) cs))))]
      (prune-binaries (assoc-in payload [:kdbx :entry] (k/xml-str (set-child e hist)))))))

(defn- update-meta [db-payload f]
  (update-in db-payload [:kdbx-db :skeleton]
             (fn [sk] (let [doc (k/parse-xml-str sk)]
                        (k/xml-str (set-child doc (f (or (k/child doc :Meta) (el :Meta)))))))))

(defn db-settings
  "Settings of a KeePass database (File > Database Settings)."
  [db-payload]
  (let [m (k/child (k/parse-xml-str (get-in db-payload [:kdbx-db :skeleton])) :Meta)]
    {:name (str (k/child-text m :DatabaseName))
     :description (str (k/child-text m :DatabaseDescription))
     :default-username (str (k/child-text m :DefaultUserName))
     :history-max-items (or (some-> (k/child-text m :HistoryMaxItems) str/trim parse-long) 10)
     :recycle-bin (not= "False" (k/child-text m :RecycleBinEnabled))
     :master-key-changed (iso-sec (k/child-text m :MasterKeyChanged))}))

(defn set-db-settings
  "Sets settings; changed fields get their *Changed timestamp like in
   KeePass (important for synchronizing). A new name also renames the
   record's title (in the current language)."
  [db-payload settings now]
  (let [old (db-settings db-payload)
        settings (cond-> settings
                   (contains? settings :recycle-bin) (update :recycle-bin #(if % "True" "False")))
        old (update old :recycle-bin #(if % "True" "False"))
        fields [[:name :DatabaseName :DatabaseNameChanged]
                [:description :DatabaseDescription :DatabaseDescriptionChanged]
                [:default-username :DefaultUserName :DefaultUserNameChanged]
                [:history-max-items :HistoryMaxItems nil]
                [:recycle-bin :RecycleBinEnabled :RecycleBinChanged]]
        changed (for [[kw tag stamp] fields
                      :when (and (contains? settings kw) (not= (str (get settings kw)) (str (get old kw))))]
                  [tag stamp (str (get settings kw))])]
    (if (empty? changed)
      db-payload
      (cond-> (update-meta db-payload
                           (fn [m] (reduce (fn [m [tag stamp v]] (cond-> (set-text m tag v) stamp (set-text stamp now)))
                                           (set-text m :SettingsChanged now)
                                           changed)))
        (contains? settings :name) (assoc :title (db-title (:name settings)))))))

(defn touch-master-key
  "Time of the last master key change (Meta/MasterKeyChanged)."
  [db-payload now]
  (update-meta db-payload #(set-text % :MasterKeyChanged now)))

;; ================================================================ Groups and recycle bin (like KeePass)
;;
;; Groups are addressed by their folder path (\"Server/Linux\"), the way
;; entries carry it in the :folder field. That is why siblings must not have
;; the same name. The groups live in the group tree of the database record
;; (skeleton); the caller updates the entries (rebase-folder), and the
;; export then assigns them to their group again.

(defn- skel [db-payload] (k/parse-xml-str (get-in db-payload [:kdbx-db :skeleton])))

(defn- put-skel [db-payload doc] (assoc-in db-payload [:kdbx-db :skeleton] (k/xml-str doc)))

(defn folder-segments [path] (vec (remove str/blank? (map str/trim (str/split (str path) #"/")))))

(defn- join-path [parent name] (str/join "/" (conj (folder-segments parent) name)))

(defn- parent-path [path] (str/join "/" (pop (folder-segments path))))

(defn- index-of [pred xs] (first (keep-indexed #(when (pred %2) %1) xs)))

(defn- root-loc
  "Path (for get-in) to the top-level group in the document."
  [doc]
  (when-let [ri (index-of #(tag? :Root %) (:content doc))]
    (when-let [gi (index-of #(tag? :Group %) (:content (nth (:content doc) ri)))]
      [:content ri :content gi])))

(defn- named-group [name] (fn [x] (and (tag? :Group x) (= name (str (k/child-text x :Name))))))

(defn- group-loc [doc path]
  (when-let [rl (root-loc doc)]
    (reduce (fn [loc name]
              (if-let [i (index-of (named-group name) (:content (get-in doc loc)))]
                (conj loc :content i)
                (reduced nil)))
            rl (folder-segments path))))

(defn- need-group [doc path]
  (or (group-loc doc path)
      (throw (i18n/error :kp/group-not-found {:path path} {:type :not-found}))))

(defn- check-group-name [name]
  (let [n (str/trim (str name))]
    (when (str/blank? n) (throw (i18n/error :kp/group-name-empty nil {:type :invalid})))
    (when (str/includes? n "/") (throw (i18n/error :kp/group-name-slash nil {:type :invalid})))
    n))

(defn- free-name
  "name, or with a counter if a sibling group already has that name."
  [g name]
  (first (remove #(some (named-group %) (:content g))
                 (cons name (map #(str name " (" % ")") (iterate inc 2))))))

(defn- name-taken! [g name]
  (when (some (named-group name) (:content g))
    (throw (i18n/error :kp/group-exists {:name name} {:type :exists}))))

(defn- touch-group [g t k]
  (set-child g (set-text (or (k/child g :Times) (times-el t)) k t)))

(defn- walk-groups
  "[{:path :uuid :group}] of all groups below the top-level one, in document order."
  [doc]
  (when-let [rl (root-loc doc)]
    ((fn visit [g path]
       (mapcat (fn [sub]
                 (let [p (join-path path (str (k/child-text sub :Name)))]
                   (cons {:path p :uuid (k/child-text sub :UUID) :group sub} (visit sub p))))
               (k/children g :Group)))
     (get-in doc rl) "")))

(defn group-paths
  "All groups of the database as folder paths (empty ones too)."
  [db-payload]
  (mapv :path (walk-groups (skel db-payload))))

(defn recycle-bin
  "Folder path of the recycle bin, nil if it is disabled or missing (yet)."
  [db-payload]
  (let [doc (skel db-payload)
        meta (k/child doc :Meta)
        u (k/child-text meta :RecycleBinUUID)]
    (when (and (not= "False" (k/child-text meta :RecycleBinEnabled)) u (not= zero-uuid u))
      (some #(when (= u (:uuid %)) (:path %)) (walk-groups doc)))))

(defn recycle-bin-enabled? [db-payload]
  (not= "False" (k/child-text (k/child (skel db-payload) :Meta) :RecycleBinEnabled)))

(defn in-folder?
  "Is folder f in path or below it?"
  [f path]
  (let [f (str/join "/" (folder-segments f)) path (str/join "/" (folder-segments path))]
    (and (not (str/blank? path)) (or (= f path) (str/starts-with? f (str path "/"))))))

(defn rebase-folder
  "Folder after renaming/moving the group old -> new; nil if f is not below
   it."
  [f old new]
  (when (in-folder? f old)
    (let [rest-segs (drop (count (folder-segments old)) (folder-segments f))]
      (str/join "/" (concat (folder-segments new) rest-segs)))))

(defn add-group
  "New (empty) group below parent. Returns [db-payload' path]."
  [db-payload parent name now]
  (let [doc (skel db-payload)
        name (check-group-name name)
        loc (need-group doc parent)]
    (name-taken! (get-in doc loc) name)
    [(put-skel db-payload (update-in doc loc update :content #(conj (vec %) (new-group-el (new-uuid) name now))))
     (join-path parent name)]))

(defn rename-group
  "Renames a group. Returns [db-payload' new-path]."
  [db-payload path name now]
  (let [doc (skel db-payload)
        name (check-group-name name)
        _ (when (empty? (folder-segments path)) (throw (i18n/error :kp/group-rename-root nil {:type :invalid})))
        loc (need-group doc path)]
    (when (not= name (peek (folder-segments path)))
      (name-taken! (get-in doc (pop (pop loc))) name))
    [(put-skel db-payload (update-in doc loc #(-> % (set-text :Name name) (touch-group now :LastModificationTime))))
     (join-path (parent-path path) name)]))

(defn move-group
  "Moves a group with everything in it below target. rename?: on a name
   clash in the target, rename with a counter (error otherwise). Returns
   [db-payload' new-path]."
  [db-payload path target now & [rename?]]
  (let [doc (skel db-payload)
        segs (folder-segments path)
        _ (when (empty? segs) (throw (i18n/error :kp/group-move-root nil {:type :invalid})))
        _ (when (or (in-folder? target path))
            (throw (i18n/error :kp/group-move-into-itself nil {:type :invalid})))
        loc (need-group doc path)
        g (get-in doc loc)
        _ (need-group doc target)
        doc (update-in doc (pop (pop loc)) update :content #(vec (remove (fn [x] (identical? x g)) %)))
        tloc (need-group doc target)
        name (if rename? (free-name (get-in doc tloc) (peek segs)) (do (name-taken! (get-in doc tloc) (peek segs)) (peek segs)))
        g (-> g (set-text :Name name) (touch-group now :LocationChanged))]
    [(put-skel db-payload (update-in doc tloc update :content #(conj (vec %) g)))
     (join-path target name)]))

(defn remove-group
  "Removes a group with its subgroups and records it in <DeletedObjects>
   like KeePass. The caller deletes the entries in it."
  [db-payload path now]
  (let [doc (skel db-payload)
        _ (when (empty? (folder-segments path)) (throw (i18n/error :kp/group-delete-root nil {:type :invalid})))
        loc (need-group doc path)
        g (get-in doc loc)
        uuids (cons (k/child-text g :UUID) (map :uuid (walk-groups (assoc-in doc (root-loc doc) g))))
        doc (update-in doc (pop (pop loc)) update :content #(vec (remove (fn [x] (identical? x g)) %)))
        doc (if (some #{(k/child-text (k/child doc :Meta) :RecycleBinUUID)} uuids)
              (set-child doc (-> (k/child doc :Meta) (set-text :RecycleBinUUID zero-uuid) (set-text :RecycleBinChanged now)))
              doc)]
    (reduce (fn [p u] (add-deleted p u now)) (put-skel db-payload doc) (remove nil? uuids))))

(defn ensure-recycle-bin
  "Creates the recycle bin if it does not exist yet (like KeePass on the
   first delete: icon 43, not searchable, no auto-type). Its name is in the
   current language (like KeePass); it is recognized by RecycleBinUUID, not
   by name. Returns [db-payload' path]."
  [db-payload now]
  (if-let [p (recycle-bin db-payload)]
    [db-payload p]
    (let [doc (skel db-payload)
          rl (root-loc doc)
          name (free-name (get-in doc rl) (i18n/t :kp/recycle-bin))
          u (new-uuid)
          g (-> (new-group-el u name now)
                (set-text :IconID "43")
                (set-text :EnableAutoType "false")
                (set-text :EnableSearching "false"))
          doc (update-in doc rl update :content #(conj (vec %) g))
          doc (set-child doc (-> (k/child doc :Meta)
                                 (set-text :RecycleBinEnabled "True")
                                 (set-text :RecycleBinUUID u)
                                 (set-text :RecycleBinChanged now)))]
      [(put-skel db-payload doc) name])))

(defn set-group-icon
  "Icon of a group (standard icon, replaces a custom one)."
  [db-payload path icon-id now]
  (let [doc (skel db-payload)
        loc (need-group doc path)]
    (put-skel db-payload (update-in doc loc #(-> (apply-look % {:kdbx {:icon {:id (long icon-id)}}})
                                                 (touch-group now :LastModificationTime))))))
