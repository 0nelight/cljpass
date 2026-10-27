(ns cljpass.autoopen
  "AutoOpen: opening further KeePass files automatically when a database is
   unlocked - compatible with the KeePass plugin KeeAutoExec (Dominik
   Reichl, GPL-2.0-or-later, https://keepass.info/plugins.html#keeautoexec)
   and with KeePassXC, so the same AutoOpen group works in all three.

   Every entry in a group named AutoOpen (any depth, case-insensitive, with
   its subgroups) that has a URL describes a database:

     URL        path of the .kdbx file; relative to the folder of the current
                file (KeePassXC), file:// and kdbx:// are accepted, \\ works
                as / outside Windows
     Password   master password
     UserName   path of the key file (or attachment KeyFile.bin)

   Without password and key file, or with a wrong one, the unlock dialog
   asks for the master key (like KeeAutoExec and KeePassXC).

   Custom fields (like KeeAutoExec, values True/False):

     Enabled                 False = do not open automatically (expired
                             entries count as False)
     Priority                order (number, smaller first; default: entry order)
     IfDevice                comma-separated computer names, !name excludes
     SkipIfNotExists         True = silently skip a missing file
     SkipIfKeyFileNotExists  True = silently skip a missing key file
     Focus                   Restore = keep the current tab in front

   Placeholders in all fields: {DB_PATH} {DB_DIR} {DB_NAME} {DB_BASENAME}
   {DB_EXT} {ENV_DIRSEP} {TITLE} {USERNAME} {PASSWORD} {URL} {NOTES}
   {S:field} and %ENVIRONMENT_VARIABLE%.

   Not supported (KeeAutoExec only): remote URLs (Ioc* fields), KeyProvider,
   UserAccount (Windows user account as part of the key).

   This namespace is pure (no file access); cljpass.service reads the key
   files and opens the databases."
  (:require [clojure.string :as str]
            [cljpass.keepass :as kp])
  (:import [java.net InetAddress URI]
           [java.nio.file Path Paths]
           [java.time Instant LocalDate ZoneOffset]))

(def group-name "AutoOpen")

(def keyfile-attachment
  "Attachment that serves as key file when UserName is empty (KeeAutoExec)."
  "KeyFile.bin")

;; ================================================================ Selection

(defn auto-open-folder?
  "Is the folder (path without root group) an AutoOpen group or inside one?"
  [folder]
  (boolean (some #(.equalsIgnoreCase group-name (str/trim %)) (str/split (str folder) #"/"))))

(def ^:private core-fields
  {"Title" :title "UserName" :username "Password" :password "URL" :url "Notes" :notes})

(defn raw-field
  "Value of a KeePass field: standard field or custom field (exact name)."
  [payload nm]
  (if-let [k (core-fields nm)]
    (str (get payload k ""))
    (str (some #(when (= nm (:name %)) (:value %)) (:custom-fields payload)))))

;; ================================================================ Placeholders

(defn- db-parts [db-file]
  (let [f (str db-file)
        nm (if (str/blank? f) "" (str (.getFileName (Paths/get f (make-array String 0)))))
        dot (.lastIndexOf nm ".")]
    {"DB_PATH" f
     "DB_DIR" (if (str/blank? f) "" (str (.getParent (.toAbsolutePath (Paths/get f (make-array String 0))))))
     "DB_NAME" nm
     "DB_BASENAME" (if (pos? dot) (subs nm 0 dot) nm)
     "DB_EXT" (if (pos? dot) (subs nm (inc dot)) "")}))

(defn compile-str
  "Replaces placeholders (KeePass spelling, case-insensitive) and
   %VARIABLE% environment variables. Unknown ones stay as they are. One
   pass: values are not expanded again.
   ctx: {:payload :db-file :env {name value}}."
  [s {:keys [payload db-file env]}]
  (let [db (db-parts db-file)
        env (or env {})
        sep (str java.io.File/separator)
        field (fn [k] (raw-field payload k))]
    (str/replace (str s) #"(?i)\{([A-Z_]+)\}|\{S:([^}]*)\}|%([A-Za-z0-9_()]+)%"
                 (fn [[m ph custom var]]
                   (cond
                     custom (field custom)
                     var (or (get env var)
                             (some (fn [[k v]] (when (.equalsIgnoreCase (str k) var) v)) env)
                             m)
                     :else (let [u (str/upper-case ph)]
                             (cond
                               (contains? db u) (get db u)
                               (= u "ENV_DIRSEP") sep
                               (= u "TITLE") (field "Title")
                               (= u "USERNAME") (field "UserName")
                               (= u "PASSWORD") (field "Password")
                               (= u "URL") (field "URL")
                               (= u "NOTES") (field "Notes")
                               :else m)))))))

(defn- field [payload nm ctx] (str/trim (compile-str (raw-field payload nm) ctx)))

(defn- bool-field
  "True/False (case-insensitive); nil for empty or anything else."
  [payload nm ctx]
  (let [v (str/lower-case (field payload nm ctx))]
    (case v "true" true "false" false nil)))

;; ================================================================ Paths

(defn unquote-path
  "\"C:\\a b\\x.kdbx\" -> C:\\a b\\x.kdbx (like KeePass for quoted paths)."
  [s]
  (let [s (str/trim (str s))]
    (if (str/starts-with? s "\"")
      (let [end (str/index-of s "\"" 1)]
        (if end (subs s 1 end) (subs s 1)))
      s)))

(defn resolve-path
  "Path from the URL or UserName field -> absolute path. kdbx:// is removed
   (KeePassXC), file:// URLs become paths, relative paths count from base-dir
   (the folder of the current file)."
  [s base-dir]
  (let [s (unquote-path s)
        ;; paths written on Windows ({DB_DIR}\x.kdbx)
        s (if (= "/" java.io.File/separator) (str/replace s "\\" "/") s)
        s (if (re-find #"(?i)^kdbx://" s) (subs s 7) s)]
    (cond
      (str/blank? s) nil
      (re-find #"(?i)^file:" s)
      (str (try (Paths/get (URI. (str/replace s " " "%20")))
                (catch Exception _ (Paths/get (str/replace s #"(?i)^file:/*" "/") (make-array String 0)))))
      :else
      (let [p (Paths/get s (make-array String 0))]
        (str (.normalize ^Path (if (or (.isAbsolute p) (str/blank? base-dir) (re-find #"^(\\\\|/)" s))
                                 p
                                 (.resolve (Paths/get (str base-dir) (make-array String 0)) p))))))))

;; ================================================================ Device

(defn device-names
  "Names of this computer for IfDevice: the Windows computer name, the host
   name and its short form, all lower case."
  []
  (let [host (try (.getHostName (InetAddress/getLocalHost)) (catch Exception _ nil))]
    (into #{} (comp (remove str/blank?) (map str/trim) (map str/lower-case))
          [(System/getenv "COMPUTERNAME") (System/getenv "HOSTNAME") host
           (some-> host (str/split #"\.") first)])))

(defn- csv-fields [s]
  (map #(let [t (str/trim %)]
          (str/trim (if (and (str/starts-with? t "\"") (str/ends-with? t "\"") (> (count t) 1))
                      (subs t 1 (dec (count t)))
                      t)))
       (str/split (str s) #",")))

(defn device-enabled?
  "IfDevice like KeeAutoExec: a named device always opens, an excluded one
   (!name) never. Otherwise: open if the list has exclusions or no names at
   all. devices: set of lower-case names of this computer."
  [if-device devices]
  (if (or (str/blank? if-device) (empty? devices))
    true
    (loop [[f & more] (remove str/blank? (csv-fields if-device)) incl false excl false]
      (cond
        (nil? f) (or excl (not incl))
        (str/starts-with? f "!") (if (devices (str/lower-case (subs f 1))) false (recur more incl true))
        :else (if (devices (str/lower-case f)) true (recur more true excl))))))

;; ================================================================ Items

(defn expired?
  "Expiry of the payload (date: midnight UTC, or instant) reached?"
  [payload ^Instant now]
  (let [s (str/trim (str (:expires payload)))]
    (when-not (str/blank? s)
      (when-let [^Instant t (or (try (Instant/parse s) (catch Exception _ nil))
                                (try (.toInstant (.atStartOfDay (LocalDate/parse s) ZoneOffset/UTC)) (catch Exception _ nil)))]
        (not (.isAfter t now))))))

(defn items
  "AutoOpen entries of a database, sorted by priority (stable).
   entries: [{:id :payload}]; opts: {:db-file :base-dir :env :devices :now
   :exclude-folder}.
   Returns [{:id :title :label :file :enabled :device :priority}]
   without secrets. :device is false when IfDevice excludes this computer."
  [entries {:keys [db-file base-dir env devices now exclude-folder]}]
  (let [base (or base-dir (get (db-parts db-file) "DB_DIR"))
        now (or now (Instant/now))
        devices (or devices (device-names))]
    (->> entries
         (filter #(auto-open-folder? (:folder (:payload %))))
         (remove #(and exclude-folder (kp/in-folder? (:folder (:payload %)) exclude-folder)))
         (keep (fn [{:keys [payload] :as e}]
                 (let [ctx {:payload payload :db-file db-file :env env}
                       url (field payload "URL" ctx)]
                   (when-not (str/blank? url) [e ctx url]))))
         ;; default priority: position among the entries with a URL (KeeAutoExec)
         (map-indexed (fn [i [{:keys [id payload]} ctx url]]
                     (let [pri (field payload "Priority" ctx)
                           enabled (bool-field payload "Enabled" ctx)]
                       {:id id
                        :title (str (:title payload))
                        :label url
                        :file (resolve-path url base)
                        :enabled (if (some? enabled) enabled (not (expired? payload now)))
                        :device (device-enabled? (field payload "IfDevice" ctx) devices)
                        :priority (or (parse-long pri) i)})))
         (sort-by :priority)
         vec)))

(defn target
  "What to open for one AutoOpen entry - with secrets, without file access.
   {:file :password :keyfile (path) :keyfile-attachment? :skip-if-missing
    :skip-if-key-missing :restore-focus}; nil without URL.
   base-dir: folder for relative paths (default: that of db-file)."
  [payload {:keys [db-file env base-dir]}]
  (let [ctx {:payload payload :db-file db-file :env env}
        base (or base-dir (get (db-parts db-file) "DB_DIR"))
        url (field payload "URL" ctx)]
    (when-not (str/blank? url)
      (let [kf (field payload "UserName" ctx)]
        {:file (resolve-path url base)
         ;; the password is used as it is (no trimming), like KeeAutoExec
         :password (not-empty (compile-str (raw-field payload "Password") ctx))
         :keyfile (when-not (str/blank? kf) (resolve-path kf base))
         :keyfile-attachment (and (str/blank? kf) (some? (kp/attachment-data payload keyfile-attachment)))
         :skip-if-missing (true? (or (bool-field payload "SkipIfNotExists" ctx)
                                     (bool-field payload "Skip if not exists" ctx)))
         :skip-if-key-missing (true? (bool-field payload "SkipIfKeyFileNotExists" ctx))
         :restore-focus (.equalsIgnoreCase "Restore" (field payload "Focus" ctx))}))))
