(ns cljpass.local
  "Local data of a device: configuration, protected identity and the
   SQLite cache.

   Modes (config.edn):
   - Server:  {:mode :server :server URL :org-hash H :user U [:file last locally used file]}
   - Local:   {:mode :standalone :file \"...kdbx\"
               [:link {:server :org-hash :user :state :requested|:disconnected}]}
     :link remembers a requested (or earlier) server connection.
   Old configurations without :mode are server mode.

   On Windows the private keys are stored encrypted with DPAPI (CurrentUser)
   in %LOCALAPPDATA%\\cljpass. DPAPI is bound to the Windows logon and
   also works without a reachable domain controller. The user never sees
   a key."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.fs :as fs]
            [cljpass.proc :as proc]))

(defn windows? [] (str/starts-with? (str/lower-case (System/getProperty "os.name")) "windows"))

(def ^:dynamic *home* "Overrides the local directory (tests)." nil)

(defn home []
  (or *home*
      (System/getenv "CLJPASS_HOME")
      (if (windows?)
        (str (fs/path (System/getenv "LOCALAPPDATA") "cljpass"))
        (str (fs/path (System/getProperty "user.home") ".local" "share" "cljpass")))))

(defn- file [n] (str (fs/path (home) n)))
(defn config-file [] (file "config.edn"))
(defn identity-file [] (file "identity.edn"))
(defn cache-file [] (file "cache.db"))

(defn- read-edn [f] (when (fs/exists? f) (edn/read-string (slurp f))))

(defn- write-edn! [f data]
  (fs/create-dirs (fs/parent f))
  (let [tmp (str f ".tmp")]
    (spit tmp (binding [*print-length* nil *print-level* nil] (pr-str data)))
    (fs/move tmp f true)
    (when-not (windows?) (fs/set-owner-only! f))
    f))

;; ---------------------------------------------------------------- Configuration

(defn machine-dir
  "Where IT distributes defaults (GPO/software deployment):
   %ProgramData%\\cljpass or /etc/cljpass."
  []
  (if (windows?)
    (str (fs/path (or (System/getenv "ProgramData") "C:\\ProgramData") "cljpass"))
    "/etc/cljpass"))

(defn machine-config
  "Defaults distributed by IT: org.edn in machine-dir
   {:server \"https://pw.example.local\" :org-hash \"...\"}"
  []
  (read-edn (or (System/getenv "CLJPASS_MACHINE_CONFIG")
                (str (fs/path (machine-dir) "org.edn")))))

(defn changers-file [] (file "changers.edn"))

(defn- read-changers
  "changers.edn decides which program gets a password - a file anyone else
   may write would decide it for us, so that one is refused instead of
   read."
  [f]
  (when (fs/exists? f)
    (when (fs/world-writable? f)
      (throw (i18n/error :app/changers-writable {:file f} {:type :invalid})))
    (read-edn f)))

(defn load-changers
  "Where a password change at the target may come from (cljpass.rotate):
   the machine-wide file IT distributes is the base, the user's own file
   adds to it.

     {:dirs [\"/opt/cljpass/rotation\"]          ; plugins: one script each
      :defaults {:generate {:length 20} :otp true :timeout 120}
      :changers {:switch {:cmd [\"/usr/local/bin/switch-password.bb\"]}}}

   :dirs holds the directories an entry may name a script in, :changers
   the fixed ones, :defaults what applies to a script without its own
   entry."
  []
  (let [m (read-changers (or (System/getenv "CLJPASS_CHANGERS")
                             (str (fs/path (machine-dir) "changers.edn"))))
        u (read-changers (changers-file))]
    {:dirs (vec (distinct (concat (:dirs m) (:dirs u))))
     :defaults (merge (:defaults m) (:defaults u))
     :changers (merge (:changers m) (:changers u))}))

(defn load-config [] (read-edn (config-file)))

(defn load-config! []
  (or (load-config)
      (throw (i18n/error :app/device-not-enrolled nil {:type :not-enrolled}))))

(defn save-config! [cfg] (write-edn! (config-file) cfg))

(defn standalone?
  "Local mode with a KeePass file (without a server)?"
  [cfg]
  (= :standalone (:mode cfg)))

(defn standalone-allowed?
  "IT can disable local mode via org.edn: {:standalone false}."
  []
  (not (false? (:standalone (machine-config)))))

(defn default-kdbx-file []
  (str (if (windows?)
         (fs/path (System/getProperty "user.home") "Documents" "cljpass.kdbx")
         (fs/path (System/getProperty "user.home") "cljpass.kdbx"))))

(defn default-user
  "Windows logon name in lower case (AD sAMAccountName)."
  []
  (some-> (or (System/getenv "USERNAME") (System/getenv "USER")) str/lower-case))

;; ---------------------------------------------------------------- UI preferences

(defn prefs-file [] (file "prefs.edn"))

(defn load-prefs
  "The user's preferences (generator profiles, columns, lock timeout,
   recently opened files). No secrets. Unreadable = empty."
  []
  (or (try (read-edn (prefs-file)) (catch Exception _ nil)) {}))

(defn preferred-lang
  "Language for UI and CLI: the user's choice (prefs :lang), else the
   operating system's language, else English."
  []
  (or (i18n/normalize (:lang (load-prefs))) (i18n/os-lang) i18n/default-lang))

(defn update-prefs!
  "Saves (f prefs); returns the new preferences."
  [f]
  (locking prefs-file
    (let [m (f (load-prefs))]
      (write-edn! (prefs-file) m)
      m)))

;; ---------------------------------------------------------------- Identity protection

(def ^:private ps-dpapi
  "Add-Type -AssemblyName System.Security
   $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
   $e=[Text.Encoding]::UTF8.GetBytes('cljpass identity v1')
   if($env:CLJPASS_DPAPI_OP -eq 'protect'){$r=[Security.Cryptography.ProtectedData]::Protect($b,$e,'CurrentUser')}
   else{$r=[Security.Cryptography.ProtectedData]::Unprotect($b,$e,'CurrentUser')}
   [Convert]::ToBase64String($r)")

(defn- dpapi [op data-b64]
  (let [{:keys [exit out err]} (proc/run ["powershell.exe" "-NoProfile" "-NonInteractive" "-Command" ps-dpapi]
                                         data-b64 {:env {"CLJPASS_DPAPI_OP" op}})]
    (when-not (zero? exit) (throw (i18n/error :app/dpapi-failed {:error err} {:type :dpapi})))
    (str/trim out)))

(defn default-protector [] (if (windows?) :dpapi :file))

(defn protect [protector ^bytes data]
  (case protector
    :dpapi {:protector :dpapi :blob (dpapi "protect" (c/b64 data))}
    ;; :file - file permissions only (Linux development, tests)
    :file {:protector :file :blob (c/b64 data)}))

(defn unprotect ^bytes [{:keys [protector blob]}]
  (case protector
    :dpapi (c/unb64 (dpapi "unprotect" blob))
    :file (c/unb64 blob)))

(defn save-identity! [ident protector]
  (write-edn! (identity-file) (protect protector (codec/->bytes ident))))

(defn identity-exists? [] (fs/exists? (identity-file)))

(defn load-identity-bytes
  "Protected identity as bytes (the caller hands them to secmem)."
  ^bytes []
  (unprotect (or (read-edn (identity-file))
                 (throw (i18n/error :app/no-identity nil {:type :not-enrolled})))))

(defn load-identity [] (codec/parse (c/utf8-str (load-identity-bytes))))

;; ---------------------------------------------------------------- File picker

(def ^:private ps-pick-file
  "Windows open/save dialog. Output: path (UTF-8) or nothing."
  "Add-Type -AssemblyName System.Windows.Forms
   [Console]::OutputEncoding=[Text.Encoding]::UTF8
   if($env:CLJPASS_SAVE -eq '1'){$d=New-Object System.Windows.Forms.SaveFileDialog; $d.OverwritePrompt=$false}
   else{$d=New-Object System.Windows.Forms.OpenFileDialog; $d.CheckFileExists=$true}
   $d.Filter='KeePass-Datenbank (*.kdbx)|*.kdbx'
   $d.DefaultExt='kdbx'
   $f=$env:CLJPASS_FILE
   if($f){ try{ $d.InitialDirectory=[IO.Path]::GetDirectoryName($f); $d.FileName=[IO.Path]::GetFileName($f) }catch{} }
   $o=New-Object System.Windows.Forms.Form -Property @{TopMost=$true}
   if($d.ShowDialog($o) -eq 'OK'){[Console]::Out.Write($d.FileName)}")

(defn pick-file
  "File picker of the operating system (Windows only). Returns the path, nil
   on cancel, :unsupported on other systems."
  [{:keys [save file]}]
  (if-not (windows?)
    :unsupported
    (let [{:keys [exit out err]} (proc/run ["powershell.exe" "-NoProfile" "-NonInteractive" "-STA" "-Command" ps-pick-file]
                                           nil {:env {"CLJPASS_SAVE" (if save "1" "0") "CLJPASS_FILE" (str file)}})]
      (when-not (zero? exit) (throw (i18n/error :app/file-picker-failed {:error err} {:type :pick-file})))
      (not-empty (str/trim out)))))
