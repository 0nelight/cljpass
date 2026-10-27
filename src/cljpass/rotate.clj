(ns cljpass.rotate
  "Changing a password AT THE TARGET (switch, appliance, web UI), not only
   in the vault: cljpass generates the new password, runs a changer program
   for the target, and stores the password according to what that program
   reports back.

   A CHANGER IS A PLUGIN, and a plugin is a PROCESS - never code loaded
   into cljpass: one script per kind of target, in a directory this
   machine declares. The vault holds no command and no code, so a broken
   or hostile plugin reaches neither the keys nor the ontology of entries;
   it gets two secrets, once each, and nothing else. There is no plugin
   API into the vault, on purpose.

   Which plugin an ENTRY uses is the entry's business (field Changer),
   WHERE plugins may live is the machine's (changers.edn beside config.edn
   plus the machine-wide one IT distributes, cljpass.local/load-changers):

     {:dirs [\"/home/me/.config/cljpass/rotation\"]
      :defaults {:generate {:length 20 :special false}  ; the target's rules
                 :otp true                              ; no change without a code
                 :timeout 120}
      :changers {:switch {:cmd [\"/usr/local/bin/switch-password.bb\" \"--change\"]}}}

   So \"Changer: switch-password.bb\" names a script in one of :dirs, and
   \"Changer: switch\" one of the fixed entries under :changers. A shared
   entry can pick among what this machine already trusts; it cannot bring
   a command of its own. A plugin whose file anyone else may write is
   refused - whoever may write it would own the password.

   Entry fields (like cljpass.autoopen, placeholders included):

     Changer    name of the changer, e.g. switch (without it no rotation)
     Target     host for the changer; without it the host of the URL, else
                the ssh field (cljpass.channel/target)
     RotateOtp  entry whose TOTP releases the change (\"self\" = this one)

   HOW THE CHANGER IS CALLED - nothing secret in argv, in the environment
   or in a file, and nothing on stdin either:

     argv    <cmd ...> <mode> <host>          so it also runs by hand
     env     CLJPASS_ROTATE_USER / _TITLE / _URL   facts, no secrets
             CLJPASS_SECRET        path of a helper script
             CLJPASS_SECRET_SOCKET / _TOKEN   the same thing without the
                                              helper (cljpass agent secret)
     secrets \"$CLJPASS_SECRET\" old  ->  the password in place
             \"$CLJPASS_SECRET\" new  ->  the new one
             Each answered EXACTLY ONCE, over a socket only this user can
             reach, with a one-time token, and only while the changer runs
             (cljpass.ipc) - the same way ssh gets a password through
             SSH_ASKPASS.
     stdout  anything readable, and as its LAST line one JSON object
             {\"state\":\"ok\"|\"failed\"|\"unknown\", \"verified\":bool,
              \"persisted\":bool, \"message\":\"...\"}
     mode    \"probe\" = write the password that is already in place: that
             proves login, field names, encoding and Apply without changing
             anything (the probe shot of switch-access-list.bb). \"set\" =
             the real change, which has to end in a fresh login with the
             new password (\"verified\").

   What is stored, and why:

     ok        the new password; the old one stays in the history
     unknown   the same, plus a warning - the write may have landed, and
               the history then holds both candidates to try. A changer
               that cannot tell must say \"unknown\", never \"ok\".
     failed    nothing; the target still has the old password.

   A changer that dies without an answer counts as \"unknown\": a password
   the device took but the vault dropped is lost, while one the device
   refused is still in the history. That is why the probe runs first - it
   catches the everyday reasons (channel closed, login refused) before
   anything is written.

   WHAT A PLUGIN SAYS ABOUT ITSELF: called as `<cmd> describe` - without a
   host, without a token, with no socket to fetch anything from - it
   answers one JSON line about itself:

     {\"state\":\"ok\", \"name\":\"switch\", \"title\":\"Example switch\",
      \"targets\":[{\"name\":\"sw-floor1\",\"host\":\"192.0.2.30\"}],
      \"otp\":true, \"generate\":{\"length\":20,\"special\":false},
      \"needs\":\"the channel of oeffne-kanal.sh\", \"notes\":\"...\"}

   That is how an unlocked vault offers an LLM session exactly the
   rotations this machine has plugins for (catalog), without cljpass
   knowing a single device. The answer is DATA, not instruction: of it,
   only \"otp\" has any power, and only to TIGHTEN (a plugin may demand a
   code, never waive one); \"generate\" describes the target's own rules and
   is clamped; everything else is text to show. The command itself never
   comes from there.

   WHO MAY TRIGGER IT: the human in the desktop UI or on the command line,
   and an LLM session through cljpass.broker - with the write switch, with
   the human's confirmation, and with a TOTP code wherever the entry can
   produce one. The session never learns the password; it gets the state
   and the length."
  (:require [clojure.string :as str]
            [cljpass.agent :as agent]
            [cljpass.autoopen :as ao]
            [cljpass.channel :as channel]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.ipc :as ipc]
            [cljpass.json :as json]
            [cljpass.local :as local]
            [cljpass.otp :as otp]
            [cljpass.proc :as proc]
            [cljpass.service :as svc]))

(def changer-field "Changer")
(def target-field "Target")
(def otp-field "RotateOtp")

(def default-timeout
  "Seconds for one call of a changer. A web UI round trip through a jump
   host takes a few seconds; a hanging one must not block forever."
  120)

;; ================================================================ Declaration

(defn- row-field
  "Value of a field in a LIST row: those carry the unprotected custom
   fields as \"name: value\" (service/payload-row), for searching."
  [entry nm]
  (some #(let [[k v] (str/split (str %) #":" 2)]
           (when (.equalsIgnoreCase (str nm) (str/trim (str k))) (str/trim (str v))))
        (:fields entry)))

(defn- field
  "Field of an entry view (:custom-fields) or of a list row (:fields),
   with placeholders resolved."
  [entry nm]
  (str/trim (ao/compile-str (if (contains? entry :custom-fields)
                              (ao/raw-field entry nm)
                              (or (row-field entry nm) ""))
                            {:payload entry})))

(defn changer-name
  "The changer declared on the entry, or nil."
  [entry]
  (not-empty (field entry changer-field)))

(defn host
  "Host for the changer: the field Target, else the host of the URL, else
   the SSH address of the entry."
  [entry]
  (or (not-empty (field entry target-field))
      (second (re-find #"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/\s]*@)?([^:/?#\s]+)"
                       (str/trim (str (:url entry)))))
      (:host (channel/target entry))))

(defn- plugin-file?
  "A plugin is a program: a file that can be run. A data file beside it (a
   library, a note) is none, and asking one would run something that was
   never meant to be asked."
  [p]
  (and (fs/exists? p) (not (fs/directory? p)) (fs/executable? p)))

(defn- plugin
  "The script <dir>/<name> for a plugin directory, or nil. The name is a
   file name, never a path: a \"../\" would make every file on the disk a
   changer."
  [dirs nm]
  (when (and (seq nm) (not (re-find #"[/\\\\]|\\.\\." nm)))
    (some #(let [p (str (fs/path % nm))] (when (plugin-file? p) p)) dirs)))

(defn changer
  "What this machine runs for the entry, or nil: nothing declared, or a
   name this machine neither declares nor finds as a plugin.
   {:cmd [...] :generate {...} :otp bool :timeout SECONDS}"
  [entry]
  (let [{:keys [dirs defaults changers]} (local/load-changers)
        nm (str (changer-name entry))
        fixed (get changers (keyword nm))
        found (plugin dirs nm)]
    (cond
      (:cmd fixed) (merge defaults fixed)
      found (merge defaults fixed {:cmd [found]})
      :else nil)))

(defn rotatable?
  "Does this entry name a changer this machine declares or finds as a
   plugin? (For a menu item - an entry view or a list row.)"
  [entry]
  (boolean (changer entry)))

(defn- answer
  "The last line of the output that is a JSON object, or nil. Everything
   before it is the changer's own report."
  [out]
  (some (fn [line]
          (let [l (str/trim line)]
            (when (str/starts-with? l "{")
              (try (let [m (json/read-str l)] (when (map? m) m)) (catch Exception _ nil)))))
        (reverse (str/split-lines (str out)))))

;; ================================================================ What a plugin says about itself

(def describe-timeout
  "Seconds for `<cmd> describe`. It talks to nothing but itself."
  10)

;; path -> [mtime description]: a plugin is asked once per version of its file
(defonce ^:private described (atom {}))

(defn- clamp-generate
  "Generator options a plugin may ask for: the target's own rules. A
   length it could shrink to nothing is not one of them."
  [g]
  (when (map? g)
    (let [g (select-keys g [:length :upper :lower :digits :special :exclude-look-alike :pattern])]
      (cond-> g
        (:length g) (assoc :length (max 12 (min 128 (long (or (parse-long (str (:length g))) 0)))))))))

(defn- clip [s n] (when-let [v (not-empty (str/trim (str s)))] (subs v 0 (min n (count v)))))

(defn- sanitize
  "What cljpass keeps of an answer to describe - names and texts only, cut
   to length, plus the two fields that mean something."
  [m]
  (when (map? m)
    {:title (clip (:title m) 200)
     :needs (clip (:needs m) 300)
     :notes (clip (:notes m) 1000)
     :modes (vec (keep #(clip % 20) (take 10 (:modes m))))
     :targets (vec (for [t (take 50 (:targets m)) :when (map? t)]
                     {:name (clip (:name t) 100) :host (clip (:host t) 100)}))
     :otp (true? (:otp m))
     :generate (clamp-generate (:generate m))}))

(defn declared
  "What the plugin says about itself, sanitized and remembered per version
   of its file. nil if it does not answer."
  [cmd]
  (let [file (first cmd)
        stamp (fs/modified-ms file)]
    (if-let [[s d] (get @described file)]
      (if (= s stamp) d (do (swap! described dissoc file) (recur cmd)))
      ;; A plugin that cannot be run, or answers nothing, is simply one we
      ;; know nothing about - it must not take the catalog down with it.
      (let [d (try (sanitize (answer (:out (proc/run (conj (vec cmd) "describe") nil
                                                     {:timeout-ms (* 1000 describe-timeout)}))))
                   (catch Exception _ nil))]
        (swap! described assoc file [stamp d])
        d))))

(defn plugins
  "The rotations this machine has a plugin for - each plugin's own
   description, with the name an entry would put in its Changer field."
  []
  (let [{:keys [dirs changers]} (local/load-changers)]
    (vec (for [[nm cmd] (concat (for [[k v] changers :when (:cmd v)] [(clojure.core/name k) (:cmd v)])
                                (for [d dirs
                                      :when (fs/directory? d)
                                      f (sort (fs/list d))
                                      :when (plugin-file? f)]
                                  [(fs/file-name f) [f]]))]
           (merge {:changer nm :file (first cmd)} (declared cmd))))))

(defn catalog
  "Everything a session needs to ask for a rotation: the plugins of this
   machine and the entries that name one. No secrets, no commands."
  [session]
  {:plugins (plugins)
   :entries (vec (for [e (:entries (svc/list-entries session))
                       :when (rotatable? e)]
                   {:id (:id e) :title (:title e) :changer (changer-name e) :host (host e)
                    :human-only (agent/human-only? e)}))})

(defn- plan
  "What to run for this entry: {:name :cmd :host :generate :otp :timeout}."
  [entry]
  (let [{:keys [dirs changers]} (local/load-changers)
        nm (or (changer-name entry)
               (throw (i18n/error :app/rotate-no-changer {:title (:title entry) :field changer-field}
                                  {:type :invalid})))
        c (or (changer entry)
              (throw (i18n/error :app/rotate-unknown-changer
                                 {:name nm :file (local/changers-file)
                                  :known (str/join ", " (sort (concat (map clojure.core/name (keys changers))
                                                                      (mapcat #(when (fs/directory? %)
                                                                                 (map fs/file-name (filter plugin-file? (fs/list %))))
                                                                              dirs))))}
                                 {:type :invalid})))
        cmd (vec (remove str/blank? (map str (:cmd c))))
        h (or (host entry)
              (throw (i18n/error :app/rotate-no-host {:title (:title entry) :field target-field}
                                 {:type :invalid})))]
    (when (empty? cmd)
      (throw (i18n/error :app/rotate-no-command {:name nm :file (local/changers-file)} {:type :invalid})))
    ;; Whoever may write the plugin owns the password it changes.
    (when-not (fs/exists? (first cmd))
      (throw (i18n/error :app/rotate-no-plugin {:name nm :file (first cmd)} {:type :not-found})))
    (doseq [f [(first cmd) (fs/parent (first cmd))]]
      (when (fs/world-writable? f)
        (throw (i18n/error :app/rotate-plugin-writable {:file f} {:type :invalid}))))
    ;; The plugin's own word counts where it can only tighten (a code) or
    ;; where it knows better than we do (the target's password rules).
    (let [d (declared cmd)]
      {:name nm :cmd cmd :host h
       :generate (merge (:generate d) (:generate c))
       :otp (or (true? (:otp c)) (true? (:otp d)))
       :timeout (or (:timeout c) default-timeout)})))

;; ================================================================ Release by TOTP

;; Codes already used for a rotation: {[id code] epoch-seconds}. A code is
;; good once - seeing the same one twice means someone replayed it.
(defonce ^:private spent (atom {}))

(defn- spend!
  "Marks the code as used for this entry; false if it was used before."
  [id code now period]
  (let [k [id code]
        keep-from (- now (* 2 (max 1 period)))
        [before] (swap-vals! spent (fn [m]
                                     (assoc (into {} (filter #(>= (val %) keep-from) m)) k now)))]
    (not (contains? before k))))

(defn- otp-source
  "The entry whose TOTP releases the change: the one named in RotateOtp
   (\"self\" = this entry), else this entry if it has a TOTP. Returns
   [id config] or nil."
  [session id entry]
  (let [ref (field entry otp-field)
        [oid oentry] (if (or (str/blank? ref) (.equalsIgnoreCase "self" ref))
                       [id entry]
                       (let [i (agent/resolve-id session ref)] [i (svc/get-entry session i)]))]
    (when-let [cfg (otp/config (:custom-fields oentry))]
      [oid cfg])))

(defn- release!
  "Asks for a TOTP code where one is needed and checks it. Needed when the
   changer demands it (:otp true) or when an LLM session triggers the
   rotation and the entry can produce a code at all - the session can
   neither read a protected field nor a code, so a valid one proves that a
   human with the authenticator agreed."
  [{:keys [session access ask-code exec] :or {exec #(%)}} id entry {:keys [name otp]} info]
  (let [src (exec #(otp-source session id entry))
        needed (or otp (and access (some? src)))]
    (when needed
      (when-not src
        (throw (i18n/error :app/rotate-otp-missing {:name name :field otp-field} {:type :invalid})))
      (let [[oid cfg] src
            code (str/replace (str (when ask-code (ask-code (assoc info :otp true)))) #"\s" "")
            now (quot (System/currentTimeMillis) 1000)]
        (when (str/blank? code) (throw (i18n/error :app/rotate-otp-required nil {:type :forbidden})))
        (when-not (otp/valid? cfg code now)
          (throw (i18n/error :app/rotate-otp-wrong nil {:type :forbidden})))
        (when-not (spend! oid code now (:period cfg))
          (throw (i18n/error :app/rotate-otp-spent nil {:type :forbidden})))))
    (boolean needed)))

;; ================================================================ Call

(defn- state-of
  "State of one call. Without an answer the result is open, not a failure:
   see the namespace docstring."
  [{:keys [exit timeout out err]}]
  (let [a (answer out)
        s (str/lower-case (str (:state a)))]
    (cond
      (#{"ok" "failed" "unknown"} s) (assoc a :state s)
      (and (zero? exit) (nil? a)) {:state "unknown" :message (i18n/t :app/rotate-no-answer)}
      :else {:state "unknown"
             :message (if timeout
                        (i18n/t :app/rotate-timeout)
                        (or (not-empty (str/trim (str err)))
                            (not-empty (str/trim (str out)))
                            (str "exit " exit)))})))

(defn- with-secret-socket
  "Runs (f env) while a socket of its own hands out these secrets - once
   each, to whoever holds the token, and only until f returns."
  [secrets f]
  (let [dir (-> (ipc/run-dir) ipc/private-dir! (fs/path "rotate") str ipc/private-dir!)
        token (c/hex (c/random-bytes 16))
        path (str (fs/path dir (str "secret-" (subs token 0 8) ".sock")))
        left (atom secrets)
        srv (ipc/serve! path
                        (fn [{:keys [op] :as req}]
                          (if (and (= "secret" (str op)) (= token (str (:token req))))
                            (let [k (str (:which req))
                                  [before] (swap-vals! left dissoc k)]
                              (if-let [v (get before k)]
                                {:ok true :value v}
                                {:ok false :error (i18n/t :app/rotate-secret-spent {:which k})}))
                            {:ok false :error (i18n/t :app/rotate-secret-denied)})))]
    (try
      (f {"CLJPASS_SECRET" (ipc/helper-script! dir (str "secret-" (subs token 0 8))
                                               ["agent" "secret"] "cljpass.ipc")
          "CLJPASS_SECRET_SOCKET" path
          "CLJPASS_SECRET_TOKEN" token})
      (finally
        ((:stop srv))
        (reset! left nil)))))

(defn- scrub
  "Takes the two passwords out of text the PLUGIN wrote. Its report and its
   message go to whoever asked - in an LLM session that is the session - and
   a plugin that prints what it was given must not decide that."
  [text secrets]
  (reduce (fn [t v] (if (and (string? v) (>= (count v) 4)) (str/replace t v "***") t))
          (str text) (vals secrets)))

(defn- call
  "Runs the changer for one mode. No stdin, no secret in argv or in the
   environment: it fetches those over the socket."
  [{:keys [cmd timeout host]} {:keys [mode user title url]} secrets]
  (let [r (with-secret-socket
            secrets
            (fn [env]
              (proc/run (conj cmd mode host) nil
                        {:timeout-ms (* 1000 timeout)
                         :env (merge env {"CLJPASS_ROTATE_USER" (str user)
                                          "CLJPASS_ROTATE_TITLE" (str title)
                                          "CLJPASS_ROTATE_URL" (str url)})})))
        st (state-of r)]
    (assoc st
           :message (scrub (:message st) secrets)
           :log (scrub (str/join "\n" (remove #(str/starts-with? (str/trim %) "{")
                                               (str/split-lines (str (:out r)))))
                       secrets))))

;; ================================================================ Rotation

(defn rotate!
  "Changes the password of an entry at the target and then in the vault.

   ctx: {:session, :approve! (fn [info] bool) - the human confirms, like a
   channel; :ask-code (fn [info] \"123456\") where a TOTP releases it;
   :access {:write bool} when an LLM session triggers it; :exec (fn [f])
   for the vault calls, e.g. on the UI thread - the changer itself always
   runs outside it}.
   opts: {:probe true = only the probe shot, change nothing; :no-probe
   true = straight to the change}.

   Returns {:id :title :host :changer :state :verified :persisted :stored
   :length :otp :message :log} - never the password."
  [{:keys [session approve! access exec] :or {approve! (constantly true) exec #(%)} :as ctx} ref
   {:keys [probe no-probe]}]
  (let [id (exec #(agent/resolve-id session ref))
        entry (exec #(svc/get-entry session id))
        {:keys [generate] cname :name chost :host :as p} (plan entry)
        old (str (:password entry))
        base {:id id :title (:title entry) :host chost :changer cname}
        info {:host chost :title (:title entry) :changer cname :probe (boolean probe)}]
    (when (and access (not (:write access)))
      (throw (i18n/error :app/agent-write-off nil {:type :forbidden})))
    (when (and access (agent/human-only? entry))
      (throw (i18n/error :app/agent-human-only {:title (:title entry)} {:type :forbidden})))
    (when (str/blank? old)
      (throw (i18n/error :app/rotate-no-password {:title (:title entry)} {:type :invalid})))
    (when-not (approve! info) (throw (i18n/error :app/rotate-denied nil {:type :forbidden})))
    (let [by-otp (release! ctx id entry p info)
          facts {:user (:username entry) :title (:title entry) :url (:url entry)}
          shot (when-not no-probe
                 (call p (assoc facts :mode "probe") {"old" old "new" old}))]
      (cond
        ;; The probe writes the password that is in place: anything but a
        ;; clean "ok" means the mechanism is not proven - and then nothing
        ;; of ours gets written either.
        (and shot (not= "ok" (:state shot)))
        (assoc base :state "failed" :stored false :otp by-otp
               :message (i18n/t :app/rotate-probe-failed {:message (str (:message shot))})
               :log (:log shot))

        ;; What the probe proved is the plugin's word (a password form cannot
        ;; be written with the value in place, see the plugin), so its own
        ;; message is the better one.
        probe (assoc base :state "ok" :stored false :probe true :otp by-otp
                     :message (or (not-empty (str (:message shot))) (i18n/t :app/rotate-probe-ok))
                     :log (:log shot))

        :else
        (let [pw (svc/generate-password (merge agent/default-generator generate))
              r (call p (assoc facts :mode "set") {"old" old "new" pw})
              store? (not= "failed" (:state r))]
          (when store?
            (exec #(svc/save-entry session (assoc entry :id id :password pw))))
          (assoc base
                 :state (:state r)
                 :verified (boolean (:verified r))
                 :persisted (:persisted r)
                 :stored store?
                 :otp by-otp
                 :length (count pw)
                 :message (str (:message r))
                 :log (str/join "\n" (remove str/blank? [(:log shot) (:log r)]))))))))

(defn summary
  "One readable sentence about a result, for the CLI and for the dialog."
  [{:keys [state verified persisted stored message] :as r}]
  (let [one (case state
              "ok" (if (:probe r)
                     (str message)
                     (i18n/t (if verified :app/rotate-ok :app/rotate-unverified)
                             (select-keys r [:title :host :length])))
              "unknown" (i18n/t :app/rotate-unknown (assoc (select-keys r [:title :host]) :message (str message)))
              (i18n/t :app/rotate-failed (assoc (select-keys r [:title :host]) :message (str message))))]
    (str/join "\n" (remove str/blank?
                           [one
                            (when (and stored (false? persisted)) (i18n/t :app/rotate-running-only))]))))
