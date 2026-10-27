(ns cljpass.channel
  "SSH channels for an LLM session: cljpass logs in with
   the entry's password or key, the session only gets the socket of an
   OpenSSH ControlMaster and runs `ssh -S <socket> x <command>`. It never
   sees a password, a key or a TOTP code.

   - The human approves every channel (approve!) and answers every prompt
     cljpass does not answer itself (ask-human!): TOTP codes, host keys,
     prompts of jump hosts.
   - The password goes only to a prompt for exactly user@host of the
     entry, never to a jump host.
   - A key comes from an attachment of the entry and lives in a private
     ssh-agent only until the master is up.
   - Channels close after their time, on lock and on exit.

   Linux/macOS only: Win32-OpenSSH has no ControlMaster."
  (:require [clojure.string :as str]
            [cljpass.agent :as agent]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.proc :as proc])
  (:import [java.time Instant]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]))

(defonce ^:private channels (atom {}))  ; name -> {:socket :target :title :expires}
(defonce ^:private logins (atom {}))    ; askpass token -> {:password :user :host :ask-human!}

(defonce ^:private scheduler
  (delay (Executors/newSingleThreadScheduledExecutor
          (reify java.util.concurrent.ThreadFactory
            (newThread [_ r] (doto (Thread. ^Runnable r "cljpass-channels") (.setDaemon true)))))))

;; ================================================================ Target

(def ^:private host-re #"[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:]+\]")
(def ^:private user-re #"[A-Za-z0-9._][A-Za-z0-9._-]*")

(defn- parse-addr
  "\"[user@]host[:port]\" or ssh://... -> {:user :host :port}, nil if invalid
   (also against option injection: nothing may start with '-')."
  [s default-user]
  (when-let [[_ u h p] (re-matches #"(?:ssh://)?(?:([^@/\s]+)@)?([^:/\s]+|\[[^\]]+\])(?::(\d{1,5}))?/?" (str/trim (str s)))]
    (let [u (or u (not-empty default-user))]
      (when (and u (re-matches user-re u) (re-matches host-re h))
        {:user u :host h :port (if p (parse-long p) 22)}))))

(defn target
  "SSH address of an entry: custom field \"ssh\", else an ssh:// URL. The
   user defaults to the entry's user name."
  [entry]
  (or (some #(when (and (= "ssh" (str/lower-case (:name %))) (not (:protected %)))
               (parse-addr (:value %) (:username entry)))
            (:custom-fields entry))
      (when (str/starts-with? (str/lower-case (str (:url entry))) "ssh://")
        (parse-addr (:url entry) (:username entry)))))

;; ================================================================ Prompts (SSH_ASKPASS)

(defn- prompt-kind [prompt {:keys [user host]}]
  (let [p (str/lower-case (str prompt))]
    (cond
      (and (str/includes? p "password") (str/includes? p (str/lower-case (str user "@" host)))) :target-password
      (str/includes? p "passphrase") :passphrase
      :else :human)))

(defn answer
  "Answers a prompt of ssh for the channel with token. Returns the answer
   (to ssh, not to the session) or nil = cancel."
  [token prompt]
  (when-let [{:keys [password ask-human! used] :as l} (@logins token)]
    (case (prompt-kind prompt l)
      ;; once: a second password prompt means the first one was wrong
      :target-password (when (and password (not used)) (swap! logins assoc-in [token :used] true) password)
      :passphrase password
      :human (ask-human! {:prompt (str prompt) :target (str (:user l) "@" (:host l)) :title (:title l)}))))

;; ================================================================ Open / close

(defn list-channels []
  (vec (for [[nm ch] (sort-by key @channels)]
         (assoc (select-keys ch [:socket :target :title :expires]) :name nm))))

(defn close! [nm]
  (when-let [{:keys [socket]} (@channels nm)]
    (proc/run ["ssh" "-S" socket "-O" "exit" "x"])
    (fs/delete-if-exists socket)
    (swap! channels dissoc nm)
    true))

(defn close-all! [] (doseq [nm (keys @channels)] (close! nm)))

(defn- slug [s]
  (let [x (-> (str/lower-case (str s)) (str/replace #"[^a-z0-9]+" "-") (str/replace #"^-+|-+$" ""))]
    (subs x 0 (min 24 (count x)))))

(defn- wait-for [p ms]
  (loop [n (quot ms 50)]
    (cond (fs/exists? p) true
          (zero? n) false
          :else (do (Thread/sleep 50) (recur (dec n))))))

(defn- private-agent!
  "ssh-agent of its own holding only the key. Returns {:socket :proc}."
  [dir token key env]
  (let [sock (str (fs/path dir (str "agent-" (subs token 0 8) ".sock")))
        p (proc/spawn! ["ssh-agent" "-D" "-a" sock])]
    (when-not (wait-for sock 3000)
      (.destroy ^Process p)
      (throw (i18n/error :app/channel-failed {:error "ssh-agent"} {:type :channel})))
    (let [r (proc/run ["ssh-add" "-q" "-"] key {:env (assoc env "SSH_AUTH_SOCK" sock)})]
      (when-not (zero? (:exit r))
        (.destroy ^Process p)
        (throw (i18n/error :app/channel-failed {:error (str/trim (:err r))} {:type :channel}))))
    {:socket sock :proc p}))

(defn open!
  "Opens a channel for an entry. ctx: {:session :dir :askpass (path of the
   helper) :approve! (fn [info] bool) :ask-human! (fn [info] answer|nil)}.
   Returns {:name :socket :target :expires :usage}."
  [{:keys [session dir socket askpass approve! ask-human! exec] :or {exec #(%)}} ref minutes]
  (when (str/starts-with? (str/lower-case (System/getProperty "os.name")) "windows")
    (throw (i18n/error :app/channel-unsupported nil {:type :unsupported})))
  (let [minutes (max 1 (min 480 (or minutes 30)))
        {:keys [entry password key]} (exec #(agent/secrets-for-channel session ref))
        tgt (or (target entry) (throw (i18n/error :app/channel-no-target {:title (:title entry)} {:type :invalid})))
        addr (str (:user tgt) "@" (:host tgt))
        by-agent (some #{agent/agent-tag} (str/split (str (:tags entry)) #";"))]
    (when-not (or password key) (throw (i18n/error :app/channel-no-secret {:title (:title entry)} {:type :invalid})))
    (when-not (approve! {:title (:title entry) :target (str addr ":" (:port tgt)) :minutes minutes
                         :changed-by-agent (boolean by-agent)})
      (throw (i18n/error :app/channel-denied nil {:type :forbidden})))
    (let [nm (str (or (not-empty (slug (:title entry))) "ssh") "-" (subs (c/hex (c/random-bytes 3)) 0 4))
          sock (str (fs/path dir (str nm ".sock")))
          token (c/hex (c/random-bytes 16))
          env {"SSH_ASKPASS" askpass "SSH_ASKPASS_REQUIRE" "force" "CLJPASS_ASKPASS" token
               "CLJPASS_AGENT_SOCKET" socket
               "DISPLAY" (or (System/getenv "DISPLAY") ":0")}
          _ (swap! logins assoc token {:password password :user (:user tgt) :host (:host tgt) :title (:title entry)
                                       :ask-human! ask-human!})
          ag (when key (private-agent! dir token key env))]
      (try
        (let [r (proc/run (concat ["ssh" "-M" "-S" sock "-f" "-N"
                                   "-o" "ControlPersist=yes" "-o" "NumberOfPasswordPrompts=1"
                                   "-o" "ServerAliveInterval=5" "-o" "ServerAliveCountMax=2"
                                   "-p" (str (:port tgt)) "-l" (:user tgt)]
                                  (when ag ["-o" (str "IdentityAgent=" (:socket ag))])
                                  ["--" (:host tgt)])
                          nil {:env env})]
          (when-not (and (zero? (:exit r)) (fs/exists? sock))
            (throw (i18n/error :app/channel-failed {:error (or (not-empty (str/trim (:err r))) (str "exit " (:exit r)))}
                               {:type :channel}))))
        (finally
          (swap! logins dissoc token)
          (when ag (.destroy ^Process (:proc ag)) (fs/delete-if-exists (:socket ag)))))
      (let [expires (.plusSeconds (Instant/now) (* 60 minutes))]
        (swap! channels assoc nm {:socket sock :target addr :title (:title entry) :expires (str expires)})
        (.schedule ^ScheduledExecutorService @scheduler ^Runnable #(close! nm) (long minutes) TimeUnit/MINUTES)
        {:name nm :socket sock :target addr :expires (str expires)
         :usage (str "ssh -S " sock " x '<command>'")}))))
