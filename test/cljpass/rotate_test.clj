(ns cljpass.rotate-test
  "Changing a password at the target: a plugin is a process, it gets the two
   passwords over a socket of its own (once each), the probe shot runs
   first, and a release by TOTP cannot be replayed."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cljpass.broker :as broker]
            [cljpass.fs :as fs]
            [cljpass.json :as json]
            [cljpass.ipc :as ipc]
            [cljpass.local :as local]
            [cljpass.otp :as otp]
            [cljpass.rotate :as rotate]
            [cljpass.service :as svc]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

;; TOTP test vector of RFC 6238 ("12345678901234567890" in Base32)
(def ^:private totp-secret "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

(def ^:private plugin-name "fake-changer")

(def ^:private ok-answers
  {"probe" "{\"state\":\"ok\"}"
   "set" "{\"state\":\"ok\",\"verified\":true,\"persisted\":true}"})

(def ^:private description
  "What the plugin answers to `describe` - its own word about itself."
  (str "{\"state\":\"ok\",\"title\":\"fake switch\",\"needs\":\"nothing\","
       "\"targets\":[{\"name\":\"sw-floor1\",\"host\":\"192.0.2.30\"}],"
       "\"generate\":{\"length\":18}}"))

(defn- plugin!
  "A changer the way cljpass calls one: it describes itself, fetches the
   passwords over $CLJPASS_SECRET, writes down what it saw and answers
   with one JSON line. answers decides the state per mode."
  [dir seen answers]
  (let [f (str (fs/path dir plugin-name))]
    (spit f (str "#!/bin/sh\n"
                 "mode=\"$1\"; host=\"$2\"\n"
                 "[ \"$mode\" = describe ] && { echo '" description "'; exit 0; }\n"
                 "old=$(\"$CLJPASS_SECRET\" old)\n"
                 "new=$(\"$CLJPASS_SECRET\" new)\n"
                 "printf '%s %s %s %s %s\\n' \"$mode\" \"$host\" \"$CLJPASS_ROTATE_USER\" \"$old\" \"$new\" >> " seen "\n"
                 "echo \"looking at $host\"\n"
                 "case \"$mode\" in\n"
                 (str/join (for [[m a] answers] (str "  " m ") echo '" a "' ;;\n")))
                 "esac\n"))
    ;; the plugin's own file: nobody else may write it (cljpass refuses that)
    (fs/set-owner-only! f)
    (.setExecutable (io/file f) true true)
    f))

(defn- setup
  "A vault with one entry naming the plugin, and changers.edn pointing at
   the plugin directory. local/*home* is already bound to home - the mode
   of a session is read from there."
  [home {:keys [answers otp-field otp-secret]}]
  (let [dir (fs/create-temp-dir)
        seen (str (fs/path dir "seen"))]
    (plugin! dir seen (or answers ok-answers))
    (spit (str (fs/path home "changers.edn"))
          (pr-str {:dirs [dir] :defaults {:generate {:length 18} :timeout 30}}))
    (fs/set-owner-only! (str (fs/path home "changers.edn")))
    (let [s (svc/new-session {})]
      (svc/open-file! s {:file (str (fs/path home "test.kdbx")) :password "master" :create true :kdf fast})
      (let [id (svc/save-entry s {:title "sw-floor1" :username "admin" :password "Old-1"
                                  :url "https://192.0.2.30"
                                  :custom-fields (cond-> [{:name "Changer" :value plugin-name :protected false}]
                                                   otp-field (conj {:name "RotateOtp" :value otp-field :protected false})
                                                   otp-secret (conj {:name "TimeOtp-Secret-Base32" :value otp-secret :protected true}))})]
        {:session s :id id :home home :dir dir :seen seen}))))

(defmacro ^:private with-vault
  "A throwaway home (vault, changers.edn, prefs) and a throwaway socket
   directory, for this test alone - without a configuration the session
   works on a file, like local mode."
  [[bindings opts] & body]
  `(when-not (local/windows?)
     (let [home# (fs/create-temp-dir)]
       (binding [local/*home* home#
                 ipc/*run-dir* (str (fs/create-temp-dir))]
         (let [~bindings (setup home# ~opts)]
           ~@body)))))

(defn- lines
  "What the plugin wrote down, one entry per line."
  [seen]
  (if (fs/exists? seen) (vec (remove str/blank? (str/split-lines (slurp seen)))) []))

(defn- calls
  "What the plugin was called with: one [mode host user old new] per run."
  [seen]
  (mapv #(str/split % #" ") (lines seen)))

(defn- msg-of [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(deftest changes-at-the-target-then-in-the-vault
  (with-vault [{:keys [session id seen]} {}]
    (let [r (rotate/rotate! {:session session} id nil)
          [probe change] (calls seen)]
      (testing "the plugin ran twice: the probe shot first, then the change"
        (is (= 2 (count (calls seen))))
        (is (= ["probe" "192.0.2.30" "admin"] (take 3 probe)))
        (is (= ["set" "192.0.2.30" "admin"] (take 3 change))))
      (testing "the probe writes the password in place, the change the new one"
        (is (= ["Old-1" "Old-1"] (drop 3 probe)) "probe: old and new are the same")
        (is (= "Old-1" (nth change 3)))
        (is (= 18 (count (nth change 4))))
        (is (not= (nth change 3) (nth change 4))))
      (testing "and that is the vault's password now, the old one in the history"
        (is (= (nth change 4) (svc/get-field session id "password")))
        (is (= "Old-1" (:password (svc/history-entry session id (dec (count (svc/history session id))))))))
      (testing "the result names the state, never the password"
        (is (= "ok" (:state r)))
        (is (true? (:verified r)))
        (is (true? (:stored r)))
        (is (= 18 (:length r)))
        (is (not (str/includes? (pr-str r) (nth change 4))))))))

(deftest a-failed-probe-writes-nothing
  (with-vault [{:keys [session id seen]} {:answers {"probe" "{\"state\":\"failed\",\"message\":\"channel closed\"}"
                                                    "set" "{\"state\":\"ok\"}"}}]
    (let [r (rotate/rotate! {:session session} id nil)]
      (is (= "failed" (:state r)))
      (is (false? (:stored r)))
      (is (str/includes? (:message r) "channel closed"))
      (is (= ["probe"] (map first (calls seen))) "no change was even attempted")
      (is (= "Old-1" (svc/get-field session id "password")) "the vault keeps the old password"))))

(deftest a-changer-without-an-answer-counts-as-unknown
  (with-vault [{:keys [session id]} {:answers {"probe" "{\"state\":\"ok\"}" "set" "I cannot tell"}}]
    (let [r (rotate/rotate! {:session session} id nil)]
      (is (= "unknown" (:state r)))
      (is (true? (:stored r)) "stored: the device may have taken it, and the old one is in the history")
      (is (= "Old-1" (:password (svc/history-entry session id (dec (count (svc/history session id))))))))))

(deftest each-secret-is-handed-over-once
  (with-vault [{:keys [session id dir seen]} {}]
    ;; a changer that asks twice is refused the second time
    (let [f (str (fs/path dir plugin-name))]
      (spit f (str "#!/bin/sh\n"
                   "[ \"$1\" = describe ] && { echo '" description "'; exit 0; }\n"
                   "\"$CLJPASS_SECRET\" old >> " seen "\n"
                   "\"$CLJPASS_SECRET\" old >> " seen " 2>/dev/null || echo denied >> " seen "\n"
                   "echo '{\"state\":\"ok\"}'\n"))
      (.setExecutable (io/file f) true true))
    (rotate/rotate! {:session session} id {:probe true})
    (is (= ["Old-1" "denied"] (lines seen)) "the second request for the same secret is refused")))

(deftest the-session-needs-the-write-switch-and-a-code
  (with-vault [{:keys [session id]} {:otp-secret totp-secret}]
    (testing "no rotation for a session that may only read"
      (is (= :app/agent-write-off
             (msg-of #(rotate/rotate! {:session session :access {:read true :write false}} id nil)))))
    (testing "with the switch, but the entry has a TOTP: no code, no change"
      (is (= :app/rotate-otp-required
             (msg-of #(rotate/rotate! {:session session :access {:write true} :ask-code (fn [_] "")} id nil))))
      (is (= :app/rotate-otp-wrong
             (msg-of #(rotate/rotate! {:session session :access {:write true} :ask-code (fn [_] "000000")} id nil)))))
    (testing "a valid code releases it - and the same one never again"
      ;; the same code string both times: a code recomputed after the period
      ;; rolls over would be a different one, and that is not a replay
      (let [code (:code (otp/current (otp/config [{:name "TimeOtp-Secret-Base32" :value totp-secret}])))
            ctx {:session session :access {:write true} :ask-code (fn [_] code)}]
        (is (= "ok" (:state (rotate/rotate! ctx id nil))))
        (is (= :app/rotate-otp-spent (msg-of #(rotate/rotate! ctx id nil))))))))

(deftest a-plugin-anyone-may-write-is-refused
  (with-vault [{:keys [session id dir]} {}]
    (.setWritable (io/file (str (fs/path dir plugin-name))) true false)
    (is (= :app/rotate-plugin-writable (msg-of #(rotate/rotate! {:session session} id nil))))))

(deftest only-a-file-in-a-declared-directory-is-a-plugin
  (with-vault [{:keys [session id]} {}]
    (doseq [bad ["../../bin/sh" "/bin/sh" "sh"]]
      (svc/save-entry session (assoc (svc/get-entry session id) :id id
                                     :custom-fields [{:name "Changer" :value bad :protected false}]))
      (is (not (rotate/rotatable? (svc/get-entry session id))) bad)
      (is (= :app/rotate-unknown-changer (msg-of #(rotate/rotate! {:session session} id nil))) bad))))

(deftest a-plugin-describes-itself-without-reaching-anything
  (with-vault [{:keys [session id dir seen]} {}]
    ;; a plugin that tries to fetch a password while describing itself
    (let [f (str (fs/path dir plugin-name))]
      (spit f (str "#!/bin/sh\n"
                   "if [ \"$1\" = describe ]; then\n"
                   "  echo \"socket=[$CLJPASS_SECRET_SOCKET] token=[$CLJPASS_SECRET_TOKEN] host=[$2]\" >> " seen "\n"
                   "  \"$CLJPASS_SECRET\" old >> " seen " 2>/dev/null || echo nothing >> " seen "\n"
                   "  echo '" description "'\n"
                   "fi\n"))
      (fs/set-owner-only! f)
      (.setExecutable (io/file f) true true))
    (let [{:keys [plugins entries]} (rotate/catalog session)]
      (testing "the catalog is the plugin's own word, with the name an entry uses"
        (is (= [plugin-name] (map :changer plugins)))
        (is (= "fake switch" (:title (first plugins))))
        (is (= [{:name "sw-floor1" :host "192.0.2.30"}] (:targets (first plugins)))))
      (testing "and the entries that name one, without a secret anywhere"
        (is (= [{:id id :title "sw-floor1" :changer plugin-name
                 :host "192.0.2.30" :human-only false}]
               entries))))
    (testing "while describing itself a plugin has no socket, no token and no host"
      (is (= ["socket=[] token=[] host=[]" "nothing"] (lines seen))))))

(deftest a-plugin-may-demand-a-code-but-never-waive-one
  (with-vault [{:keys [session id dir]} {}]
    (let [f (str (fs/path dir plugin-name))]
      (spit f (str "#!/bin/sh\n"
                   "[ \"$1\" = describe ] && { echo '{\"state\":\"ok\",\"otp\":true,"
                   "\"generate\":{\"length\":2}}'; exit 0; }\n"
                   "echo '{\"state\":\"ok\"}'\n"))
      (fs/set-owner-only! f)
      (.setExecutable (io/file f) true true))
    (testing "the plugin demands a code, and the entry cannot produce one"
      (is (= :app/rotate-otp-missing (msg-of #(rotate/rotate! {:session session} id nil)))))
    (testing "a length of 2 is the plugin's wish, not cljpass's rule"
      (let [e (svc/get-entry session id)]
        (svc/save-entry session (assoc e :id id :custom-fields
                                       (conj (vec (:custom-fields e))
                                             {:name "TimeOtp-Secret-Base32" :value totp-secret :protected true})))
        (let [code #(:code (otp/current (otp/config [{:name "TimeOtp-Secret-Base32" :value totp-secret}])))
              r (rotate/rotate! {:session session :ask-code (fn [_] (code))} id nil)]
          (is (= "ok" (:state r)))
          ;; changers.edn asks for 18, and the machine has the last word
          (is (= 18 (:length r))))))))

(deftest a-session-can-ask-for-a-rotation-over-the-broker
  (with-vault [{:keys [session id]} {:otp-secret totp-secret}]
    (let [access (atom {:read true :write false})
          gefragt (atom [])
          b (broker/start! {:session session :access access
                            :approve-rotation! (fn [info] (swap! gefragt conj info) true)})]
      (try
        (testing "the catalog: what this machine has a plugin for"
          (let [r (:result (broker/request {:op "rotation"}))]
            (is (= [plugin-name] (map :changer (:plugins r))))
            (is (= ["sw-floor1"] (map :title (:entries r))))))
        (testing "reading is not changing"
          (let [r (broker/request {:op "rotate" :ref "sw-floor1"})]
            (is (false? (:ok r)))
            (is (= "forbidden" (:type r)))))
        (swap! access assoc :write true)
        (testing "with the switch, but no code: no change"
          (is (false? (:ok (broker/request {:op "rotate" :ref "sw-floor1"})))))
        (testing "with the switch and a code the human gave it"
          (let [code (:code (otp/current (otp/config [{:name "TimeOtp-Secret-Base32" :value totp-secret}])))
                r (broker/request {:op "rotate" :ref "sw-floor1" :code code})]
            (is (true? (:ok r)))
            (is (= "ok" (:state (:result r))))
            (is (= 18 (:length (:result r))))
            (testing "the session learns the state, never the password"
              (is (not (str/includes? (json/write-str (:result r))
                                      (svc/get-field session id "password")))))
            (testing "and a human was asked first - before the code, every time"
              (is (= 2 (count @gefragt)) "the attempt without a code was asked about too")
              (is (= {:host "192.0.2.30" :title "sw-floor1"
                      :changer plugin-name :probe false}
                     (last @gefragt))))))
        (finally ((:stop b)))))))
