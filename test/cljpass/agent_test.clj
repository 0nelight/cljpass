(ns cljpass.agent-test
  "Access for an LLM session: nothing secret leaves
   cljpass, writing only with the switch, channels give the password only
   to their own target."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cljpass.agent :as agent]
            [cljpass.broker :as broker]
            [cljpass.channel :as channel]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.ipc :as ipc]
            [cljpass.json :as json]
            [cljpass.local :as local]
            [cljpass.service :as svc]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(def ^:private secrets ["Pw-Old-1" "Pw-New-2" "4711" "JBSWY3DPEHPK3PXP" "KEY-MATERIAL"])

(defn- leaks
  "Secrets that occur anywhere in x (as JSON, the way the session sees it)."
  [x]
  (let [s (json/write-str x)] (filter #(str/includes? s %) secrets)))

(defn- msg-of [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:msg (ex-data e)))))

(defn- setup []
  (let [s (svc/new-session {})
        file (str (fs/path (fs/create-temp-dir) "test.kdbx"))]
    (svc/open-file! s {:file file :password "master" :create true :kdf fast})
    (let [id (svc/save-entry s {:title "wlan-ap1" :username "admin" :password "Pw-Old-1" :url "http://192.0.2.10"
                                :folder "Net" :notes "Acme AP"
                                :custom-fields [{:name "PIN" :value "4711" :protected true}
                                                {:name "TimeOtp-Secret-Base32" :value "JBSWY3DPEHPK3PXP" :protected true}
                                                {:name "ssh" :value "admin@192.0.2.10" :protected false}]
                                :attach [{:name "id_netz" :data (c/utf8 "-----BEGIN OPENSSH PRIVATE KEY-----\nKEY-MATERIAL\n-----END OPENSSH PRIVATE KEY-----\n")}]})]
      (svc/save-entry s (assoc (svc/get-entry s id) :id id :password "Pw-New-2"))
      (svc/save-entry s (assoc (svc/get-entry s id) :id id :notes "Acme AP v2"))
      (svc/save-entry s {:title "mgmt-host" :username "ops" :password "x" :tags "human-only" :folder "Net"})
      [s id])))

(deftest reading-without-secrets
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [[s id] (setup)]
      (testing "find: all entries, nothing secret"
        (let [r (agent/find-entries s nil {})]
          (is (= #{"wlan-ap1" "mgmt-host"} (set (map :title r))))
          (is (empty? (leaks r)))))
      (testing "find by IP, user, field"
        (is (= ["wlan-ap1"] (map :title (agent/find-entries s "192.0.2.10" {}))))
        (is (= ["mgmt-host"] (map :title (agent/find-entries s "ops net" {})))))
      (testing "show: has-password, protected fields without value, attachment name only"
        (let [e (agent/show s "wlan-ap1")]
          (is (= id (:id e)))
          (is (:has-password e))
          (is (= [{:name "PIN" :protected true} {:name "TimeOtp-Secret-Base32" :protected true}
                  {:name "ssh" :value "admin@192.0.2.10" :protected false}]
                 (:custom-fields e)))
          (is (= ["id_netz"] (map :name (:attachments e))))
          (is (empty? (leaks e)))))
      (testing "history: same password = same group, no hash, no value"
        (let [h (agent/history s id)]
          (is (= 3 (count h)))
          (is (= ["A" "A" "B"] (map :password-group h)) "current and previous share Pw-New-2, the oldest differs")
          (is (empty? (leaks h)))
          (is (not-any? #(re-find #"[0-9a-f]{8}" (str (:password-group %))) h))))
      (testing "find in older versions"
        (svc/save-entry s (assoc (svc/get-entry s id) :id id :url "http://192.0.2.11"))
        (is (empty? (agent/find-entries s "http://192.0.2.10 acme" {})) "current URL no longer matches")
        (is (= [id] (map :id (agent/find-entries s "http://192.0.2.10 acme" {:history true}))))))))

(deftest writing-only-with-the-switch
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [[s id] (setup)
          off {:read true :write false}
          on {:read true :write true}]
      (testing "switch off: nothing changes"
        (is (= :app/agent-write-off (msg-of #(agent/update-entry! s off id {:notes "x"}))))
        (is (= :app/agent-write-off (msg-of #(agent/create-entry! s off {:title "fresh"}))))
        (is (= :app/agent-write-off (msg-of #(agent/generate-password! s off id {}))))
        (is (= :app/agent-write-off (msg-of #(agent/delete-entry! s off id)))))
      (testing "metadata: changed, tagged claude, secrets untouched"
        (let [e (agent/update-entry! s on "wlan-ap1" {:url "http://192.0.2.11" :add-tags "invalid"
                                                        :fields {:mac "aa:bb"} :remove-fields ["ssh"]})]
          (is (= "http://192.0.2.11" (:url e)))
          (is (= #{"invalid" "claude"} (set (:tags e))))
          (is (= ["PIN" "TimeOtp-Secret-Base32" "mac"] (map :name (:custom-fields e))))
          (is (= "Pw-New-2" (svc/get-field s id "password")))
          (is (= "4711" (:value (first (:custom-fields (svc/get-entry s id))))))))
      (testing "no password, no protected field"
        (is (= :app/agent-password-readonly (msg-of #(agent/update-entry! s on id {:password "x"}))))
        (is (= :app/agent-protected-field (msg-of #(agent/update-entry! s on id {:fields {:PIN "0000"}}))))
        (is (= :app/agent-protected-field (msg-of #(agent/update-entry! s on id {:remove-fields ["PIN"]})))))
      (testing "new password: set, never returned, old one in the history"
        (let [r (agent/generate-password! s on id {:length 30})]
          (is (= 30 (:length r)))
          (is (= #{:id :title :generated :length} (set (keys r))))
          (is (= 30 (count (svc/get-field s id "password"))))
          (is (= ["A" "B"] (take 2 (map :password-group (agent/history s id)))))))
      (testing "new entry with a generated password"
        (let [e (agent/create-entry! s on {:title "fresh" :username "u" :generate true})]
          (is (:has-password e))
          (is (= ["claude"] (:tags e)))))
      (testing "human-only: no new password, no channel"
        (is (= :app/agent-human-only (msg-of #(agent/generate-password! s on "mgmt-host" {}))))
        (is (= :app/agent-human-only (msg-of #(agent/secrets-for-channel s "mgmt-host")))))
      (testing "ambiguous titles need the ID"
        (svc/save-entry s {:title "fresh" :password "y"})
        (is (= :app/agent-ambiguous (msg-of #(agent/show s "fresh"))))))))

(deftest channel-target-and-prompts
  (testing "address from the field ssh or an ssh:// URL, nothing that looks like an option"
    (is (= {:user "admin" :host "192.0.2.10" :port 22}
           (channel/target {:custom-fields [{:name "ssh" :value "admin@192.0.2.10"}]})))
    (is (= {:user "ops" :host "mgmt-host" :port 2222} (channel/target {:url "ssh://mgmt-host:2222" :username "ops"})))
    (is (nil? (channel/target {:url "http://192.0.2.10" :username "admin"})))
    (is (nil? (channel/target {:custom-fields [{:name "ssh" :value "-oProxyCommand=touch /tmp/x"}] :username "a"})))
    (is (nil? (channel/target {:custom-fields [{:name "ssh" :value "-x@host"}]})))
    (is (nil? (channel/target {:custom-fields [{:name "ssh" :value "a@b" :protected true}]})) "protected: not an address"))
  (testing "the password goes only to user@host of the entry, once; everything else to the human"
    (let [asked (atom [])
          token "t1"]
      (with-redefs-fn {#'channel/logins (atom {token {:password "Pw-New-2" :user "admin" :host "192.0.2.10" :title "w"
                                                      :ask-human! (fn [i] (swap! asked conj (:prompt i)) "123456")}})}
        (fn []
          (is (= "123456" (channel/answer token "(ops@192.0.2.20) Verification code: ")))
          (is (= "123456" (channel/answer token "ops@192.0.2.20's password: ")) "jump host: human, not the entry")
          (is (= "Pw-New-2" (channel/answer token "admin@192.0.2.10's password: ")))
          (is (nil? (channel/answer token "admin@192.0.2.10's password: ")) "second try: no")
          (is (nil? (channel/answer "other" "admin@192.0.2.10's password: ")) "unknown token")
          (is (= 2 (count @asked))))))))

(deftest broker-over-the-socket
  (binding [local/*home* (str (fs/create-temp-dir))
            ipc/*run-dir* (str (fs/create-temp-dir))]
    (let [[s _] (setup)
          access (atom {:read true :write false})
          changes (atom 0)
          b (broker/start! {:session s :access access :on-change #(swap! changes inc)})]
      (try
        (testing "read"
          (let [r (broker/request {:op "find" :query "wlan"})]
            (is (:ok r))
            (is (= ["wlan-ap1"] (map :title (:result r))))
            (is (empty? (leaks r)))))
        (testing "write off -> error, nothing changed"
          (let [r (broker/request {:op "update" :ref "wlan-ap1" :changes {:notes "x"}})]
            (is (not (:ok r)))
            (is (str/includes? (str/lower-case (:error r)) "claude") (:error r))
            (is (zero? @changes))))
        (testing "write on"
          (swap! access assoc :write true)
          (let [r (broker/request {:op "update" :ref "wlan-ap1" :changes {:notes "fresh" :fields {:mac "aa"}}})]
            (is (:ok r))
            (is (= "fresh" (get-in r [:result :notes])))
            (is (= 1 @changes))))
        (testing "read off -> nothing at all"
          (swap! access assoc :read false)
          (is (not (:ok (broker/request {:op "show" :ref "wlan-ap1"}))))
          (is (= {:read false} (:result (broker/request {:op "status"})))))
        (testing "the log has requests, no values"
          (let [log (slurp (str (fs/path local/*home* "agent.log")))]
            (is (str/includes? log "update \"wlan-ap1\" ok"))
            (is (not (str/includes? log "fresh")))))
        (finally ((:stop b)))))))
