(ns cljpass.broker
  "Local socket for an LLM session. Runs inside the unlocked
   desktop UI; `cljpass agent ...` is the client.

   - Unix domain socket in a directory only the user can open, one JSON
     line in, one JSON line out (cljpass.ipc).
   - What may be read or changed decides cljpass.agent, the switches
     (access atom {:read :write}) the human in the UI.
   - Log of every request without values: <home>/agent.log."
  (:require [cljpass.agent :as agent]
            [cljpass.channel :as channel]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.ipc :as ipc]
            [cljpass.local :as local]
            [cljpass.rotate :as rotate]
            [cljpass.service :as svc])
  (:import [java.time Instant]))

(set! *warn-on-reflection* true)

(defn socket-path []
  (or (some-> (System/getenv "CLJPASS_AGENT_SOCKET") not-empty)
      (str (fs/path (ipc/run-dir) "agent.sock"))))

(defn- log! [req ok]
  (try
    (spit (str (fs/path (local/home) "agent.log"))
          (str (Instant/now) " " (:op req) (when-let [r (or (:ref req) (:name req) (:query req))] (str " " (pr-str (str r))))
               (if ok " ok" (str " " ok)) "\n")
          :append true)
    (catch Exception _ nil)))

;; ================================================================ Requests

(defn- askpass-script!
  "Helper for SSH_ASKPASS: calls `cljpass agent askpass` with this
   program (native binary, jar or classpath)."
  [dir]
  (ipc/helper-script! dir "askpass" ["agent" "askpass"]))

(defn handle
  "ctx: {:session :access (atom {:read :write}) :exec (fn [f] result, e.g. on
   the UI thread) :on-change (fn []) :approve! :ask-human! :dir :askpass}."
  [{:keys [session access exec on-change] :or {exec #(%) on-change (fn [])} :as ctx} {:keys [op] :as req}]
  (let [acc @access
        need-read #(when-not (:read acc) (throw (i18n/error :app/agent-off nil {:type :forbidden})))
        run (fn [f] (need-read) (exec #(binding [svc/*background* true] (f))))
        write (fn [f] (let [r (run f)] (on-change) r))]
    (case op
      "status" (if (:read acc) (run #(agent/status session acc)) {:read false})
      "find" (run #(agent/find-entries session (:query req) {:history (:history req)}))
      "show" (run #(agent/show session (:ref req)))
      "history" (run #(agent/history session (:ref req)))
      "update" (write #(agent/update-entry! session acc (:ref req) (:changes req)))
      "create" (write #(agent/create-entry! session acc (:changes req)))
      "generate" (write #(agent/generate-password! session acc (:ref req) (:options req)))
      "delete" (write #(agent/delete-entry! session acc (:ref req)))
      "group" (write #(agent/add-group! session acc (:parent req) (:name req)))
      "ssh-open" (do (need-read)
                     (let [r (channel/open! (assoc ctx :exec #(exec (fn [] (binding [svc/*background* true] (%)))))
                                            (:ref req) (:minutes req))]
                       (on-change)
                       r))
      ;; What rotations this machine has a plugin for, and which entries
      ;; name one: the plugins describe themselves, so an unlocked vault
      ;; offers the session exactly what is installed here, and cljpass
      ;; knows no device (cljpass.rotate/catalog).
      "rotation" (run #(rotate/catalog session))
      ;; A password change at the target: the write switch, the human's
      ;; confirmation and - wherever the entry can produce one - a TOTP
      ;; code the session had to be given. The session never sees the
      ;; password, only the state and the length (cljpass.rotate).
      "rotate" (do (need-read)
                   (let [r (rotate/rotate!
                            (assoc ctx
                                   :access acc
                                   :exec (fn [f] (exec #(binding [svc/*background* true] (f))))
                                   :approve! (or (:approve-rotation! ctx) (:approve! ctx))
                                   :ask-code (fn [_] (str (:code req))))
                            (:ref req)
                            {:probe (boolean (:probe req))})]
                     (on-change)
                     r))
      "ssh-close" (let [r {:closed (boolean (channel/close! (str (:name req))))}] (on-change) r)
      "channels" (channel/list-channels)
      "askpass" (if-let [a (channel/answer (str (:token req)) (:prompt req))] {:answer a} {:cancel true})
      (throw (i18n/error :app/agent-unknown-op {:op (str op)} {:type :invalid})))))

(defn- respond
  "One request -> one answer. cljpass.ipc has already parsed the line."
  [ctx req]
  (try
    (let [r (handle ctx req)]
      (when-not (= "askpass" (:op req)) (log! req true))
      {:ok true :result r})
    (catch Throwable t
      (log! req (or (:msg (ex-data t)) (.getName (class t))))
      {:ok false :error (or (.getMessage t) (str t)) :type (some-> (:type (ex-data t)) name)})))

;; ================================================================ Server / client

(defn start!
  "Starts the broker. Returns {:path :stop (fn [])}."
  [ctx]
  (let [dir (ipc/private-dir! (ipc/run-dir))
        path (str (fs/path dir "agent.sock"))
        ctx (assoc ctx :dir (ipc/private-dir! (str (fs/path dir "channels")))
                   :askpass (askpass-script! dir) :socket path)
        srv (ipc/serve! path (fn [req] (respond ctx req)))]
    {:path path
     :stop (fn [] ((:stop srv)) (channel/close-all!))}))

(defn request
  "Client: sends req, returns the answer {:ok :result|:error}."
  [req]
  (let [path (socket-path)]
    (when-not (fs/exists? path) (throw (i18n/error :app/agent-not-running nil {:type :unavailable})))
    (ipc/call path req)))
