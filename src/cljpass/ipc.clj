(ns cljpass.ipc
  "Local unix-domain sockets: one JSON line in, one JSON line out, in a
   directory only the user can open ($XDG_RUNTIME_DIR/cljpass, else
   <home>/run).

   Two users, the same plumbing: cljpass.broker (access for an LLM
   session) and cljpass.rotate (handing a password to a changer cljpass
   started). That is what makes a secret reachable for a program we
   started without ever putting it in argv, in the environment or in a
   file - the program asks for it over the socket, with a one-time token,
   exactly like ssh does through SSH_ASKPASS."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.json :as json]
            [cljpass.local :as local])
  (:import [java.lang ProcessHandle]
           [java.net StandardProtocolFamily UnixDomainSocketAddress]
           [java.nio.channels Channels ServerSocketChannel SocketChannel]
           [java.nio.file Files LinkOption]
           [java.nio.file.attribute PosixFilePermissions]))

(set! *warn-on-reflection* true)

(def ^:dynamic *run-dir* "Overrides the socket directory (tests)." nil)

(defn run-dir []
  (or *run-dir*
      (some-> (System/getenv "CLJPASS_RUN_DIR") not-empty)
      (some-> (System/getenv "XDG_RUNTIME_DIR") not-empty (fs/path "cljpass") str)
      (str (fs/path (local/home) "run"))))

(defn private-dir!
  "Creates the directory and takes it away from everyone else."
  [d]
  (fs/create-dirs d)
  (try (Files/setPosixFilePermissions (fs/path d) (PosixFilePermissions/fromString "rwx------"))
       (catch UnsupportedOperationException _ nil))
  d)

(defn helper-script!
  "A small script that calls THIS program (native binary, jar or
   classpath) with args plus its own first argument - the way a child
   process reaches cljpass without knowing how cljpass was started.

   dev-ns short-circuits the JVM case to that namespace's -main: a helper
   should not drag the whole CLI (and with it the UI and its native
   libraries) into a throwaway process. In the native binary there is only
   one entry point, so there args apply.
   Returns the path."
  [dir nm args & [dev-ns]]
  (let [cmd (.orElse (.command (.info (ProcessHandle/current))) "java")
        argv (cond
               (System/getProperty "org.graalvm.nativeimage.imagecode") (cons cmd args)
               dev-ns [cmd "-cp" (System/getProperty "java.class.path") "clojure.main" "-m" dev-ns]
               :else (concat [cmd "-cp" (System/getProperty "java.class.path") "clojure.main" "-m" "cljpass.main"] args))
        q #(str "'" (str/replace % "'" "'\\''") "'")
        f (str (fs/path dir nm))]
    (spit f (str "#!/bin/sh\nexec " (str/join " " (map q argv)) " \"$1\"\n"))
    (try (Files/setPosixFilePermissions (fs/path f) (PosixFilePermissions/fromString "rwx------"))
         (catch UnsupportedOperationException _ nil))
    f))

;; ================================================================ Server / client

(defn- serve-one [handler ^SocketChannel ch]
  (with-open [ch ch
              r (io/reader (Channels/newInputStream ch) :encoding "UTF-8")
              w (io/writer (Channels/newOutputStream ch) :encoding "UTF-8")]
    (when-let [line (.readLine ^java.io.BufferedReader r)]
      (.write w (str (json/write-str (handler (try (json/read-str line) (catch Exception _ nil)))) "\n"))
      (.flush w))))

(defn serve!
  "Listens on path and answers every connection with (handler request).
   Returns {:path :stop (fn [])}."
  [path handler]
  (fs/delete-if-exists path)
  (let [server (doto (ServerSocketChannel/open StandardProtocolFamily/UNIX)
                 (.bind (UnixDomainSocketAddress/of ^String path)))
        _ (fs/set-owner-only! path)
        serve (fn [ch] (let [^Runnable r (bound-fn [] (try (serve-one handler ch) (catch Exception _ nil)))]
                         (doto (Thread. r) (.setDaemon true) (.start))))
        ^Runnable loop-fn (bound-fn []
                            (while (.isOpen server)
                              (try (serve (.accept server))
                                   (catch Exception _ nil))))
        t (Thread. loop-fn "cljpass-ipc")]
    (.setDaemon t true)
    (.start t)
    {:path path
     :stop (fn []
             (.close server)
             (when (Files/exists (fs/path path) (make-array LinkOption 0)) (fs/delete-if-exists path)))}))

(defn call
  "Client: sends req to the socket at path, returns the answer."
  [path req]
  (with-open [ch (SocketChannel/open (UnixDomainSocketAddress/of ^String (str path)))
              w (io/writer (Channels/newOutputStream ch) :encoding "UTF-8")
              r (io/reader (Channels/newInputStream ch) :encoding "UTF-8")]
    (.write w (str (json/write-str req) "\n"))
    (.flush w)
    (json/read-str (.readLine ^java.io.BufferedReader r))))

;; ================================================================ Secret for a changer

(defn secret
  "Fetches \"old\" or \"new\" from the socket of the running rotation
   (cljpass.rotate): {:value \"...\"} or {:error \"...\"}. This is the whole
   job of the helper a changer calls - and the reason a changer needs no
   secret in argv, in its environment or on stdin."
  [which]
  (if-let [sock (not-empty (str (System/getenv "CLJPASS_SECRET_SOCKET")))]
    (try
      (call sock {:op "secret" :token (System/getenv "CLJPASS_SECRET_TOKEN") :which (str which)})
      (catch Exception e {:error (or (.getMessage e) (str e))}))
    {:error (i18n/t :app/rotate-secret-no-socket)}))

(defn -main
  "The helper itself (JVM runs): one secret of the running rotation to
   stdout. Deliberately without the rest of the program."
  [& [which]]
  (let [{:keys [value error]} (secret which)]
    (if value
      (do (println value) (flush))
      (do (binding [*out* *err*] (println error)) (System/exit 1)))))
