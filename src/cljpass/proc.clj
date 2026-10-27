(ns cljpass.proc
  "Starts external programs (PowerShell for DPAPI, AD, clipboard).
   Secrets go via stdin, never via the command line.

   PowerShell: arguments after -Command are appended to the script text,
   $args stays empty. Therefore pass parameters as environment variables
   ($env:CLJPASS_...)."
  (:require [clojure.java.io :as io])
  (:import [java.lang ProcessBuilder ProcessBuilder$Redirect]
           [java.util List]
           [java.util.concurrent TimeUnit]))

(defn- read-async
  "Reads a stream in a daemon thread (no future: its thread pool keeps the
   process alive for another 60 s after the end)."
  [^java.io.InputStream in]
  (let [p (promise)]
    (doto (Thread. ^Runnable (fn [] (deliver p (try (slurp in :encoding "UTF-8") (catch Exception _ "")))))
      (.setDaemon true)
      (.start))
    p))

(defn- builder ^ProcessBuilder [cmd env]
  (let [pb (ProcessBuilder. ^List (mapv str cmd))]
    (doseq [[k v] env] (.put (.environment pb) (str k) (str v)))
    pb))

(defn run
  "Starts cmd (sequence of strings), writes `in` (optional) to stdin,
   waits and returns {:exit :out :err}. env: additional environment
   variables. timeout-ms kills the program when it does not finish in
   time; the result then carries :timeout true and :exit -1 - a program
   that got a secret on stdin must not keep running with it."
  [cmd & [in {:keys [env timeout-ms]}]]
  (let [p (.start (builder cmd env))
        err (read-async (.getErrorStream p))
        out (read-async (.getInputStream p))]
    (with-open [w (io/writer (.getOutputStream p) :encoding "UTF-8")]
      (when in (.write w (str in))))
    (if (and timeout-ms (not (.waitFor p (long timeout-ms) TimeUnit/MILLISECONDS)))
      (do (.destroyForcibly p)
          (.waitFor p)
          {:exit -1 :timeout true :out @out :err @err})
      {:exit (.waitFor p) :out @out :err @err})))

(defn spawn!
  "Starts cmd in the background; output is discarded."
  [cmd & [in {:keys [env]}]]
  (let [p (.start (doto (builder cmd env)
                    (.redirectOutput ProcessBuilder$Redirect/DISCARD)
                    (.redirectError ProcessBuilder$Redirect/DISCARD)))]
    (with-open [w (io/writer (.getOutputStream p) :encoding "UTF-8")]
      (when in (.write w (str in))))
    p))
