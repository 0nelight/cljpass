(ns cljpass.fs
  "The few file functions we need, directly on java.nio.
   Deliberately without a third-party library: fewer dependencies in the
   password manager."
  (:refer-clojure :exclude [list])
  (:import [java.nio.file CopyOption Files LinkOption OpenOption Path Paths StandardCopyOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

(def ^:private no-follow (make-array LinkOption 0))
(def ^:private no-attrs (make-array FileAttribute 0))

(defn path ^Path [root & parts]
  (Paths/get (str root) (into-array String (map str parts))))

(defn exists? [p] (Files/exists (path p) no-follow))
(defn directory? [p] (Files/isDirectory (path p) no-follow))
(defn file-name [p] (str (.getFileName (path p))))
(defn parent [p] (some-> (.getParent (.toAbsolutePath (path p))) str))
(defn absolutize [p] (str (.toAbsolutePath (path p))))
(defn cwd [] (absolutize "."))

(defn modified-ms
  "Last change of the file in milliseconds, 0 if it cannot be read."
  [p]
  (try (.toMillis (Files/getLastModifiedTime (path p) no-follow)) (catch Exception _ 0)))

(defn create-dirs [p] (Files/createDirectories (path p) no-attrs) (str p))

(defn create-temp-dir [] (str (Files/createTempDirectory "cljpass" no-attrs)))

(defn delete-if-exists [p] (Files/deleteIfExists (path p)))

(defn move
  "Moves p to q. replace? overwrites an existing target (atomically where
   the file system supports it), otherwise the call fails."
  ([p q] (move p q false))
  ([p q replace?]
   (let [opts (if replace?
                [StandardCopyOption/REPLACE_EXISTING StandardCopyOption/ATOMIC_MOVE]
                [])]
     (try
       (Files/move (path p) (path q) ^"[Ljava.nio.file.CopyOption;" (into-array CopyOption opts))
       (catch java.nio.file.AtomicMoveNotSupportedException _
         (Files/move (path p) (path q) ^"[Ljava.nio.file.CopyOption;"
                     (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING])))))
   (str q)))

(defn list
  "Paths (strings) of the entries of a directory."
  [dir]
  (with-open [s (Files/list (path dir))]
    (mapv str (iterator-seq (.iterator s)))))

(defn read-bytes ^bytes [p] (Files/readAllBytes (path p)))

(defn write-bytes [p ^bytes data]
  (Files/write (path p) data ^"[Ljava.nio.file.OpenOption;" (make-array OpenOption 0))
  (str p))

(defn executable? [p] (Files/isExecutable (path p)))

(defn world-writable?
  "May anyone on this machine write the file? (POSIX; false where the file
   system has no POSIX permissions, e.g. Windows. Group write is not asked
   about: a plugin lives in the user's own checkout, whose group is the
   user - a rule against that would only get chmod-ed away.)

   Follows a symbolic link, because the question is who may write what will
   actually run - a link of one's own is always lrwxrwxrwx and would
   otherwise answer the question for its target."
  [p]
  (try
    (boolean (some #{"OTHERS_WRITE"}
                   (map str (Files/getPosixFilePermissions (path p) (make-array LinkOption 0)))))
    (catch UnsupportedOperationException _ false)
    (catch java.io.IOException _ false)))

(defn set-owner-only!
  "Only the owner may read/write (POSIX; no effect on Windows)."
  [p]
  (try (Files/setPosixFilePermissions (path p) (PosixFilePermissions/fromString "rw-------"))
       (catch UnsupportedOperationException _ nil))
  (str p))
