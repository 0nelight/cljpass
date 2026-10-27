(ns cljpass.secmem
  "Memory protection modeled after KeePass (ProtectedString /
   ProtectedBinary):

   - Secrets (private keys, passwords) are kept in RAM only in encrypted
     form, with a random key that is generated at process start and never
     leaves the process. A memory image (crash dump, swap file,
     hibernation) therefore contains no plaintext of the data at rest.
   - Decryption happens only for the duration of an operation, into a
     byte array that is overwritten with zeros afterwards.
   - After inactivity the vault locks: all secrets are dropped from
     memory (see cljpass.service).

   Limits (as with KeePass on .NET): as soon as a password is displayed or
   put on the clipboard, an immutable string is created that only the
   garbage collector removes. The JCA copies keys internally. Hence: as
   briefly as possible, as rarely as possible."
  (:require [cljpass.crypto :as c])
  (:import [java.util Arrays]))

;; New per process - create at run time only, never at build time (native-image).
(def ^:private process-key (delay (c/random-bytes 32)))
(def ^:private aad (c/utf8 "cljpass secmem v1"))

(defn wipe!
  "Overwrites a byte or char array with zeros."
  [a]
  (cond
    (bytes? a) (Arrays/fill ^bytes a (byte 0))
    (instance? (class (char-array 0)) a) (Arrays/fill ^chars a (char 0)))
  nil)

(defrecord Protected [box]
  Object
  (toString [_] "#<Protected ****>"))

(defmethod print-method Protected [_ ^java.io.Writer w] (.write w "#<Protected ****>"))

(defn protect
  "Encrypts `plain` in memory and overwrites the original."
  [^bytes plain]
  (try (->Protected (c/aead-encrypt @process-key plain aad))
       (finally (wipe! plain))))

(defn protect-str [^String s] (protect (c/utf8 s)))

(defn with-plain
  "Calls (f bytes) with the plaintext and overwrites it afterwards."
  [^Protected p f]
  (let [b (c/aead-decrypt @process-key (:box p) aad)]
    (try (f b) (finally (wipe! b)))))

(defn reveal-str
  "Plaintext as a string - use only for display/clipboard."
  ^String [p]
  (with-plain p #(c/utf8-str %)))
