(ns cljpass.crypto
  "Cryptographic primitives. Everything from the JCA that Babashka ships:
   Ed25519 (signatures), X25519 + HKDF-SHA256 + AES-256-GCM (sealed box),
   PBKDF2 (one-time codes for device transfer)."
  (:require [clojure.string]
            [cljpass.i18n :as i18n])
  (:import [java.security KeyPairGenerator KeyFactory Signature SecureRandom MessageDigest]
           [java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec]
           [javax.crypto KeyAgreement Cipher Mac SecretKeyFactory]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec PBEKeySpec]
           [java.util Base64 Arrays]))

;; Create on first use only: otherwise native-image would bake a random
;; generator created at load time, including its state, into the binary.
(def ^:private rng (delay (SecureRandom.)))
(defn- ^SecureRandom secure-random [] @rng)

(defn random-bytes ^bytes [n]
  (let [b (byte-array n)] (.nextBytes (secure-random) b) b))

(defn b64 ^String [^bytes b] (.encodeToString (Base64/getEncoder) b))
(defn unb64 ^bytes [^String s] (.decode (Base64/getDecoder) s))

(defn utf8 ^bytes [^String s] (.getBytes s "UTF-8"))
(defn utf8-str ^String [^bytes b] (String. b "UTF-8"))

(defn sha256 ^bytes [^bytes b] (.digest (MessageDigest/getInstance "SHA-256") b))

(defn hex [^bytes b] (apply str (map #(format "%02x" (bit-and % 0xff)) b)))

(defn bytes= [^bytes a ^bytes b] (MessageDigest/isEqual a b))

(defn concat-bytes ^bytes [& arrs]
  (let [out (java.io.ByteArrayOutputStream.)]
    (doseq [^bytes a arrs] (.write out a 0 (count a)))
    (.toByteArray out)))

;; ---------------------------------------------------------------- Keys
;; On the wire and in storage keys are 32 raw bytes (base64), as in
;; CryptoKit/WebCrypto. The JCA needs X.509/PKCS#8 - for Ed25519/X25519 the
;; wrapping is a fixed prefix.

(defn- unhex ^bytes [^String h]
  (byte-array (map #(unchecked-byte (Integer/parseInt (apply str %) 16)) (partition 2 h))))

(def ^:private der-prefix
  {["Ed25519" :pub] (unhex "302a300506032b6570032100")
   ["Ed25519" :priv] (unhex "302e020100300506032b657004220420")
   ["X25519" :pub] (unhex "302a300506032b656e032100")
   ["X25519" :priv] (unhex "302e020100300506032b656e04220420")})

(defn- strip-der ^bytes [alg kind ^bytes der]
  (let [^bytes pre (der-prefix [alg kind])]
    (when-not (and (= (alength der) (+ (alength pre) 32))
                   (bytes= pre (Arrays/copyOf der (alength pre))))
      (throw (i18n/error :core/unexpected-key-encoding nil {:alg alg})))
    (Arrays/copyOfRange der (alength pre) (alength der))))

(defn- raw-key ^bytes [s]
  (let [b (unb64 s)]
    (when-not (= 32 (alength b)) (throw (i18n/error :core/key-must-be-32-bytes nil {})))
    b))

(defn- gen-keypair [alg]
  (let [kp (.generateKeyPair (KeyPairGenerator/getInstance ^String alg))]
    {:pub (b64 (strip-der alg :pub (.getEncoded (.getPublic kp))))
     :priv (b64 (strip-der alg :priv (.getEncoded (.getPrivate kp))))}))

(defn gen-sign-keypair [] (gen-keypair "Ed25519"))
(defn gen-box-keypair [] (gen-keypair "X25519"))

(defn- pub-key ^java.security.PublicKey [alg s]
  (.generatePublic (KeyFactory/getInstance ^String alg)
                   (X509EncodedKeySpec. (concat-bytes (der-prefix [alg :pub]) (raw-key s)))))

(defn- priv-key ^java.security.PrivateKey [alg s]
  (.generatePrivate (KeyFactory/getInstance ^String alg)
                    (PKCS8EncodedKeySpec. (concat-bytes (der-prefix [alg :priv]) (raw-key s)))))

(defn fingerprint
  "Human-readable fingerprint of a public key (base64)."
  [pub-b64]
  (->> (hex (Arrays/copyOf (sha256 (unb64 pub-b64)) 16))
       (partition 4) (map #(apply str %)) (clojure.string/join "-")))

;; ---------------------------------------------------------------- Signatures

(defn sign ^String [priv-b64 ^bytes msg]
  (let [s (doto (Signature/getInstance "Ed25519") (.initSign (priv-key "Ed25519" priv-b64)) (.update msg))]
    (b64 (.sign s))))

(defn verify? [pub-b64 ^bytes msg sig-b64]
  (try
    (let [s (doto (Signature/getInstance "Ed25519") (.initVerify (pub-key "Ed25519" pub-b64)) (.update msg))]
      (.verify s (unb64 sig-b64)))
    (catch Exception _ false)))

;; ---------------------------------------------------------------- AEAD

(defn aead-encrypt
  "AES-256-GCM. Returns {:n nonce :ct ciphertext} (base64)."
  [^bytes key ^bytes plaintext ^bytes aad]
  (let [nonce (random-bytes 12)
        c (doto (Cipher/getInstance "AES/GCM/NoPadding")
            (.init Cipher/ENCRYPT_MODE (SecretKeySpec. key "AES") (GCMParameterSpec. 128 nonce))
            (.updateAAD aad))]
    {:n (b64 nonce) :ct (b64 (.doFinal c plaintext))}))

(defn aead-decrypt ^bytes [^bytes key {:keys [n ct]} ^bytes aad]
  (let [c (doto (Cipher/getInstance "AES/GCM/NoPadding")
            (.init Cipher/DECRYPT_MODE (SecretKeySpec. key "AES") (GCMParameterSpec. 128 (unb64 n)))
            (.updateAAD aad))]
    (.doFinal c (unb64 ct))))

;; ---------------------------------------------------------------- HKDF

(defn- hmac ^bytes [^bytes key ^bytes data]
  (.doFinal (doto (Mac/getInstance "HmacSHA256") (.init (SecretKeySpec. key "HmacSHA256"))) data))

(defn hkdf
  "HKDF-SHA256 (RFC 5869), output <= 32 bytes."
  ^bytes [^bytes ikm ^bytes salt ^bytes info n]
  {:pre [(<= n 32)]}
  (let [prk (hmac salt ikm)
        t1 (hmac prk (concat-bytes info (byte-array [1])))]
    (Arrays/copyOf t1 (int n))))

;; ---------------------------------------------------------------- Sealed Box

(def ^:private seal-info (utf8 "cljpass seal v1"))

(defn- check-shared
  "Low-order points yield an all-zero secret - reject."
  ^bytes [^bytes shared]
  (when (every? zero? shared) (throw (i18n/error :core/invalid-x25519-key nil {:type :bad-key})))
  shared)

(defn seal
  "Encrypts `plaintext` for the owner of `recipient-pub` (X25519).
   Ephemeral key pair -> ECDH -> HKDF -> AES-GCM. `aad` binds the context
   (e.g. entry ID + version), so that ciphertexts cannot be moved."
  [recipient-pub ^bytes plaintext ^bytes aad]
  (let [eph (gen-box-keypair)
        ka (doto (KeyAgreement/getInstance "X25519")
             (.init (priv-key "X25519" (:priv eph)))
             (.doPhase (pub-key "X25519" recipient-pub) true))
        shared (check-shared (.generateSecret ka))
        k (hkdf shared (concat-bytes (unb64 (:pub eph)) (unb64 recipient-pub)) seal-info 32)]
    (assoc (aead-encrypt k plaintext aad) :epk (:pub eph))))

(defn unseal ^bytes [recipient-pub recipient-priv {:keys [epk] :as box} ^bytes aad]
  (let [ka (doto (KeyAgreement/getInstance "X25519")
             (.init (priv-key "X25519" recipient-priv))
             (.doPhase (pub-key "X25519" epk) true))
        shared (check-shared (.generateSecret ka))
        k (hkdf shared (concat-bytes (unb64 epk) (unb64 recipient-pub)) seal-info 32)]
    (aead-decrypt k box aad)))

;; ---------------------------------------------------------------- Password-based keys

(def pbkdf2-iterations 600000)

(defn pbkdf2 ^bytes [^String secret ^bytes salt iterations]
  (.getEncoded (.generateSecret (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
                                (PBEKeySpec. (.toCharArray secret) salt (int iterations) 256))))

(def ^:private ^String code-alphabet "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

(defn one-time-code
  "Random one-time code, 16 characters from 32 symbols = 80 bits, in groups of 4."
  []
  (->> (repeatedly 16 #(.charAt code-alphabet (.nextInt (secure-random) (count code-alphabet))))
       (partition 4) (map #(apply str %)) (clojure.string/join "-")))

(defn normalize-code [s]
  (-> s clojure.string/upper-case (clojure.string/replace #"[^A-Z0-9]" "")))
