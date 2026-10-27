(ns cljpass.kdbx
  "KeePass file format KDBX. Reading: 3.1 and 4.x, writing: 4.x.

   This layer works on the XML document so that nothing gets lost that is
   not explicitly known here (plugin data, future elements). To do so the
   XML is normalized on reading and converted back on writing:
   - protected values (Protected=\"True\") are plain text in the document,
     the attribute is kept,
   - timestamps are ISO-8601 (UTC, seconds) in the document,
   - attachments live outside the XML in :binaries {\"<Ref>\" {:protected :data}}.

   Supported: AES-256, ChaCha20 and Twofish (cipher), AES-KDF, Argon2d and
   Argon2id (key derivation), password and/or key file.
   Argon2, Salsa20, ChaCha20 and Twofish come from Bouncy Castle."
  (:require [clojure.data.xml :as xml]
            [clojure.string :as str]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.nio ByteBuffer ByteOrder]
           [java.util Arrays]
           [java.util.zip GZIPInputStream GZIPOutputStream]
           [javax.crypto Cipher Mac]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]
           [java.security MessageDigest]
           [org.bouncycastle.crypto StreamCipher]
           [org.bouncycastle.crypto.engines ChaCha7539Engine Salsa20Engine TwofishEngine]
           [org.bouncycastle.crypto.generators Argon2BytesGenerator]
           [org.bouncycastle.crypto.modes CBCBlockCipher]
           [org.bouncycastle.crypto.paddings PaddedBufferedBlockCipher PKCS7Padding]
           [org.bouncycastle.crypto.params Argon2Parameters Argon2Parameters$Builder KeyParameter ParametersWithIV]))

(defn- fail!
  "Throws a :kdbx error (or the :type given in data) with the text for key k."
  [k & [params data]]
  (throw (i18n/error k params (merge {:type :kdbx} data))))

;; ================================================================ Bytes

(defn- sha256 ^bytes [& arrs] (c/sha256 (apply c/concat-bytes arrs)))
(defn- sha512 ^bytes [& arrs] (.digest (MessageDigest/getInstance "SHA-512") ^bytes (apply c/concat-bytes arrs)))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes data]
  (let [m (Mac/getInstance "HmacSHA256")]
    (.init m (SecretKeySpec. k "HmacSHA256"))
    (.doFinal m data)))

(defn- le-buf ^ByteBuffer [n] (.order (ByteBuffer/allocate n) ByteOrder/LITTLE_ENDIAN))
(defn- u16 ^bytes [v] (.array (.putShort (le-buf 2) (unchecked-short v))))
(defn- u32 ^bytes [v] (.array (.putInt (le-buf 4) (unchecked-int v))))
(defn- u64 ^bytes [v] (.array (.putLong (le-buf 8) (long v))))

(defn- rd-u32 [^bytes b off] (bit-and (.getInt (.order (ByteBuffer/wrap b) ByteOrder/LITTLE_ENDIAN) (int off)) 0xffffffff))
(defn- rd-i32 [^bytes b off] (.getInt (.order (ByteBuffer/wrap b) ByteOrder/LITTLE_ENDIAN) (int off)))
(defn- rd-u16 [^bytes b off] (bit-and (.getShort (.order (ByteBuffer/wrap b) ByteOrder/LITTLE_ENDIAN) (int off)) 0xffff))
(defn- rd-u64 [^bytes b off] (.getLong (.order (ByteBuffer/wrap b) ByteOrder/LITTLE_ENDIAN) (int off)))

(defn- slice ^bytes [^bytes b from to]
  (when (or (neg? from) (> to (alength b)) (> from to)) (fail! :kp/kdbx-truncated))
  (Arrays/copyOfRange b (int from) (int to)))

(defn- gunzip ^bytes [^bytes b]
  (with-open [in (GZIPInputStream. (ByteArrayInputStream. b))]
    (.readAllBytes in)))

(defn- gzip ^bytes [^bytes b]
  (let [out (ByteArrayOutputStream.)]
    (with-open [z (GZIPOutputStream. out)] (.write z b 0 (alength b)))
    (.toByteArray out)))

(defn- hex->bytes ^bytes [^String h]
  (let [h (str/replace h #"[\s-]" "")]
    (byte-array (map #(unchecked-byte (Integer/parseInt (subs h % (+ % 2)) 16)) (range 0 (count h) 2)))))

(def ^:private cipher-aes (hex->bytes "31c1f2e6bf714350be5805216afc5aff"))
(def ^:private cipher-chacha (hex->bytes "d6038a2b8b6f4cb5a524339a31dbb59a"))
(def ^:private cipher-twofish (hex->bytes "ad68f29f576f4bb9a36ad47af965346c"))
(def ^:private kdf-aes (hex->bytes "c9d9f39a628a4460bf740d08c18a4fea"))
(def ^:private kdf-aes-kdbx4 (hex->bytes "7c02bb8279a74ac0927d114a00648238"))
(def ^:private kdf-argon2d (hex->bytes "ef636ddf8c29444b91f7a9a403e30a0c"))
(def ^:private kdf-argon2id (hex->bytes "9e298b1956db4773b23dfc3ec6f0a1e6"))

(def ^:private sig1 (u32 0x9AA2D903))
(def ^:private sig2 (u32 0xB54BFB67))

;; ================================================================ Stream ciphers (Bouncy Castle)

(defn- keystream
  "Returns a function that XORs bytes with the running key stream (the
   state is kept between calls)."
  [kind ^bytes key ^bytes nonce]
  (let [^StreamCipher engine (case kind :chacha20 (ChaCha7539Engine.) :salsa20 (Salsa20Engine.))]
    (.init engine true (ParametersWithIV. (KeyParameter. key) nonce))
    (fn [^bytes data]
      (let [out (byte-array (alength data))]
        (.processBytes engine data 0 (alength data) out 0)
        out))))

(defn- inner-stream [id ^bytes key]
  (case (long id)
    2 (keystream :salsa20 (sha256 key) (hex->bytes "E830094B97205D2A"))
    3 (let [h (sha512 key)] (keystream :chacha20 (slice h 0 32) (slice h 32 44)))
    (fail! :kp/kdbx-inner-stream-unsupported {:id id})))

;; ================================================================ Keys

(defn- keyfile-hash
  "KeePass key file: XML v1/v2, 32 raw bytes, 64 hex characters or any
   other file (SHA-256)."
  ^bytes [^bytes kf]
  (let [s (try (String. kf "UTF-8") (catch Exception _ ""))]
    (or (when (str/includes? s "<KeyFile")
          (let [doc (xml/parse-str s :support-dtd false)
                ver (some #(when (= :Meta (:tag %))
                             (some (fn [e] (when (= :Version (:tag e)) (first (:content e)))) (:content %)))
                          (:content doc))
                data (some #(when (= :Key (:tag %))
                              (some (fn [e] (when (= :Data (:tag e)) e)) (:content %)))
                           (:content doc))]
            (when data
              (if (str/starts-with? (str ver) "2")
                (hex->bytes (apply str (:content data)))
                (c/unb64 (str/trim (apply str (:content data))))))))
        (when (= 32 (alength kf)) kf)
        (when (and (= 64 (alength kf)) (re-matches #"[0-9a-fA-F]{64}" s)) (hex->bytes s))
        (c/sha256 kf))))

(defn- composite-key ^bytes [{:keys [password ^bytes keyfile]}]
  (when (and (nil? password) (nil? keyfile))
    (fail! :kp/kdbx-credentials-required))
  (apply sha256 (concat (when password [(c/sha256 (c/utf8 password))])
                        (when keyfile [(keyfile-hash keyfile)]))))

(defn- aes-kdf
  "rounds x AES-256-ECB on both 16-byte halves. Trick: CBC over zero
   blocks with IV = half yields exactly this chain, so the JCA computes in
   large chunks instead of block by block."
  ^bytes [^bytes composite ^bytes seed rounds]
  (let [half (fn [^bytes iv]
               (let [ci (Cipher/getInstance "AES/CBC/NoPadding")
                     chunk 65536
                     zeros (byte-array (* 16 chunk))]
                 (.init ci Cipher/ENCRYPT_MODE (SecretKeySpec. seed "AES") (IvParameterSpec. iv))
                 (loop [left (long rounds) last iv]
                   (if (zero? left)
                     last
                     (let [n (min left chunk)
                           out (.update ci zeros 0 (int (* 16 n)))]
                       (recur (- left n) (slice out (- (alength out) 16) (alength out))))))))]
    (sha256 (half (slice composite 0 16)) (half (slice composite 16 32)))))

;; ================================================================ VariantDictionary (KDBX 4)

(defn- read-vdict [^bytes b]
  (when (not= 1 (bit-shift-right (rd-u16 b 0) 8)) (fail! :kp/kdbx-vdict-version))
  (loop [off 2 m (array-map)]
    (let [t (bit-and (aget b off) 0xff)]
      (if (zero? t)
        m
        (let [kl (rd-i32 b (inc off))
              k (String. (slice b (+ off 5) (+ off 5 kl)) "UTF-8")
              vo (+ off 5 kl)
              vl (rd-i32 b vo)
              raw (slice b (+ vo 4) (+ vo 4 vl))
              v (case t
                  0x04 (rd-u32 raw 0)
                  0x05 (rd-u64 raw 0)
                  0x08 (not (zero? (aget raw 0)))
                  0x0C (rd-i32 raw 0)
                  0x0D (rd-u64 raw 0)
                  0x18 (String. raw "UTF-8")
                  0x42 raw
                  (fail! :kp/kdbx-vdict-type {:type t}))]
          (recur (+ vo 4 vl) (assoc m k v)))))))

(defn- write-vdict
  "items: [[key type value] ...]"
  ^bytes [items]
  (apply c/concat-bytes
         (u16 0x0100)
         (concat
          (for [[k t v] items
                :let [kb (c/utf8 k)
                      vb (case t
                           0x04 (u32 v) 0x05 (u64 v) 0x08 (byte-array [(if v 1 0)])
                           0x0C (u32 v) 0x0D (u64 v) 0x18 (c/utf8 v) 0x42 v)]]
            (c/concat-bytes (byte-array [(unchecked-byte t)]) (u32 (alength kb)) kb (u32 (alength ^bytes vb)) vb))
          [(byte-array [0])])))

(defn- derive-key
  "KDF parameters -> transformed key (32 bytes)."
  ^bytes [^bytes composite {:strs [$UUID] :as params}]
  (cond
    (or (Arrays/equals ^bytes $UUID ^bytes kdf-aes) (Arrays/equals ^bytes $UUID ^bytes kdf-aes-kdbx4))
    (aes-kdf composite (params "S") (params "R"))

    (or (Arrays/equals ^bytes $UUID ^bytes kdf-argon2d) (Arrays/equals ^bytes $UUID ^bytes kdf-argon2id))
    (let [p (-> (Argon2Parameters$Builder. (if (Arrays/equals ^bytes $UUID ^bytes kdf-argon2d)
                                              Argon2Parameters/ARGON2_d
                                              Argon2Parameters/ARGON2_id))
                (.withVersion (int (params "V" 0x13)))
                (.withSalt ^bytes (params "S"))
                (.withSecret ^bytes (params "K" (byte-array 0)))
                (.withAdditional ^bytes (params "A" (byte-array 0)))
                (.withMemoryAsKB (int (quot (long (params "M")) 1024)))
                (.withIterations (int (params "I")))
                (.withParallelism (int (params "P")))
                (.build))
          gen (doto (Argon2BytesGenerator.) (.init p))
          out (byte-array 32)]
      (.generateBytes gen composite out)
      out)

    :else (fail! :kp/kdbx-unknown-kdf)))

(defn- kdf-params
  "Options for writing -> VariantDictionary items."
  [{:keys [kdf rounds memory-kib iterations parallelism]
    :or {kdf :argon2id rounds 10000000 memory-kib 65536 iterations 10 parallelism 2}}]
  (case kdf
    :aes [["$UUID" 0x42 kdf-aes] ["R" 0x05 rounds] ["S" 0x42 (c/random-bytes 32)]]
    (:argon2d :argon2id)
    [["$UUID" 0x42 (if (= kdf :argon2d) kdf-argon2d kdf-argon2id)]
     ["S" 0x42 (c/random-bytes 32)] ["P" 0x04 parallelism] ["M" 0x05 (* 1024 memory-kib)]
     ["I" 0x05 iterations] ["V" 0x04 0x13]]
    (fail! :kp/kdbx-unknown-kdf-option {:kdf kdf})))

(defn kdf-opts
  "KDF parameters of a file that was read (:kdf from read-kdbx) -> options
   for write-kdbx. This way saving keeps the strength the user configured
   (e.g. in KeePass). KDBX 3.1 with AES-KDF stays AES-KDF."
  [{:strs [$UUID] :as params}]
  (cond
    (nil? $UUID) {}
    (or (Arrays/equals ^bytes $UUID ^bytes kdf-aes) (Arrays/equals ^bytes $UUID ^bytes kdf-aes-kdbx4))
    {:kdf :aes :rounds (long (params "R"))}
    (or (Arrays/equals ^bytes $UUID ^bytes kdf-argon2d) (Arrays/equals ^bytes $UUID ^bytes kdf-argon2id))
    {:kdf (if (Arrays/equals ^bytes $UUID ^bytes kdf-argon2d) :argon2d :argon2id)
     :memory-kib (quot (long (params "M")) 1024)
     :iterations (long (params "I"))
     :parallelism (long (params "P"))}
    :else {}))

;; ================================================================ Cipher

(defn- crypt ^bytes [mode cipher-id ^bytes key ^bytes iv ^bytes data]
  (cond
    (Arrays/equals ^bytes cipher-id ^bytes cipher-aes)
    (let [ci (Cipher/getInstance "AES/CBC/PKCS5Padding")]
      (.init ci (int (if (= mode :encrypt) Cipher/ENCRYPT_MODE Cipher/DECRYPT_MODE))
             (SecretKeySpec. key "AES") (IvParameterSpec. iv))
      (try (.doFinal ci data)
           (catch Exception _
             (fail! :kp/kdbx-bad-key nil {:type :kdbx-bad-key}))))

    (Arrays/equals ^bytes cipher-id ^bytes cipher-chacha)
    ((keystream :chacha20 key iv) data)

    (Arrays/equals ^bytes cipher-id ^bytes cipher-twofish)
    (let [ci (PaddedBufferedBlockCipher. (CBCBlockCipher/newInstance (TwofishEngine.)) (PKCS7Padding.))
          out (byte-array (.getOutputSize ci (alength data)))]
      (.init ci (= mode :encrypt) (ParametersWithIV. (KeyParameter. key) iv))
      (try
        (let [n (.processBytes ci data 0 (alength data) out 0)
              n (+ n (.doFinal ci out n))]
          (slice out 0 n))
        (catch Exception _
          (fail! :kp/kdbx-bad-key nil {:type :kdbx-bad-key}))))

    :else (fail! :kp/kdbx-unknown-cipher)))

;; ================================================================ XML normalization

(def time-tags
  "Elements holding a timestamp (KDBX 4: Base64 of int64 seconds since 0001-01-01)."
  #{:CreationTime :LastModificationTime :LastAccessTime :ExpiryTime :LocationChanged
    :DeletionTime :DatabaseNameChanged :DatabaseDescriptionChanged :DefaultUserNameChanged
    :MasterKeyChanged :RecycleBinChanged :EntryTemplatesGroupChanged :SettingsChanged})

(def ^:private epoch-offset 62135596800)

(defn now-iso [] (str (.truncatedTo (java.time.Instant/now) java.time.temporal.ChronoUnit/SECONDS)))

(defn- b64-time->iso [^String s]
  (try
    (let [secs (rd-u64 (c/unb64 (str/trim s)) 0)]
      (str (java.time.Instant/ofEpochSecond (- secs epoch-offset))))
    (catch Exception _ s)))

(defn- iso->b64-time [^String s]
  (try
    (c/b64 (u64 (+ epoch-offset (.getEpochSecond (java.time.Instant/parse (str/trim s))))))
    (catch Exception _ s)))

(defn text [e] (apply str (filter string? (:content e))))

(defn element? [x] (and (map? x) (contains? x :tag)))

(defn- strip-ws
  "Removes whitespace between elements; the text content of leaves stays
   unchanged (even if it consists of spaces only)."
  [e]
  (if (element? e)
    (let [content (vec (:content e))]
      (assoc e :content (if (some element? content)
                          (mapv strip-ws (remove #(and (string? %) (str/blank? %)) content))
                          content)))
    e))

(defn- map-times [e f]
  (if (element? e)
    (if (and (time-tags (:tag e)) (not (some element? (:content e))))
      (assoc e :content [(f (text e))])
      (update e :content #(mapv (fn [x] (map-times x f)) %)))
    e))

(defn- protected? [e] (= "True" (get-in e [:attrs :Protected])))

(defn- map-protected
  "Applies f to all protected values, in document order."
  [e f]
  (if (element? e)
    (if (protected? e)
      (assoc e :content [(f (text e))])
      (update e :content #(mapv (fn [x] (map-protected x f)) %)))
    e))

(defn children [e tag] (filter #(and (element? %) (= tag (:tag %))) (:content e)))
(defn child [e tag] (first (children e tag)))
(defn child-text [e tag] (some-> (child e tag) text))

;; ================================================================ Reading

(defn- read-header-fields [^bytes b off size-bytes]
  (loop [off off fields {}]
    (let [id (bit-and (aget b off) 0xff)
          n (if (= 2 size-bytes) (rd-u16 b (inc off)) (rd-u32 b (inc off)))
          dstart (+ off 1 size-bytes)
          data (slice b dstart (+ dstart n))]
      (if (zero? id)
        [fields (+ dstart n)]
        (recur (+ dstart n) (assoc fields id data))))))

(defn- read-hashed-blocks
  "KDBX 3.1: [u32 index][32 SHA-256][i32 length][data] ..."
  ^bytes [^bytes b]
  (let [out (ByteArrayOutputStream.)]
    (loop [off 0 idx 0]
      (let [n (rd-i32 b (+ off 4 32))
            h (slice b (+ off 4) (+ off 36))
            data (slice b (+ off 40) (+ off 40 n))]
        (when (not= idx (rd-u32 b off)) (fail! :kp/kdbx-block-order))
        (if (zero? n)
          (.toByteArray out)
          (do (when-not (c/bytes= h (c/sha256 data)) (fail! :kp/kdbx-block-checksum))
              (.write out data 0 n)
              (recur (+ off 40 n) (inc idx))))))))

(defn- block-key ^bytes [^bytes hmac-key idx] (sha512 (u64 idx) hmac-key))

(defn- read-hmac-blocks
  "KDBX 4: [32 HMAC][i32 length][data] ..."
  ^bytes [^bytes b ^bytes hmac-key]
  (let [out (ByteArrayOutputStream.)]
    (loop [off 0 idx 0]
      (let [mac (slice b off (+ off 32))
            n (rd-i32 b (+ off 32))
            data (slice b (+ off 36) (+ off 36 n))]
        (when-not (c/bytes= mac (hmac-sha256 (block-key hmac-key idx) (c/concat-bytes (u64 idx) (u32 n) data)))
          (fail! :kp/kdbx-block-hmac))
        (if (zero? n)
          (.toByteArray out)
          (do (.write out data 0 n) (recur (+ off 36 n) (inc idx))))))))

(defn- parse-xml [^bytes b]
  (strip-ws (xml/parse (ByteArrayInputStream. b) :support-dtd false :namespace-aware false)))

(defn parse-xml-str
  "XML fragment (e.g. a stored <Entry>) -> element, normalized."
  [^String s]
  (strip-ws (xml/parse-str s :support-dtd false :namespace-aware false)))

(defn xml-str ^String [e] (xml/emit-str e))

(defn read-kdbx
  "bytes + {:password :keyfile} -> {:version [major minor] :xml :binaries
   :public-custom-data :kdf :cipher}. :xml is normalized (see ns doc)."
  [^bytes b creds]
  (when-not (and (> (alength b) 12) (c/bytes= (slice b 0 4) sig1) (c/bytes= (slice b 4 8) sig2))
    (fail! :kp/kdbx-not-kdbx nil {:type :kdbx-format}))
  (let [minor (rd-u16 b 8) major (rd-u16 b 10)
        composite (composite-key creds)]
    (case (long major)
      (3 2)
      (let [[f end] (read-header-fields b 12 2)
            header (slice b 0 end)
            params {"$UUID" kdf-aes "S" (f 5) "R" (rd-u64 (f 6) 0)}
            transformed (derive-key composite params)
            key (sha256 (f 4) transformed)
            plain (crypt :decrypt (f 2) key (f 7) (slice b end (alength b)))
            _ (when-not (c/bytes= (slice plain 0 32) (f 9))
                (fail! :kp/kdbx-bad-key nil {:type :kdbx-bad-key}))
            payload (read-hashed-blocks (slice plain 32 (alength plain)))
            payload (if (= 1 (rd-u32 (f 3) 0)) (gunzip payload) payload)
            stream (inner-stream (rd-u32 (f 10) 0) (f 8))
            doc (-> (parse-xml payload)
                    (map-protected #(c/utf8-str (stream (c/unb64 %)))))
            meta (child doc :Meta)
            hh (child-text meta :HeaderHash)
            _ (when (and hh (not (c/bytes= (c/unb64 hh) (c/sha256 header))))
                (fail! :kp/kdbx-header-hash))
            binaries (into {} (for [bin (children (child meta :Binaries) :Binary)
                                    :let [raw (c/unb64 (str/trim (text bin)))]]
                                [(get-in bin [:attrs :ID])
                                 {:protected false
                                  :data (if (and (= "True" (get-in bin [:attrs :Compressed])) (pos? (alength raw)))
                                          (gunzip raw)
                                          raw)}]))
            doc (update doc :content
                        (fn [cs] (mapv #(if (= :Meta (:tag %))
                                          (update % :content (fn [ms] (vec (remove (fn [m] (#{:HeaderHash :Binaries} (:tag m))) ms))))
                                          %)
                                       cs)))]
        {:version [major minor] :xml doc :binaries binaries
         :cipher (f 2) :kdf params})

      4
      (let [[f end] (read-header-fields b 12 4)
            header (slice b 0 end)
            _ (when-not (c/bytes= (slice b end (+ end 32)) (c/sha256 header))
                (fail! :kp/kdbx-header-sha256))
            params (read-vdict (f 11))
            transformed (derive-key composite params)
            hmac-key (sha512 (f 4) transformed (byte-array [1]))
            _ (when-not (c/bytes= (slice b (+ end 32) (+ end 64))
                                  (hmac-sha256 (block-key hmac-key -1) header))
                (fail! :kp/kdbx-bad-key nil {:type :kdbx-bad-key}))
            enc (read-hmac-blocks (slice b (+ end 64) (alength b)) hmac-key)
            plain (crypt :decrypt (f 2) (sha256 (f 4) transformed) (f 7) enc)
            plain (if (= 1 (rd-u32 (f 3) 0)) (gunzip plain) plain)
            ;; inner header
            [inner xml-start] (loop [off 0 acc {:binaries []}]
                                (let [id (bit-and (aget plain off) 0xff)
                                      n (rd-i32 plain (inc off))
                                      data (slice plain (+ off 5) (+ off 5 n))
                                      nxt (+ off 5 n)]
                                  (case id
                                    0 [acc nxt]
                                    1 (recur nxt (assoc acc :stream-id (rd-u32 data 0)))
                                    2 (recur nxt (assoc acc :stream-key data))
                                    3 (recur nxt (update acc :binaries conj
                                                         {:protected (= 1 (bit-and (aget data 0) 1))
                                                          :data (slice data 1 (alength data))}))
                                    (recur nxt acc))))
            stream (inner-stream (:stream-id inner) (:stream-key inner))
            doc (-> (parse-xml (slice plain xml-start (alength plain)))
                    (map-protected #(c/utf8-str (stream (c/unb64 %))))
                    (map-times b64-time->iso))]
        {:version [major minor] :xml doc
         :binaries (into {} (map-indexed (fn [i x] [(str i) x]) (:binaries inner)))
         :public-custom-data (f 12)
         :cipher (f 2) :kdf params})

      (fail! :kp/kdbx-version-unsupported {:version (str major "." minor)} {:type :kdbx-format}))))

;; ================================================================ Writing

(defn- write-header [fields]
  (apply c/concat-bytes
         (concat (for [[id ^bytes data] fields]
                   (c/concat-bytes (byte-array [(unchecked-byte id)]) (u32 (alength data)) data))
                 [(c/concat-bytes (byte-array [0]) (u32 4) (byte-array [13 10 13 10]))])))

(defn- write-hmac-blocks ^bytes [^bytes data ^bytes hmac-key]
  (let [out (ByteArrayOutputStream.)
        bs (* 1024 1024)
        n (alength data)]
    (loop [off 0 idx 0]
      (let [len (min bs (- n off))
            chunk (slice data off (+ off len))]
        (.write out (hmac-sha256 (block-key hmac-key idx) (c/concat-bytes (u64 idx) (u32 len) chunk)))
        (.write out (u32 len))
        (.write out chunk)
        (when (pos? len) (recur (+ off len) (inc idx)))))
    (.toByteArray out)))

(defn- needs-41?
  "Does the document contain elements that only exist since KDBX 4.1?"
  [e]
  (and (element? e)
       (or (child e :PreviousParentGroup)
           (and (= :Group (:tag e)) (child e :Tags))
           (and (= :Entry (:tag e)) (child e :QualityCheck))
           (and (= :Item (:tag e)) (child e :LastModificationTime))
           (and (= :Icon (:tag e)) (or (child e :Name) (child e :LastModificationTime)))
           (some needs-41? (:content e)))))

(defn write-kdbx
  "{:xml :binaries [{:protected :data}] :public-custom-data} + {:password
   :keyfile :kdf ...} -> bytes (KDBX 4.0, or 4.1 if the document contains
   elements from 4.1). Attachment refs in the XML must be the indexes in
   :binaries."
  ^bytes [{:keys [xml binaries public-custom-data]} opts]
  (let [composite (composite-key opts)
        seed (c/random-bytes 32)
        iv (c/random-bytes 16)
        params (kdf-params opts)
        header (write-header (cond-> [[2 cipher-aes] [3 (u32 1)] [4 seed] [7 iv]
                                      [11 (write-vdict params)]]
                               public-custom-data (conj [12 public-custom-data])))
        minor (if (needs-41? xml) 1 0)
        header (c/concat-bytes sig1 sig2 (u16 minor) (u16 4) header)
        transformed (derive-key composite (into {} (map (fn [[k _ v]] [k v]) params)))
        hmac-key (sha512 seed transformed (byte-array [1]))
        stream-key (c/random-bytes 64)
        stream (inner-stream 3 stream-key)
        doc (-> xml
                (map-times iso->b64-time)
                (map-protected #(c/b64 (stream (c/utf8 %)))))
        inner (apply c/concat-bytes
                     (concat [(byte-array [1]) (u32 4) (u32 3)
                              (byte-array [2]) (u32 64) stream-key]
                             (for [{:keys [protected ^bytes data]} binaries]
                               (c/concat-bytes (byte-array [3]) (u32 (inc (alength data)))
                                               (byte-array [(if protected 1 0)]) data))
                             [(byte-array [0]) (u32 0)]))
        plain (gzip (c/concat-bytes inner (c/utf8 (xml/emit-str doc))))
        enc (crypt :encrypt cipher-aes (sha256 seed transformed) iv plain)]
    (c/concat-bytes header
                    (c/sha256 header)
                    (hmac-sha256 (block-key hmac-key -1) header)
                    (write-hmac-blocks enc hmac-key))))

;; ================================================================ KeePass XML (unencrypted)
;;
;; File > Export > "KeePass XML (2.x)": the same document as in the KDBX
;; file, but in plain text. Differences to the normalized form: protected
;; values carry ProtectInMemory="True" instead of Protected="True", times
;; are ISO-8601, attachments are in Meta/Binaries (Base64, gzip).

(defn- rename-attr [e from to]
  (if (element? e)
    (cond-> (update e :content #(mapv (fn [x] (rename-attr x from to)) %))
      (= "True" (get-in e [:attrs from])) (update :attrs #(-> % (dissoc from) (assoc to "True"))))
    e))

(defn- any-time->iso [^String s]
  (let [s (str/trim (str s))]
    (if (or (str/blank? s) (re-find #"^\d{4}-\d{2}-\d{2}" s)) s (b64-time->iso s))))

(defn read-xml
  "KeePass XML export -> like read-kdbx: {:version :xml :binaries}.
   DTDs are not processed (no external entities)."
  [^bytes b]
  (let [doc (try (parse-xml b) (catch Exception e (fail! :kp/xml-invalid {:detail (ex-message e)} {:type :kdbx-format})))
        _ (when-not (= :KeePassFile (:tag doc))
            (fail! :kp/xml-not-keepass nil {:type :kdbx-format}))
        doc (-> doc (rename-attr :ProtectInMemory :Protected) (map-times any-time->iso))
        meta (child doc :Meta)
        binaries (into {} (for [bin (children (child meta :Binaries) :Binary)
                                :let [^bytes raw (try (c/unb64 (str/trim (text bin))) (catch Exception _ (byte-array 0)))]]
                            [(get-in bin [:attrs :ID])
                             {:protected false
                              :data (if (and (= "True" (get-in bin [:attrs :Compressed])) (pos? (alength raw)))
                                      (gunzip raw)
                                      raw)}]))
        doc (update doc :content
                    (fn [cs] (mapv #(if (= :Meta (:tag %))
                                      (update % :content (fn [ms] (vec (remove (fn [m] (#{:HeaderHash :Binaries} (:tag m))) ms))))
                                      %)
                                   cs)))]
    {:version [2 0] :xml doc :binaries binaries}))

(defn write-xml
  "{:xml :binaries [{:protected :data}]} -> KeePass XML (UTF-8), the way
   KeePass exports it. Caution: all passwords in plain text."
  ^bytes [{:keys [xml binaries]}]
  (let [bins (xml/element* :Binaries {}
                           (map-indexed (fn [i {:keys [^bytes data]}]
                                          (xml/element :Binary {:ID (str i) :Compressed "True"} (c/b64 (gzip data))))
                                        binaries))
        doc (-> (rename-attr xml :Protected :ProtectInMemory)
                (update :content (fn [cs] (mapv #(if (and (= :Meta (:tag %)) (seq binaries))
                                                   (update % :content (fn [ms] (conj (vec ms) bins)))
                                                   %)
                                                cs))))]
    (c/utf8 (xml/emit-str doc))))
