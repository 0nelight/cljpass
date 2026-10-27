(ns cljpass.otp
  "Time-based one-time passwords (TOTP, RFC 6238) from the fields of an
   entry - in the formats that KeePass and KeePassXC write:

   - KeePass 2.47+: TimeOtp-Secret(-Hex/-Base32/-Base64), TimeOtp-Length,
     TimeOtp-Period, TimeOtp-Algorithm (HMAC-SHA-1/-256/-512)
   - KeePassXC: field \"otp\" with an otpauth://totp/... URI or
     key=...&step=..&size=..&otpHashMode=.. (KeeOtp)
   - older KeePassXC/TrayTOTP: \"TOTP Seed\" + \"TOTP Settings\" (\"30;6\",
     \"30;S\" for Steam)

   The secret stays in the entry; only the current code goes out."
  (:require [clojure.string :as str]
            [cljpass.crypto :as c])
  (:import [java.net URLDecoder]
           [java.nio ByteBuffer]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(set! *warn-on-reflection* true)

(def ^:private b32-alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defn base32-decode
  "RFC 4648 without mandatory padding; spaces, hyphens and lower case are
   allowed. nil for invalid characters."
  ^bytes [s]
  (let [s (str/upper-case (str/replace (str s) #"[\s=-]" ""))]
    (when (and (seq s) (every? #(str/index-of b32-alphabet %) s))
      (let [out (java.io.ByteArrayOutputStream.)]
        (loop [[ch & more] s buf 0 bits 0]
          (if (nil? ch)
            (.toByteArray out)
            (let [buf (bit-or (bit-shift-left buf 5) (long (str/index-of b32-alphabet ch)))
                  bits (+ bits 5)]
              (if (>= bits 8)
                (do (.write out (int (bit-and (bit-shift-right buf (- bits 8)) 0xff)))
                    (recur more (bit-and buf 0xff) (- bits 8)))
                (recur more buf bits)))))))))

(defn- hex-decode ^bytes [s]
  (let [s (str/replace (str s) #"\s" "")]
    (when (and (seq s) (even? (count s)) (re-matches #"[0-9a-fA-F]+" s))
      (byte-array (map #(unchecked-byte (Integer/parseInt (apply str %) 16)) (partition 2 s))))))

(def ^:private algos {"SHA1" "HmacSHA1" "SHA256" "HmacSHA256" "SHA512" "HmacSHA512"})

(defn- algo [s]
  (get algos (str/replace (str/upper-case (str s)) #"^HMAC|[^A-Z0-9]" "") "HmacSHA1"))

(defn- query-params [q]
  (into {} (for [kv (str/split (str q) #"&")
                 :let [[k v] (str/split kv #"=" 2)]
                 :when (seq k)]
             [(str/lower-case (URLDecoder/decode ^String k "UTF-8")) (URLDecoder/decode (str v) "UTF-8")])))

(defn- clamp-digits [n] (if (and n (<= 4 n 10)) n 6))
(defn- clamp-period [n] (if (and n (<= 1 n 3600)) n 30))

(defn- from-otp-field
  "KeePassXC \"otp\": otpauth URI or key=...&step=...&size=..."
  [v]
  (let [v (str/trim (str v))]
    (if (str/starts-with? (str/lower-case v) "otpauth://")
      (let [[_ kind q] (re-find #"(?i)^otpauth://([a-z]+)/[^?]*\??(.*)$" v)
            p (query-params q)
            steam? (= "steam" (str/lower-case (str (p "encoder"))))]
        (when (= "totp" (str/lower-case (str kind)))
          {:secret (base32-decode (p "secret"))
           :period (clamp-period (parse-long (str (p "period"))))
           :digits (if steam? 5 (clamp-digits (parse-long (str (p "digits")))))
           :algo (algo (p "algorithm"))
           :steam steam?}))
      (let [p (query-params v)]
        (when (p "key")
          {:secret (base32-decode (p "key"))
           :period (clamp-period (parse-long (str (p "step"))))
           :digits (clamp-digits (parse-long (str (p "size"))))
           :algo (algo (p "otphashmode"))
           :steam false})))))

(defn- from-keepass
  "KeePass 2.47+: TimeOtp-*."
  [f]
  (let [secret (or (some-> (f "TimeOtp-Secret") not-empty c/utf8)
                   (some-> (f "TimeOtp-Secret-Hex") hex-decode)
                   (some-> (f "TimeOtp-Secret-Base32") base32-decode)
                   (some-> (f "TimeOtp-Secret-Base64") str/trim not-empty (#(try (c/unb64 %) (catch Exception _ nil)))))]
    (when secret
      {:secret secret
       :period (clamp-period (parse-long (str/trim (str (f "TimeOtp-Period")))))
       :digits (clamp-digits (parse-long (str/trim (str (f "TimeOtp-Length")))))
       :algo (algo (f "TimeOtp-Algorithm"))
       :steam false})))

(defn- from-seed
  "TrayTOTP / older KeePassXC: \"TOTP Seed\" + \"TOTP Settings\" (period;digits|S)."
  [f]
  (when-let [seed (not-empty (str/trim (str (f "TOTP Seed"))))]
    (let [[period size] (str/split (str (f "TOTP Settings")) #";")
          steam? (= "S" (str/upper-case (str/trim (str size))))]
      {:secret (base32-decode seed)
       :period (clamp-period (parse-long (str/trim (str period))))
       :digits (if steam? 5 (clamp-digits (parse-long (str/trim (str size)))))
       :algo "HmacSHA1"
       :steam steam?})))

(def field-names
  "Field names that identify a TOTP entry."
  #{"otp" "TOTP Seed" "TimeOtp-Secret" "TimeOtp-Secret-Hex" "TimeOtp-Secret-Base32" "TimeOtp-Secret-Base64"})

(defn configured?
  "Does the entry (list of custom fields {:name :value}) have a TOTP field?"
  [custom-fields]
  (boolean (some #(field-names (:name %)) custom-fields)))

(defn config
  "Custom fields -> {:secret :period :digits :algo :steam} or nil."
  [custom-fields]
  (let [m (into {} (map (juxt :name :value)) custom-fields)
        f #(get m %)
        cfg (or (from-keepass f)
                (some-> (f "otp") from-otp-field)
                (from-seed f))]
    (when (seq (:secret cfg)) cfg)))

(def ^:private steam-chars "23456789BCDFGHJKMNPQRTVWXY")

(defn code
  "Code for the point in time epoch-seconds."
  [{:keys [^bytes secret period digits algo steam]} epoch-seconds]
  (let [counter (quot (long epoch-seconds) (long period))
        mac (doto (Mac/getInstance ^String algo) (.init (SecretKeySpec. secret ^String algo)))
        h (.doFinal mac (.array (.putLong (ByteBuffer/allocate 8) counter)))
        off (bit-and (aget h (dec (alength h))) 0x0f)
        bin (bit-or (bit-shift-left (bit-and (aget h off) 0x7f) 24)
                    (bit-shift-left (bit-and (aget h (+ off 1)) 0xff) 16)
                    (bit-shift-left (bit-and (aget h (+ off 2)) 0xff) 8)
                    (bit-and (aget h (+ off 3)) 0xff))]
    (if steam
      (loop [i 0 v bin sb (StringBuilder.)]
        (if (= i 5)
          (str sb)
          (recur (inc i) (quot v 26) (.append sb (.charAt ^String steam-chars (int (mod v 26)))))))
      (let [s (str (mod bin (long (Math/pow 10 digits))))]
        (str (apply str (repeat (- digits (count s)) "0")) s)))))

(defn current
  "Current code: {:code :remaining (seconds until it changes) :period}."
  ([cfg] (current cfg (quot (System/currentTimeMillis) 1000)))
  ([{:keys [period] :as cfg} now]
   {:code (code cfg now)
    :remaining (- period (mod now period))
    :period period}))

(defn valid?
  "Does the code match this configuration? One step before and after count
   as well, as every TOTP verifier allows for a clock that drifts."
  ([cfg given] (valid? cfg given (quot (System/currentTimeMillis) 1000)))
  ([{:keys [period] :as cfg} given now]
   (let [c (str/replace (str given) #"\s" "")]
     (boolean (and (seq c)
                   (some #(= c (code cfg (+ now (* (long period) (long %))))) [0 -1 1]))))))

(defn otp-uri
  "otpauth URI (KeePassXC format) for a Base32 secret."
  [label base32 {:keys [period digits algo] :or {period 30 digits 6 algo "SHA1"}}]
  (str "otpauth://totp/" (java.net.URLEncoder/encode (str label) "UTF-8")
       "?secret=" (str/upper-case (str/replace (str base32) #"[\s=]" ""))
       "&period=" period "&digits=" digits "&algorithm=" algo))

(def ^:private b32-chars "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defn base32-encode
  "Bytes -> Base32 (RFC 4648, without padding characters)."
  [^bytes b]
  (let [sb (StringBuilder.)]
    (loop [i 0 buf 0 bits 0]
      (cond
        (>= bits 5) (do (.append sb (.charAt ^String b32-chars (int (bit-and (bit-shift-right buf (- bits 5)) 31))))
                        (recur i buf (- bits 5)))
        (< i (alength b)) (recur (inc i) (bit-or (bit-shift-left (bit-and buf 0xff) 8) (bit-and (aget b i) 0xff)) (+ bits 8))
        (pos? bits) (.append sb (.charAt ^String b32-chars (int (bit-and (bit-shift-left buf (- 5 bits)) 31))))))
    (str sb)))

(defn uri
  "otpauth URI for the TOTP settings of an entry (whatever format they are
   stored in), nil without TOTP."
  [label custom-fields]
  (when-let [{:keys [secret period digits algo steam]} (config custom-fields)]
    (cond-> (otp-uri label (base32-encode secret)
                     {:period period :digits digits :algo (str/replace (str algo) #"^Hmac" "")})
      steam (str "&encoder=steam"))))
