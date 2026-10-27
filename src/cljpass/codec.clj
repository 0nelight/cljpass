(ns cljpass.codec
  "Canonical JSON (subset of RFC 8785 / JCS) and signed envelopes.
   See doc/FORMAT.md §3.

   Internally: Clojure maps with kebab-case keywords. On the wire:
   snake_case, keys sorted, no whitespace, integers only, nil fields are
   omitted (except :prev)."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]))

(def format-version 1)

(defn- key->wire ^String [k]
  (str/replace (if (keyword? k) (name k) (str k)) "-" "_"))

(defn- wire->key [^String k]
  (keyword (str/replace k "_" "-")))

(defn- escape-char [cp]
  (case (int cp)
    34 "\\\"" 92 "\\\\" 8 "\\b" 12 "\\f" 10 "\\n" 13 "\\r" 9 "\\t"
    (when (< cp 0x20) (format "\\u%04x" (int cp)))))

(defn- write-string [^StringBuilder sb ^String s]
  (.append sb \")
  (dotimes [i (.length s)]
    (let [ch (.charAt s i)]
      (if-let [e (escape-char (int ch))] (.append sb ^String e) (.append sb ch))))
  (.append sb \"))

(declare ->str)

(defn- write-json [^StringBuilder sb x]
  (cond
    (nil? x) (.append sb "null")
    (boolean? x) (.append sb (if x "true" "false"))
    (integer? x) (do (when-not (<= 0 x 9007199254740991)
                       (throw (i18n/error :core/json-integer-out-of-range nil {:value x})))
                     (.append sb (str x)))
    (number? x) (throw (i18n/error :core/json-float-not-allowed nil {:value x}))
    (string? x) (write-string sb x)
    (keyword? x) (write-string sb (name x))
    (map? x) (let [entries (->> x
                                (remove (fn [[k v]] (and (nil? v) (not= k :prev))))
                                (map (fn [[k v]] [(key->wire k) v]))
                                (sort-by first))]
               (.append sb \{)
               (doseq [[i [k v]] (map-indexed vector entries)]
                 (when (pos? i) (.append sb \,))
                 (write-string sb k) (.append sb \:) (write-json sb v))
               (.append sb \}))
    (set? x) (write-json sb (vec (sort-by ->str x)))
    (sequential? x) (do (.append sb \[)
                        (doseq [[i v] (map-indexed vector x)]
                          (when (pos? i) (.append sb \,))
                          (write-json sb v))
                        (.append sb \]))
    :else (throw (i18n/error :core/json-not-serializable {:type (str (type x))} {:value x}))))

(defn ->str
  "Canonical JSON."
  ^String [x]
  (let [sb (StringBuilder.)] (write-json sb x) (str sb)))

(defn ->bytes ^bytes [x] (c/utf8 (->str x)))

(defn parse [^String s] (json/read-str s :key-fn wire->key))

(defn hash-of
  "SHA-256 (hex) over the canonical form."
  [x]
  (c/hex (c/sha256 (->bytes x))))

;; ---------------------------------------------------------------- signed envelopes

(defn- signing-input ^bytes [type body signer]
  (->bytes {:body body :signer signer :type (name type) :v format-version}))

(defn sign-doc
  "Signs `body` (wire form) for a document type. The type is part of the
   signature (domain separation)."
  [type body signer sign-priv]
  {:v format-version
   :type (name type)
   :body body
   :signer signer
   :sig (c/sign sign-priv (signing-input type body signer))})

(defn doc-valid?
  [{:keys [v type body signer sig]} expected-type sign-pub]
  (boolean
   (and (= format-version v)
        (= (name expected-type) type)
        (string? signer) (string? sig) (string? sign-pub)
        (c/verify? sign-pub (signing-input expected-type body signer) sig))))
