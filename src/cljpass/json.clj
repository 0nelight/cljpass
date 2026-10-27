(ns cljpass.json
  "JSON for HTTP responses and AD export (not canonical - for that see
   cljpass.codec)."
  (:require [clojure.data.json :as json]))

(defn- write-value [_ v]
  (cond
    (or (nil? v) (string? v) (number? v) (boolean? v) (map? v) (coll? v)) v
    (keyword? v) (if-let [ns (namespace v)] (str ns "/" (name v)) (name v))
    :else (str v)))

(defn write-str ^String [x]
  (json/write-str x :value-fn write-value :escape-slash false :escape-unicode false))

(defn read-str
  "Keys as keywords."
  [^String s]
  (json/read-str s :key-fn keyword))
