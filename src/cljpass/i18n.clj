(ns cljpass.i18n
  "Translations. English is the base language, German is complete as well.

   Catalogs: resources/i18n/<area>.<lang>.edn, one map per file with
   namespaced keywords whose namespace is the area:

     {:core/entry-not-found \"Entry {id} not found\"}

   Areas: core (vault, storage, crypto, server), app (service, local files,
   admin), kp (KeePass formats: KDBX, XML, CSV, export), desktop (SWT main
   window), dialogs (SWT dialogs), cli (command line), ui (web UI, served
   as JSON).

   Placeholders are written {name} and filled from a params map. Counted
   texts use two keys, <key>.one and <key>.other (see tn).

   The current language is *lang*. Desktop and CLI set it once at start
   (set-lang!), the web UI binds it per request (header X-CljPass-Lang)."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.util Locale]))

(def languages ["en" "de"])
(def default-lang "en")
(def areas ["core" "app" "kp" "desktop" "dialogs" "cli" "ui"])

(defn- load-catalog [lang]
  (reduce (fn [m area]
            (if-let [r (io/resource (str "i18n/" area "." lang ".edn"))]
              (merge m (edn/read-string (slurp r)))
              m))
          {} areas))

;; Read when the namespace is loaded - with native-image at build time, so the
;; catalogs are part of the binary and need no resource lookup at run time.
(def catalogs (into {} (for [l languages] [l (load-catalog l)])))

(def ^:dynamic *lang* default-lang)

(defn normalize
  "\"de\", \"de-AT\", \"de_AT.UTF-8\" -> \"de\". nil for unsupported languages."
  [x]
  (let [s (str/lower-case (str x))
        l (subs s 0 (min 2 (count s)))]
    (when (some #{l} languages) l)))

(defn set-lang!
  "Sets the language for the whole process (desktop, CLI). Unknown -> English."
  [lang]
  (alter-var-root #'*lang* (constantly (or (normalize lang) default-lang))))

(defn os-lang
  "Language of the operating system: CLJPASS_LANG, then the usual locale
   variables, then the JVM default locale. nil if none is supported."
  []
  (some normalize
        [(System/getenv "CLJPASS_LANG")
         (System/getenv "LC_ALL") (System/getenv "LC_MESSAGES") (System/getenv "LANG")
         (.getLanguage (Locale/getDefault))]))

(defn locale
  "java.util.Locale for the current language (date and number formats)."
  ^Locale []
  (Locale/forLanguageTag *lang*))

(defn- fill [^String s params]
  (if (empty? params)
    s
    (str/replace s #"\{([A-Za-z0-9_-]+)\}"
                 (fn [[m p]] (if (contains? params (keyword p)) (str (get params (keyword p))) m)))))

(defn tr
  "Text for key k in language lang; falls back to English, then to the key."
  ([lang k] (tr lang k nil))
  ([lang k params]
   (fill (or (get-in catalogs [lang k]) (get-in catalogs [default-lang k]) (str k)) params)))

(defn t
  "Text for key k in the current language (*lang*)."
  ([k] (tr *lang* k nil))
  ([k params] (tr *lang* k params)))

(defn tn
  "Counted text: uses <k>.one for n = 1, else <k>.other; {n} is filled in."
  ([k n] (tn k n nil))
  ([k n params]
   (t (keyword (namespace k) (str (name k) (if (= 1 n) ".one" ".other")))
      (assoc params :n n))))

(defn error
  "ex-info whose message is the text for k in the current language. ex-data
   carries :msg and :params, so the message can be shown in another
   language later (e.g. after crossing the HTTP boundary)."
  ([k] (error k nil nil))
  ([k params] (error k params nil))
  ([k params data]
   (ex-info (t k params) (merge data {:msg k :params params}))))

(defn message
  "Message of an exception in the current language: translated again when
   it carries a :msg key, otherwise its plain message."
  [^Throwable e]
  (let [{:keys [msg params]} (ex-data e)]
    (if (keyword? msg) (t msg params) (ex-message e))))

(defn ui-catalog
  "All :ui/* texts of a language as {\"ui/key\" text} for the web UI."
  [lang]
  (let [lang (or (normalize lang) default-lang)]
    (into {} (for [[k v] (merge (catalogs default-lang) (catalogs lang))
                   :when (= "ui" (namespace k))]
               [(str (namespace k) "/" (name k)) v]))))
