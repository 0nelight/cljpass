(ns cljpass.csv
  "Reading and writing CSV (RFC 4180) and mapping the columns to entries -
   for exchanging data with KeePass, KeePassXC and other password managers.

   Import: the first row names the columns. Recognized are the names from
   KeePass (1.x CSV and generic export), KeePassXC, Bitwarden, Chrome,
   Firefox and German names. Unknown columns become custom fields so that
   nothing gets lost. The delimiters , ; or tab are detected (a German
   Excel saves with ;).

   Export: columns like KeePassXC (its import and many other programs read
   that), plus tags and expiry date. The column names are fixed English
   names (not translated), so other programs recognize them."
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n]))

;; ================================================================ Reading and writing

(defn- delimiter
  "Delimiter from the first line (outside of quotes)."
  [^String s]
  (let [line (loop [i 0 q false]
               (cond (>= i (count s)) s
                     (= \" (.charAt s i)) (recur (inc i) (not q))
                     (and (not q) (#{\newline \return} (.charAt s i))) (subs s 0 i)
                     :else (recur (inc i) q)))
        unq (str/replace line #"\"[^\"]*\"" "")
        n (fn [c] (count (filter #{c} unq)))]
    (->> [\, \; \tab] (sort-by n >) first)))

(defn parse
  "Text -> [[cell ...] ...]. Quoted cells may contain delimiters, line
   breaks and \"\". Empty lines are dropped."
  [^String s]
  (let [s (cond-> s (str/starts-with? s "﻿") (subs 1))
        d (char (delimiter s))
        n (count s)
        rows (java.util.ArrayList.)
        row (java.util.ArrayList.)
        cell (StringBuilder.)
        end-cell! #(do (.add row (str cell)) (.setLength cell 0))
        end-row! #(do (end-cell!)
                      (when-not (and (= 1 (.size row)) (str/blank? (.get row 0))) (.add rows (vec row)))
                      (.clear row))]
    (loop [i 0 q false]
      (if (>= i n)
        (do (when (or (pos? (.length cell)) (pos? (.size row))) (end-row!)) (vec rows))
        (let [c (.charAt s i)]
          (cond
            q (cond (and (= c \") (< (inc i) n) (= \" (.charAt s (inc i)))) (do (.append cell \") (recur (+ i 2) true))
                    (= c \") (recur (inc i) false)
                    :else (do (.append cell c) (recur (inc i) true)))
            (= c \") (recur (inc i) true)
            (= c d) (do (end-cell!) (recur (inc i) false))
            (= c \return) (do (end-row!) (recur (if (and (< (inc i) n) (= \newline (.charAt s (inc i)))) (+ i 2) (inc i)) false))
            (= c \newline) (do (end-row!) (recur (inc i) false))
            :else (do (.append cell c) (recur (inc i) false))))))))

(defn- quote-cell [v]
  (let [v (str v)]
    (str "\"" (str/replace v "\"" "\"\"") "\"")))

(defn write
  "[[cell ...] ...] -> text (RFC 4180, all cells quoted, CRLF)."
  [rows]
  (str/join (for [r rows] (str (str/join "," (map quote-cell r)) "\r\n"))))

;; ================================================================ Columns

(def ^:private columns
  "Field -> column names (lower case) from the common programs. The German
   names are data (headers of German files), not UI text."
  {:title #{"title" "account" "name" "titel" "eintrag"}
   :username #{"username" "user name" "login name" "login" "login_username" "benutzername" "benutzer" "user" "email"}
   :password #{"password" "passwort" "login_password" "kennwort"}
   :url #{"url" "web site" "website" "login_uri" "uri" "adresse"}
   :notes #{"notes" "comments" "note" "notizen" "kommentar" "bemerkung" "extra"}
   :folder #{"group" "folder" "gruppe" "ordner" "grouping" "path"}
   :totp #{"totp" "login_totp" "otp" "otpauth"}
   :tags #{"tags" "tag"}
   :expires #{"expires" "expiry" "läuft ab" "ablaufdatum" "expiry time"}})

(def ^:private ignored
  "Housekeeping columns of other programs that do not become custom fields."
  #{"icon" "last modified" "created" "favorite" "type" "reprompt" "fields" "guid" "httprealm"
    "formactionorigin" "timecreated" "timelastused" "timepasswordchanged" "modified" "creation time"
    "last modification time" "last access time" "uuid" "id"})

(defn- field-of [header]
  (let [h (str/lower-case (str/trim header))]
    (or (some (fn [[k names]] (when (names h) k)) columns)
        (when (ignored h) :ignore))))

(defn- strip-root
  "KeePassXC writes the name of the top-level group in front of every path
   (\"Root/Server\"). If all paths start the same, that start is dropped."
  [folders]
  (let [firsts (set (map #(first (str/split % #"/")) (remove str/blank? folders)))]
    (if (and (= 1 (count firsts)) (every? #(not (str/blank? %)) folders)
             (some #(str/includes? % "/") folders))
      (let [root (first firsts)]
        (mapv #(if (= % root) "" (subs % (inc (count root)))) folders))
      (vec folders))))

(defn- date-of [s]
  (let [s (str/trim (str s))]
    (or (re-find #"^\d{4}-\d{2}-\d{2}" s)
        (when-let [[_ d m y] (re-find #"^(\d{1,2})\.(\d{1,2})\.(\d{4})" s)]
          (format "%s-%02d-%02d" y (parse-long m) (parse-long d)))
        "")))

(defn import-rows
  "CSV text -> [payload ...]. Throws if no column is recognized."
  [^String text]
  (let [[header & rows] (parse text)
        fields (mapv field-of header)
        _ (when-not (some #{:title :username :password :url} fields)
            (throw (i18n/error :kp/csv-no-columns nil {:type :invalid})))
        entries (for [r rows
                      :let [cells (map vector header fields (concat r (repeat "")))
                            known (reduce (fn [m [_ f v]] (if (and f (not= f :ignore) (str/blank? (get m f))) (assoc m f v) m)) {} cells)
                            extra (vec (for [[h f v] cells :when (and (nil? f) (not (str/blank? v)) (not (str/blank? h)))]
                                         {:name (str/trim h) :value v :protected false}))
                            totp (str/trim (str (:totp known)))]
                      :when (some #(not (str/blank? (str (get known %)))) [:title :username :password :url :notes])]
                  {:title (let [t (str/trim (str (:title known)))]
                            (if (str/blank? t) (or (some-> (:url known) str/trim not-empty) (str (:username known))) t))
                   :username (str (:username known))
                   :password (str (:password known))
                   :url (str (:url known))
                   :notes (str (:notes known))
                   :folder (str/join "/" (remove str/blank? (map str/trim (str/split (str/replace (str (:folder known)) "\\" "/") #"/"))))
                   :expires (date-of (:expires known))
                   :tags (str/join ";" (remove str/blank? (map str/trim (str/split (str (:tags known)) #"[;,]"))))
                   :custom-fields (cond-> extra
                                    (not (str/blank? totp)) (conj {:name "otp" :value totp :protected true}))})
        entries (vec entries)
        folders (strip-root (map :folder entries))]
    (mapv #(assoc %1 :folder %2) entries folders)))

(def export-header
  "Column names of the CSV export, as KeePassXC writes and reads them.
   Deliberately not translated: they are a file format, not UI text."
  ["Group" "Title" "Username" "Password" "URL" "Notes" "TOTP" "Tags" "Expires"])

(defn export-rows
  "[{:payload} ...] -> CSV text like KeePassXC. root: name of the top-level
   group (KeePassXC paths start with it). totp-fn returns the otpauth value."
  [payloads root totp-fn]
  (write (cons export-header
               (for [p payloads]
                 [(str/join "/" (remove str/blank? [root (:folder p)]))
                  (:title p) (:username p) (:password p) (:url p) (:notes p)
                  (str (totp-fn p)) (str/replace (str (:tags p)) ";" ",") (str (:expires p))]))))
