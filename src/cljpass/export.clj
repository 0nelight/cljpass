(ns cljpass.export
  "Unencrypted output like in KeePass: print (HTML) and export using an
   XSL stylesheet (KeePass: \"Transform using XSL Stylesheet\", e.g.
   KDBX_DetailsLight_HTML.xsl from the KeePass package). The stylesheet
   gets the KeePass XML (2.x), exactly like in KeePass."
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.net URI]
           [java.nio.file Files LinkOption Path Paths]
           [javax.xml XMLConstants]
           [javax.xml.transform ErrorListener TransformerException URIResolver]
           [javax.xml.transform.stream StreamResult StreamSource]))

;; ================================================================ Print (HTML)

(defn- esc [s]
  (-> (str s) (str/replace "&" "&amp;") (str/replace "<" "&lt;") (str/replace ">" "&gt;") (str/replace "\"" "&quot;")))

(defn- cell [s] (str "<td>" (str/replace (esc s) "\n" "<br>") "</td>"))

(defn html
  "Print view: one table per group (like KeePass: File > Print). Headings
   are in the current language. opts: {:passwords true} also prints the
   passwords."
  [title payloads {:keys [passwords]}]
  (str "<!DOCTYPE html>\n<html lang=\"" (esc i18n/*lang*) "\"><head><meta charset=\"utf-8\"><title>" (esc title) "</title>\n"
       "<style>body{font-family:sans-serif;font-size:10pt;margin:1.5em}h1{font-size:14pt}h2{font-size:12pt;margin-top:1.5em}"
       "table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:3px 5px;text-align:left;vertical-align:top}"
       "th{background:#eee}td.pw{font-family:monospace}@media print{h2{page-break-after:avoid}tr{page-break-inside:avoid}}</style>"
       "</head><body>\n<h1>" (esc title) "</h1>\n"
       (str/join
        (for [[folder ps] (sort-by key (group-by #(str (:folder %)) payloads))]
          (str "<h2>" (esc (if (str/blank? folder) title folder)) "</h2>\n<table><tr><th>" (esc (i18n/t :kp/print-title)) "</th><th>" (esc (i18n/t :kp/print-username)) "</th>"
               (when passwords (str "<th>" (esc (i18n/t :kp/print-password)) "</th>"))
               "<th>" (esc (i18n/t :kp/print-url)) "</th><th>" (esc (i18n/t :kp/print-notes)) "</th></tr>\n"
               (str/join (for [p ps]
                           (str "<tr>" (cell (:title p)) (cell (:username p))
                                (when passwords (str "<td class=\"pw\">" (esc (:password p)) "</td>"))
                                (cell (:url p))
                                (cell (str/join "\n" (remove str/blank? [(:notes p)
                                                                        (when-not (str/blank? (:tags p)) (i18n/t :kp/print-tags {:tags (str/replace (:tags p) ";" ", ")}))
                                                                        (when-not (str/blank? (:expires p)) (i18n/t :kp/print-expires {:date (:expires p)}))])))
                                "</tr>\n")))
               "</table>\n")))
       "</body></html>\n"))

;; ================================================================ XSL stylesheet

(defn- resolver
  "Only files in the stylesheet's folder (and below): KeePass stylesheets
   include KDBX_Common.xsl. Everything else (other paths, http, ...) is
   rejected."
  ^URIResolver [^Path dir]
  (reify URIResolver
    (resolve [_ href base]
      (let [^Path p (try (-> (Paths/get (URI. (str (.resolve (URI. (str base)) (str href)))))
                             .toAbsolutePath .normalize)
                         (catch Exception _ nil))]
        ;; compare real paths: a symlink in the folder must not point outside
        (when-not (and p (Files/isRegularFile p (make-array LinkOption 0))
                       (.startsWith (.toRealPath p (make-array LinkOption 0)) (.toRealPath dir (make-array LinkOption 0))))
          (throw (TransformerException. ^String (i18n/t :kp/xsl-access-denied {:href href}))))
        (doto (StreamSource. (ByteArrayInputStream. (Files/readAllBytes p)))
          (.setSystemId (str (.toUri p))))))))

(def ^:private quiet
  "Errors as exceptions (with a text for the user), not additionally on stderr."
  (reify ErrorListener
    (warning [_ _])
    (error [_ e] (throw e))
    (fatalError [_ e] (throw e))))

(defn- with-cause
  "Like i18n/error, but keeps the original exception as the cause."
  [k params data ^Throwable cause]
  (let [^Throwable e (i18n/error k params data)]
    (ex-info (ex-message e) (ex-data e) cause)))

(defn transform
  "Transforms KeePass XML with an XSL stylesheet (file). Returns the output (bytes).
   Saxon-HE: no Java extension functions; files only from the stylesheet's
   folder; no DTDs/external entities in the KeePass XML."
  ^bytes [^bytes xml xsl-file]
  (try
    (let [^Path file (-> (Paths/get (str xsl-file) (make-array String 0)) .toAbsolutePath .normalize)
          f (net.sf.saxon.TransformerFactoryImpl.)
          _ (.setFeature f XMLConstants/FEATURE_SECURE_PROCESSING true)
          _ (.setErrorListener f quiet)
          _ (.setURIResolver f (resolver (.getParent file)))
          t (.newTransformer f (doto (StreamSource. (ByteArrayInputStream. (Files/readAllBytes file)))
                                 (.setSystemId (str (.toUri file)))))
          _ (.setURIResolver t (resolver (.getParent file)))
          _ (.setErrorListener t quiet)
          out (ByteArrayOutputStream.)]
      (.transform t (StreamSource. (ByteArrayInputStream. xml)) (StreamResult. out))
      (.toByteArray out))
    (catch TransformerException e
      (throw (with-cause :kp/xsl-error {:detail (ex-message e)} {:type :invalid} e)))
    (catch java.nio.file.NoSuchFileException e
      (throw (with-cause :kp/xsl-not-found {:detail (ex-message e)} {:type :not-found} e)))))
