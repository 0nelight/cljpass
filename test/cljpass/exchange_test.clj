(ns cljpass.exchange-test
  "KeePass parity stage 2.4: CSV, KeePass XML, print (HTML), XSL stylesheets."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cljpass.crypto :as c]
            [cljpass.csv :as csv]
            [cljpass.export :as ex]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.kdbx :as k]
            [cljpass.local :as local]
            [cljpass.service :as svc]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- tmp-file [n] (str (fs/path (fs/create-temp-dir) n)))

(defn- by-title [s t] (first (filter #(= t (:title %)) (:entries (svc/list-entries s)))))

(deftest csv-format
  (testing "RFC 4180: quotes, delimiters and line breaks in cells"
    (is (= [["a" "b,c" "d\"e"] ["x\ny" "" "z"]] (csv/parse "a,\"b,c\",\"d\"\"e\"\r\n\"x\ny\",,z\r\n")))
    (is (= [["a" "b"] ["1" "2"]] (csv/parse "﻿a;b\n1;2\n\n")) "Excel (German): ; and BOM")
    (is (= [["a" "b"]] (csv/parse "a\tb")))
    (let [rows [["Ti\"tle" "a,b" "Line1\nLine2" ""]]]
      (is (= rows (csv/parse (csv/write rows))))))

  (testing "KeePassXC: top-level group is dropped, TOTP becomes field otp"
    (let [[a b] (csv/import-rows (str "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n"
                                      "\"Root/Server\",\"Web\",\"admin\",\"pw1\",\"https://web\",\"n\",\"otpauth://totp/x?secret=ABC\",\"0\",\"2024\",\"2024\"\n"
                                      "\"Root\",\"Mail\",\"me\",\"pw2\",\"\",\"\",\"\",\"0\",\"\",\"\"\n"))]
      (is (= {:title "Web" :username "admin" :password "pw1" :url "https://web" :notes "n" :folder "Server" :expires "" :tags ""
              :custom-fields [{:name "otp" :value "otpauth://totp/x?secret=ABC" :protected true}]}
             a))
      (is (= "" (:folder b)))))

  (testing "Bitwarden, Chrome, unknown columns as custom fields"
    (let [[bw] (csv/import-rows "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPersonal,1,login,Bank,,,0,https://bank,customer,secret,\n")
          [ch] (csv/import-rows "name,url,username,password,note\n,https://x.example,u,p,\n")
          [ot] (csv/import-rows "Titel;Benutzername;Passwort;Kundennummer;Läuft ab\nA;b;c;4711;31.12.2030\n")]
      (is (= ["Bank" "customer" "secret" "https://bank" "Personal" []] ((juxt :title :username :password :url :folder :custom-fields) bw)))
      (is (= "https://x.example" (:title ch)) "without a title: URL")
      (is (= [{:name "Kundennummer" :value "4711" :protected false}] (:custom-fields ot)))
      (is (= "2030-12-31" (:expires ot)))))

  (testing "no recognizable columns: error instead of garbage data"
    (is (thrown-with-msg? Exception #"No known columns" (csv/import-rows "foo,bar\n1,2\n")))
    (is (= :invalid (:type (try (csv/import-rows "foo,bar\n1,2\n") nil (catch Exception e (ex-data e))))))))

(deftest exchange-in-file
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})]
      (svc/open-file! s {:file (tmp-file "quelle.kdbx") :password "m" :create true :kdf fast})
      (svc/save-entry s {:title "Web <b>" :username "admin" :password "p&w\"1" :url "https://web" :folder "Server/Linux"
                         :notes "Line 1\nLine 2" :tags "a;b"
                         :custom-fields [{:name "PIN" :value "1234" :protected true}
                                         {:name "TimeOtp-Secret-Base32" :value "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" :protected true}]
                         :attach [{:name "key.txt" :data (c/utf8 "key-data")}]})
      (svc/save-entry s {:title "Trashed" :password "x"})
      (svc/delete-entry s (:id (by-title s "Trashed")))
      (let [xml (:data (svc/export-file s {:format :xml}))
            csv-out (c/utf8-str (:data (svc/export-file s {:format :csv})))
            html (c/utf8-str (:data (svc/export-file s {:format :html})))
            html-pw (c/utf8-str (:data (svc/export-file s {:format :html :passwords true})))]
        (testing "KeePass XML like KeePass: ProtectInMemory, attachments in Meta/Binaries"
          (let [doc (k/parse-xml-str (c/utf8-str xml))]
            (is (str/includes? (c/utf8-str xml) "ProtectInMemory=\"True\">1234<"))
            (is (not (str/includes? (c/utf8-str xml) "Protected=")))
            (is (= 1 (count (k/children (k/child (k/child doc :Meta) :Binaries) :Binary))))))
        (testing "CSV like KeePassXC, without the recycle bin"
          (let [[h & rows] (csv/parse csv-out)]
            (is (= csv/export-header h))
            (is (= 1 (count rows)))
            (is (= ["quelle/Server/Linux" "Web <b>" "admin" "p&w\"1"] (take 4 (first rows))))
            (is (str/starts-with? (nth (first rows) 6) "otpauth://totp/") "TOTP from TimeOtp-* as a URI")))
        (testing "print: passwords only on request, everything escaped"
          (is (str/includes? html "Web &lt;b&gt;"))
          (is (not (str/includes? html "p&amp;w")))
          (is (str/includes? html-pw "p&amp;w&quot;1"))
          (is (not (str/includes? html "Trashed")) "recycle bin is not printed")
          (is (str/includes? html "<html lang=\"en\">"))
          (is (str/includes? html "<th>Title</th><th>User name</th><th>URL</th><th>Notes</th>"))
          (is (str/includes? html-pw "<th>Password</th>"))
          (is (str/includes? html "Tags: a, b"))
          (let [de (binding [i18n/*lang* "de"] (ex/html "T" [{:title "x" :expires "2030-01-01"}] {:passwords true}))]
            (is (str/includes? de "<html lang=\"de\">"))
            (is (str/includes? de "<th>Titel</th><th>Benutzername</th><th>Passwort</th>"))
            (is (str/includes? de "Läuft ab: 2030-01-01"))))

        (testing "import into a new file: XML lossless, CSV the fields"
          (let [s2 (svc/new-session {})]
            (binding [local/*home* (str (fs/create-temp-dir))]
              (svc/open-file! s2 {:file (tmp-file "ziel.kdbx") :password "m" :create true :kdf fast})
              (is (= 2 (:imported (svc/import-file s2 {:format :xml :data xml}))))
              (let [e (by-title s2 "Web <b>")]
                (is (= "p&w\"1" (svc/get-field s2 (:id e) "password")))
                (is (= "Server/Linux" (:folder e)))
                (is (= "key-data" (c/utf8-str (svc/attachment-data s2 (:id e) "key.txt"))))
                (is (= ["a" "b"] (:tags e)))
                (is (re-matches #"\d{6}" (:code (svc/otp s2 (:id e))))))
              (is (= 1 (:imported (svc/import-file s2 {:format :csv :data (c/utf8 csv-out)}))))
              (is (= 2 (count (filter #(= "Web <b>" (:title %)) (:entries (svc/list-entries s2)))))))))

        (testing "XSL stylesheet like in KeePass, with an included Common file"
          (let [dir (str (fs/create-temp-dir))
                main (str (fs/path dir "KDBX_Liste.xsl"))]
            (spit (str (fs/path dir "KDBX_Common.xsl"))
                  (str "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
                       "<xsl:template name=\"feld\"><xsl:param name=\"k\"/><xsl:value-of select=\"String[Key=$k]/Value\"/></xsl:template>"
                       "</xsl:stylesheet>"))
            (spit main (str "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
                            "<xsl:include href=\"KDBX_Common.xsl\"/><xsl:output method=\"text\"/>"
                            "<xsl:template match=\"/\"><xsl:for-each select=\"//Group/Entry\">"
                            "<xsl:call-template name=\"feld\"><xsl:with-param name=\"k\" select=\"'Title'\"/></xsl:call-template>;"
                            "<xsl:call-template name=\"feld\"><xsl:with-param name=\"k\" select=\"'Password'\"/></xsl:call-template>"
                            "<xsl:text>&#10;</xsl:text></xsl:for-each></xsl:template></xsl:stylesheet>"))
            (is (str/includes? (c/utf8-str (:data (svc/export-file s {:format :xsl :xsl main}))) "Web <b>;p&w\"1"))))

        (testing "XSL stylesheet must not read anything outside its folder and not call Java"
          (let [secret (tmp-file "secret.txt")
                _ (spit secret "top-secret")
                dir (str (fs/create-temp-dir))
                vorlage (fn [n body] (let [f (str (fs/path dir n))]
                                       (spit f (str "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" "
                                                    "xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\">"
                                                    "<xsl:output method=\"text\"/><xsl:template match=\"/\">" body "</xsl:template></xsl:stylesheet>"))
                                       f))
                link (str (fs/path dir "link.txt"))
                _ (java.nio.file.Files/createSymbolicLink (fs/path link) (fs/path secret) (make-array java.nio.file.attribute.FileAttribute 0))
                out (fn [f] (try (c/utf8-str (:data (svc/export-file s {:format :xsl :xsl f}))) (catch Exception e (ex-message e))))]
            (is (str/includes? (out (vorlage "a.xsl" (str "<xsl:copy-of select=\"unparsed-text('file://" secret "')\"/>"))) "denied"))
            (is (str/includes? (out (vorlage "b.xsl" (str "<xsl:copy-of select=\"document('file://" secret "')\"/>"))) "denied"))
            (is (str/includes? (out (vorlage "c.xsl" "<xsl:copy-of select=\"document('link.txt')\"/>")) "denied") "symlink pointing outside")
            (is (str/includes? (out (vorlage "d.xsl" "<xsl:copy-of select=\"document('https://example.com/')\"/>")) "denied"))
            (is (not (str/includes? (out (vorlage "e.xsl" "<xsl:value-of select=\"rt:getRuntime()\"/>")) "java.lang.Runtime@")))))
        (testing "broken stylesheet: understandable error"
          (let [f (tmp-file "kaputt.xsl")]
            (spit f "<not-xsl/>")
            (is (thrown-with-msg? Exception #"XSL stylesheet" (ex/transform xml f)))
            (is (= :kp/xsl-error (:msg (try (ex/transform xml f) nil (catch Exception e (ex-data e))))))))))))
