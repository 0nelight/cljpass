(ns cljpass.kdbx-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.identity :as ident]
            [cljpass.kdbx :as k]
            [cljpass.keepass :as kp]
            [cljpass.store :as store]
            [cljpass.vault :as v]))

;; Fast KDF parameters for tests
(def ^:private fast {:password "secret" :kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(def ^:private sample-xml
  "Everything KeePass and plugins can write into a file - plus an element
   nobody knows. (The German names are fixture data.)"
  "<KeePassFile>
  <Meta>
    <Generator>KeePass</Generator>
    <DatabaseName>Example</DatabaseName>
    <DatabaseNameChanged>2024-01-02T03:04:05Z</DatabaseNameChanged>
    <DatabaseDescription>Test</DatabaseDescription>
    <MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectPassword>True</ProtectPassword></MemoryProtection>
    <CustomIcons>
      <Icon><UUID>SWNvbklEMDAwMDAwMDAwMA==</UUID><Data>iVBORw0KGgo=</Data><Name>Logo</Name><LastModificationTime>2024-01-02T03:04:05Z</LastModificationTime></Icon>
    </CustomIcons>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <RecycleBinUUID>UmVjeWNsZUJpbjAwMDAwMA==</RecycleBinUUID>
    <CustomData>
      <Item><Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key><Value>1000</Value></Item>
      <Item><Key>Plugin.Setting</Key><Value>42</Value><LastModificationTime>2024-01-02T03:04:05Z</LastModificationTime></Item>
    </CustomData>
    <ZukunftsElement Attr=\"x\"><Kind>unbekannt</Kind></ZukunftsElement>
  </Meta>
  <Root>
    <Group>
      <UUID>Um9vdEdyb3VwMDAwMDAwMA==</UUID>
      <Name>Example</Name>
      <Notes/>
      <IconID>48</IconID>
      <Times><CreationTime>2024-01-02T03:04:05Z</CreationTime><Expires>False</Expires></Times>
      <Entry>
        <UUID>RW50cnkxMDAwMDAwMDAwMA==</UUID>
        <IconID>0</IconID>
        <CustomIconUUID>SWNvbklEMDAwMDAwMDAwMA==</CustomIconUUID>
        <ForegroundColor>#FF0000</ForegroundColor>
        <Tags>prod;db</Tags>
        <Times><CreationTime>2024-01-02T03:04:05Z</CreationTime><ExpiryTime>2030-01-01T00:00:00Z</ExpiryTime><Expires>True</Expires><UsageCount>7</UsageCount></Times>
        <String><Key>Notes</Key><Value>Line 1
Line 2</Value></String>
        <String><Key>Password</Key><Value Protected=\"True\">p@ss&lt;&gt;&amp;</Value></String>
        <String><Key>Title</Key><Value>DB prod</Value></String>
        <String><Key>URL</Key><Value>https://db.example</Value></String>
        <String><Key>UserName</Key><Value>root</Value></String>
        <String><Key>PIN</Key><Value Protected=\"True\">1234</Value></String>
        <String><Key>Leer</Key><Value>  </Value></String>
        <String><Key>otp</Key><Value Protected=\"True\">otpauth://totp/x?secret=ABC</Value></String>
        <Binary><Key>key.pem</Key><Value Ref=\"0\"/></Binary>
        <AutoType><Enabled>True</Enabled><DataTransferObfuscation>1</DataTransferObfuscation>
          <Association><Window>*Putty*</Window><KeystrokeSequence>{PASSWORD}{ENTER}</KeystrokeSequence></Association></AutoType>
        <CustomData><Item><Key>KPXC_BROWSER_x</Key><Value>{\"a\":1}</Value></Item></CustomData>
        <QualityCheck>False</QualityCheck>
        <PluginXYZ>secret plugin info</PluginXYZ>
        <History>
          <Entry>
            <UUID>RW50cnkxMDAwMDAwMDAwMA==</UUID>
            <Times><LastModificationTime>2023-01-01T00:00:00Z</LastModificationTime></Times>
            <String><Key>Password</Key><Value Protected=\"True\">old</Value></String>
            <String><Key>Title</Key><Value>DB prod</Value></String>
            <Binary><Key>old.txt</Key><Value Ref=\"1\"/></Binary>
          </Entry>
        </History>
      </Entry>
      <Group>
        <UUID>R3J1cHBlMTAwMDAwMDAwMA==</UUID>
        <Name>Server</Name>
        <Tags>infra</Tags>
        <CustomData><Item><Key>Group-Plugin</Key><Value>yes</Value></Item></CustomData>
        <Entry>
          <UUID>RW50cnkyMDAwMDAwMDAwMA==</UUID>
          <String><Key>Title</Key><Value>Router</Value></String>
          <String><Key>Password</Key><Value Protected=\"True\">r1</Value></String>
        </Entry>
        <Group>
          <UUID>TGVlcmVHcnVwcGUwMDAwMA==</UUID>
          <Name>Empty Group</Name>
        </Group>
      </Group>
      <Group>
        <UUID>UmVjeWNsZUJpbjAwMDAwMA==</UUID>
        <Name>Papierkorb</Name>
        <Entry>
          <UUID>RW50cnkzMDAwMDAwMDAwMA==</UUID>
          <String><Key>Title</Key><Value>Geloescht</Value></String>
        </Entry>
      </Group>
    </Group>
    <DeletedObjects><DeletedObject><UUID>R2Vsb2VzY2h0MDAwMDAwMA==</UUID><DeletionTime>2024-02-02T00:00:00Z</DeletionTime></DeletedObject></DeletedObjects>
  </Root>
</KeePassFile>")

(def ^:private sample-binaries
  [{:protected true :data (c/utf8 "-----BEGIN KEY-----")}
   {:protected false :data (byte-array [0 1 2 -1])}])

(def ^:private public-custom-data (byte-array [0 1 0x42 0 0 0 0]))

(defn- sample-file ^bytes []
  (k/write-kdbx {:xml (k/parse-xml-str sample-xml) :binaries sample-binaries
                 :public-custom-data public-custom-data}
                fast))

(defn- bins-by-index [r] (mapv #(get (:binaries r) (str %)) (range (count (:binaries r)))))
(defn- same-bins? [a b] (= (map (juxt :protected (comp vec :data)) a) (map (juxt :protected (comp vec :data)) b)))

(deftest kdbx-file-roundtrip
  (let [r (k/read-kdbx (sample-file) {:password "secret"})]
    (is (= [4 1] (:version r)) "elements from 4.1 -> file is written as 4.1")
    (is (= (k/parse-xml-str sample-xml) (:xml r)))
    (is (same-bins? sample-binaries (bins-by-index r)))
    (is (= (vec public-custom-data) (vec (:public-custom-data r)))))
  (testing "wrong password"
    (let [e (try (k/read-kdbx (sample-file) {:password "falsch"}) nil (catch Exception e e))]
      (is (= :kdbx-bad-key (:type (ex-data e))))
      (is (= :kp/kdbx-bad-key (:msg (ex-data e))))
      (is (= "Wrong password or wrong key file" (ex-message e)))))
  (testing "key file and AES-KDF"
    (let [kf (c/random-bytes 32)
          data (k/write-kdbx {:xml (k/parse-xml-str sample-xml) :binaries []}
                             {:password "pw" :keyfile kf :kdf :aes :rounds 1000})]
      (is (= "Example" (k/child-text (k/child (:xml (k/read-kdbx data {:password "pw" :keyfile kf})) :Meta) :DatabaseName)))
      (is (thrown? Exception (k/read-kdbx data {:password "pw"}))))))

;; ---------------------------------------------------------------- with vault

(defn- setup []
  (let [st (store/mem-store)
        alice (ident/new-identity "alice")
        admin (ident/new-identity "admin")
        {:keys [org-hash]} (v/create-org! st "Test GmbH" admin)
        org (v/load-org st org-hash)]
    (v/submit-request! st org alice)
    (v/write-roster! st org admin
                     (fn [r] (reduce v/add-user (v/add-user r (ident/public-part admin))
                                     (v/pending-requests st (v/latest-roster {})))))
    #(v/open-ctx st org-hash alice nil)))

(defn- import! [ctx-fn file]
  (let [{:keys [db entries]} (kp/import-doc (k/read-kdbx file {:password "secret"}) {:source "company.kdbx"})]
    (v/create-entry! (ctx-fn) db)
    (doseq [e entries] (v/create-entry! (ctx-fn) e))
    (count entries)))

(defn- export! [ctx-fn]
  (let [items (for [{:keys [head payload]} (:entries (v/list-entries (ctx-fn)))]
                {:payload payload :modified (:created-at head)})
        doc (kp/export-doc items {})]
    (k/read-kdbx (k/write-kdbx doc fast) {:password "secret"})))

(deftest lossless-import-export
  (let [ctx (setup)]
    (is (= 3 (import! ctx (sample-file))))
    (testing "standard fields in the vault"
      (let [by-title (into {} (map (juxt #(get-in % [:payload :title]) :payload)) (:entries (v/list-entries (ctx))))
            db (by-title "DB prod")]
        (is (= ["root" "p@ss<>&" "https://db.example" "Line 1\nLine 2" "" "2030-01-01"]
               (map db [:username :password :url :notes :folder :expires])))
        (is (= [{:name "PIN" :value "1234" :protected true}
                {:name "Leer" :value "  " :protected false}
                {:name "otp" :value "otpauth://totp/x?secret=ABC" :protected true}]
               (:custom-fields db))
            "custom fields show up in the app under Advanced")
        (is (= "Server" (:folder (by-title "Router"))))
        (is (= "Papierkorb" (:folder (by-title "Geloescht"))))
        (is (by-title "KeePass database: Example") "database record, title in the current language")
        (is (= "Example" (kp/db-title-name "KeePass database: Example")))
        (is (= "Example" (kp/db-title-name "KeePass-Datenbank: Example")) "German titles are recognized too")))
    (testing "export yields exactly the original - including plugin data and unknown elements"
      (let [r (export! ctx)]
        (is (= (k/parse-xml-str sample-xml) (:xml r)))
        (is (same-bins? sample-binaries (bins-by-index r)))
        (is (= (vec public-custom-data) (vec (:public-custom-data r))))))))

(defn- entry-el [r title]
  (first (filter #(and (= :Entry (:tag %))
                       (some (fn [s] (and (= "Title" (k/child-text s :Key)) (= title (k/child-text s :Value))))
                             (k/children % :String)))
                 (tree-seq k/element? :content (k/child (:xml r) :Root)))))

(deftest edits-in-vault
  (let [ctx (setup)
        _ (import! ctx (sample-file))
        find (fn [t] (first (filter #(= t (get-in % [:payload :title])) (:entries (v/list-entries (ctx))))))
        {:keys [id payload]} (find "DB prod")]
    ;; like service/save-entry: the change is merged over the old payload
    (v/update-entry! (ctx) id (merge payload {:password "new" :folder "Server/New" :expires "" :extra "kept"
                                              :custom-fields [{:name "PIN" :value "9999" :protected true}
                                                              {:name "New" :value "x" :protected false}]}))
    (v/create-entry! (ctx) {:title "Only in vault" :username "u" :password "p" :folder "Server" :notes "" :url "" :expires "2031-05-06"})
    (let [r (export! ctx)
          e (entry-el r "DB prod")
          strs (into {} (for [s (k/children e :String)] [(k/child-text s :Key) (k/child-text s :Value)]))]
      (testing "changed entry: new password, old state in the history, rest unchanged"
        (is (= "new" (strs "Password")))
        (is (= "9999" (strs "PIN")))
        (is (= "x" (strs "New")))
        (is (not (contains? strs "otp")) "custom field removed in the app disappears")
        (is (= "secret plugin info" (k/child-text e :PluginXYZ)))
        (is (= 2 (count (k/children (k/child e :History) :Entry))))
        (is (= "p@ss<>&" (let [old (last (k/children (k/child e :History) :Entry))]
                           (some #(when (= "Password" (k/child-text % :Key)) (k/child-text % :Value))
                                 (k/children old :String)))))
        (is (= "False" (k/child-text (k/child e :Times) :Expires))))
      (testing "new folder is created as a group"
        (let [server (first (filter #(and (= :Group (:tag %)) (= "Server" (k/child-text % :Name)))
                                    (tree-seq k/element? :content (:xml r))))
              new-group (first (filter #(= "New" (k/child-text % :Name)) (k/children server :Group)))]
          (is (some #(= e %) (k/children new-group :Entry)))
          (is (some #(= "Only in vault" (some (fn [s] (when (= "Title" (k/child-text s :Key)) (k/child-text s :Value)))
                                              (k/children % :String)))
                    (k/children server :Entry)))))
      (testing "vault fields without a KeePass counterpart survive the round trip"
        (let [{:keys [entries]} (kp/import-doc r {})
              back (first (filter #(= "DB prod" (:title %)) entries))
              native (first (filter #(= "Only in vault" (:title %)) entries))]
          (is (= "kept" (:extra back)))
          (is (nil? (k/child (k/parse-xml-str (get-in back [:kdbx :entry])) :cljpass)))
          (is (= "2031-05-06" (:expires native)))
          (is (= "Server" (:folder native))))))))

(deftest export-without-import
  (let [ctx (setup)]
    (v/create-entry! (ctx) {:title "A" :username "u" :password "p" :url "" :notes "" :folder "X/Y" :expires "irgendwann"})
    (let [r (export! ctx)
          back (first (:entries (kp/import-doc r {})))]
      (is (= "X/Y" (:folder back)))
      (is (= "p" (:password back)))
      (is (= "irgendwann" (:expires back)) "unreadable expiry date is not lost"))))

(deftest icons-for-display
  (let [ctx (setup)
        _ (import! ctx (sample-file))
        entries (:entries (v/list-entries (ctx)))
        by-title (into {} (map (juxt #(get-in % [:payload :title]) :payload)) entries)]
    (testing "custom icon of an entry as a data URL"
      (is (= {:id 0 :name "Key"
              :custom {:uuid "SWNvbklEMDAwMDAwMDAwMA==" :name "Logo" :data-url "data:image/png;base64,iVBORw0KGgo="}}
             (kp/entry-icon (by-title "DB prod")))))
    (testing "standard icon and entries without KeePass origin"
      (is (= {:id 0 :name "Key"} (kp/entry-icon (by-title "Router"))))
      (is (= {:id 0 :name "Key"} (kp/entry-icon {:title "only vault"})))
      (is (= 69 (count kp/standard-icons))))
    (testing "folder icons from the database"
      (let [icons (into {} (map (juxt :folder :icon)) (kp/folder-icons (keep :kdbx-db (vals by-title))))]
        (is (= {:id 48 :name "Folder"} (icons "")))
        (is (= {:id 0 :name "Key"} (icons "Server")))
        (is (contains? icons "Server/Empty Group"))))))

(deftest payloads-survive-canonical-json
  (testing "vault payloads are stored as canonical JSON - nothing may change in the process"
    (let [{:keys [db entries]} (kp/import-doc (k/read-kdbx (sample-file) {:password "secret"}) {:source "x.kdbx"})]
      (doseq [p (cons db entries)]
        (is (= p (codec/parse (codec/->str p))))))))
