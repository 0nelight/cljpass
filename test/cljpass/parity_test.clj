(ns cljpass.parity-test
  "KeePass features (doc/KEEPASS-PARITY.md, stage 1): TOTP, tags,
   attachments, history, password check, master key, database settings -
   in local mode and on the server."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.admin :as admin]
            [cljpass.crypto :as c]
            [cljpass.fs :as fs]
            [cljpass.identity :as idn]
            [cljpass.kdbx :as k]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.otp :as otp]
            [cljpass.server :as server]
            [cljpass.service :as svc]))

(def ^:private fast {:kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})

(defn- tmp-file [n] (str (fs/path (fs/create-temp-dir) n)))

(defn- err-key
  "i18n key (:msg of the ex-data) of the exception f throws, nil if none."
  [f]
  (try (f) nil (catch Exception e (:msg (ex-data e)))))

(defn- file-entry
  "Entry straight from the file (as KeePass sees it) plus attachments {name bytes}."
  [file creds title]
  (let [doc (k/read-kdbx (fs/read-bytes file) creds)
        e (some (fn [e] (when (= title (some #(when (= "Title" (k/child-text % :Key)) (k/child-text % :Value))
                                              (k/children e :String)))
                          e))
                (filter #(= :Entry (:tag %))
                        (tree-seq #(#{:Group :Root :KeePassFile} (:tag %)) :content (:xml doc))))]
    {:entry e
     :doc doc
     :attachments (into {} (for [b (k/children e :Binary)]
                             [(k/child-text b :Key) (:data (get (:binaries doc) (get-in (k/child b :Value) [:attrs :Ref])))]))}))

;; ================================================================ TOTP

(deftest totp
  (testing "RFC 6238, appendix B (8 digits)"
    (let [cfg (fn [secret algo] {:secret (c/utf8 secret) :period 30 :digits 8 :algo algo :steam false})
          sha1 (cfg "12345678901234567890" "HmacSHA1")
          sha256 (cfg "12345678901234567890123456789012" "HmacSHA256")
          sha512 (cfg "1234567890123456789012345678901234567890123456789012345678901234" "HmacSHA512")]
      (is (= "94287082" (otp/code sha1 59)))
      (is (= "07081804" (otp/code sha1 1111111109)))
      (is (= "65353130" (otp/code sha1 20000000000)))
      (is (= "46119246" (otp/code sha256 59)))
      (is (= "90693936" (otp/code sha512 59)))))

  (testing "Base32"
    (is (= "12345678901234567890" (c/utf8-str (otp/base32-decode "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))))
    (is (= "12345678901234567890" (c/utf8-str (otp/base32-decode "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"))))
    (is (nil? (otp/base32-decode "not-base32!"))))

  (let [b32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        at59 #(:code (otp/current (otp/config %) 59))]
    (testing "all formats yield the same code"
      (is (= "287082" (at59 [{:name "otp" :value (str "otpauth://totp/Example:alice?secret=" b32 "&issuer=Example")}])))
      (is (= "287082" (at59 [{:name "otp" :value (str "key=" b32 "&step=30&size=6")}])))
      (is (= "287082" (at59 [{:name "TimeOtp-Secret-Base32" :value b32}])))
      (is (= "287082" (at59 [{:name "TimeOtp-Secret" :value "12345678901234567890"}])))
      (is (= "287082" (at59 [{:name "TimeOtp-Secret-Hex" :value "3132333435363738393031323334353637383930"}])))
      (is (= "287082" (at59 [{:name "TOTP Seed" :value b32} {:name "TOTP Settings" :value "30;6"}]))))
    (testing "parameters"
      (is (= "94287082" (at59 [{:name "otp" :value (str "otpauth://totp/x?secret=" b32 "&digits=8")}])))
      (is (= "46119246" (at59 [{:name "TimeOtp-Secret" :value "12345678901234567890123456789012"}
                               {:name "TimeOtp-Algorithm" :value "HMAC-SHA-256"}
                               {:name "TimeOtp-Length" :value "8"}])))
      (is (= 5 (count (at59 [{:name "otp" :value (str "otpauth://totp/x?secret=" b32 "&encoder=steam")}]))))
      (is (= {:remaining 1 :period 30} (select-keys (otp/current (otp/config [{:name "otp" :value (str "key=" b32)}]) 59)
                                                    [:remaining :period]))))
    (testing "no or broken TOTP"
      (is (nil? (otp/config [{:name "PIN" :value "1234"}])))
      (is (nil? (otp/config [{:name "otp" :value "otpauth://hotp/x?secret=" }])))
      (is (otp/configured? [{:name "otp" :value "x"}]))
      (is (not (otp/configured? [{:name "PIN" :value "1"}]))))))

;; ================================================================ Tags: older data

(deftest tags-compat
  (let [doc (kp/empty-doc "t")
        e (k/parse-xml-str (str "<Entry><UUID>" (kp/id->uuid (str (random-uuid))) "</UUID><Tags>a, b</Tags>"
                                "<String><Key>Title</Key><Value>X</Value></String>"
                                "<Times><LastModificationTime>2020-01-01T00:00:00Z</LastModificationTime></Times><History/></Entry>"))
        root (k/child (k/child (:xml doc) :Root) :Group)
        xml (update (:xml doc) :content
                    (fn [cs] (mapv #(if (= :Root (:tag %))
                                      (update % :content (fn [rs] (mapv (fn [g] (if (= :Group (:tag g)) (update g :content conj e) g)) rs)))
                                      %)
                                   cs)))
        {:keys [db entries]} (kp/import-doc {:xml xml :binaries {}} {})
        p (first entries)
        legacy (dissoc p :tags)]
    (is (some? root))
    (is (= "a;b" (:tags p)))
    (testing "payload from before :tags: tags stay, no history item"
      (let [out (:xml (kp/export-doc [{:payload db} {:payload legacy}] {}))
            e2 (first (filter #(= :Entry (:tag %)) (tree-seq #(contains? #{:KeePassFile :Root :Group} (:tag %)) :content out)))]
        (is (= "a, b" (k/child-text e2 :Tags)) "text unchanged")
        (is (empty? (k/children (k/child e2 :History) :Entry)))
        (is (= (kp/core-hash p) (kp/core-hash legacy)))))))

;; ================================================================ Local mode

(deftest file-mode-features
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [s (svc/new-session {})
          file (tmp-file "parity.kdbx")
          creds {:password "master"}]
      (svc/open-file! s {:file file :password "master" :create true :kdf fast})

      (testing "tags: in the file as <Tags> like KeePass, normalized"
        (let [id (svc/save-entry s {:title "Mail" :password "a" :tags "privat, wichtig;privat"})]
          (is (= "privat;wichtig" (:tags (svc/get-entry s id))))
          (is (= ["privat" "wichtig"] (:tags (first (:entries (svc/list-entries s))))))
          (is (= "privat;wichtig" (k/child-text (:entry (file-entry file creds "Mail")) :Tags)))
          (svc/save-entry s {:id id :title "Mail" :password "b"})
          (is (= "privat;wichtig" (:tags (svc/get-entry s id))) "saved without :tags: tags stay")
          (svc/delete-entry s id)))

      (let [id (svc/save-entry s {:title "Server" :username "root" :password "Sommer2024"
                                  :custom-fields [{:name "otp" :value "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                                                   :protected true}
                                                  {:name "Rack" :value "B7" :protected false}]
                                  :attach [{:name "id_rsa.pub" :data (c/utf8 "ssh-ed25519 AAAA")}]})]
        (testing "TOTP: the list only shows that there is one; code from the service"
          (let [row (first (filter #(= id (:id %)) (:entries (svc/list-entries s))))]
            (is (true? (:otp row)))
            (is (= ["Rack: B7"] (:fields row)) "protected fields never in the search"))
          (is (re-matches #"\d{6}" (:code (svc/otp s id))))
          (is (= :app/no-totp (err-key #(svc/otp s (svc/save-entry s {:title "ohne"}))))))

        (testing "attachments: on creation, readable for KeePass in the file"
          (is (= [{:name "id_rsa.pub" :size 16}] (:attachments (svc/get-entry s id))))
          (is (= "ssh-ed25519 AAAA" (c/utf8-str (svc/attachment-data s id "id_rsa.pub"))))
          (is (= "ssh-ed25519 AAAA" (c/utf8-str (get (:attachments (file-entry file creds "Server")) "id_rsa.pub")))))

        (testing "add, replace, remove attachment - old state in the history"
          (svc/save-entry s {:id id :title "Server" :username "root" :password "Sommer2024"
                             :custom-fields (:custom-fields (svc/get-entry s id))
                             :attach [{:name "notiz.txt" :data (c/utf8 "hallo")}
                                      {:name "id_rsa.pub" :data (c/utf8 "ssh-ed25519 BBBB")}]})
          (is (= #{"id_rsa.pub" "notiz.txt"} (set (map :name (:attachments (svc/get-entry s id))))))
          (is (= "ssh-ed25519 BBBB" (c/utf8-str (svc/attachment-data s id "id_rsa.pub"))))
          (is (= 2 (count (svc/history s id))) "exactly one history item for the change")
          (svc/save-entry s (assoc (svc/get-entry s id) :password "Winter2025" :detach ["notiz.txt"]))
          (is (= ["id_rsa.pub"] (map :name (:attachments (svc/get-entry s id)))))
          (is (= 3 (count (svc/history s id))) "field and attachment change together: one history item")
          (let [{:keys [entry attachments doc]} (file-entry file creds "Server")]
            (is (= #{"id_rsa.pub"} (set (keys attachments))))
            (is (= 2 (count (k/children (k/child entry :History) :Entry))))
            (is (= 3 (count (:binaries doc))) "attachments of the history stay in the file")))

        (testing "history: show, restore, delete"
          (let [v1 (svc/history-entry s id 1)]
            (is (= "Sommer2024" (:password v1)))
            (is (= ["id_rsa.pub"] (map :name (:attachments v1)))))
          (svc/restore-history s id 1)
          (is (= "Sommer2024" (svc/get-field s id "password")))
          (is (= "ssh-ed25519 AAAA" (c/utf8-str (svc/attachment-data s id "id_rsa.pub"))))
          (is (= 4 (count (svc/history s id))) "the state before restoring is in the history")
          (is (= "Winter2025" (:password (svc/history-entry s id 3))))
          (svc/delete-history s id 1)
          (is (= 3 (count (svc/history s id))))
          (is (= :app/version-not-found (err-key #(svc/history-entry s id 9)))))

        (testing "password check: duplicate and weak passwords"
          (let [dup (svc/save-entry s {:title "Kopie" :password "Sommer2024"})
                strong (svc/save-entry s {:title "Stark" :password "k7#Qx!v9Lp@2Zr$8Wm^4"})
                r (svc/password-report s)]
            (is (= [(vec (sort [id dup]))] (:duplicates r)))
            (is (some #{id} (:weak r)))
            (is (not (some #{strong} (:weak r))))))

        (testing "database settings like KeePass"
          (is (= "parity" (:name (svc/db-settings s))))
          (svc/set-db-settings! s {:name "Personal" :description "My passwords" :default-username "me" :history-max-items 2})
          (is (= {:name "Personal" :description "My passwords" :default-username "me" :history-max-items 2}
                 (dissoc (svc/db-settings s) :master-key-changed :recycle-bin)))
          (is (= "Personal" (:org (svc/list-entries s))))
          (is (= "me" (:default-username (svc/list-entries s))))
          (let [meta (k/child (:xml (:doc (file-entry file creds "Server"))) :Meta)]
            (is (= "Personal" (k/child-text meta :DatabaseName)))
            (is (= "2" (k/child-text meta :HistoryMaxItems))))
          (is (= :app/invalid-history-max-items (err-key #(svc/set-db-settings! s {:history-max-items "viele"})))))

        (testing "history is limited to HistoryMaxItems"
          (doseq [pw ["a1" "a2" "a3" "a4"]]
            (svc/save-entry s (assoc (svc/get-entry s id) :password pw)))
          (is (= 3 (count (svc/history s id))) "2 old + current state")
          (is (= 2 (count (k/children (k/child (:entry (file-entry file creds "Server")) :History) :Entry)))))

        (testing "change master key"
          (let [before (:master-key-changed (svc/db-settings s))]
            (Thread/sleep 1100)
            (svc/change-master-key! s {:password "new"})
            (is (not= before (:master-key-changed (svc/db-settings s)))))
          (is (= :kp/kdbx-bad-key (err-key #(k/read-kdbx (fs/read-bytes file) creds))))
          (svc/lock! s)
          (svc/open-file! s {:file file :password "new"})
          (is (= "a4" (svc/get-field s id "password"))))))))

;; ================================================================ Server mode

(defn- free-port [] (with-open [s (java.net.ServerSocket. 0)] (.getLocalPort s)))

(deftest server-mode-features
  (let [port (free-port)
        url (str "http://127.0.0.1:" port)
        stop (server/start! {:db (str (fs/path (fs/create-temp-dir) "server.db")) :port port :bind "127.0.0.1" :init-token "t"})
        home (str (fs/create-temp-dir))
        s (svc/new-session {})
        ident (idn/new-identity "admin")]
    (try
      (binding [local/*home* home]
        (let [{:keys [org-hash]} (admin/init-org! url "t" "Example" ident)]
          (local/save-identity! ident :file)
          (local/save-config! {:server url :org-hash org-hash :user "admin"})
          (svc/unlock! s)
          (is (= :active (:state (svc/status s)))))
        (let [id (svc/save-entry s {:title "VPN" :password "old" :tags "net"
                                    :attach [{:name "client.ovpn" :data (c/utf8 "remote vpn")}]})]
          (testing "tags and attachments in the vault"
            (is (= "net" (:tags (svc/get-entry s id))))
            (is (= [{:name "client.ovpn" :size 10}] (:attachments (svc/get-entry s id))))
            (is (= "remote vpn" (c/utf8-str (svc/attachment-data s id "client.ovpn")))))

          (testing "view and restore an older version (new version in the vault)"
            (svc/save-entry s (assoc (svc/get-entry s id) :password "new"))
            (is (= "old" (:password (svc/history-entry s id 1))))
            (svc/restore-history s id 1)
            (is (= "old" (svc/get-field s id "password")))
            (is (= 3 (count (svc/history s id))))
            (is (= :app/history-immutable (err-key #(svc/delete-history s id 1)))))

          (testing "local features are blocked in server mode"
            (is (= :app/master-key-file-only (err-key #(svc/change-master-key! s {:password "x"}))))
            (is (= :app/db-settings-file-only (err-key #(svc/db-settings s)))))

          (testing "export: attachment and tags in the KeePass file"
            (let [{:keys [data]} (svc/export-kdbx s {:password "x" :kdf :argon2id :memory-kib 1024 :iterations 1 :parallelism 1})
                  f (tmp-file "export.kdbx")]
              (fs/write-bytes f data)
              (let [{:keys [entry attachments]} (file-entry f {:password "x"} "VPN")]
                (is (= "net" (k/child-text entry :Tags)))
                (is (= "remote vpn" (c/utf8-str (get attachments "client.ovpn")))))))))
      (finally (stop)))))
