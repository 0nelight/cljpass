(ns cljpass.agent
  "Access for an LLM session.

   The session manages entries but never sees a secret: passwords,
   protected custom fields, attachment contents and TOTP codes stay in this
   process. Reading covers everything else; writing needs the switch
   :write in the access map, which only the human sets (desktop UI).
   Every write tags the entry with \"claude\", the old state stays in the
   history like in KeePass.

   Each function takes the service session and returns plain data that is
   safe to hand to the session (JSON)."
  (:require [clojure.string :as str]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.keepass :as kp]
            [cljpass.service :as svc]))

(def agent-tag "claude")

(def human-only-tags
  "Entries with one of these tags are never used for a channel or a new
   password by the session (e.g. the TOTP of the jump host)."
  #{"human-only" "nur-mensch"})

(defn- tag-seq [t] (if (sequential? t) (vec (mapcat kp/tag-list t)) (kp/tag-list t)))

(defn- tags-of [e] (tag-seq (:tags e)))

(defn human-only? [e] (boolean (some (comp human-only-tags str/lower-case) (tags-of e))))

;; ================================================================ What the session may see

(def ^:private row-keys [:id :title :username :url :notes :folder :expires :tags :fields :otp :attachments
                         :modified :version :recycled])

(defn- safe-fields [cfs]
  (vec (for [{:keys [name value protected]} cfs]
         (if protected
           {:name name :protected true}
           {:name name :value value :protected false}))))

(defn- safe-entry
  "Entry view without secrets. :has-password tells whether one is set,
   :otp whether TOTP is configured."
  [e]
  (-> (select-keys e [:id :title :username :url :notes :folder :expires :otp :modified :version :permission :attachments])
      (assoc :tags (tags-of e)
             :custom-fields (safe-fields (:custom-fields e))
             :has-password (not (str/blank? (str (:password e))))
             :human-only (human-only? e))))

(defn status [session {:keys [write]}]
  (let [locked (svc/locked? session)]
    (cond-> {:locked locked :write (boolean write)}
      (not locked) (merge (let [l (svc/list-entries session)]
                            {:mode (:mode l) :file (:file l) :name (:org l) :entries (count (:entries l))
                             :groups (:groups l)})))))

(defn- haystack [e]
  (str/lower-case (str/join "\n" (concat [(:title e) (:username e) (:url e) (:notes e) (:folder e)]
                                         (tags-of e) (:fields e)))))

(defn- history-meta
  "Older versions without secrets. Versions with the same password get the
   same :password-group (A, B, ...), so the session can tell which ones
   are worth trying - without any hash or part of the value."
  [session id]
  (let [cur (svc/get-entry session id)
        hist (svc/history session id)
        olds (for [{:keys [version date]} hist :when (< version (count hist))]
               (assoc (svc/history-entry session id version) :version version :date date))
        all (cons (assoc cur :version (count hist) :date (:modified cur) :current true) olds)
        digest #(c/hex (c/sha256 (c/utf8 (str (:password %)))))
        groups (zipmap (distinct (map digest all)) (map #(str (char (+ 65 (mod % 26)))) (range)))]
    (vec (for [v all]
           (-> (select-keys v [:version :date :title :username :url :notes :current])
               (assoc :has-password (not (str/blank? (str (:password v))))
                      :password-group (groups (digest v))))))))

(defn find-entries
  "All entries (query nil) or those whose title, user, URL, notes, folder,
   tags or unprotected fields contain every word of query. With :history
   also matches older versions (old title/URL/user)."
  [session query {:keys [history]}]
  (let [words (remove str/blank? (str/split (str/lower-case (str query)) #"\s+"))
        hit? (fn [s] (every? #(str/includes? s %) words))
        rows (:entries (svc/list-entries session))]
    (vec (for [e rows
               :let [now (hit? (haystack e))
                     old (when (and (not now) history (seq words))
                           (some #(when (hit? (haystack %)) (:version %)) (history-meta session (:id e))))]
               :when (or now old)]
           (cond-> (assoc (select-keys e row-keys) :tags (tags-of e))
             old (assoc :matched-version old))))))

(defn resolve-id
  "ID or exact title (case-insensitive) -> ID. Several matches are an error
   listing the candidates."
  [session ref]
  (let [rows (:entries (svc/list-entries session))
        ref (str ref)]
    (or (some #(when (= ref (:id %)) ref) rows)
        (let [hits (filter #(= (str/lower-case ref) (str/lower-case (:title %))) rows)]
          (case (count hits)
            1 (:id (first hits))
            0 (throw (i18n/error :app/agent-no-entry {:ref ref} {:type :not-found}))
            (throw (i18n/error :app/agent-ambiguous {:ref ref :ids (str/join ", " (map :id hits))}
                               {:type :invalid})))))))

(defn show [session ref]
  (let [id (resolve-id session ref)]
    (assoc (safe-entry (svc/get-entry session id)) :id id)))

(defn history [session ref]
  (history-meta session (resolve-id session ref)))

;; ================================================================ What the session may change

(def ^:private editable [:title :username :url :notes :folder :expires])

(defn- require-write! [{:keys [write]}]
  (when-not write (throw (i18n/error :app/agent-write-off nil {:type :forbidden}))))

(defn- edit-fields
  "Custom fields: set (name -> value) and remove (names). Protected fields
   can be neither set nor removed - their value is a secret."
  [cfs {:keys [fields remove-fields]}]
  (let [fields (into {} (for [[k v] fields] [(if (keyword? k) (name k) (str k)) v]))
        remove-fields (map str remove-fields)
        protected (set (keep #(when (:protected %) (:name %)) cfs))
        touched (concat (keys fields) remove-fields)]
    (when-let [bad (seq (filter protected touched))]
      (throw (i18n/error :app/agent-protected-field {:name (first bad)} {:type :forbidden})))
    (let [gone (set (concat remove-fields (keys fields)))]
      (vec (concat (remove #(gone (:name %)) cfs)
                   (for [[k v] fields] {:name k :value (str v) :protected false}))))))

(defn- with-agent-tag [tags] (str/join ";" (distinct (concat (tag-seq tags) [agent-tag]))))

(defn- checked-changes [changes]
  (when (contains? changes :password)
    (throw (i18n/error :app/agent-password-readonly nil {:type :forbidden})))
  changes)

(defn update-entry!
  "changes: any of :title :username :url :notes :folder :expires, :tags
   (replaces), :add-tags, :fields {name value}, :remove-fields [name]."
  [session access ref changes]
  (require-write! access)
  (let [changes (checked-changes changes)
        id (resolve-id session ref)
        cur (svc/get-entry session id)
        tags (cond-> (if (contains? changes :tags) (tag-seq (:tags changes)) (tags-of cur))
               (:add-tags changes) (concat (tag-seq (:add-tags changes))))]
    (svc/save-entry session (merge cur
                                   (select-keys changes editable)
                                   {:id id
                                    :custom-fields (edit-fields (:custom-fields cur) changes)
                                    :tags (with-agent-tag tags)}))
    (show session id)))

(def default-generator {:length 24 :upper true :lower true :digits true :special true :exclude-look-alike true})

(defn- new-password [opts] (svc/generate-password (merge default-generator opts)))

(defn create-entry!
  "New entry; :generate true (or generator options) sets a password the
   session never sees."
  [session access {:keys [generate] :as changes}]
  (require-write! access)
  (let [changes (checked-changes (dissoc changes :generate))
        id (svc/save-entry session (merge (zipmap editable (repeat ""))
                                          (select-keys changes editable)
                                          {:custom-fields (edit-fields [] changes)
                                           :tags (with-agent-tag (concat (tag-seq (:tags changes))
                                                                         (tag-seq (:add-tags changes))))}
                                          (when generate
                                            {:password (new-password (when (map? generate) generate))})))]
    (show session id)))

(defn generate-password!
  "Replaces the password with a new one. The old one stays in the history,
   the session gets only the length."
  [session access ref opts]
  (require-write! access)
  (let [id (resolve-id session ref)
        cur (svc/get-entry session id)]
    (when (human-only? cur) (throw (i18n/error :app/agent-human-only {:title (:title cur)} {:type :forbidden})))
    (let [pw (new-password opts)]
      (svc/save-entry session (assoc cur :id id :password pw :tags (with-agent-tag (tags-of cur))))
      {:id id :title (:title cur) :generated true :length (count pw)})))

(defn delete-entry! [session access ref]
  (require-write! access)
  (let [id (resolve-id session ref)]
    {:id id :result (svc/delete-entry session id)}))

(defn add-group! [session access parent name]
  (require-write! access)
  {:group (svc/add-group! session (str parent) (str name))})

;; ================================================================ Secrets for a channel (never returned to the session)

(defn secrets-for-channel
  "Password and private key of an entry for cljpass.channel. Stays in
   this process."
  [session ref]
  (let [id (resolve-id session ref)
        e (svc/get-entry session id)]
    (when (human-only? e) (throw (i18n/error :app/agent-human-only {:title (:title e)} {:type :forbidden})))
    {:id id :entry e
     :password (not-empty (str (:password e)))
     :key (some (fn [{:keys [name]}]
                  (let [b (svc/attachment-data session id name)
                        s (String. ^bytes b "UTF-8")]
                    (when (re-find #"-----BEGIN [A-Z ]*PRIVATE KEY-----" s) s)))
                (:attachments e))}))
