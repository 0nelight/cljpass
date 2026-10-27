(ns cljpass.vault
  "Core as described in doc/FORMAT.md: organization, roster, group keys,
   entries with cryptographic ACLs, validation rules.

   Permissions (like Passbolt): :read < :update < :owner for u:<user> / g:<group>.
   - Reading: enforced by encryption (entry key only for authorized principals).
   - Writing/sharing: every version is signed; all clients (and the
     server) check that the author had the permission according to the
     previous ACL.
   - Admins only manage the roster, they have no entry or group keys."
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.store :as store]))

(def perm-rank {:read 1 :update 2 :owner 3})

(defn perm>= [a b] (>= (perm-rank a 0) (perm-rank b 0)))

(defn fail!
  "Throws ex-info. (fail! k params data) with an i18n key k; the two-argument
   form takes a plain message string (or a key without params)."
  ([msg data]
   (throw (if (keyword? msg) (i18n/error msg nil data) (ex-info msg data))))
  ([k params data]
   (throw (i18n/error k params data))))

;; ================================================================ Organization (§4.1)

(def org-path "org.json")

(defn- org-from-wire [w]
  (assoc w :admins (into {} (map (juxt :user identity)) (:admins w))))

(defn create-org!
  "New vault. Returns {:org-hash .. :recovery-priv ..}. The recovery
   private key belongs in offline storage, not on a server."
  [st org-name admin-ident]
  (let [admin (store/safe-name (:user admin-ident))
        recovery (c/gen-box-keypair)
        body {:org-id (str (random-uuid))
              :name org-name
              :admins [{:user admin :sign-pub (get-in admin-ident [:sign :pub])}]
              :recovery-pub (:pub recovery)}]
    (store/write-doc! st org-path (codec/sign-doc :org body admin (get-in admin-ident [:sign :priv])))
    {:org-hash (codec/hash-of body) :org-id (:org-id body)
     :recovery-priv (:priv recovery) :recovery-pub (:pub recovery)}))

(defn- check-org-doc [{:keys [body signer] :as doc}]
  (when-not (codec/doc-valid? doc :org (:sign-pub (first (filter #(= signer (:user %)) (:admins body)))))
    (fail! :core/org-bad-signature nil {:type :bad-signature}))
  (org-from-wire body))

(defn load-org
  "Loads org.json and checks the pinned hash. pinned-hash nil = unpinned
   (only the server, which trusts its own database)."
  [st pinned-hash]
  (let [{:keys [body] :as doc} (or (store/read-doc st org-path) (fail! :core/no-org nil {:type :no-org}))]
    (when (and pinned-hash (not= pinned-hash (codec/hash-of body)))
      (fail! :core/org-pin-mismatch nil {:type :org-mismatch}))
    (assoc (check-org-doc doc) :hash (codec/hash-of body))))

;; ================================================================ Roster (§5)

(defn- roster-from-wire [w]
  {:version (:version w) :prev (:prev w) :org-id (:org-id w)
   :users (into {} (for [u (:users w)]
                     [(:user u) (-> (select-keys u [:sign-pub :box-pub :display-name])
                                    (assoc :status (keyword (:status u))))]))
   :groups (into {} (for [g (:groups w)]
                      [(:group g) (cond-> {:epoch (:epoch g) :members (set (:members g)) :deleted (boolean (:deleted g))}
                                    (:source g) (assoc :source (keyword (:source g))))]))})

(defn roster->wire [r]
  {:version (:version r) :prev (:prev r) :org-id (:org-id r)
   :users (vec (for [[u m] (sort-by key (:users r))]
                 (-> (select-keys m [:sign-pub :box-pub :display-name])
                     (assoc :user u :status (name (:status m))))))
   :groups (vec (for [[g m] (sort-by key (:groups r))]
                  (cond-> {:group g :epoch (:epoch m) :members (vec (sort (:members m)))
                           :deleted (boolean (:deleted m))}
                    (:source m) (assoc :source (name (:source m))))))})

(defn roster-path [n] (str "roster/" (store/pad n) ".json"))

(defn- check-roster-doc
  "R1-R4 for a roster version against the previous one (prev-hash)."
  [org {:keys [body signer] :as doc} n prev-hash]
  (let [admin-pub (get-in org [:admins signer :sign-pub])]
    (when-not (and admin-pub (codec/doc-valid? doc :roster admin-pub))
      (fail! :core/roster-bad-signature {:n n} {:type :bad-signature}))
    (when-not (and (= n (:version body)) (= prev-hash (:prev body)) (= (:org-id org) (:org-id body)))
      (fail! :core/roster-chain-broken {:n n} {:type :bad-chain}))
    (assoc (roster-from-wire body) :hash (codec/hash-of body))))

(defn load-rosters
  "Loads and checks the complete roster chain. Returns {version roster}."
  [st org]
  (loop [[[n p] & more] (store/numbered st "roster/") prev-hash nil acc {}]
    (if-not n
      acc
      (let [r (check-roster-doc org (store/read-doc st p) n prev-hash)]
        (recur more (:hash r) (assoc acc n r))))))

(defn latest-roster [rosters]
  (let [v (apply max 0 (keys rosters))]
    (get rosters v {:version 0 :users {} :groups {}})))

(defn write-roster!
  "New roster version (admins only). `f` receives the current content
   (:users, :groups) and returns the new one."
  [st org admin-ident f]
  (let [admin (:user admin-ident)
        _ (when-not (get-in org [:admins admin]) (fail! :core/roster-admins-only nil {:type :forbidden}))
        cur (latest-roster (load-rosters st org))
        n (inc (:version cur))
        new (-> (f (select-keys cur [:users :groups]))
                (select-keys [:users :groups])
                (assoc :version n :prev (:hash cur) :org-id (:org-id org)))]
    (store/write-doc! st (roster-path n)
                      (codec/sign-doc :roster (roster->wire new) admin (get-in admin-ident [:sign :priv])))
    new))

(defn active-user [roster user]
  (let [u (get-in roster [:users user])]
    (when (= :active (:status u)) u)))

(defn groups-of [roster user]
  (set (for [[g {:keys [members deleted]}] (:groups roster)
             :when (and (not deleted) (contains? members user))]
         g)))

(defn permission
  "Effective permission of a user on an ACL under a roster."
  [roster acl user]
  (when (active-user roster user)
    (->> (cons (str "u:" user) (map #(str "g:" %) (groups-of roster user)))
         (keep acl) (sort-by perm-rank) last)))

;; ---------------------------------------------------------------- Roster operations (pure functions)

(defn add-user [roster {:keys [user sign-pub box-pub display-name]}]
  (update-in roster [:users user]
             (fn [old] (cond-> (assoc old :sign-pub sign-pub :box-pub box-pub :status :active)
                         display-name (assoc :display-name display-name)))))

(defn set-group-members
  "Sets the members. If someone is removed, a new epoch begins (§5)."
  [roster group members]
  (let [old (get-in roster [:groups group])
        members (set members)
        removed (set/difference (:members old #{}) members)]
    (assoc-in roster [:groups group]
              (cond-> (assoc (or old {:epoch 1 :source :manual}) :members members :deleted false)
                (seq removed) (update :epoch inc)))))

(defn disable-user [roster user]
  (reduce (fn [r g] (set-group-members r g (disj (get-in r [:groups g :members]) user)))
          (assoc-in roster [:users user :status] :disabled)
          (groups-of roster user)))

(defn delete-group [roster group]
  (-> roster (set-group-members group #{}) (assoc-in [:groups group :deleted] true)))

;; ================================================================ Enrollment (§8)

(defn request-path [user] (str "requests/" (store/safe-name user) ".json"))
(defn escrow-path [user] (str "escrow/" (store/safe-name user) ".json"))

(defn- escrow-aad [user] (c/utf8 (str "escrow:" user)))

(defn request-docs
  "Request and escrow of an identity as canonical JSON:
   {:request str :escrow str :body request-body}."
  [org ident]
  (let [user (store/safe-name (:user ident))
        priv (get-in ident [:sign :priv])
        body {:user user :sign-pub (get-in ident [:sign :pub]) :box-pub (get-in ident [:box :pub])}]
    {:body body
     :request (codec/->str (codec/sign-doc :request body user priv))
     :escrow (codec/->str (codec/sign-doc :escrow
                                          {:user user
                                           :box (c/seal (:recovery-pub org) (codec/->bytes ident) (escrow-aad user))}
                                          user priv))}))

(defn submit-request!
  "User's client: request activation of the public keys, deposit the
   identity for the org recovery key."
  [st org ident]
  (let [{:keys [body request escrow]} (request-docs org ident)
        user (:user body)]
    ;; the request first: the server checks the escrow against its keys
    (store/put-obj! st (request-path user) request)
    (store/put-obj! st (escrow-path user) escrow)
    body))

(defn valid-request [doc user]
  (let [{:keys [body]} doc]
    (when (and (= user (:user body) (:signer doc)) (codec/doc-valid? doc :request (:sign-pub body)))
      body)))

(defn pending-requests
  "Valid requests whose keys are not yet active in the roster."
  [st roster]
  (for [f (store/children st "requests/")
        :let [[_ user] (re-matches #"(.+)\.json" f)]
        :when user
        :let [req (valid-request (store/read-doc st (str "requests/" f)) user)]
        :when (and req (not= (:sign-pub req) (:sign-pub (active-user roster user))))]
    (assoc req :fingerprint (c/fingerprint (:sign-pub req))
           :known (boolean (get-in roster [:users user])))))

(defn open-escrow [st org user recovery-priv]
  (let [doc (or (store/read-doc st (escrow-path user)) (fail! :core/no-escrow {:user user} {:type :not-found}))]
    (codec/parse (c/utf8-str (c/unseal (:recovery-pub org) recovery-priv (get-in doc [:body :box]) (escrow-aad user))))))

;; ================================================================ Context

(defn open-ctx
  "Everything a client needs per operation. ident = nil for validation only
   (server). state = local anti-rollback state."
  [st pinned-hash ident state]
  (let [org (load-org st pinned-hash)
        rosters (load-rosters st org)
        roster (latest-roster rosters)]
    (when (< (:version roster) (:roster-version state 0))
      (fail! :core/roster-rollback {:version (:version roster) :seen (:roster-version state)}
             {:type :rollback}))
    {:store st :org org :rosters rosters :roster roster :roster-version (:version roster)
     :ident ident
     :seen (atom (assoc (or state {}) :roster-version (:version roster)))
     :group-keys (atom {})}))

(defn me [ctx] (get-in ctx [:ident :user]))

(defn remember-seen! [ctx id version]
  (swap! (:seen ctx) update-in [:entries id] (fnil max 0) version))

;; ================================================================ Group keys (§7)

(defn- epoch-prefix [group epoch] (str "groups/" (store/safe-name group) "/" epoch "/"))
(defn- key-path [g e] (str (epoch-prefix g e) "key.json"))
(defn- wrap-path [g e u] (str (epoch-prefix g e) "wrap-" (store/safe-name u) ".json"))
(defn- wrap-aad [g e u] (c/utf8 (str "group:" g ":" e ":" u)))

(defn- group-doc-ok?
  "G1/G2: in roster R (from the document) the signer is an active member
   of g, and in R e is the current epoch of g."
  [ctx doc type g e]
  (let [{:keys [body signer]} doc
        rv (:roster-version body)
        r (get-in ctx [:rosters rv])
        grp (get-in r [:groups g])]
    (and r grp (not (:deleted grp))
         (= e (:epoch grp) (:epoch body))
         (= g (:group body))
         (contains? (:members grp) signer)
         (active-user r signer)
         (codec/doc-valid? doc type (get-in r [:users signer :sign-pub])))))

(defn group-pub [ctx g e]
  (let [doc (store/read-doc (:store ctx) (key-path g e))]
    (when (and doc (group-doc-ok? ctx doc :group-key g e))
      (get-in doc [:body :box-pub]))))

(defn- key-matches? [pub priv]
  (let [probe (c/random-bytes 16)]
    (try (c/bytes= probe (c/unseal pub priv (c/seal pub probe (byte-array 0)) (byte-array 0)))
         (catch Exception _ false))))

(defn group-priv
  "Private group key (epoch e) for me, if valid (G1-G3)."
  [ctx g e]
  (let [k [g e]]
    (if (contains? @(:group-keys ctx) k)
      (get @(:group-keys ctx) k)
      (let [me (me ctx)
            pub (group-pub ctx g e)
            doc (when pub (store/read-doc (:store ctx) (wrap-path g e me)))
            priv (when (and doc (= me (get-in doc [:body :user])) (group-doc-ok? ctx doc :group-wrap g e))
                   (try
                     (let [p (c/utf8-str (c/unseal (get-in ctx [:ident :box :pub]) (get-in ctx [:ident :box :priv])
                                                   (get-in doc [:body :box]) (wrap-aad g e me)))]
                       (when (key-matches? pub p) p))
                     (catch Exception _ nil)))]
        (swap! (:group-keys ctx) assoc k priv)
        priv))))

(defn- create-ignoring-conflict! [st path doc]
  (try (store/write-doc! st path doc) true
       (catch clojure.lang.ExceptionInfo e
         (if (= :conflict (:type (ex-data e))) false (throw e)))))

(defn maintain-groups!
  "On every sync in a member's client: create missing epoch keys, provide
   new members with the key. Returns a log."
  [ctx]
  (let [me (me ctx)
        st (:store ctx)
        rv (:roster-version ctx)
        roster (:roster ctx)
        sign-priv (get-in ctx [:ident :sign :priv])
        log (atom [])]
    (doseq [[g {:keys [epoch members deleted]}] (:groups roster)
            :when (and (not deleted) (contains? members me) (active-user roster me))]
      (when-not (store/get-obj st (key-path g epoch))
        (let [kp (c/gen-box-keypair)]
          (when (create-ignoring-conflict! st (key-path g epoch)
                                           (codec/sign-doc :group-key {:group g :epoch epoch :box-pub (:pub kp) :roster-version rv}
                                                           me sign-priv))
            (create-ignoring-conflict! st (wrap-path g epoch me)
                                       (codec/sign-doc :group-wrap
                                                       {:group g :epoch epoch :user me :roster-version rv
                                                        :box (c/seal (get-in ctx [:ident :box :pub]) (c/utf8 (:priv kp))
                                                                     (wrap-aad g epoch me))}
                                                       me sign-priv))
            (swap! log conj (i18n/t :core/group-key-created {:group g :epoch epoch})))
          (swap! (:group-keys ctx) dissoc [g epoch])))
      (when-let [priv (group-priv ctx g epoch)]
        (doseq [m (sort members)
                :let [u (active-user roster m)]
                :when (and u (not (store/get-obj st (wrap-path g epoch m))))]
          (when (create-ignoring-conflict! st (wrap-path g epoch m)
                                           (codec/sign-doc :group-wrap
                                                           {:group g :epoch epoch :user m :roster-version rv
                                                            :box (c/seal (:box-pub u) (c/utf8 priv) (wrap-aad g epoch m))}
                                                           me sign-priv))
            (swap! log conj (i18n/t :core/group-access-granted {:group g :user m}))))))
    @log))

;; ================================================================ Entries (§6)

(defn entry-prefix [id] (str "entries/" (store/safe-name id) "/"))
(defn- entry-path [id n] (str (entry-prefix id) (store/pad n) ".json"))
(defn- entry-aad [id version] (c/utf8 (str "entry:" id ":" version)))
(defn- entry-wrap-aad [id version principal] (c/utf8 (str "entry-key:" id ":" version ":" principal)))

(defn entry-from-wire [w]
  (assoc w
         :acl (into {} (for [{:keys [principal perm]} (:acl w)] [principal (keyword perm)]))
         :wraps (into {} (for [{:keys [principal box]} (:wraps w)] [principal box]))))

(defn entry->wire [e]
  (assoc e
         :acl (vec (for [[p perm] (sort-by key (:acl e))] {:principal p :perm (name perm)}))
         :wraps (vec (for [[p box] (sort-by key (:wraps e))] {:principal p :box box}))))

(defn- principal-ok? [pr]
  (boolean (re-matches (re-pattern (str "[ug]:" store/name-re)) (str pr))))

(defn- expected-wraps
  "E7: wrap principals that belong to the ACL under roster r (nil for an unknown group)."
  [r acl]
  (let [ks (for [[pr _] acl]
             (if (str/starts-with? pr "g:")
               (let [g (get-in r [:groups (subs pr 2)])]
                 (when (and g (not (:deleted g))) (str pr "#" (:epoch g))))
               pr))]
    (when (every? some? ks) (set ks))))

(defn- reject!
  "Rejects version n of entry id; the text for k gets {id} and {n}."
  ([id n k type] (reject! id n k nil type))
  ([id n k params type] (fail! k (assoc params :id id :n n) {:type type})))

(defn verify-version
  "Checks a version (E1-E7) against the last valid predecessor
   (prev = {:body .. :hash ..} or nil). Returns the internal body or throws."
  [ctx id doc prev n]
  (let [{:keys [body signer]} doc
        _ (when-not (map? body) (reject! id n :core/entry-bad-doc :bad-doc))
        e (entry-from-wire body)
        {:keys [version roster-version acl author deleted]} e
        r (get-in ctx [:rosters roster-version])
        pb (:body prev)]
    ;; E1
    (when-not (and (= n version) (= id (:entry-id e)))
      (reject! id n :core/entry-number-mismatch :bad-chain))
    ;; E2
    (when-not (and r (<= roster-version (:roster-version ctx)) (or (nil? pb) (>= roster-version (:roster-version pb))))
      (reject! id n :core/entry-bad-roster-version :bad-chain))
    ;; E3
    (when-not (and (= author signer) (active-user r author)
                   (codec/doc-valid? doc :entry (get-in r [:users author :sign-pub])))
      (reject! id n :core/entry-bad-signature {:signer signer} :bad-signature))
    ;; E4
    (when-not (and (seq acl) (some #{:owner} (vals acl)) (every? perm-rank (vals acl)) (every? principal-ok? (keys acl))
                   (boolean? deleted))
      (reject! id n :core/entry-bad-acl :bad-acl))
    (if (nil? prev)
      ;; E5
      (when-not (and (nil? (:prev e)) (= :owner (acl (str "u:" author))))
        (reject! id n :core/entry-first-version-owner :bad-acl))
      ;; E6
      (let [needs (if (or (not= acl (:acl pb)) (not= deleted (:deleted pb))) :owner :update)]
        (when-not (= (:hash prev) (:prev e))
          (reject! id n :core/entry-chain-broken :bad-chain))
        (when-not (perm>= (permission r (:acl pb) author) needs)
          (reject! id n :core/entry-no-permission {:author author :perm (name needs)} :forbidden))))
    ;; E7
    (when-not (= (expected-wraps r acl) (set (keys (:wraps e))))
      (reject! id n :core/entry-wraps-mismatch :bad-acl))
    e))

(defn load-entry
  "Loads the version chain. Invalid versions are skipped and reported
   (§6.1). Returns {:head :hash :prev-head :max-number :warnings :skipped}."
  [ctx id]
  (let [st (:store ctx)
        files (store/numbered st (entry-prefix id))
        _ (when (empty? files) (fail! :core/entry-not-found {:id id} {:type :not-found}))
        {:keys [head prev-head skipped]}
        (reduce (fn [acc [n p]]
                  (let [doc (try (store/read-doc st p) (catch Exception _ nil))]
                    (try
                      (let [e (verify-version ctx id doc (:head acc) n)]
                        (assoc acc :prev-head (:head acc) :head {:body e :hash (codec/hash-of (:body doc))}))
                      (catch clojure.lang.ExceptionInfo ex
                        (update acc :skipped conj {:version n :signer (:signer doc) :reason (ex-message ex)})))))
                {:head nil :prev-head nil :skipped []}
                files)
        _ (when-not head (fail! :core/entry-no-valid-version {:id id} {:type :no-valid-version}))
        body (:body head)
        seen (get-in @(:seen ctx) [:entries id] 0)
        roster (:roster ctx)
        warnings (cond-> (mapv #(if (:signer %)
                                  (i18n/t :core/warning-invalid-change-by
                                          {:version (:version %) :signer (:signer %) :reason (:reason %)})
                                  (i18n/t :core/warning-invalid-change
                                          {:version (:version %) :reason (:reason %)}))
                               skipped)
                   (and prev-head
                        (not (perm>= (permission roster (get-in prev-head [:body :acl]) (:author body))
                                     (if (= (get-in prev-head [:body :acl]) (:acl body)) :update :owner))))
                   (conj (i18n/t :core/warning-author-lost-permission))
                   (some (fn [[pr _]] (and (str/starts-with? pr "u:") (not (active-user roster (subs pr 2))))) (:acl body))
                   (conj (i18n/t :core/warning-shared-with-disabled)))]
    (when (< (:version body) seen)
      (fail! :core/entry-rollback {:id id :version (:version body) :seen seen} {:type :rollback}))
    (remember-seen! ctx id (:version body))
    {:head body :hash (:hash head) :prev-head (:body prev-head)
     :max-number (first (last files)) :warnings warnings :skipped skipped}))

(defn entry-ids [ctx] (store/children (:store ctx) "entries/"))

(defn decrypt-entry
  "Decrypts the content of the head version for me; nil without access."
  [ctx head]
  (let [{:keys [entry-id version wraps data]} head
        me (me ctx)
        candidates (concat
                    (when-let [w (wraps (str "u:" me))]
                      [[(str "u:" me) (get-in ctx [:ident :box :pub]) (get-in ctx [:ident :box :priv]) w]])
                    (for [[pr w] wraps
                          :let [[_ g e] (re-matches #"g:(.+)#(\d+)" pr)]
                          :when g
                          :let [e (parse-long e) priv (group-priv ctx g e)]
                          :when priv]
                      [pr (group-pub ctx g e) priv w]))]
    (some (fn [[pr pub priv w]]
            (try
              (let [k (c/unseal pub priv w (entry-wrap-aad entry-id version pr))]
                (codec/parse (c/utf8-str (c/aead-decrypt k data (entry-aad entry-id version)))))
              (catch Exception _ nil)))
          candidates)))

(defn- wrap-for-acl [ctx id version acl entry-key]
  (into {}
        (for [[pr _] acl]
          (let [[kind nm] (str/split pr #":" 2)]
            (case kind
              "u" (let [u (or (active-user (:roster ctx) nm)
                              (fail! :core/user-not-active {:user nm} {:type :unknown-principal}))]
                    [pr (c/seal (:box-pub u) entry-key (entry-wrap-aad id version pr))])
              "g" (let [g (get-in ctx [:roster :groups nm])
                        _ (when (or (nil? g) (:deleted g))
                            (fail! :core/group-not-found {:group nm} {:type :unknown-principal}))
                        pub (or (group-pub ctx nm (:epoch g))
                                (fail! :core/group-not-ready {:group nm} {:type :group-not-ready}))
                        k (str pr "#" (:epoch g))]
                    [k (c/seal pub entry-key (entry-wrap-aad id version k))])
              (fail! :core/unknown-principal {:principal pr} {:type :unknown-principal}))))))

(defn- write-version!
  "loaded = result of load-entry (nil for a new entry)."
  [ctx id loaded acl payload deleted?]
  (let [me (me ctx)
        version (inc (or (:max-number loaded) 0))
        entry-key (c/random-bytes 32)
        e {:entry-id id
           :version version
           :prev (:hash loaded)
           :roster-version (:roster-version ctx)
           :author me
           :created-at (store/now)
           :acl acl
           :deleted (boolean deleted?)
           :wraps (wrap-for-acl ctx id version acl entry-key)
           :data (c/aead-encrypt entry-key (codec/->bytes payload) (entry-aad id version))}
        doc (codec/sign-doc :entry (entry->wire e) me (get-in ctx [:ident :sign :priv]))]
    ;; the same rules as for all readers - before writing
    (verify-version ctx id doc (when loaded {:body (:head loaded) :hash (:hash loaded)}) version)
    (store/write-doc! (:store ctx) (entry-path id version) doc)
    (remember-seen! ctx id version)
    e))

(defn create-entry!
  "New entry; the creator is owner. Returns the internal body (:entry-id)."
  [ctx payload]
  (write-version! ctx (str (random-uuid)) nil {(str "u:" (me ctx)) :owner} payload false))

(defn- current [ctx id]
  (let [l (load-entry ctx id)]
    (when (get-in l [:head :deleted]) (fail! :core/entry-deleted nil {:type :deleted}))
    l))

(defn update-entry! [ctx id payload]
  (let [l (current ctx id)]
    (write-version! ctx id l (get-in l [:head :acl]) payload false)))

(defn set-acl!
  "Share / change / revoke permissions (needs :owner). New key only for
   the new ACL."
  [ctx id new-acl]
  (let [l (current ctx id)
        payload (or (decrypt-entry ctx (:head l)) (fail! :core/no-read-access nil {:type :forbidden}))]
    (write-version! ctx id l new-acl payload false)))

(defn share!
  "Sets the permission for a principal (\"u:bob\", \"g:it\"); perm nil = revoke."
  [ctx id principal perm]
  (let [acl (get-in (current ctx id) [:head :acl])]
    (set-acl! ctx id (if perm (assoc acl principal perm) (dissoc acl principal)))))

(defn delete-entry! [ctx id]
  (let [l (current ctx id)]
    (write-version! ctx id l (get-in l [:head :acl]) {} true)))

(defn list-entries
  "Readable, non-deleted entries plus a list of errors."
  [ctx]
  (let [results (for [id (entry-ids ctx)]
                  (try
                    (let [{:keys [head warnings]} (load-entry ctx id)]
                      (when-not (:deleted head)
                        (when-let [payload (decrypt-entry ctx head)]
                          {:id id :head head :payload payload :warnings warnings
                           :my-perm (permission (:roster ctx) (:acl head) (me ctx))})))
                    (catch clojure.lang.ExceptionInfo e
                      {:id id :error (ex-message e)})))
        results (remove nil? results)]
    {:entries (sort-by #(str/lower-case (str (get-in % [:payload :title]))) (remove :error results))
     :errors (filter :error results)}))

(defn entry-history
  "All versions (including invalid ones) for display."
  [ctx id]
  (let [{:keys [skipped]} (load-entry ctx id)
        bad (into {} (map (juxt :version :reason) skipped))]
    (vec (for [[n p] (reverse (store/numbered (:store ctx) (entry-prefix id)))
               :let [{:keys [body signer]} (try (store/read-doc (:store ctx) p) (catch Exception _ nil))]]
           {:version n :author (or (:author body) signer) :date (:created-at body)
            :deleted (:deleted body) :acl-size (count (:acl body))
            :valid (not (contains? bad n)) :reason (bad n)}))))

(defn version-payload
  "Content of an older, valid version (for display and restore); nil if
   I cannot decrypt it."
  [ctx id n]
  (let [{:keys [skipped]} (load-entry ctx id)
        _ (when (some #(= n (:version %)) skipped)
            (fail! :core/version-invalid {:n n} {:type :bad-chain}))
        path (some (fn [[m p]] (when (= m n) p)) (store/numbered (:store ctx) (entry-prefix id)))
        _ (when-not path (fail! :core/version-not-found {:n n} {:type :not-found}))
        e (entry-from-wire (:body (store/read-doc (:store ctx) path)))]
    (when-not (:deleted e) (decrypt-entry ctx e))))

;; ================================================================ Server-side validation (§9)

(defn validate-new-object
  "Checks an object before the server accepts it. Needs public keys only.
   Throws ex-info {:type :invalid} on a violation."
  [st path body-str]
  (let [doc (try (codec/parse body-str) (catch Exception _ (fail! :core/invalid-json nil {:type :invalid})))
        invalid! (fn [k & [params]] (fail! k params {:type :invalid}))
        re-name (str store/name-re)]
    (try
      (cond
        (= path org-path)
        (check-org-doc doc)

        (re-matches #"roster/\d{8}\.json" path)
        (let [org (load-org st nil)
              cur (latest-roster (load-rosters st org))
              n (parse-long (subs path 7 15))]
          (when-not (= n (inc (:version cur))) (invalid! :core/roster-version-gap))
          (check-roster-doc org doc n (:hash cur)))

        (re-matches (re-pattern (str "requests/(" re-name ")\\.json")) path)
        (let [[_ u] (re-matches #"requests/(.+)\.json" path)]
          (or (valid-request doc u) (invalid! :core/request-not-self-signed)))

        (re-matches (re-pattern (str "escrow/(" re-name ")\\.json")) path)
        (let [[_ u] (re-matches #"escrow/(.+)\.json" path)
              req (some-> (store/read-doc st (request-path u)) (valid-request u))
              ctx (open-ctx st nil nil nil)
              keys (remove nil? [(:sign-pub req) (:sign-pub (active-user (:roster ctx) u))])]
          (when-not (and (= u (:signer doc) (get-in doc [:body :user]))
                         (some #(codec/doc-valid? doc :escrow %) keys))
            (invalid! :core/escrow-not-signed-by-user)))

        (re-matches (re-pattern (str "groups/(" re-name ")/(\\d+)/key\\.json")) path)
        (let [[_ g e] (re-matches #"groups/(.+)/(\d+)/key\.json" path)
              ctx (open-ctx st nil nil nil)]
          (when-not (and (= (:epoch (get-in ctx [:roster :groups g])) (parse-long e))
                         (group-doc-ok? ctx doc :group-key g (parse-long e)))
            (invalid! :core/group-key-invalid)))

        (re-matches (re-pattern (str "groups/(" re-name ")/(\\d+)/wrap-(" re-name ")\\.json")) path)
        (let [[_ g e u] (re-matches #"groups/(.+)/(\d+)/wrap-(.+)\.json" path)
              e (parse-long e)
              ctx (open-ctx st nil nil nil)
              r (get-in ctx [:rosters (get-in doc [:body :roster-version])])]
          (when-not (and (group-doc-ok? ctx doc :group-wrap g e)
                         (= u (get-in doc [:body :user]))
                         (contains? (get-in r [:groups g :members]) u))
            (invalid! :core/group-wrap-invalid)))

        (re-matches #"entries/[0-9a-f-]{36}/\d{8}\.json" path)
        (let [[_ id n] (re-matches #"entries/(.+)/(\d{8})\.json" path)
              n (parse-long n)
              ctx (open-ctx st nil nil nil)
              loaded (when (seq (store/numbered st (entry-prefix id))) (load-entry ctx id))]
          (when-not (= n (inc (or (:max-number loaded) 0))) (invalid! :core/entry-version-not-next))
          (verify-version ctx id doc (when loaded {:body (:head loaded) :hash (:hash loaded)}) n))

        :else (invalid! :core/unknown-path {:path path}))
      (catch clojure.lang.ExceptionInfo e
        (if (= :invalid (:type (ex-data e)))
          (throw e)
          ;; keep :msg/:params so the text can be translated again later
          (throw (ex-info (ex-message e) (merge (select-keys (ex-data e) [:msg :params]) {:type :invalid}))))))
    true))
