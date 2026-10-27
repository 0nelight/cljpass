(ns cljpass.admin
  "Admin functions: create the vault, approve users, AD sync, recovery,
   device transfer."
  (:require [cljpass.i18n :as i18n]
            [cljpass.json :as json]
            [cljpass.proc :as proc]
            [clojure.string :as str]
            [cljpass.codec :as codec]
            [cljpass.crypto :as c]
            [cljpass.identity :as idn]
            [cljpass.remote :as remote]
            [cljpass.store :as store]
            [cljpass.vault :as v]))

;; ================================================================ Create the vault

(defn init-org!
  "Creates the vault on a fresh server: org.json + first roster with the
   admin as active user. Returns {:org-hash :recovery-priv}."
  [server init-token org-name admin-ident]
  (let [tmp (store/mem-store)
        res (v/create-org! tmp org-name admin-ident)
        org (v/load-org tmp (:org-hash res))]
    (case (remote/put-object! server admin-ident v/org-path (store/get-obj tmp v/org-path) {:init-token init-token})
      :ok nil
      :conflict (throw (i18n/error :app/vault-exists-on-server nil {:type :conflict})))
    (v/write-roster! tmp org admin-ident #(v/add-user % (idn/public-part admin-ident)))
    (case (remote/put-object! server admin-ident (v/roster-path 1) (store/get-obj tmp (v/roster-path 1)))
      :ok nil
      :conflict (throw (i18n/error :app/roster-exists nil {:type :conflict})))
    (select-keys res [:org-hash :recovery-priv])))

;; ================================================================ Approval

(defn approve!
  "Takes a request into the roster. If a fingerprint is given (read out by
   the user), it must match."
  [ctx admin-ident user {:keys [fingerprint display-name]}]
  (let [st (:store ctx)
        req (or (first (filter #(= user (:user %)) (v/pending-requests st (:roster ctx))))
                (throw (i18n/error :app/no-pending-request {:user user} {:type :not-found})))]
    (when (and fingerprint (not= (c/normalize-code fingerprint) (c/normalize-code (:fingerprint req))))
      (throw (i18n/error :app/fingerprint-mismatch nil {:type :fingerprint-mismatch})))
    (v/write-roster! st (:org ctx) admin-ident
                     #(v/add-user % (cond-> req display-name (assoc :display-name display-name))))
    req))

(defn plan-auto-approve
  "Which pending requests the server has confirmed with Kerberos (§8.1)
   (pure function). attestations: [{:user :sign-pub :principal}].
   Returns {:approve [request ...] :skipped [{:user :reason}]}: a disabled
   user is not re-enabled automatically, and the confirmation must be for
   exactly the key of the current request."
  [roster pending attestations]
  (let [by-user (into {} (map (juxt :user identity)) attestations)]
    (reduce (fn [acc {:keys [user sign-pub] :as req}]
              (let [a (by-user user)]
                (cond
                  (nil? a) acc
                  (not= sign-pub (:sign-pub a)) (update acc :skipped conj {:user user :reason :other-key})
                  (= :disabled (get-in roster [:users user :status])) (update acc :skipped conj {:user user :reason :disabled})
                  :else (update acc :approve conj (assoc req :principal (:principal a))))))
            {:approve [] :skipped []}
            pending)))

(defn auto-approve!
  "Approves all requests confirmed by Kerberos in one roster version.
   Returns {:approved [user ...] :skipped [...]}."
  [ctx admin-ident attestations]
  (let [st (:store ctx)
        {:keys [approve skipped]} (plan-auto-approve (:roster ctx) (v/pending-requests st (:roster ctx)) attestations)]
    (when (seq approve)
      (v/write-roster! st (:org ctx) admin-ident
                       #(reduce (fn [r req] (v/add-user r (select-keys req [:user :sign-pub :box-pub]))) % approve)))
    {:approved (mapv :user approve) :skipped skipped}))

(defn set-group! [ctx admin-ident group members]
  (let [members (set (map (comp store/safe-name str/lower-case) members))
        inactive (remove #(v/active-user (:roster ctx) %) members)]
    (when (seq inactive)
      (throw (i18n/error :app/users-not-approved {:users (str/join ", " (sort inactive))} {:type :unknown-principal})))
    (v/write-roster! (:store ctx) (:org ctx) admin-ident
                     #(v/set-group-members % (store/safe-name group) members))))

(defn disable-user! [ctx admin-ident user]
  (v/write-roster! (:store ctx) (:org ctx) admin-ident #(v/disable-user % user)))

;; ================================================================ AD sync

(def ^:private ps-ad-export
  "Users and groups via ADSI (Samba AD and MS AD) as JSON."
  "$ErrorActionPreference='Stop'
   $prefix=$env:CLJPASS_AD_PREFIX
   function All($filter,$props){ $s=[adsisearcher]$filter; $s.PageSize=1000; $props|%{[void]$s.PropertiesToLoad.Add($_)}; $s.FindAll() }
   $users=@{}
   foreach($u in All '(&(objectCategory=person)(objectClass=user))' @('samaccountname','useraccountcontrol','displayname','distinguishedname')){
     $p=$u.Properties
     $users[[string]$p.distinguishedname[0]]=@{name=([string]$p.samaccountname[0]).ToLower(); enabled=(([int]$p.useraccountcontrol[0] -band 2) -eq 0); displayName=[string]($p.displayname|select -first 1)}
   }
   $groups=@()
   foreach($g in All ('(&(objectClass=group)(cn='+$prefix+'*))') @('cn','member')){
     $m=@($g.Properties.member | %{ if($users.ContainsKey([string]$_)){ $users[[string]$_].name } })
     $groups+=@{name=([string]$g.Properties.cn[0]).ToLower(); members=$m}
   }
   @{users=@($users.Values); groups=$groups} | ConvertTo-Json -Depth 5 -Compress")

(defn read-ad
  "Source \"adsi\" (Windows PC in the domain) or path to a JSON file
   {\"users\":[{\"name\",\"enabled\",\"displayName\"}],\"groups\":[{\"name\",\"members\":[...]}]}
   (e.g. generated with samba-tool/ldapsearch)."
  [source prefix]
  (if (= source "adsi")
    (let [{:keys [exit out err]} (proc/run ["powershell.exe" "-NoProfile" "-NonInteractive" "-Command" ps-ad-export]
                                           nil {:env {"CLJPASS_AD_PREFIX" (str prefix)}})]
      (when-not (zero? exit) (throw (i18n/error :app/ad-unavailable {:error err} {:type :ad-unavailable})))
      (json/read-str out))
    (json/read-str (slurp source))))

(defn plan-sync
  "New roster from AD data (pure function). Groups with the prefix are taken
   over without it (pw-it -> it). Only approved users become group
   members."
  [roster {:keys [users groups]} prefix]
  (let [ad-users (into {} (map (juxt #(str/lower-case (:name %)) identity) users))
        r (reduce (fn [r [u {:keys [status]}]]
                    (let [ad (ad-users u)]
                      (cond-> r
                        (and (= :active status) (or (nil? ad) (not (:enabled ad)))) (v/disable-user u)
                        (and ad (seq (:displayName ad))) (assoc-in [:users u :display-name] (:displayName ad)))))
                  roster (:users roster))
        ad-groups (into {} (for [{:keys [name members]} groups
                                 :let [name (str/lower-case name)]
                                 :when (str/starts-with? name prefix)
                                 :let [g (subs name (count prefix))]
                                 :when (re-matches store/name-re g)]
                             [g (set (filter #(v/active-user r %) (map str/lower-case members)))]))
        r (reduce (fn [r [g members]]
                    (if (and (= members (get-in r [:groups g :members])) (not (get-in r [:groups g :deleted])))
                      r
                      (-> (v/set-group-members r g members) (assoc-in [:groups g :source] :ad))))
                  r ad-groups)]
    (reduce (fn [r [g {:keys [source deleted]}]]
              (if (and (= :ad source) (not deleted) (not (contains? ad-groups g)))
                (v/delete-group r g)
                r))
            r (:groups r))))

(defn ad-sync!
  "AD -> roster. Writes a new roster version only when something changed."
  [ctx admin-ident {:keys [source prefix] :or {source "adsi" prefix "pw-"}}]
  (let [ad (read-ad source prefix)
        cur (select-keys (:roster ctx) [:users :groups])
        planned (plan-sync cur ad prefix)]
    (if (= planned cur)
      {:changed false}
      (do (v/write-roster! (:store ctx) (:org ctx) admin-ident (constantly planned))
          {:changed true}))))

;; ================================================================ Transfer / recovery (§8, §10)

(defn transfer-blob
  "Encrypts the identity with a one-time code (transfer to a new device)."
  [ident]
  (let [code (c/one-time-code)
        salt (c/random-bytes 16)
        k (c/pbkdf2 (c/normalize-code code) salt c/pbkdf2-iterations)]
    {:code code
     :file {:format "cljpass-transfer-v1"
            :user (:user ident)
            :salt (c/b64 salt)
            :iterations c/pbkdf2-iterations
            :box (c/aead-encrypt k (codec/->bytes ident) (c/utf8 (str "transfer:" (:user ident))))}}))

(defn open-transfer [{:keys [user salt iterations box]} code]
  (let [k (c/pbkdf2 (c/normalize-code code) (c/unb64 salt) iterations)]
    (try
      (codec/parse (c/utf8-str (c/aead-decrypt k box (c/utf8 (str "transfer:" user)))))
      (catch Exception _ (throw (i18n/error :app/transfer-bad-code nil {:type :bad-code}))))))
