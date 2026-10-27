(ns cljpass.kerberos
  "Kerberos (SPNEGO, \"Negotiate\") on the server: proves which domain user
   sends an enrollment request, so that no fingerprint has to be read out.

   The server only accepts tickets (acceptor). It needs a keytab with the
   key of its service principal, e.g. HTTP/pw.example.local@EXAMPLE.LOCAL, and
   never talks to the domain controller itself.

   Only used for enrollment (doc/FORMAT.md §8.1): everyday requests stay
   signed with the user's key and work without a DC."
  (:require [clojure.string :as str]
            [cljpass.crypto :as c]
            [cljpass.i18n :as i18n]
            [cljpass.store :as store])
  (:import [javax.security.auth Subject]
           [javax.security.auth.callback CallbackHandler]
           [javax.security.auth.login AppConfigurationEntry AppConfigurationEntry$LoginModuleControlFlag
            Configuration LoginContext]
           [org.ietf.jgss GSSContext GSSCredential GSSManager Oid]
           [java.util.concurrent Callable]))

(set! *warn-on-reflection* true)

(defn- mechs
  "Kerberos 5 and SPNEGO (created only when used, not while building the
   native binary)."
  ^"[Lorg.ietf.jgss.Oid;" []
  (into-array Oid [(Oid. "1.3.6.1.5.5.2") (Oid. "1.2.840.113554.1.2.2")]))

(defn- jaas-config
  "JAAS configuration for Krb5LoginModule as acceptor with a keytab (no
   jaas.conf file needed)."
  [keytab principal]
  (proxy [Configuration] []
    (getAppConfigurationEntry [_]
      (into-array AppConfigurationEntry
                  [(AppConfigurationEntry. "com.sun.security.auth.module.Krb5LoginModule"
                                           AppConfigurationEntry$LoginModuleControlFlag/REQUIRED
                                           {"useKeyTab" "true" "keyTab" (str keytab) "principal" (str principal)
                                            "storeKey" "true" "isInitiator" "false" "doNotPrompt" "true"
                                            "refreshKrb5Config" "true"})]))))

(defn- as-subject [^Subject subject f]
  (Subject/callAs subject (reify Callable (call [_] (f)))))

(defn- ensure-krb5-config!
  "Without krb5.conf (e.g. in the container) the JDK does not know a
   default realm and refuses to start. An acceptor never contacts the KDC,
   so the realm is enough (the KDC entry is only a placeholder)."
  [realm]
  (when-not (or (System/getProperty "java.security.krb5.conf")
                (System/getProperty "java.security.krb5.realm")
                (System/getenv "KRB5_CONFIG")
                (.exists (java.io.File. "/etc/krb5.conf")))
    (System/setProperty "java.security.krb5.realm" (str/upper-case realm))
    (System/setProperty "java.security.krb5.kdc" "localhost")))

(defn acceptor
  "Logs in with the keytab. opts: {:keytab path :principal \"HTTP/host@REALM\"
   (or \"*\" for every key in the keytab) :realm \"EXAMPLE.LOCAL\"}.
   Returns the acceptor for `accept`."
  [{:keys [keytab principal realm]}]
  (when-not (and keytab realm) (throw (i18n/error :core/kerberos-config-incomplete nil {:type :usage})))
  (ensure-krb5-config! realm)
  (let [subject (Subject.)
        lc (LoginContext. "cljpass" subject (reify CallbackHandler (handle [_ _]))
                          ^Configuration (jaas-config keytab (or principal "*")))]
    (.login lc)
    (let [cred (as-subject subject
                           #(.createCredential (GSSManager/getInstance) nil GSSCredential/INDEFINITE_LIFETIME
                                               (mechs)
                                               GSSCredential/ACCEPT_ONLY))]
      {:subject subject :cred cred :realm (str/upper-case realm)})))

(defn user-of
  "Kerberos principal -> user name in the roster, or nil. Only users of
   the configured realm, no service principals (x/y) or machine accounts."
  [realm principal]
  (let [[_ n r] (re-matches #"([^@/]+)@([^@/]+)" (str principal))]
    (when (and n (= (str/upper-case r) realm))
      (let [u (str/lower-case n)]
        (when (re-matches store/name-re u) u)))))

(defn ntlm-token? [^bytes token]
  (and (>= (alength token) 8) (= "NTLMSSP" (String. token 0 7 "ISO-8859-1"))))

(defn negotiate-token
  "Token bytes from an \"Authorization: Negotiate <b64>\" header, or nil."
  ^bytes [header]
  (when-let [[_ t] (some->> header (re-matches #"(?i)Negotiate\s+(\S+)"))]
    (try (c/unb64 t) (catch Exception _ nil))))

(defn accept
  "Checks a SPNEGO/Kerberos token (one round, as sent by Windows).
   Returns {:principal \"alice@EXAMPLE.LOCAL\" :user \"alice\"|nil :out bytes|nil}.
   Throws {:type :kerberos :reason ...} if the token is not valid."
  [{:keys [subject ^GSSCredential cred realm]} ^bytes token]
  (when (ntlm-token? token)
    (throw (i18n/error :core/kerberos-ntlm nil {:type :kerberos :reason "ntlm"})))
  (as-subject subject
              (fn []
                (let [^GSSContext ctx (.createContext (GSSManager/getInstance) cred)]
                  (try
                    (let [^bytes out (try (.acceptSecContext ctx token 0 (alength token))
                                   (catch org.ietf.jgss.GSSException e
                                     (throw (i18n/error :core/kerberos-invalid {:detail (ex-message e)}
                                                        {:type :kerberos :reason (ex-message e)}))))]
                      (when-not (.isEstablished ctx)
                        (throw (i18n/error :core/kerberos-invalid {:detail "not established"}
                                           {:type :kerberos :reason "not established"})))
                      (let [p (str (.getSrcName ctx))]
                        {:principal p :user (user-of realm p) :out (when (and out (pos? (alength out))) out)}))
                    (finally (.dispose ctx)))))))
