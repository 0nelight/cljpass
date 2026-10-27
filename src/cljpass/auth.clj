(ns cljpass.auth
  "Authentication at the server without password and without DC: every
   request is signed with the user's Ed25519 key.

     Authorization: CljPass u=<user>,t=<unix-ms>,n=<nonce>,s=<signature>

   Signed is:
     cljpass-req-v1\\n<METHOD>\\n<path+query>\\n<t>\\n<n>\\n<sha256-hex(body)>

   The server accepts +-5 minutes of clock skew and each nonce only once.
   Authentication only protects against abuse of the server - the security
   of the data does not depend on it (everything is signed and encrypted)."
  (:require [clojure.string :as str]
            [cljpass.crypto :as c]))

(def max-skew-ms (* 5 60 1000))

(defn- signing-string [method path t n body]
  (str "cljpass-req-v1\n" (str/upper-case (name method)) "\n" path "\n" t "\n" n "\n"
       (c/hex (c/sha256 (or body (byte-array 0))))))

(defn header
  "Authorization header for a request. body as byte array or nil."
  [ident method path ^bytes body]
  (let [t (System/currentTimeMillis)
        n (c/b64 (c/random-bytes 16))
        s (c/sign (get-in ident [:sign :priv]) (c/utf8 (signing-string method path t n body)))]
    (str "CljPass u=" (:user ident) ",t=" t ",n=" n ",s=" s)))

(defn parse-header [h]
  (when-let [[_ params] (and h (re-matches #"CljPass (.+)" h))]
    (let [m (into {} (for [kv (str/split params #",")
                           :let [[k v] (str/split kv #"=" 2)]]
                       [(keyword k) v]))]
      (when (every? m [:u :t :n :s]) m))))

(defn make-nonce-cache [] (atom {}))

(defn- fresh-nonce? [cache n now]
  (let [ok (atom false)]
    (swap! cache (fn [m]
                   (let [m (into {} (remove (fn [[_ exp]] (< exp now))) m)]
                     (if (contains? m n)
                       (do (reset! ok false) m)
                       (do (reset! ok true) (assoc m n (+ now (* 2 max-skew-ms))))))))
    @ok))

(defn verify
  "Checks the header. `key-of` returns the public signing key for a user
   name (or nil). Returns the user name or nil."
  [nonce-cache key-of authorization method path ^bytes body]
  (when-let [{:keys [u t n s]} (parse-header authorization)]
    (let [now (System/currentTimeMillis)
          t (parse-long t)]
      (when (and t (<= (abs (- now t)) max-skew-ms))
        (when-let [pub (key-of u)]
          (when (and (c/verify? pub (c/utf8 (signing-string method path t n body)) s)
                     (fresh-nonce? nonce-cache n now))
            u))))))
