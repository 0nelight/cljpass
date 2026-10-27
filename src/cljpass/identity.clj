(ns cljpass.identity
  "A user's identity: Ed25519 (signing) + X25519 (encryption), keys as
   32 raw bytes (doc/FORMAT.md §8)."
  (:require [cljpass.crypto :as c]
            [cljpass.store :as store]))

(defn new-identity [user]
  {:user (store/safe-name user) :sign (c/gen-sign-keypair) :box (c/gen-box-keypair)})

(defn public-part [ident]
  {:user (:user ident) :sign-pub (get-in ident [:sign :pub]) :box-pub (get-in ident [:box :pub])})

(defn fingerprint [ident] (c/fingerprint (get-in ident [:sign :pub])))
