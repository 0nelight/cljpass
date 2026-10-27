(ns cljpass.crypto-test
  (:require [clojure.test :refer [deftest is]]
            [cljpass.crypto :as c]
            [cljpass.secmem :as sm]))

(deftest sign-verify
  (let [{:keys [pub priv]} (c/gen-sign-keypair)
        sig (c/sign priv (c/utf8 "hallo"))]
    (is (c/verify? pub (c/utf8 "hallo") sig))
    (is (not (c/verify? pub (c/utf8 "hallO") sig)))))

(deftest seal-unseal
  (let [{:keys [pub priv]} (c/gen-box-keypair)
        box (c/seal pub (c/utf8 "secret") (c/utf8 "ctx"))]
    (is (= "secret" (c/utf8-str (c/unseal pub priv box (c/utf8 "ctx")))))
    (is (thrown? Exception (c/unseal pub priv box (c/utf8 "anderer-ctx"))) "AAD binds the context")
    (let [other (c/gen-box-keypair)]
      (is (thrown? Exception (c/unseal (:pub other) (:priv other) box (c/utf8 "ctx")))))))

(deftest hkdf-rfc5869-case1
  ;; RFC 5869 test case 1, first 32 bytes
  (let [ikm (byte-array (repeat 22 0x0b))
        salt (byte-array (range 0 13))
        info (byte-array (map unchecked-byte (range 0xf0 0xfa)))]
    (is (= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
           (c/hex (c/hkdf ikm salt info 32))))))

(deftest one-time-code
  (let [code (c/one-time-code)]
    (is (re-matches #"[A-Z2-9]{4}(-[A-Z2-9]{4}){3}" code))
    (is (= 16 (count (c/normalize-code (clojure.string/lower-case code)))))))

(deftest secmem
  (let [src (c/utf8 "password")
        p (sm/protect src)]
    (is (every? zero? src) "original is overwritten")
    (is (= "#<Protected ****>" (pr-str p)))
    (is (= "password" (sm/reveal-str p)))
    (let [leak (atom nil)]
      (sm/with-plain p #(reset! leak %))
      (is (every? zero? @leak) "plaintext buffer is wiped after use"))))
