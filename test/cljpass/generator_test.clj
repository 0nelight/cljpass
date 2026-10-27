(ns cljpass.generator-test
  "KeePass parity stage 2.5: generator with patterns, custom characters and
   profiles; quality estimate with pattern recognition."
  (:require [clojure.test :refer [deftest is testing]]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.local :as local]
            [cljpass.pwgen :as pw]
            [cljpass.service :as svc]))

(deftest patterns
  (testing "placeholders like KeePass"
    (is (re-matches #"[0-9a-f]{10}" (pw/generate {:pattern "h{10}"})))
    (is (re-matches #"([0-9A-F]{2}-){5}[0-9A-F]{2}" (pw/generate {:pattern "HH\\-HH\\-HH\\-HH\\-HH\\-HH"})))
    (is (re-matches #"[A-Z][a-z]{3}[0-9]{2}[,.;:]" (pw/generate {:pattern "ul{3}d{2}p"})))
    (is (re-matches #"u[0-9]x" (pw/generate {:pattern "\\ud\\x"})) "\\ stands for the character itself"))
  (testing "custom sets with exclusion"
    (let [p (pw/generate {:pattern "[dA^0O1lI]{400}"})]
      (is (= 400 (count p)))
      (is (not (re-find #"[0O1lI]" p)))
      (is (re-find #"[2-9]" p)))
    (is (re-matches #"[xyz]{20}" (pw/generate {:pattern "[\\x\\y\\z]{20}"})) "placeholder letters with \\"))
  (testing "shuffling keeps the characters"
    (is (= (sort "AAAA1111") (sort (pw/generate {:pattern "\\A{4}\\1{4}" :permute true})))))
  (testing "understandable errors"
    (doseq [[p msg k] [["q" #"unknown placeholder q" :core/pattern-unknown-placeholder]
                       ["d{3" #"\} missing" :core/pattern-missing-brace]
                       ["[abc" #"\] missing" :core/pattern-missing-bracket]
                       ["{3}" #"\{n\} without anything before" :core/pattern-repeat-nothing-before]
                       ["[^a]" #"empty set" :core/pattern-empty-set]
                       ["d\\" #"at the end" :core/pattern-backslash-at-end]]]
      (is (thrown-with-msg? Exception msg (pw/generate {:pattern p})) p)
      (is (= k (try (pw/generate {:pattern p}) nil
                    (catch clojure.lang.ExceptionInfo e (:msg (ex-data e))))) p))))

(deftest charsets
  (testing "custom characters, exclusion"
    (let [p (pw/generate {:length 256 :lower true :custom "€§" :exclude "aeiou"})]
      (is (= 256 (count p)))
      (is (re-find #"[€§]" p))
      (is (not (re-find #"[aeiou]" p)))))
  (testing "each character at most once"
    (let [p (pw/generate {:length 36 :lower true :digits true :no-repeat true})]
      (is (= 36 (count (set p))) "all 36 characters exactly once"))
    (is (thrown-with-msg? Exception #"at most 10" (pw/generate {:length 11 :digits true :no-repeat true}))))
  (testing "nothing left"
    (is (thrown-with-msg? Exception #"No characters" (pw/generate {:digits true :exclude "0123456789"})))))

(deftest quality
  (let [q pw/quality]
    (testing "patterns are recognized"
      (is (< (q "password") 10))
      (is (< (q "P@ssw0rd") 16) "leetspeak")
      (is (< (q "Sommer2024!") 35) "word + year + character")
      (is (< (q "qwertz123") 20) "keyboard sequence")
      (is (< (q "aaaaaaaaaaaaaaaaaaaa") 15) "repetition")
      (is (< (q "abcdefghijklmnop") 15) "sequence")
      (is (< (q "hallohallohallo") 20) "repeated word")
      (is (< (q "drowssap") 12) "reversed"))
    (testing "random stays strong"
      (is (> (q "k7#Qx!v9Lp@2Zr$8Wm^4") 100))
      (is (> (q (pw/generate {:length 24 :upper true :lower true :digits true :special true})) 120)))
    (testing "limits"
      (is (= 0 (q "")))
      (is (< (q "Sommer2024") svc/weak-bits)))))

(deftest profiles
  (binding [local/*home* (str (fs/create-temp-dir))]
    (is (some #(= "MAC address" (:name %)) (svc/generator-profiles)))
    (is (some #(= "MAC-Adresse" (:name %)) (binding [i18n/*lang* "de"] (vec (svc/generator-profiles)))))
    (svc/save-generator-profile! {:name "Router" :pattern "A{16}" :secret "do not store"})
    (is (= {:name "Router" :pattern "A{16}"} (last (svc/generator-profiles))))
    (svc/save-generator-profile! {:name "Router" :length 12 :digits true})
    (is (= 1 (count (filter #(= "Router" (:name %)) (svc/generator-profiles)))) "same name replaces")
    (is (= :exists (try (svc/save-generator-profile! {:name "MAC address"}) nil
                        (catch clojure.lang.ExceptionInfo e (:type (ex-data e))))))
    (is (thrown-with-msg? Exception #"Pattern" (svc/save-generator-profile! {:name "x" :pattern "q"})))
    (svc/delete-generator-profile! "Router")
    (is (not-any? #(= "Router" (:name %)) (svc/generator-profiles)))))
