(ns cljpass.i18n-test
  "Catalogs: every key in every language, same placeholders, and every key
   used in the sources exists."
  (:require [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.test :refer [deftest is testing]]
            [cljpass.i18n :as i18n]))

(defn- placeholders [s] (set (map second (re-seq #"\{([A-Za-z0-9_-]+)\}" s))))

(deftest catalogs-complete
  (let [{:strs [en de]} i18n/catalogs]
    (is (seq en))
    (testing "same keys in English and German"
      (is (= #{} (set/difference (set (keys en)) (set (keys de)))) "missing in German")
      (is (= #{} (set/difference (set (keys de)) (set (keys en)))) "missing in English"))
    (testing "same placeholders"
      (doseq [[k v] en :let [d (get de k)] :when d]
        (is (= (placeholders v) (placeholders d)) (str k))))
    (testing "every key has the namespace of its catalog area"
      (doseq [k (keys en)]
        (is (some #{(namespace k)} i18n/areas) (str k))))))

(defn- clj-files []
  (->> (file-seq (io/file "src"))
       (filter #(re-find #"\.clj$" (str %)))
       (remove #(re-find #"i18n\.clj$" (str %)))))

(deftest used-keys-exist
  (let [en (get i18n/catalogs "en")
        known? (fn [k] (or (contains? en (keyword k))
                           (contains? en (keyword (str k ".one")))
                           (contains? en (keyword (str k ".other")))))
        area-re (re-pattern (str ":((?:" (clojure.string/join "|" i18n/areas) ")/[A-Za-z0-9.-]+)"))
        ;; web UI: t('ui/key') / tn('ui/key', n)
        js-re #"\bt[n]?\(\s*['\"](ui/[A-Za-z0-9.-]+)['\"]"
        used (concat (for [f (clj-files) k (map second (re-seq area-re (slurp f)))] [k f])
                     (let [f (io/file "resources/ui/app.js")]
                       (when (.exists f) (for [k (map second (re-seq js-re (slurp f)))] [k f]))))]
    (doseq [[k f] used]
      (is (known? k) (str "unknown key " k " in " f)))))

(deftest translate
  (is (= "Internal error: x" (i18n/tr "en" :core/internal-error {:detail "x"})))
  (is (= "Interner Fehler: x" (i18n/tr "de" :core/internal-error {:detail "x"})))
  (is (= "Interner Fehler: x" (binding [i18n/*lang* "de"] (i18n/t :core/internal-error {:detail "x"}))))
  (is (= ":core/does-not-exist" (i18n/t :core/does-not-exist)) "unknown keys show the key")
  (is (= "de" (i18n/normalize "de_AT.UTF-8")))
  (is (nil? (i18n/normalize "fr")))
  (let [e (binding [i18n/*lang* "de"] (i18n/error :core/internal-error {:detail "x"} {:type :x}))]
    (is (= "Interner Fehler: x" (ex-message e)))
    (is (= :x (:type (ex-data e))))
    (is (= "Internal error: x" (i18n/message e)) "re-translated in the current language")))
