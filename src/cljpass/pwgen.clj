(ns cljpass.pwgen
  "Password generator and quality estimate as in KeePass 2.x.

   Generator:
   - character sets (upper case, lower case, digits, ...), plus custom
     characters, characters to exclude, each character at most once.
   - patterns with the KeePass syntax:
       a  lower case and digits           A  letters and digits
       U  upper case and digits           d  digit
       h  hex lower   H  hex upper        l  lower-case letter
       u  upper-case letter               L  letter
       v  vowel lower  V  vowel  Z  vowel upper
       c  consonant lower  C  consonant  z  consonant upper
       p  punctuation ,.;:                b  brackets ()[]{}<>
       s  special characters (7-bit)      S  printable 7-bit ASCII
       x  Latin-1 characters
       \\X  the character X itself          {n} previous one n times
       [...] custom set of placeholders and \\ characters, ^ excludes
     Optionally the characters are shuffled afterwards.
   - profiles: built-in ones as in KeePass (hex key, MAC address) and custom ones.

   Quality: estimated strength in bits. Like KeePass it splits the password
   into the cheapest parts: words from a list of common passwords and words
   (also with leetspeak and capitalization), repetitions, sequences (abc,
   135), keyboard sequences (qwertz, asdf), years, otherwise single
   characters."
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n])
  (:import [java.security SecureRandom]))

(set! *warn-on-reflection* true)

(def ^:private rng (delay (SecureRandom.))) ; create at run time, not at build time

(defn- rand-int* ^long [n] (.nextInt ^SecureRandom @rng (int n)))

;; ================================================================ Character sets

(def charsets
  {:upper "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
   :lower "abcdefghijklmnopqrstuvwxyz"
   :digits "0123456789"
   :minus "-" :underline "_" :space " "
   :special "!\"#$%&'*+,./:;=?@\\^`|~"
   :brackets "[]{}()<>"})

(def ^:private look-alike (set "O0Il1|"))

(def ^:private latin1 (apply str (map char (range 0xA1 0x100))))

(def ^:private placeholders
  (let [lo "abcdefghijklmnopqrstuvwxyz" up (str/upper-case lo) dg "0123456789"
        vo "aeiou" co "bcdfghjklmnpqrstvwxyz"]
    {\a (str lo dg) \A (str lo up dg) \U (str up dg) \d dg
     \h "0123456789abcdef" \H "0123456789ABCDEF"
     \l lo \u up \L (str lo up)
     \v vo \V (str vo (str/upper-case vo)) \Z (str/upper-case vo)
     \c co \C (str co (str/upper-case co)) \z (str/upper-case co)
     \p ",.;:" \b "()[]{}<>"
     \s "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
     \S (apply str (map char (range 0x21 0x7F)))
     \x latin1}))

(defn- bad-pattern [k & [params]] (throw (i18n/error k params {:type :invalid})))

(defn parse-pattern
  "Pattern -> [[char ...] ...], the allowed characters per position."
  [^String pattern]
  (let [n (count pattern)]
    (loop [i 0 out []]
      (if (>= i n)
        out
        (let [c (.charAt pattern i)]
          (case c
            \\ (if (< (inc i) n)
                 (recur (+ i 2) (conj out [(.charAt pattern (inc i))]))
                 (bad-pattern :core/pattern-backslash-at-end))
            \{ (let [close (str/index-of pattern "}" i)
                     k (some-> close (#(subs pattern (inc i) %)) str/trim parse-long)]
                 (cond (nil? close) (bad-pattern :core/pattern-missing-brace)
                       (or (nil? k) (neg? k) (> k 1024)) (bad-pattern :core/pattern-repeat-range {:syntax "{n}"})
                       (empty? out) (bad-pattern :core/pattern-repeat-nothing-before {:syntax "{n}"})
                       :else (recur (inc (long close)) (into (pop out) (repeat k (peek out))))))
            \[ (let [close (loop [j (inc i)]
                             (cond (>= j n) nil
                                   (= \\ (.charAt pattern j)) (recur (+ j 2))
                                   (= \] (.charAt pattern j)) j
                                   :else (recur (inc j))))
                     _ (when-not close (bad-pattern :core/pattern-missing-bracket))
                     [inc-set exc-set] (loop [j (inc i) excl false acc [#{} #{}]]
                                         (if (>= j close)
                                           acc
                                           (let [x (.charAt pattern j)
                                                 slot (if excl 1 0)]
                                             (cond
                                               (= x \^) (recur (inc j) true acc)
                                               (= x \\) (recur (+ j 2) excl (update acc slot conj (.charAt pattern (inc j))))
                                               (placeholders x) (recur (inc j) excl (update acc slot into (placeholders x)))
                                               :else (recur (inc j) excl (update acc slot conj x))))))
                     chars (vec (sort (remove exc-set inc-set)))]
                 (when (empty? chars) (bad-pattern :core/pattern-empty-set))
                 (recur (inc (long close)) (conj out chars)))
            (if-let [set (placeholders c)]
              (recur (inc i) (conj out (vec set)))
              (bad-pattern :core/pattern-unknown-placeholder {:char c}))))))))

(defn- shuffle! [^objects arr]
  (doseq [i (range (dec (alength arr)) 0 -1)]
    (let [j (rand-int* (inc i)) t (aget arr i)]
      (aset arr i (aget arr j)) (aset arr j t)))
  arr)

(defn- from-pattern [{:keys [pattern permute]}]
  (let [slots (parse-pattern (str pattern))
        _ (when (empty? slots) (bad-pattern :core/pattern-empty))
        _ (when (> (count slots) 4096) (bad-pattern :core/pattern-too-long))
        arr (object-array (map #(nth % (rand-int* (count %))) slots))]
    (apply str (if permute (shuffle! arr) arr))))

(defn- from-charsets
  [{:keys [length exclude-look-alike custom exclude no-repeat] :or {length 20} :as opts}]
  (let [gone (cond-> (set (str exclude)) exclude-look-alike (into look-alike))
        chosen (filter #(get opts %) (keys charsets))
        classes (->> chosen
                     (map #(vec (distinct (remove gone (charsets %)))))
                     (remove empty?))
        extra (vec (distinct (remove gone (str custom))))
        classes (cond-> (vec classes) (seq extra) (conj extra))
        classes (if (or (seq classes) (seq chosen) (seq (str custom))) classes [(vec (remove gone (:lower charsets)))])
        all (vec (distinct (apply concat classes)))
        _ (when (empty? all) (throw (i18n/error :core/no-characters-left nil {:type :invalid})))
        length (min 256 (max (long length) (count classes) 4))
        _ (when (and no-repeat (> length (count all)))
            (throw (i18n/error :core/no-repeat-too-long {:max (count all)} {:type :invalid})))]
    (if no-repeat
      ;; one per class, then from the rest without replacement
      (let [firsts (reduce (fn [acc cls] (let [left (vec (remove (set acc) cls))]
                                           (if (seq left) (conj acc (nth left (rand-int* (count left)))) acc)))
                           [] classes)
            pool (shuffle! (object-array (remove (set firsts) all)))]
        (apply str (shuffle! (object-array (concat firsts (take (- length (count firsts)) pool))))))
      (let [pick #(nth % (rand-int* (count %)))
            arr (object-array (concat (map pick classes) (repeatedly (- length (count classes)) #(pick all))))]
        (apply str (shuffle! arr))))))

(defn generate
  "opts: character sets {:length 20 :upper true ... :custom \"\" :exclude \"\"
   :no-repeat false :exclude-look-alike false} or pattern {:pattern \"...\"
   :permute false}."
  [opts]
  (if (not (str/blank? (str (:pattern opts))))
    (from-pattern opts)
    (from-charsets opts)))

(def ^:private builtin-profile-defs
  [{:name :core/profile-auto :builtin true :length 20 :upper true :lower true :digits true}
   {:name :core/profile-strong :builtin true :length 24 :upper true :lower true :digits true :special true
    :exclude-look-alike true}
   {:name :core/profile-hex-40 :builtin true :pattern "h{10}"}
   {:name :core/profile-hex-128 :builtin true :pattern "h{32}"}
   {:name :core/profile-hex-256 :builtin true :pattern "h{64}"}
   {:name :core/profile-mac-address :builtin true :pattern "HH\\-HH\\-HH\\-HH\\-HH\\-HH"}
   {:name :core/profile-pin-6 :builtin true :pattern "d{6}"}])

(defn localized-builtin-profiles
  "Built-in profiles (like KeePass) with names in the current language."
  []
  (mapv #(update % :name i18n/t) builtin-profile-defs))

(def builtin-profiles
  "Built-in profiles (like KeePass). A sequential collection whose names are
   looked up on every use, so they follow the current language."
  (reify
    clojure.lang.Seqable
    (seq [_] (seq (localized-builtin-profiles)))
    clojure.lang.Counted
    (count [_] (count builtin-profile-defs))
    clojure.lang.Sequential
    java.lang.Iterable
    (iterator [_] (.iterator ^java.lang.Iterable (localized-builtin-profiles)))))

(def profile-keys
  "What a profile stores."
  (into [:name :length :pattern :permute :custom :exclude :no-repeat :exclude-look-alike] (keys charsets)))

;; ================================================================ Quality

(def ^:private words-text
  "Common passwords and words, most common first (rank = position)."
  "123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890 123123 abc123 1234 password1
iloveyou 1q2w3e4r 000000 qwerty123 zaq12wsx dragon sunshine princess letmein 654321 monkey 1qaz2wsx 123321
qwertyuiop superman asdfghjkl trustno1 football baseball welcome admin master shadow passwort hallo
geheim schatz sommer winter qwertz qwertz123 hallo123 passwort1 test test123 michael jennifer hunter
charlie killer soccer batman access hello freedom whatever starwars passw0rd login solo flower loveme
mustang ashley bailey 696969 121212 666666 7777777 888888 987654321 secret guest root changeme default
server computer internet samsung apple google windows microsoft summer spring autumn love money family
friends orange banana cheese chocolate cookie pepper ginger maggie buster tigger jordan harley ranger
thomas robert daniel andrew joshua matthew jessica amanda nicole hannah liebe ichliebedich fussball
fußball bayern borussia schalke werder hamburg berlin muenchen münchen koeln köln deutschland
oesterreich österreich wien schweiz zuerich zürich sonne mond sterne blume katze hund maus mausi
baerchen bärchen engel prinzessin schnecke hase hasi schatzi schatzilein familie freunde arbeit firma
kennwort anmeldung benutzer administrator willkommen start asdfgh yxcvbnm montag dienstag mittwoch
donnerstag freitag samstag sonntag januar februar maerz märz april mai juni juli august september
oktober november dezember fruehling frühling herbst andreas stefan christian peter markus alexander
tobias sabine petra andrea claudia julia anna lisa laura sarah maria hans juergen jürgen wolfgang
klaus uwe frank dieter sebastian florian lukas leon paul felix max sophie emma mia lena lea tennis
hockey golf pokemon minecraft fortnite matrix mercedes porsche ferrari audi bmw volkswagen toyota
honda yamaha harley dallas chelsea arsenal liverpool barcelona madrid juventus america canada
london paris rome tokyo china india russia france germany england spain italy summer2020 winter2020
monday tuesday wednesday thursday friday saturday sunday january february march june july october
november december black white red blue green yellow purple silver golden diamond crystal rainbow
magic angel devil heaven hell tiger lion eagle falcon wolf bear dolphin horse rabbit turtle snake
spider dragon phoenix unicorn wizard knight king queen prince lord god jesus christ bible church
music guitar piano drums rock metal jazz blues disco party beach ocean river mountain forest island
garden flower rose lily daisy sunflower coffee tea beer wine vodka whisky pizza pasta burger
chicken steak bacon sausage cake candy sugar honey butter bread cheese milk water fire earth wind
storm thunder lightning snow rain cloud star moon sun planet galaxy universe space rocket
jupiter mars venus saturn pluto nasa alpha beta gamma delta omega sigma zeta theta lambda
hallo1 hallo12 hallo1234 schatz1 sommer1 winter1 geheim1 test1 admin1 admin123 root123 user
benutzer1 kennwort1 passwort123 password123 welcome1 letmein1 qwerty1 abc abcd abcde abcdef
qwe asd yxc zxc qaz wsx edc rfv tgb zhn ujm")

(def ^:private dictionary
  (delay (into {} (map-indexed (fn [i w] [w (inc i)])) (distinct (str/split (str/trim words-text) #"\s+")))))

(def ^:private keyboard-rows
  ["qwertzuiopü" "asdfghjklöä" "yxcvbnm" "qwertyuiop" "asdfghjkl" "zxcvbnm" "1234567890" "!\"§$%&/()=?"
   "1qaz2wsx3edc4rfv5tgb6zhn7ujm8ik9ol0p" "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"])

(def ^:private leet {\0 \o \1 \i \3 \e \4 \a \5 \s \7 \t \8 \b \@ \a \$ \s \! \i \| \l})

(defn- log2 ^double [x] (/ (Math/log (max 1.0 (double x))) (Math/log 2)))

(defn- pool-size [^String pw]
  (+ (if (re-find #"[a-z]" pw) 26 0) (if (re-find #"[A-Z]" pw) 26 0) (if (re-find #"[0-9]" pw) 10 0)
     (if (re-find #"[\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]" pw) 33 0) (if (re-find #"[^\x20-\x7E]" pw) 100 0)))

(defn- word-cost
  "Cost of a word from the list (rank, capitalization, leetspeak, reversed)
   or nil."
  [^String s]
  (when (>= (count s) 3)
    (let [lower (str/lower-case s)
          unleet (apply str (map #(get leet % %) lower))
          subs (count (filter leet lower))
          caps (let [ups (count (filter #(Character/isUpperCase ^char %) s))]
                 (cond (zero? ups) 0
                       (or (= ups (count s)) (and (= 1 ups) (Character/isUpperCase (.charAt s 0)))) 1
                       :else ups))
          d @dictionary
          hit (fn [w extra] (when-let [r (d w)] (+ (log2 r) extra)))]
      (when-let [hits (seq (remove nil? [(hit lower 0) (when (pos? subs) (hit unleet subs))
                                         (hit (str/reverse lower) 1) (when (pos? subs) (hit (str/reverse unleet) (inc subs)))]))]
        (+ caps (apply min hits))))))

(defn- sequence? [^String s]
  (and (>= (count s) 3)
       (let [ds (map #(- (int %2) (int %1)) s (rest s))]
         (and (apply = ds) (<= 1 (Math/abs (long (first ds))) 2)))))

(defn- keyboard? [^String s]
  (let [l (str/lower-case s)]
    (and (>= (count l) 3) (some #(or (str/includes? % l) (str/includes? % (str/reverse l))) keyboard-rows))))

(defn quality
  "Estimated strength in bits (like the quality bar in KeePass)."
  ^long [pw]
  (let [^String pw (str pw)
        n (count pw)
        char-bits (log2 (max 1 (pool-size pw)))
        best (double-array (inc n) Double/POSITIVE_INFINITY)]
    (aset best 0 0.0)
    (doseq [i (range n)
            :let [base (aget best i)]
            :when (< base Double/POSITIVE_INFINITY)]
      ;; single character
      (aset best (inc i) (min (aget best (inc i)) (+ base char-bits)))
      (doseq [j (range (+ i 3) (inc (min n (+ i 32))))]
        (let [s (subs pw i j)
              len (- j i)
              costs (remove nil?
                            [(word-cost s)
                             (when (apply = s) (+ char-bits (log2 len)))
                             (when (sequence? s) (+ char-bits (log2 len) 1))
                             (when (keyboard? s) (+ 5 (log2 len)))
                             (when (and (= 4 len) (re-matches #"(19|20)\d\d" s)) (log2 200))
                             (when (and (> i 0) (str/includes? (subs pw 0 i) s)) (+ (log2 i) (log2 len)))])]
          (when (seq costs)
            (aset best j (min (aget best j) (+ base (apply min costs))))))))
    (long (Math/floor (aget best n)))))
