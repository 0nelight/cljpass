(ns cljpass.desktop.dialogs
  "Dialogs of the desktop UI, laid out as in KeePass 2.x.

   app: {:session :shell :display :local? (fn) :on-locked (fn) :copy-text! (fn)
         :folder (fn) :groups (fn) :state (fn) :icon-image (fn [icon fallback])} - see cljpass.desktop."
  (:require [clojure.string :as str]
            [cljpass.desktop.ui :as ui]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.keepass :as kp]
            [cljpass.local :as local]
            [cljpass.otp :as otp]
            [cljpass.service :as svc])
  (:import [java.time Instant LocalDate LocalDateTime ZoneId]
           [java.time.format DateTimeFormatter FormatStyle]
           [java.util Locale]
           [org.eclipse.swt SWT]
           [org.eclipse.swt.graphics Color RGB]
           [org.eclipse.swt.program Program]
           [org.eclipse.swt.widgets Button ColorDialog Combo Composite Control DateTime Display FileDialog Label ProgressBar Shell
            Spinner TabFolder TabItem Table TableColumn TableItem Text]))

(set! *warn-on-reflection* true)

;; Permission id (wire value) -> catalog key of its label.
(def perms [["read" :dialogs/perm-read] ["update" :dialogs/perm-update] ["owner" :dialogs/perm-owner]])
(def ^:private perm-keys (into {} perms))
(def perm-rank {"read" 1 "update" 2 "owner" 3})

(defn perm-label
  "Label of a permission in the current language; default (nil) for unknown ones."
  ([p] (perm-label p nil))
  ([p default] (if-let [k (perm-keys p)] (i18n/t k) default)))

(defn- perm-labels [] (mapv (comp i18n/t second) perms))

(defn fmt-date
  "ISO instant -> short local form."
  [s]
  (if (str/blank? (str s))
    ""
    (try (.format (.withZone (.withLocale (DateTimeFormatter/ofLocalizedDateTime FormatStyle/SHORT) (i18n/locale))
                             (ZoneId/systemDefault))
                  (Instant/parse (str s)))
         (catch Exception _ (str s)))))

(defn expires->local
  "Expiry (plain date or instant in UTC) -> local date/time, nil if empty."
  ^LocalDateTime [s]
  (let [s (str/trim (str s))]
    (cond
      (str/blank? s) nil
      (re-matches #"\d{4}-\d{2}-\d{2}" s) (.atStartOfDay (LocalDate/parse s))
      :else (try (LocalDateTime/ofInstant (Instant/parse s) (ZoneId/systemDefault)) (catch Exception _ nil)))))

(defn fmt-expires
  "Expiry for display: plain date in short local form, instant with time."
  [s]
  (let [s (str/trim (str s))]
    (cond
      (str/blank? s) ""
      (re-matches #"\d{4}-\d{2}-\d{2}" s) (.format (.withLocale (DateTimeFormatter/ofLocalizedDate FormatStyle/MEDIUM) (i18n/locale))
                                                   (LocalDate/parse s))
      :else (fmt-date s))))

(defn- widgets->expires
  "Date + time (local, as in KeePass) -> instant in UTC."
  [^DateTime d ^DateTime t]
  (str (.toInstant (.atZone (LocalDateTime/of (.getYear d) (inc (.getMonth d)) (.getDay d) (.getHours t) (.getMinutes t))
                            (ZoneId/systemDefault)))))

(defn- shell ^Shell [app] (:shell app))
(defn- display ^Display [app] (:display app))
(defn- local? [app] ((:local? app)))
(defn- session [app] (:session app))

(defn fail!
  "Shows an error (when locked, the main window takes over)."
  [app e]
  (if (= :locked (:type (ex-data e)))
    ((:on-locked app))
    (ui/message! (shell app) :error "cljpass" (ui/error-text e))))

(defn call
  "Service call with busy cursor; on error shows a message and returns ::failed."
  [app f]
  (try (ui/busy (display app) f)
       (catch Throwable e (fail! app e) ::failed)))

(defn ok? [r] (not= ::failed r))

(defn- set-error! [^Text err e] (.setText err (str (if (instance? Throwable e) (ui/error-text e) e))) (.pack err) (.layout (.getParent err) true))

(defn- error-label ^Text [^Composite parent & [span]]
  (let [t (Text. parent (int (bit-or SWT/READ_ONLY SWT/WRAP SWT/MULTI)))]
    (.setLayoutData t (ui/gd :fill :h :grab :h :span (or span 1) :w 380))
    (.setForeground t (.getSystemColor (.getDisplay parent) SWT/COLOR_RED))
    (.setBackground t (.getBackground parent))
    t))

;; ================================================================ File selection

(defn choose-file
  "The system's file dialog. mode :open | :save; kdbx? filters for *.kdbx."
  [^Shell parent mode kdbx? current]
  (let [fd (FileDialog. parent (int (if (= mode :save) SWT/SAVE SWT/OPEN)))]
    (when kdbx?
      (.setFilterExtensions fd ^"[Ljava.lang.String;" (into-array String ["*.kdbx" "*.*"]))
      (.setFilterNames fd ^"[Ljava.lang.String;" (into-array String [(i18n/t :dialogs/filter-kdbx) (i18n/t :dialogs/filter-all)])))
    (when-not (str/blank? current)
      (when-let [p (fs/parent current)] (.setFilterPath fd ^String p))
      (.setFileName fd (fs/file-name current)))
    (.setOverwrite fd false)
    (.open fd)))

(defn file-field
  "Text + \"...\" in one row (system file dialog). Returns the Text control."
  ^Text [^Composite parent value mode kdbx?]
  (let [row (ui/composite parent (ui/grid 2 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
        t (ui/text row value)]
    (ui/button row "..." #(when-let [f (choose-file (.getShell parent) mode kdbx? (.getText t))] (.setText t f))
               :data (ui/gd :w 30))
    t))

(defn read-keyfile [^Text t]
  (let [p (str/trim (.getText t))] (when-not (str/blank? p) (fs/read-bytes p))))

(defn- form ^Composite [^Composite body & [cols]]
  (ui/composite body (ui/grid (or cols 2) :margin 0 :hs 10 :vs 6) (ui/gd :fill :both :grab :both)))

;; ================================================================ Password generator

(declare quality-bar)

(def ^:private gen-opts (atom {:length 20 :upper true :lower true :digits true :special true}))

(def ^:private charset-checks
  [[:upper :dialogs/gen-upper] [:lower :dialogs/gen-lower]
   [:digits :dialogs/gen-digits] [:minus :dialogs/gen-minus]
   [:underline :dialogs/gen-underline] [:space :dialogs/gen-space]
   [:special :dialogs/gen-special] [:brackets :dialogs/gen-brackets]])

(defn- bits-text [b] (i18n/t :dialogs/bits {:bits b}))

(defn- save-profile-dialog [^Shell parent current]
  (let [result (atom nil)
        dlg (ui/dialog parent {:title (i18n/t :dialogs/save-profile-title) :icon-name "gen" :heading (i18n/t :dialogs/save-profile-title)
                               :sub (i18n/t :dialogs/save-profile-sub) :width 420}
                       (fn [^Composite body]
                         (let [f (form body)
                               n (do (ui/label f (i18n/t :dialogs/name)) (ui/text f (str current)))]
                           (.setFocus n) {:n n}))
                       [[(i18n/t :dialogs/save) (fn [{:keys [ctx] :as d}] (reset! result (str/trim (.getText ^Text (:n ctx)))) (ui/close! d)) :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    (not-empty @result)))

(defn generator
  "Password generator as in KeePass: character sets or pattern, profiles.
   use?: true = \"Accept\" (returns the password), else \"Copy\"."
  [app use?]
  (let [result (atom nil)
        pw (atom "")
        dlg (ui/dialog
             (shell app)
             {:title (i18n/t :dialogs/gen-title) :icon-name "gen" :heading (i18n/t :dialogs/gen-heading)
              :sub (i18n/t :dialogs/gen-sub) :width 600}
             (fn [^Composite body]
               (let [opts @gen-opts
                     f (form body)
                     ;; ------------------------------------------ Profiles
                     _ (ui/label f (i18n/t :dialogs/gen-profile))
                     prow (ui/composite f (ui/grid 3 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
                     profiles (atom (svc/generator-profiles))
                     ^Combo pc (ui/combo prow [] nil (ui/gd :fill :h :grab :h))
                     ;; ------------------------------------------ Mode
                     _ (ui/label f (i18n/t :dialogs/gen-mode))
                     mrow (ui/composite f (ui/grid 2 :margin 0 :hs 16))
                     gen-fn (atom nil)
                     by-sets (ui/radio mrow (i18n/t :dialogs/gen-by-sets) (str/blank? (:pattern opts)) #(@gen-fn))
                     by-pattern (ui/radio mrow (i18n/t :dialogs/gen-by-pattern) (not (str/blank? (:pattern opts))) #(@gen-fn))
                     _ (ui/label f (i18n/t :dialogs/gen-length))
                     len (doto (Spinner. f SWT/BORDER) (.setMinimum 4) (.setMaximum 256) (.setSelection (int (:length opts 20))))
                     box (ui/composite f (ui/grid 2 :margin 0 :hs 20 :equal true) (ui/gd :span 2 :fill :h))
                     checks (into {} (for [[k txt] charset-checks] [k (ui/check box (i18n/t txt) (get opts k))]))
                     custom (do (ui/label f (i18n/t :dialogs/gen-custom)) (ui/text f (str (:custom opts))))
                     exclude (do (ui/label f (i18n/t :dialogs/gen-exclude)) (ui/text f (str (:exclude opts))))
                     _ (ui/label f "")
                     orow (ui/composite f (ui/grid 2 :margin 0 :hs 20))
                     look (ui/check orow (i18n/t :dialogs/gen-look-alike) (:exclude-look-alike opts))
                     once (ui/check orow (i18n/t :dialogs/gen-no-repeat) (:no-repeat opts))
                     pattern (do (ui/label f (i18n/t :dialogs/gen-pattern)) (ui/text f (str (:pattern opts))))
                     _ (ui/label f "")
                     permute (ui/check f (i18n/t :dialogs/gen-permute) (:permute opts))
                     _ (ui/label f "")
                     _ (ui/wrap-label f (i18n/t :dialogs/gen-pattern-help) 460)
                     _ (ui/label f (i18n/t :dialogs/gen-preview))
                     row (ui/composite f (ui/grid 2 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
                     out (ui/text row "" :read-only true)
                     _ (ui/label f (i18n/t :dialogs/quality))
                     qrow (ui/composite f (ui/grid 2 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                     ^ProgressBar qbar (quality-bar qrow)
                     q (ui/label qrow "" (ui/gd :fill :h :grab :h))
                     current (fn []
                               (let [pat? (.getSelection by-pattern)]
                                 (cond-> {:length (.getSelection len)
                                          :custom (.getText custom) :exclude (.getText exclude)
                                          :exclude-look-alike (.getSelection look) :no-repeat (.getSelection once)
                                          :permute (.getSelection permute)
                                          :pattern (if pat? (.getText pattern) "")}
                                   true (into (for [[k ^Button b] checks] [k (.getSelection b)])))))
                     enable (fn []
                              (let [pat? (.getSelection by-pattern)]
                                (doseq [^Control c (concat [len custom exclude look once] (vals checks))] (.setEnabled c (not pat?)))
                                (.setEnabled pattern pat?) (.setEnabled permute pat?)))
                     gen (fn []
                           (enable)
                           (let [o (current)]
                             (reset! gen-opts o)
                             (try
                               (let [p (svc/generate-password o) b (svc/password-quality p)]
                                 (reset! pw p)
                                 (.setText out p)
                                 (.setSelection qbar (int (min 128 b)))
                                 (.setText q (bits-text b)))
                               (catch Exception e
                                 (reset! pw "")
                                 (.setText out "")
                                 (.setSelection qbar 0)
                                 (.setText q (ui/error-text e))))
                             (.layout qrow true)))
                     fill-profiles (fn [sel]
                                     (.setItems pc ^"[Ljava.lang.String;" (into-array String (cons (i18n/t :dialogs/gen-custom-settings) (map :name @profiles))))
                                     (.select pc (int (inc (.indexOf ^java.util.List (mapv :name @profiles) sel)))))
                     apply-profile (fn [p]
                                     (.setSelection by-pattern (not (str/blank? (:pattern p))))
                                     (.setSelection by-sets (str/blank? (:pattern p)))
                                     (.setText pattern (str (:pattern p)))
                                     (.setSelection permute (boolean (:permute p)))
                                     (when (:length p) (.setSelection len (int (:length p))))
                                     (when-not (:pattern p)
                                       (doseq [[k ^Button b] checks] (.setSelection b (boolean (get p k))))
                                       (.setText custom (str (:custom p))) (.setText exclude (str (:exclude p)))
                                       (.setSelection look (boolean (:exclude-look-alike p))) (.setSelection once (boolean (:no-repeat p))))
                                     (gen))
                     del (ui/button prow (i18n/t :dialogs/delete)
                                    #(let [i (dec (.getSelectionIndex pc))]
                                       (when-let [p (get @profiles i)]
                                         (when (and (not (:builtin p))
                                                    (ui/confirm? (.getShell pc) (i18n/t :dialogs/delete-profile-title)
                                                                 (i18n/t :dialogs/delete-profile-question {:name (:name p)})))
                                           (reset! profiles (svc/delete-generator-profile! (:name p)))
                                           (fill-profiles nil))))
                                    :data (ui/gd :w 80))]
                 (ui/button prow (i18n/t :dialogs/save-ellipsis)
                            #(when-let [nm (save-profile-dialog (.getShell pc) (:name (get @profiles (dec (.getSelectionIndex pc)))))]
                               (let [r (call app (fn [] (svc/save-generator-profile! (assoc (current) :name nm))))]
                                 (when (ok? r) (reset! profiles r) (fill-profiles nm))))
                            :data (ui/gd :w 100))
                 (.moveBelow del nil)
                 (fill-profiles nil)
                 (ui/on pc SWT/Selection (fn [_] (let [p (get @profiles (dec (.getSelectionIndex pc)))]
                                                   (.setEnabled del (boolean (and p (not (:builtin p)))))
                                                   (when p (apply-profile p)))))
                 (.setEnabled del false)
                 (reset! gen-fn gen)
                 (ui/button row "" gen :image (ui/icon (display app) "sync") :data (ui/gd :w 30))
                 (ui/on len SWT/Modify (fn [_] (gen)))
                 (doseq [^Text t [custom exclude pattern]] (ui/on t SWT/Modify (fn [_] (gen))))
                 (doseq [^Button b (concat (vals checks) [look once permute])] (ui/on b SWT/Selection (fn [_] (gen))))
                 (gen)))
             (if use?
               [[(i18n/t :dialogs/accept) (fn [d] (when (seq @pw) (reset! result @pw) (ui/close! d))) :default] [(i18n/t :dialogs/cancel) nil]]
               [[(i18n/t :dialogs/copy) (fn [d] (when (seq @pw) ((:copy-text! app) @pw (i18n/t :dialogs/password-noun)) (ui/close! d))) :default]
                [(i18n/t :dialogs/close) nil]]))]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Custom field (KeePass: "Edit Entry String")

(defn- field-dialog [^Shell parent {:keys [name value protected]}]
  (let [result (atom nil)
        dlg (ui/dialog parent {:title (i18n/t :dialogs/field-title) :icon-name "entry"
                               :heading (if name (i18n/t :dialogs/field-edit) (i18n/t :dialogs/field-add))
                               :sub (i18n/t :dialogs/field-sub) :width 480}
                       (fn [^Composite body]
                         (let [f (form body)
                               n (do (ui/label f (i18n/t :dialogs/name)) (ui/text f (or name "")))
                               v (do (ui/label f (i18n/t :dialogs/field-value) (ui/gd :valign :top))
                                     (ui/text f (or value "") :multi true :data (ui/gd :fill :both :grab :both :h 80)))
                               p (do (ui/label f "") (ui/check f (i18n/t :dialogs/field-protect) protected))]
                           {:n n :v v :p p}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (let [{:keys [^Text n ^Text v ^Button p]} ctx]
                                                 (if (str/blank? (.getText n))
                                                   (ui/message! (:shell d) :warn (i18n/t :dialogs/field-title) (i18n/t :dialogs/name-required))
                                                   (do (reset! result {:name (str/trim (.getText n)) :value (.getText v) :protected (.getSelection p)})
                                                       (ui/close! d)))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ TOTP setup

(defn totp-dialog
  "Enter the secret of a service (as KeePassXC: set up TOTP).
   Returns the custom field {:name \"otp\" :value otpauth-URI :protected true}."
  [^Shell parent label]
  (let [result (atom nil)
        dlg (ui/dialog parent {:title (i18n/t :dialogs/totp-title) :icon-name "history" :heading (i18n/t :dialogs/totp-title)
                               :sub (i18n/t :dialogs/totp-sub) :width 520}
                       (fn [^Composite body]
                         (let [f (form body)
                               secret (do (ui/label f (i18n/t :dialogs/totp-secret)) (ui/text f ""))
                               period (do (ui/label f (i18n/t :dialogs/totp-period))
                                          (doto (Spinner. f SWT/BORDER) (.setMinimum 1) (.setMaximum 3600) (.setSelection 30)))
                               digits (do (ui/label f (i18n/t :dialogs/totp-digits))
                                          (doto (Spinner. f SWT/BORDER) (.setMinimum 6) (.setMaximum 10) (.setSelection 6)))
                               err (error-label f 2)]
                           (ui/wrap-label f (i18n/t :dialogs/totp-hint) 480 2)
                           {:secret secret :period period :digits digits :err err}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (let [{:keys [^Text secret ^Spinner period ^Spinner digits err]} ctx
                                                     b32 (str/trim (.getText secret))]
                                                 (if (empty? (otp/base32-decode b32))
                                                   (set-error! err (i18n/t :dialogs/totp-invalid))
                                                   (do (reset! result {:name "otp" :protected true
                                                                       :value (otp/otp-uri label b32 {:period (.getSelection period)
                                                                                                      :digits (.getSelection digits)})})
                                                       (ui/close! d)))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Attachments

(defn fmt-size [n]
  (cond (< n 1024) (str n " B")
        (< n (* 1024 1024)) (String/format ^Locale (i18n/locale) "%.1f KB" (object-array [(/ n 1024.0)]))
        :else (String/format ^Locale (i18n/locale) "%.1f MB" (object-array [(/ n 1048576.0)]))))

(defn- confirm-overwrite? [^Shell parent path]
  (ui/confirm? parent (i18n/t :dialogs/overwrite-title) (i18n/t :dialogs/overwrite-question {:path path})))

(defn save-attachment!
  "Saves an attachment via the file dialog (as KeePass: Save As)."
  [app ^Shell parent nm get-bytes]
  (when-let [path (choose-file parent :save false nm)]
    (when (or (not (fs/exists? path))
              (confirm-overwrite? parent path))
      (let [data (call app get-bytes)]
        (when (ok? data)
          (fs/write-bytes path data)
          true)))))

;; ================================================================ History: view an older version

(defn- history-view [app ^Shell parent id version v]
  (let [pw-shown (atom false)
        dlg (ui/dialog parent {:title (i18n/t :dialogs/hist-view-title) :icon-name "history"
                               :heading (if-let [d (not-empty (fmt-date (:date v)))]
                                          (i18n/t :dialogs/hist-view-heading-date {:version version :date d})
                                          (i18n/t :dialogs/hist-view-heading {:version version}))
                               :sub (i18n/t :dialogs/hist-view-sub) :width 560}
                       (fn [^Composite body]
                         (let [f (form body)
                               row (fn [cap val] (ui/label f cap) (ui/text f (str val) :read-only true))]
                           (row (i18n/t :dialogs/entry-title) (:title v))
                           (row (i18n/t :dialogs/entry-username) (:username v))
                           (ui/label f (i18n/t :dialogs/password))
                           (let [pr (ui/composite f (ui/grid 3 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
                                 t (ui/text pr "********" :read-only true)]
                             (ui/button pr "" #(do (swap! pw-shown not) (.setText t (if @pw-shown (str (:password v)) "********")))
                                        :image (ui/icon (display app) "eye") :data (ui/gd :w 30))
                             (ui/button pr "" #((:copy-text! app) (str (:password v)) (i18n/t :dialogs/password-noun))
                                        :image (ui/icon (display app) "clipboard") :data (ui/gd :w 30)))
                           (row (i18n/t :dialogs/entry-url) (:url v))
                           (row (i18n/t :dialogs/entry-tags) (:tags v))
                           (row (i18n/t :dialogs/entry-expires) (:expires v))
                           (ui/label f (i18n/t :dialogs/entry-notes) (ui/gd :valign :top))
                           (ui/text f (str (:notes v)) :multi true :read-only true :data (ui/gd :fill :both :grab :both :h 70))
                           (row (i18n/t :dialogs/hist-view-fields) (str/join ", " (map :name (:custom-fields v))))
                           (row (i18n/t :dialogs/hist-view-attachments) (str/join ", " (map :name (:attachments v))))))
                       [[(i18n/t :dialogs/close) nil :default]])]
    (ui/run-modal! (:shell dlg))))

;; ================================================================ Entry

(defn- table ^Table [^Composite parent cols & [data]]
  (let [t (Table. parent (int (bit-or SWT/BORDER SWT/FULL_SELECTION SWT/SINGLE)))]
    (.setHeaderVisible t true)
    (.setLinesVisible t false)
    (.setLayoutData t (or data (ui/gd :fill :both :grab :both :h 180)))
    (doseq [[c w] cols] (doto (TableColumn. t SWT/NONE) (.setText c) (.setWidth (int w))))
    t))

(defn- row! ^TableItem [^Table t cells & [data]]
  (let [it (TableItem. t SWT/NONE)]
    (.setText it ^"[Ljava.lang.String;" (into-array String (map str cells)))
    (when data (.setData it data))
    it))

(defn- selected-index [^Table t] (.getSelectionIndex t))

(defn- quality-bar ^ProgressBar [^Composite parent]
  (doto (ProgressBar. parent (int (bit-or SWT/HORIZONTAL SWT/SMOOTH)))
    (.setMinimum 0) (.setMaximum 128)
    (.setLayoutData (ui/gd :fill :h :grab :h))))

(defn icon-dialog
  "Pick an icon: the 69 standard icons of KeePass. Returns the number or nil."
  [app current]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/icon-title) :icon-name "entry" :heading (i18n/t :dialogs/icon-title)
                                    :sub (i18n/t :dialogs/icon-sub) :width 460}
                       (fn [^Composite body]
                         (let [g (ui/composite body (ui/grid 12 :margin 0 :hs 2 :vs 2 :equal true))]
                           (doseq [i (range (count kp/standard-icons))]
                             (let [b (Button. g (int SWT/TOGGLE))]
                               (.setImage b ((:icon-image app) {:id i} "key"))
                               (.setToolTipText b (str i ": " (kp/standard-icons i)))
                               (.setSelection b (= i current))
                               (ui/on b SWT/Selection (fn [_] (reset! result i) (.close (.getShell b))))))))
                       [[(i18n/t :dialogs/cancel) nil :default]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn- hex->rgb ^RGB [h]
  (when-let [[_ r g b] (re-matches #"#(..)(..)(..)" (kp/norm-color h))]
    (RGB. (Integer/parseInt r 16) (Integer/parseInt g 16) (Integer/parseInt b 16))))

(defn- rgb->hex [^RGB c] (format "#%02X%02X%02X" (.-red c) (.-green c) (.-blue c)))

(defn- color-row
  "Color swatch with Choose/Default (KeePass: foreground/background color). on-change gets \"#RRGGBB\" or \"\"."
  [^Composite f caption value editable on-change]
  (ui/label f caption)
  (let [row (ui/composite f (ui/grid 3 :margin 0 :hs 6))
        ^Label sw (ui/label row "" (ui/gd :w 48 :h 18) (bit-or SWT/BORDER SWT/CENTER))
        cur (atom (kp/norm-color value))
        paint (fn [] (if-let [rgb (hex->rgb @cur)]
                       (do (.setBackground sw (Color. (.getDisplay sw) rgb)) (.setText sw ""))
                       (do (.setBackground sw nil) (.setText sw "–"))))
        pick! (fn [v] (reset! cur v) (paint) (on-change v))]
    (paint)
    (.setEnabled (ui/button row (i18n/t :dialogs/color-choose) #(let [cd (ColorDialog. (.getShell sw))]
                                                                  (when-let [rgb (hex->rgb @cur)] (.setRGB cd rgb))
                                                                  (when-let [rgb (.open cd)] (pick! (rgb->hex rgb))))
                            :data (ui/gd :w 90))
                 (boolean editable))
    (.setEnabled (ui/button row (i18n/t :dialogs/color-default) #(pick! "") :data (ui/gd :w 90)) (boolean editable))))

(defn entry-dialog
  "Add (id nil), edit or view an entry. Tabs as in KeePass:
   Entry, Advanced, Share (server only), History, Properties.
   Returns the ID after saving, else nil."
  [app id & [start-tab]]
  (let [s (session app)
        entry (if id
                (call app #(svc/get-entry s id))
                {:title "" :username (str ((or (:default-username app) (constantly "")))) :password "" :url "" :notes ""
                 :folder ((:folder app)) :expires "" :tags "" :custom-fields [] :attachments [] :permission "owner"})]
    (when (ok? entry)
      (let [editable (or (nil? id) (>= (perm-rank (:permission entry) 0) 2))
            owner (or (nil? id) (= "owner" (:permission entry)))
            local (local? app)
            custom (atom (vec (:custom-fields entry)))
            ;; Attachments: saved ones + new ones (with :data); removed saved ones go to detach
            atts (atom (vec (:attachments entry)))
            detach (atom #{})
            share (atom nil)
            look (atom {})
            result (atom nil)
            dlg
            (ui/dialog
             (shell app)
             {:title (cond (nil? id) (i18n/t :dialogs/entry-add-title) editable (i18n/t :dialogs/entry-edit-title)
                           :else (i18n/t :dialogs/entry-view-title))
              :icon-name "entry"
              :heading (if id (let [t (:title entry)] (if (str/blank? t) (i18n/t :dialogs/entry-untitled) t)) (i18n/t :dialogs/entry-new))
              :sub (cond local (let [f (:folder entry)] (if (str/blank? f) (i18n/t :dialogs/entry-database) f))
                         id (str (perm-label (:permission entry)) (when-not (str/blank? (:folder entry)) (str " - " (:folder entry))))
                         :else (i18n/t :dialogs/entry-new-sub))
              :width 640}
             (fn [^Composite body]
               (let [tabs (TabFolder. body SWT/TOP)
                     _ (.setLayoutData tabs (ui/gd :fill :both :grab :both))
                     page (fn [txt] (let [c (ui/composite tabs (ui/grid 1 :margin 10))
                                          ti (TabItem. tabs SWT/NONE)]
                                      (.setText ti txt) (.setControl ti c) [ti c]))
                     ;; ---------------------------------------------- Entry
                     [_ p1] (page (i18n/t :dialogs/tab-entry))
                     _ (when-not editable
                         (ui/wrap-label p1 (i18n/t :dialogs/entry-read-only) 560))
                     _ (doseq [w (:warnings entry)] (ui/wrap-label p1 (i18n/t :dialogs/entry-warning {:warning w}) 560))
                     f (form p1)
                     txt (fn [cap v & opts] (ui/label f cap) (let [^Text t (apply ui/text f v opts)] (.setEditable t editable) t))
                     ^Text title (do (ui/label f (i18n/t :dialogs/entry-title))
                                     (let [row (ui/composite f (ui/grid 2 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
                                           t (ui/text row (:title entry))
                                           b (ui/button row "" nil :image ((:icon-image app) (:icon entry) "key") :data (ui/gd :w 30))]
                                       (.setEditable t editable)
                                       (.setEnabled b editable)
                                       (.setToolTipText b (i18n/t :dialogs/icon-tooltip))
                                       (ui/on b SWT/Selection
                                              (fn [_] (when-let [i (icon-dialog app (if (get-in entry [:icon :custom]) -1 (get-in entry [:icon :id] 0)))]
                                                        (swap! look assoc :icon-id i)
                                                        (.setImage b ((:icon-image app) {:id i} "key")))))
                                       t))
                     user (txt (i18n/t :dialogs/entry-username) (:username entry))
                     _ (ui/label f (i18n/t :dialogs/password))
                     prow (ui/composite f (ui/grid 3 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
                     pw (ui/text prow (:password entry) :password true)
                     _ (.setEditable pw editable)
                     _ (ui/label f (i18n/t :dialogs/repeat))
                     pw2 (ui/text f (:password entry) :password true)
                     _ (.setEditable pw2 editable)
                     _ (ui/label f (i18n/t :dialogs/quality))
                     qrow (ui/composite f (ui/grid 2 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                     ^ProgressBar qbar (quality-bar qrow)
                     qtxt (ui/label qrow "" (ui/gd :w 60))
                     update-q (fn [] (let [q (svc/password-quality (.getText pw))]
                                       (.setSelection qbar (int (min 128 q))) (.setText qtxt (bits-text q))))
                     masked (atom true)
                     ;; SWT cannot toggle the password mode: recreating the field would be
                     ;; costly; instead the plain text is shown in a separate read-only
                     ;; field below (no tooltip), not in the repeat field.
                     reveal (ui/text f "" :read-only true :data (ui/gd :fill :h :grab :h :span 2 :exclude true))
                     _ (.setVisible reveal false)
                     url (txt (i18n/t :dialogs/entry-url) (:url entry))
                     ^Text tags (txt (i18n/t :dialogs/entry-tags) (:tags entry))
                     _ (.setToolTipText tags (i18n/t :dialogs/tags-tooltip))
                     _ (ui/label f (i18n/t :dialogs/entry-notes) (ui/gd :valign :top))
                     notes (ui/text f (:notes entry) :multi true :data (ui/gd :fill :both :grab :both :h 90))
                     _ (.setEditable notes editable)
                     ^Combo folder (do (ui/label f (i18n/t :dialogs/entry-group))
                                       (doto (Combo. f (int (bit-or SWT/DROP_DOWN SWT/BORDER)))
                                         (.setLayoutData (ui/gd :fill :h :grab :h))
                                         (.setItems ^"[Ljava.lang.String;" (into-array String (or (some-> (:groups app) (apply [])) [])))
                                         (.setText (str (:folder entry)))
                                         (.setEnabled (boolean editable))
                                         (.setToolTipText (i18n/t :dialogs/entry-group-tooltip))))
                     _ (ui/label f (i18n/t :dialogs/entry-expires))
                     erow (ui/composite f (ui/grid 3 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                     exp? (ui/check erow "" (not (str/blank? (:expires entry))))
                     ^DateTime exp (DateTime. erow (int (bit-or SWT/DATE SWT/DROP_DOWN SWT/BORDER)))
                     ^DateTime exp-t (DateTime. erow (int (bit-or SWT/TIME SWT/SHORT SWT/BORDER)))
                     _ (when-let [^LocalDateTime t (expires->local (:expires entry))]
                         (.setDate exp (.getYear t) (dec (.getMonthValue t)) (.getDayOfMonth t))
                         (.setTime exp-t (.getHour t) (.getMinute t) 0))
                     _ (when (str/blank? (:expires entry)) (.setTime exp-t 0 0 0))
                     exp-shown (widgets->expires exp exp-t)
                     _ (doseq [^Control c [exp exp-t]] (.setEnabled c (boolean (and editable (.getSelection exp?)))))
                     _ (.setEnabled exp? editable)
                     _ (ui/on exp? SWT/Selection (fn [_] (doseq [^Control c [exp exp-t]] (.setEnabled c (.getSelection exp?)))))
                     ;; ---------------------------------------------- Advanced
                     [_ p2] (page (i18n/t :dialogs/tab-advanced))
                     _ (ui/label p2 (i18n/t :dialogs/fields-label))
                     ct (table p2 [[(i18n/t :dialogs/col-name) 180] [(i18n/t :dialogs/col-value) 300]])
                     render-custom (fn []
                                     (.removeAll ct)
                                     (doseq [{:keys [name value protected]} @custom]
                                       (row! ct [name (if protected "********" (ui/first-line value))])))
                     cbar (ui/composite p2 (ui/grid 4 :margin 0 :hs 6) (ui/gd :fill :h))
                     edit-field (fn [i]
                                  (when-let [r (field-dialog (.getShell ct) (when i (nth @custom i)))]
                                    (swap! custom #(if i (assoc % i r) (conj % r)))
                                    (render-custom)))
                     _ (doseq [[t f] [[(i18n/t :dialogs/add) #(edit-field nil)]
                                      [(i18n/t :dialogs/edit) #(let [i (selected-index ct)] (when (>= i 0) (edit-field i)))]
                                      [(i18n/t :dialogs/delete) #(let [i (selected-index ct)]
                                                                   (when (>= i 0)
                                                                     (swap! custom (fn [v] (vec (concat (subvec v 0 i) (subvec v (inc i))))))
                                                                     (render-custom)))]]]
                         (.setEnabled (ui/button cbar t f :data (ui/gd :w 90)) editable))
                     _ (.setEnabled (ui/button cbar (i18n/t :dialogs/totp-setup-button)
                                               #(when-let [fld (totp-dialog (.getShell ct) (.getText title))]
                                                  (swap! custom (fn [v] (conj (vec (remove (fn [x] (otp/field-names (:name x))) v)) fld)))
                                                  (render-custom))
                                               :data (ui/gd :w 130))
                                    editable)
                     _ (when editable (ui/on ct SWT/DefaultSelection (fn [_] (let [i (selected-index ct)] (when (>= i 0) (edit-field i))))))
                     _ (render-custom)
                     _ (ui/label p2 (i18n/t :dialogs/attachments-label))
                     att (table p2 [[(i18n/t :dialogs/col-name) 300] [(i18n/t :dialogs/col-size) 100]] (ui/gd :fill :both :grab :both :h 90))
                     render-att (fn []
                                  (.removeAll att)
                                  (doseq [{:keys [name size data]} @atts]
                                    (row! att [name (if data (i18n/t :dialogs/attach-new {:size (fmt-size size)}) (fmt-size size))])))
                     abar (ui/composite p2 (ui/grid 3 :margin 0 :hs 6) (ui/gd :fill :h))
                     _ (.setEnabled
                        (ui/button abar (i18n/t :dialogs/attach-button)
                                   #(when-let [path (choose-file (.getShell att) :open false nil)]
                                      (let [data (fs/read-bytes path)
                                            nm (fs/file-name path)
                                            limit (if local (* 64 1024 1024) (* 2 1024 1024))]
                                        (if (> (alength data) limit)
                                          (ui/message! (.getShell att) :warn (i18n/t :dialogs/attach-title)
                                                       (i18n/t (if local :dialogs/attach-too-large-local :dialogs/attach-too-large-server)
                                                               {:max (fmt-size limit)}))
                                          (do (swap! atts (fn [v] (conj (vec (remove (fn [x] (= nm (:name x))) v))
                                                                         {:name nm :size (alength data) :data data})))
                                              (render-att)))))
                                   :data (ui/gd :w 110))
                        editable)
                     _ (ui/button abar (i18n/t :dialogs/save-as)
                                  #(let [i (selected-index att)]
                                     (when (>= i 0)
                                       (let [{:keys [name data]} (nth @atts i)]
                                         (save-attachment! app (.getShell att) name
                                                           (if data (constantly data) (fn [] (svc/attachment-data s id name)))))))
                                  :data (ui/gd :w 120))
                     _ (.setEnabled
                        (ui/button abar (i18n/t :dialogs/remove)
                                   #(let [i (selected-index att)]
                                      (when (>= i 0)
                                        (let [{:keys [name data]} (nth @atts i)]
                                          (when-not data (swap! detach conj name))
                                          (swap! atts (fn [v] (vec (concat (subvec v 0 i) (subvec v (inc i))))))
                                          (render-att))))
                                   :data (ui/gd :w 90))
                        editable)
                     _ (render-att)
                     ;; ---------------------------------------------- Share (server only)
                     share-tab
                     (when-not local
                       (let [[_ p3] (page (i18n/t :dialogs/tab-share))]
                         (if-not id
                           (do (ui/label p3 (i18n/t :dialogs/share-save-first)) nil)
                           (let [info (call app #(svc/get-acl s id))
                                 principals (if owner (let [r (call app #(svc/principals s))] (if (ok? r) r [])) [])
                                 acl (atom (if (ok? info) (vec (:acl info)) []))
                                 original (mapv (juxt :principal :permission) @acl)
                                 _ (when-not owner (ui/label p3 (i18n/t :dialogs/share-owner-only)))
                                 st (table p3 [[(i18n/t :dialogs/col-principal) 260] [(i18n/t :dialogs/col-kind) 110] [(i18n/t :dialogs/col-permission) 140]])
                                 render (fn []
                                          (.removeAll st)
                                          (doseq [{:keys [kind members active permission principal] disp :display} @acl]
                                            (let [it (row! st [disp
                                                               (if (= kind "group") (i18n/t :dialogs/share-kind-group {:members members})
                                                                   (let [k (if (= principal (str "u:" ((:me app))))
                                                                             (i18n/t :dialogs/share-kind-you)
                                                                             (i18n/t :dialogs/share-kind-user))]
                                                                     (if active k (i18n/t :dialogs/share-kind-deactivated {:kind k}))))
                                                               (perm-label permission)])]
                                              (.setImage it (ui/icon (display app) (if (= kind "group") "group" "user"))))))
                                 bar (ui/composite p3 (ui/grid 4 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                                 pc (ui/combo bar (perm-labels) (perm-label "read") (ui/gd :w 130))
                                 _ (ui/button bar (i18n/t :dialogs/share-set-permission)
                                              #(let [i (selected-index st)]
                                                 (when (>= i 0)
                                                   (swap! acl assoc-in [i :permission] (first (nth perms (.getSelectionIndex pc))))
                                                   (render)))
                                              :data (ui/gd :w 100))
                                 _ (ui/button bar (i18n/t :dialogs/remove)
                                              #(let [i (selected-index st)]
                                                 (when (>= i 0) (swap! acl (fn [v] (vec (concat (subvec v 0 i) (subvec v (inc i)))))) (render)))
                                              :data (ui/gd :w 90))
                                 _ (ui/label bar "")
                                 add (ui/composite p3 (ui/grid 3 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                                 _ (ui/label add (i18n/t :dialogs/add-label))
                                 ^Combo who (Combo. add (int (bit-or SWT/DROP_DOWN SWT/READ_ONLY)))
                                 candidates (fn [] (let [present (set (map :principal @acl))]
                                                     (vec (remove #(present (:principal %)) principals))))
                                 fill-who (fn [] (.setItems who ^"[Ljava.lang.String;"
                                                            (into-array String (for [p (candidates)]
                                                                                 (if (= "group" (:kind p))
                                                                                   (i18n/t :dialogs/share-group-suffix {:name (:display p)})
                                                                                   (str (:display p)))))))
                                 _ (.setLayoutData who (ui/gd :fill :h :grab :h))
                                 _ (ui/button add (i18n/t :dialogs/add)
                                              #(let [i (.getSelectionIndex who)]
                                                 (when (>= i 0)
                                                   (swap! acl conj (assoc (nth (candidates) i) :permission "read"))
                                                   (render) (fill-who)))
                                              :data (ui/gd :w 100))
                                 _ (ui/wrap-label p3 (i18n/t :dialogs/share-revoke-hint) 560)]
                             (doseq [^Composite c [bar add]] (doseq [ch (.getChildren c)] (.setEnabled ^org.eclipse.swt.widgets.Control ch owner)))
                             (render) (fill-who)
                             {:changed? #(not= original (mapv (juxt :principal :permission) @acl))
                              :acl acl}))))
                     _ (reset! share share-tab)
                     ;; ---------------------------------------------- History
                     [^TabItem hist-item p4] (page (i18n/t :dialogs/tab-history))
                     ht (table p4 [[(i18n/t :dialogs/col-version) 70] [(i18n/t :dialogs/col-date) 150]
                                   [(i18n/t :dialogs/col-author) 140] [(i18n/t :dialogs/col-status) 180]])
                     hist (atom [])
                     load-hist (fn [& [force]]
                                 (when (and id (or force (zero? (.getItemCount ht))))
                                   (let [h (call app #(svc/history s id))]
                                     (when (ok? h)
                                       (.removeAll ht)
                                       (reset! hist (vec h))
                                       (doseq [[i v] (map-indexed vector h)]
                                         (row! ht [(:version v) (fmt-date (:date v)) (or (:author v) "")
                                                   (cond (not (:valid v)) (i18n/t :dialogs/hist-status-rejected {:reason (:reason v)})
                                                         (:deleted v) (i18n/t :dialogs/hist-status-deleted)
                                                         (zero? i) (i18n/t :dialogs/hist-status-current)
                                                         :else (i18n/t :dialogs/hist-status-valid))]))))))
                     ;; Selection in the history: only older, valid versions
                     picked (fn [] (let [i (selected-index ht)
                                         v (when (pos? i) (get @hist i))]
                                     (when (and v (:valid v) (not (:deleted v))) v)))
                     hbar (ui/composite p4 (ui/grid 3 :margin 0 :hs 6) (ui/gd :fill :h))
                     restored (atom false)
                     _ (ui/button hbar (i18n/t :dialogs/hist-show)
                                  #(when-let [v (picked)]
                                     (let [e (call app (fn [] (svc/history-entry s id (:version v))))]
                                       (when (ok? e) (history-view app (.getShell ht) id (:version v) e))))
                                  :data (ui/gd :w 100))
                     _ (.setEnabled
                        (ui/button hbar (i18n/t :dialogs/hist-restore)
                                   #(when-let [v (picked)]
                                      (when (and (ui/confirm? (.getShell ht) (i18n/t :dialogs/hist-restore)
                                                              (i18n/t :dialogs/hist-restore-question {:version (:version v)}))
                                                 (ok? (call app (fn [] (svc/restore-history s id (:version v))))))
                                        (reset! restored true)
                                        (.close (.getShell ht))))
                                   :data (ui/gd :w 120))
                        (boolean (and id editable)))
                     _ (when local
                         (.setEnabled
                          (ui/button hbar (i18n/t :dialogs/delete)
                                     #(when-let [v (picked)]
                                        (when (and (ui/confirm? (.getShell ht) (i18n/t :dialogs/tab-history)
                                                                (i18n/t :dialogs/hist-delete-question {:version (:version v)}))
                                                   (ok? (call app (fn [] (svc/delete-history s id (:version v))))))
                                          (load-hist true)))
                                     :data (ui/gd :w 90))
                          (boolean (and id editable))))
                     _ (ui/on ht SWT/DefaultSelection
                              (fn [_] (when-let [v (picked)]
                                        (let [e (call app (fn [] (svc/history-entry s id (:version v))))]
                                          (when (ok? e) (history-view app (.getShell ht) id (:version v) e))))))
                     _ (ui/on (.getShell ht) SWT/Dispose (fn [_] (when @restored (reset! result [:saved id]))))
                     ;; ---------------------------------------------- Properties
                     [_ p5] (page (i18n/t :dialogs/tab-properties))
                     pf (form p5)
                     _ (doseq [[k v] (cond-> [[(i18n/t :dialogs/props-id) (or id (i18n/t :dialogs/props-new))]
                                              [(i18n/t :dialogs/props-version) (str (or (:version entry) "-"))]
                                              [(i18n/t :dialogs/props-modified)
                                               (let [d (fmt-date (:modified entry))]
                                                 (if-let [b (:modified-by entry)] (i18n/t :dialogs/props-modified-by {:date d :user b}) (str d)))]]
                                       (not local) (conj [(i18n/t :dialogs/props-permission) (perm-label (:permission entry) "")]))]
                         (ui/label pf k)
                         (ui/text pf v :read-only true))
                     _ (doseq [[k cap] [[:fg (i18n/t :dialogs/props-fg-color)] [:bg (i18n/t :dialogs/props-bg-color)]]]
                         (color-row pf cap (get-in entry [:colors k]) editable #(swap! look assoc k %)))]
                 (ui/button prow "" #(do (swap! masked not)
                                         (.setText reveal (.getText pw))
                                         (ui/show! reveal (not @masked)))
                            :image (ui/icon (display app) "eye") :data (ui/gd :w 30))
                 (.setEnabled (ui/button prow "" #(when-let [p (generator app true)] (.setText pw p) (.setText pw2 p) (update-q))
                                         :image (ui/icon (display app) "gen") :data (ui/gd :w 30))
                              editable)
                 (ui/on pw SWT/Modify (fn [_] (update-q) (when-not @masked (.setText reveal (.getText pw)))))
                 (update-q)
                 (ui/on tabs SWT/Selection (fn [_] (when (= hist-item (aget (.getSelection tabs) 0)) (load-hist))))
                 (let [start (case start-tab :advanced 1 :share (when share-tab 2) :history (if local 2 3) nil)]
                   (when start (.setSelection tabs (int start)) (when (= start-tab :history) (load-hist))))
                 (.setFocus title)
                 {:title title :user user :pw pw :pw2 pw2 :url url :tags tags :notes notes :folder folder :exp? exp? :exp exp
                  :exp-t exp-t :exp-shown exp-shown}))
             (cond-> []
               id (conj [(i18n/t :dialogs/duplicate) (fn [d] (reset! result [:duplicate id]) (ui/close! d)) :left])
               true (conj [(i18n/t :dialogs/ok)
                           (fn [{:keys [ctx] :as d}]
                             (let [{:keys [^Text title ^Text user ^Text pw ^Text pw2 ^Text url ^Text tags ^Text notes ^Combo folder
                                           ^Button exp? ^DateTime exp ^DateTime exp-t exp-shown]} ctx]
                               (if (and editable (not= (.getText pw) (.getText pw2)))
                                 (ui/message! (:shell d) :warn (i18n/t :dialogs/password-noun) (i18n/t :dialogs/password-mismatch))
                                 (let [payload {:id (or id "") :title (.getText title) :username (.getText user)
                                                :password (.getText pw) :url (.getText url) :notes (.getText notes)
                                                :folder (.getText folder) :tags (.getText tags)
                                                :expires (cond
                                                           (not (.getSelection exp?)) ""
                                                           ;; unchanged: as saved (plain date too)
                                                           (and (seq (:expires entry)) (= exp-shown (widgets->expires exp exp-t))) (:expires entry)
                                                           :else (widgets->expires exp exp-t))
                                                :custom-fields @custom
                                                :look @look
                                                :attach (vec (for [a @atts :when (:data a)] (select-keys a [:name :data])))
                                                :detach (vec @detach)}
                                       changed? (or (nil? id)
                                                    (some #(not= (str (get entry %)) (str (get payload %)))
                                                          [:title :username :password :url :notes :folder :expires :tags])
                                                    (not= (vec (:custom-fields entry)) @custom)
                                                    (seq (:attach payload)) (seq (:detach payload)))
                                       saved (if (and editable changed?) (call app #(svc/save-entry s payload)) id)]
                                   (when (ok? saved)
                                     (let [sh @share
                                           shared (if (and sh ((:changed? sh)))
                                                    (let [acl @(:acl sh)]
                                                      (if (some #(= "owner" (:permission %)) acl)
                                                        (call app #(svc/set-acl s id (mapv (fn [a] (select-keys a [:principal :permission])) acl)))
                                                        (do (ui/message! (:shell d) :warn (i18n/t :dialogs/tab-share) (i18n/t :dialogs/share-owner-required))
                                                            ::failed)))
                                                    true)]
                                       (when (ok? shared)
                                         (reset! result [:saved saved])
                                         (ui/close! d))))))))
                           :default])
               true (conj [(i18n/t :dialogs/cancel) nil])))]
        (ui/run-modal! (:shell dlg))
        @result))))

;; ================================================================ KeePass import/export

(def ^:private import-formats
  [[:kdbx :dialogs/import-format-kdbx]
   [:xml :dialogs/format-xml]
   [:csv :dialogs/import-format-csv]])

(defn- format-of-file [path]
  (condp re-find (str/lower-case (str path))
    #"\.xml$" :xml
    #"\.(csv|txt)$" :csv
    #"\.kdbx$" :kdbx
    nil))

(defn import-dialog [app]
  (let [result (atom nil)
        local (local? app)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/import-title) :icon-name "import" :heading (i18n/t :dialogs/import-title)
                                    :sub (i18n/t :dialogs/import-sub) :width 580}
                       (fn [^Composite body]
                         (let [f (form body)
                               labels (map (comp i18n/t second) import-formats)
                               fmt (do (ui/label f (i18n/t :dialogs/format)) (ui/combo f labels (first labels)
                                                                                         (ui/gd :fill :h :grab :h)))
                               file (do (ui/label f (i18n/t :dialogs/file)) (file-field f "" :open false))
                               pw (do (ui/label f (i18n/t :dialogs/password)) (ui/text f "" :password true))
                               kf (do (ui/label f (i18n/t :dialogs/key-file)) (file-field f "" :open false))
                               hint (ui/wrap-label f "" 500 2)
                               err (error-label f 2)
                               sync (fn []
                                      (let [k (first (get import-formats (.getSelectionIndex fmt)))]
                                        (.setEnabled pw (= k :kdbx)) (.setEnabled (.getParent kf) (= k :kdbx))
                                        (.setText hint (case k
                                                         :csv (i18n/t :dialogs/import-hint-csv)
                                                         (if local
                                                           (i18n/t :dialogs/import-hint-local)
                                                           (i18n/t :dialogs/import-hint-server))))
                                        (.layout (.getParent hint) true)))]
                           (ui/on fmt SWT/Selection (fn [_] (sync)))
                           (ui/on file SWT/Modify (fn [_] (when-let [k (format-of-file (.getText file))]
                                                            (.select fmt (int (.indexOf ^java.util.List (mapv first import-formats) k)))
                                                            (sync))))
                           (sync)
                           {:fmt fmt :file file :pw pw :kf kf :err err}))
                       [[(i18n/t :dialogs/import-button) (fn [{:keys [ctx] :as d}]
                                                           (let [{:keys [^Combo fmt ^Text file ^Text pw ^Text kf err]} ctx
                                                                 k (first (get import-formats (.getSelectionIndex fmt)))
                                                                 path (str/trim (.getText file))]
                                                             (if (str/blank? path)
                                                               (set-error! err (i18n/t :dialogs/file-required))
                                                               (try
                                                                 (let [r (ui/busy (display app)
                                                                                  #(svc/import-file (session app) {:format k
                                                                                                                   :data (fs/read-bytes path)
                                                                                                                   :password (not-empty (.getText pw))
                                                                                                                   :keyfile (read-keyfile kf)
                                                                                                                   :source (fs/file-name path)}))]
                                                                   (reset! result r)
                                                                   (ui/close! d))
                                                                 (catch Throwable e (set-error! err e))))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn- new-password-rows
  "Master password + repeat + key file."
  [^Composite f]
  {:pw (do (ui/label f (i18n/t :dialogs/master-password)) (ui/text f "" :password true))
   :pw2 (do (ui/label f (i18n/t :dialogs/repeat)) (ui/text f "" :password true))
   :kf (do (ui/label f (i18n/t :dialogs/key-file)) (file-field f "" :open false))})

(defn- check-new-password [{:keys [^Text pw ^Text pw2 ^Text kf]}]
  (cond
    (not= (.getText pw) (.getText pw2)) (i18n/t :dialogs/password-mismatch)
    (and (str/blank? (.getText pw)) (str/blank? (.getText kf))) (i18n/t :dialogs/master-key-required)
    :else nil))

(def ^:private export-formats
  [[:kdbx :dialogs/export-format-kdbx "kdbx"]
   [:xml :dialogs/format-xml "xml"]
   [:csv :dialogs/export-format-csv "csv"]
   [:html :dialogs/export-format-html "html"]
   [:xsl :dialogs/export-format-xsl "html"]])

(defn export-dialog
  "Export as in KeePass. start: format the dialog starts with
   (:html for File > Print). Returns {:file :count :format}."
  [app & [start]]
  (let [local (local? app)
        result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/export-title) :icon-name "export" :heading (i18n/t :dialogs/export-title)
                                    :sub (i18n/t :dialogs/export-sub) :width 600}
                       (fn [^Composite body]
                         (let [f (form body)
                               fmt (do (ui/label f (i18n/t :dialogs/format))
                                       (ui/combo f (map (comp i18n/t second) export-formats)
                                                 (i18n/t (second (or (first (filter #(= start (first %)) export-formats))
                                                                     (first export-formats))))
                                                 (ui/gd :fill :h :grab :h)))
                               file (do (ui/label f (i18n/t :dialogs/file))
                                        (file-field f (str (fs/path (System/getProperty "user.home") (str "cljpass-" (LocalDate/now) ".kdbx")))
                                                    :save false))
                               xsl (do (ui/label f (i18n/t :dialogs/export-xsl)) (file-field f "" :open false))
                               rows (new-password-rows f)
                               pws (do (ui/label f "") (ui/check f (i18n/t :dialogs/export-print-passwords) false))
                               open? (do (ui/label f "") (ui/check f (i18n/t :dialogs/export-open-browser) true))
                               hint (ui/wrap-label f "" 500 2)
                               err (error-label f 2)
                               sync (fn []
                                      (let [[k _ ext] (get export-formats (.getSelectionIndex fmt))]
                                        (doseq [^Control c [(:pw rows) (:pw2 rows) (.getParent ^Text (:kf rows))]] (.setEnabled c (= k :kdbx)))
                                        (.setEnabled (.getParent xsl) (= k :xsl))
                                        (.setEnabled pws (= k :html))
                                        (.setEnabled open? (boolean (#{:html :xsl} k)))
                                        (.setText file (str/replace (.getText file) #"\.[A-Za-z]+$" (str "." ext)))
                                        (.setText hint (case k
                                                         :kdbx (if local (i18n/t :dialogs/export-hint-kdbx-local)
                                                                   (i18n/t :dialogs/export-hint-kdbx-server))
                                                         :xsl (i18n/t :dialogs/export-hint-xsl)
                                                         (i18n/t :dialogs/export-hint-plain)))
                                        (.setForeground hint (.getSystemColor (display app) (if (= k :kdbx) SWT/COLOR_WIDGET_FOREGROUND SWT/COLOR_DARK_RED)))
                                        (.layout (.getParent hint) true)))]
                           (ui/on fmt SWT/Selection (fn [_] (sync)))
                           (sync)
                           (assoc rows :fmt fmt :file file :xsl xsl :pws pws :open open? :err err)))
                       [[(i18n/t :dialogs/export-button) (fn [{:keys [ctx] :as d}]
                                                           (let [{:keys [^Combo fmt ^Text file ^Text pw kf ^Text xsl ^Button pws ^Button open err]} ctx
                                                                 k (first (get export-formats (.getSelectionIndex fmt)))
                                                                 path (str/trim (.getText file))]
                                                             (if-let [problem (or (when (str/blank? path) (i18n/t :dialogs/target-file-required))
                                                                                  (when (= k :kdbx) (check-new-password ctx))
                                                                                  (when (and (= k :xsl) (str/blank? (.getText xsl))) (i18n/t :dialogs/xsl-required)))]
                                                               (set-error! err problem)
                                                               (when (or (not (fs/exists? path))
                                                                         (confirm-overwrite? (:shell d) path))
                                                                 (try
                                                                   (let [{:keys [data count]}
                                                                         (ui/busy (display app)
                                                                                  #(if (= k :kdbx)
                                                                                     (svc/export-kdbx (session app) {:password (not-empty (.getText pw)) :keyfile (read-keyfile kf)})
                                                                                     (svc/export-file (session app) {:format k :passwords (.getSelection pws)
                                                                                                                     :xsl (when (= k :xsl) (str/trim (.getText xsl)))})))]
                                                                     (fs/write-bytes path data)
                                                                     (when-not (local/windows?) (fs/set-owner-only! path))
                                                                     (when (and (#{:html :xsl} k) (.getSelection open)) (Program/launch path))
                                                                     (reset! result {:file path :count count :format k})
                                                                     (ui/close! d))
                                                                   (catch Throwable e (set-error! err e)))))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Synchronize with a file (as KeePass)

(defn sync-file-dialog [app]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/sync-title) :icon-name "conflict" :heading (i18n/t :dialogs/sync-heading)
                                    :sub (i18n/t :dialogs/sync-sub) :width 580}
                       (fn [^Composite body]
                         (let [f (form body)
                               file (do (ui/label f (i18n/t :dialogs/sync-other-file)) (file-field f "" :open true))
                               pw (do (ui/label f (i18n/t :dialogs/sync-your-password)) (ui/text f "" :password true))
                               kf (do (ui/label f (i18n/t :dialogs/key-file)) (file-field f "" :open false))
                               err (error-label f 2)]
                           (ui/wrap-label f (i18n/t :dialogs/sync-hint) 500 2)
                           {:file file :pw pw :kf kf :err err}))
                       [[(i18n/t :dialogs/sync-button) (fn [{:keys [ctx] :as d}]
                                                         (let [{:keys [^Text file ^Text pw kf err]} ctx]
                                                           (try
                                                             (reset! result (ui/busy (display app)
                                                                                     #(svc/sync-file! (session app) {:file (str/trim (.getText file))
                                                                                                                     :password (not-empty (.getText pw))
                                                                                                                     :keyfile (read-keyfile kf)})))
                                                             (ui/close! d)
                                                             (catch Throwable e (set-error! err e)))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Switch file <-> server

(defn connect-dialog
  "Local file -> server. Returns the link status or nil."
  [app defaults]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/connect-title) :icon-name "share" :heading (i18n/t :dialogs/connect-title)
                                    :sub (i18n/t :dialogs/connect-sub) :width 580}
                       (fn [^Composite body]
                         (let [f (form body)
                               server (do (ui/label f (i18n/t :dialogs/connect-server)) (ui/text f (or (:server defaults) "")))
                               hash (do (ui/label f (i18n/t :dialogs/connect-org-hash)) (ui/text f (or (:org-hash defaults) "")))
                               user (do (ui/label f (i18n/t :dialogs/entry-username)) (ui/text f (or (:user defaults) "")))
                               krb (ui/check f (i18n/t :desktop/label-kerberos) (true? (:kerberos defaults)) (ui/gd :span 2))
                               err (error-label f 2)]
                           (ui/wrap-label f (i18n/t :dialogs/connect-hint) 500 2)
                           {:server server :hash hash :user user :krb krb :err err}))
                       [[(i18n/t :dialogs/connect-button) (fn [{:keys [ctx] :as d}]
                                                            (let [{:keys [^Text server ^Text hash ^Text user ^Button krb err]} ctx]
                                                              (try
                                                                (reset! result (ui/busy (display app)
                                                                                        #(svc/connect-server! (session app)
                                                                                                              {:server (str/trim (.getText server))
                                                                                                               :org-hash (str/trim (.getText hash))
                                                                                                               :user (str/trim (.getText user))
                                                                                                               :kerberos (.getSelection krb)})))
                                                                (ui/close! d)
                                                                (catch Throwable e (set-error! err e)))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn disconnect-dialog
  "Server -> local file. Returns {:file :count} or nil."
  [app file]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/disconnect-title) :icon-name "export" :heading (i18n/t :dialogs/disconnect-title)
                                    :sub (i18n/t :dialogs/disconnect-sub) :width 600}
                       (fn [^Composite body]
                         (let [f (form body)
                               t (do (ui/label f (i18n/t :dialogs/file)) (file-field f file :save true))
                               rows (new-password-rows f)
                               err (error-label f 2)]
                           (ui/wrap-label f (i18n/t :dialogs/disconnect-hint) 520 2)
                           (assoc rows :file t :err err)))
                       [[(i18n/t :dialogs/disconnect-button)
                         (fn [{:keys [ctx] :as d}]
                           (let [{:keys [^Text file ^Text pw kf err]} ctx]
                             (if-let [problem (check-new-password ctx)]
                               (set-error! err problem)
                               (loop [opts {:file (str/trim (.getText file)) :password (.getText pw) :keyfile (read-keyfile kf)}]
                                 (let [r (try (ui/busy (display app) #(svc/disconnect! (session app) opts))
                                              (catch Throwable e e))]
                                   (if-not (instance? Throwable r)
                                     (do (reset! result r) (ui/close! d))
                                     (let [t (:type (ex-data r))]
                                       (cond
                                         (and (= t :exists)
                                              (ui/confirm? (:shell d) (i18n/t :dialogs/overwrite-title)
                                                           (i18n/t :dialogs/disconnect-overwrite-question {:message (ex-message r)})))
                                         (recur (assoc opts :overwrite true))
                                         (and (= t :pending-changes)
                                              (ui/confirm? (:shell d) (i18n/t :dialogs/disconnect-pending-title)
                                                           (i18n/t :dialogs/disconnect-pending-question {:message (ex-message r)})))
                                         (recur (assoc opts :force true))
                                         (#{:exists :pending-changes} t) nil
                                         :else (set-error! err r)))))))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Master key, database settings (local)

(defn master-key-dialog
  "File > Change Master Key. Returns true after the change."
  [app]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/master-key-title) :icon-name "lock" :heading (i18n/t :dialogs/master-key-title)
                                    :sub (i18n/t :dialogs/master-key-sub) :width 560}
                       (fn [^Composite body]
                         (let [f (form body)
                               rows (new-password-rows f)
                               err (error-label f 2)]
                           (ui/wrap-label f (i18n/t :dialogs/master-key-hint) 480 2)
                           (assoc rows :err err)))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (let [{:keys [^Text pw kf err]} ctx]
                                                 (if-let [problem (check-new-password ctx)]
                                                   (set-error! err problem)
                                                   (try
                                                     (ui/busy (display app) #(svc/change-master-key! (session app) {:password (.getText pw)
                                                                                                                    :keyfile (read-keyfile kf)}))
                                                     (reset! result true)
                                                     (ui/close! d)
                                                     (catch Throwable e (set-error! err e))))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn db-settings-dialog
  "File > Database Settings (as KeePass). Returns true after saving."
  [app]
  (let [cur (call app #(svc/db-settings (session app)))]
    (when (ok? cur)
      (let [result (atom nil)
            dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/db-settings-title) :icon-name "gear" :heading (i18n/t :dialogs/db-settings-title)
                                        :sub (i18n/t :dialogs/db-settings-sub) :width 560}
                           (fn [^Composite body]
                             (let [f (form body)
                                   nm (do (ui/label f (i18n/t :dialogs/name)) (ui/text f (:name cur)))
                                   desc (do (ui/label f (i18n/t :dialogs/db-description) (ui/gd :valign :top))
                                            (ui/text f (:description cur) :multi true :data (ui/gd :fill :both :grab :both :h 60)))
                                   du (do (ui/label f (i18n/t :dialogs/db-default-username)) (ui/text f (:default-username cur)))
                                   _ (ui/label f (i18n/t :dialogs/db-history))
                                   hrow (ui/composite f (ui/grid 2 :margin 0 :hs 6) (ui/gd :fill :h :grab :h))
                                   hmax (doto (Spinner. hrow SWT/BORDER) (.setMinimum -1) (.setMaximum 10000)
                                          (.setSelection (int (:history-max-items cur))))
                                   _ (ui/label hrow (i18n/t :dialogs/db-history-unit))
                                   bin (do (ui/label f (i18n/t :dialogs/db-recycle-bin))
                                           (ui/check f (i18n/t :dialogs/db-recycle-bin-check) (:recycle-bin cur)))
                                   _ (do (ui/label f (i18n/t :dialogs/db-master-key-changed)) (ui/text f (fmt-date (:master-key-changed cur)) :read-only true))
                                   err (error-label f 2)]
                               {:nm nm :desc desc :du du :hmax hmax :bin bin :err err}))
                           [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                                   (let [{:keys [^Text nm ^Text desc ^Text du ^Spinner hmax ^Button bin err]} ctx]
                                                     (try
                                                       (ui/busy (display app) #(svc/set-db-settings! (session app)
                                                                                                     {:name (str/trim (.getText nm))
                                                                                                      :description (.getText desc)
                                                                                                      :default-username (str/trim (.getText du))
                                                                                                      :history-max-items (.getSelection hmax)
                                                                                                      :recycle-bin (.getSelection bin)}))
                                                       (reset! result true)
                                                       (ui/close! d)
                                                       (catch Throwable e (set-error! err e)))))
                             :default]
                            [(i18n/t :dialogs/cancel) nil]])]
        (ui/run-modal! (:shell dlg))
        @result))))

;; ================================================================ Groups

(defn group-name-dialog
  "Add/rename a group: asks for the name. Returns it or nil."
  [app {:keys [title heading sub value]}]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title title :icon-name "folder" :heading heading :sub sub :width 440}
                       (fn [^Composite body]
                         (let [f (form body)
                               n (do (ui/label f (i18n/t :dialogs/name)) (ui/text f (str value)))]
                           (.selectAll n)
                           (.setFocus n)
                           {:n n}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (let [v (str/trim (.getText ^Text (:n ctx)))]
                                                 (if (str/blank? v)
                                                   (ui/message! (:shell d) :warn title (i18n/t :dialogs/name-required))
                                                   (do (reset! result v) (ui/close! d)))))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn choose-group-dialog
  "Choose a target group (move group, move entries). groups:
   folder paths; \"\" is the top level (root-name). Returns the path or nil."
  [app {:keys [title heading sub groups root-name current]}]
  (let [result (atom nil)
        items (vec (cons "" groups))
        label #(if (str/blank? %) (i18n/t :dialogs/group-top-level {:name root-name}) %)
        dlg (ui/dialog (shell app) {:title title :icon-name "folder" :heading heading :sub sub :width 480}
                       (fn [^Composite body]
                         (let [f (form body)
                               c (do (ui/label f (i18n/t :dialogs/group-target)) (ui/combo f (map label items) (label (or current "")) (ui/gd :fill :h :grab :h)))]
                           {:c c}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (reset! result (get items (.getSelectionIndex ^Combo (:c ctx))))
                                               (ui/close! d))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn tags-dialog
  "Tags for several entries: add and remove. Returns {:add :remove} or nil."
  [app {:keys [count tags]}]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/tags-title) :icon-name "list" :heading (i18n/t :dialogs/tags-title)
                                    :sub (i18n/tn :dialogs/entry-count count) :width 480}
                       (fn [^Composite body]
                         (let [f (form body)
                               add (do (ui/label f (i18n/t :dialogs/add-label)) (ui/text f ""))
                               del (do (ui/label f (i18n/t :dialogs/remove-label)) (ui/text f ""))]
                           (ui/wrap-label f (str (i18n/t :dialogs/tags-hint)
                                                 (when (seq tags) (str " " (i18n/t :dialogs/tags-existing {:tags (str/join ", " tags)}))))
                                          420 2)
                           (.setFocus add)
                           {:add add :del del}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (reset! result {:add (.getText ^Text (:add ctx)) :remove (.getText ^Text (:del ctx))})
                                               (ui/close! d))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn options-dialog
  "Tools > Options (as KeePass: Security). Returns {:idle-minutes :clipboard-seconds} or nil."
  [app {:keys [idle-minutes clipboard-seconds]}]
  (let [result (atom nil)
        dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/options-title) :icon-name "gear" :heading (i18n/t :dialogs/options-title)
                                    :sub (i18n/t :dialogs/options-sub) :width 480}
                       (fn [^Composite body]
                         (let [f (form body)
                               spin (fn [cap v lo hi unit]
                                      (ui/label f cap)
                                      (let [r (ui/composite f (ui/grid 2 :margin 0 :hs 6))
                                            sp (doto (Spinner. r SWT/BORDER) (.setMinimum (int lo)) (.setMaximum (int hi)) (.setSelection (int v)))]
                                        (ui/label r unit)
                                        sp))
                               idle (spin (i18n/t :dialogs/options-lock-after) idle-minutes 0 1440 (i18n/t :dialogs/options-lock-unit))
                               clip (spin (i18n/t :dialogs/options-clipboard-after) clipboard-seconds 1 600 (i18n/t :dialogs/options-clipboard-unit))]
                           {:idle idle :clip clip}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}]
                                               (reset! result {:idle-minutes (.getSelection ^Spinner (:idle ctx))
                                                               :clipboard-seconds (.getSelection ^Spinner (:clip ctx))})
                                               (ui/close! d))
                         :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

;; ================================================================ Conflicts

(defn conflicts-dialog [app titles]
  (let [s (session app)
        items (call app #(svc/conflicts s))]
    (when (ok? items)
      (let [items (atom items)
            title-of (fn [path] (let [[_ id] (re-find #"^entries/([^/]+)/" (str path))] (or (get titles id) path)))
            dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/conflicts-title) :icon-name "conflict" :heading (i18n/t :dialogs/conflicts-heading)
                                        :sub (i18n/t :dialogs/conflicts-sub) :width 680}
                           (fn [^Composite body]
                             (let [t (table body [[(i18n/t :dialogs/col-entry) 200] [(i18n/t :dialogs/col-problem) 260] [(i18n/t :dialogs/col-date) 130]])
                                   render (fn []
                                            (.removeAll t)
                                            (doseq [c @items] (row! t [(title-of (:path c)) (or (:error c) (:status c)) (fmt-date (:date c))])))
                                   bar (ui/composite body (ui/grid 2 :margin 0 :hs 6))
                                   act (fn [action]
                                         (let [i (selected-index t)]
                                           (when (>= i 0)
                                             (let [c (nth @items i)]
                                               (when (ok? (call app #(svc/resolve-conflict s (:id c) action)))
                                                 (swap! items #(vec (remove (fn [x] (= (:id x) (:id c))) %)))
                                                 (render))))))]
                               (ui/button bar (i18n/t :dialogs/conflicts-keep-mine) #(act :retry) :data (ui/gd :w 130))
                               (ui/button bar (i18n/t :dialogs/conflicts-discard) #(act :discard) :data (ui/gd :w 100))
                               (when (empty? @items)
                                 (ui/label body (str (i18n/t :dialogs/conflicts-none) " "
                                                     (let [n (svc/pending-count s)]
                                                       (if (pos? n) (i18n/tn :dialogs/conflicts-pending n) (i18n/t :dialogs/conflicts-all-synced))))))
                               (render)))
                           [[(i18n/t :dialogs/close) nil :default]])]
        (ui/run-modal! (:shell dlg))))))

;; ================================================================ About

(defn about-dialog [app text]
  (let [dlg (ui/dialog (shell app) {:title (i18n/t :dialogs/about-title) :icon-name "vault" :heading "cljpass"
                                    :sub (i18n/t :dialogs/about-sub) :width 520}
                       (fn [^Composite body]
                         (ui/wrap-label body (i18n/t :dialogs/about-crypto) 480)
                         (ui/wrap-label body text 480)
                         (ui/wrap-label body (i18n/t :dialogs/about-license) 480)
                         (ui/wrap-label body (i18n/t :dialogs/about-shortcuts) 480))
                       [[(i18n/t :dialogs/ok) nil :default]])]
    (ui/run-modal! (:shell dlg))))
