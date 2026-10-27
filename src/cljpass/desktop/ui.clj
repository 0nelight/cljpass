(ns cljpass.desktop.ui
  "Small SWT helpers: layout, listeners, icons (HiDPI), message boxes and
   dialogs in KeePass style (white header with a large icon, content,
   button bar at the bottom right).

   Everything without reflection (GraalVM native-image). Texts are passed
   in already translated; this namespace has no texts of its own."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io ByteArrayInputStream InputStream]
           [org.eclipse.swt SWT]
           [org.eclipse.swt.widgets Canvas]
           [org.eclipse.swt.graphics GC]
           [org.eclipse.swt.custom BusyIndicator]
           [org.eclipse.swt.graphics Color Font FontData Image ImageData ImageDataProvider Point Rectangle]
           [org.eclipse.swt.layout GridData GridLayout]
           [org.eclipse.swt.widgets Button Combo Composite Control Display Event Label Listener
            MessageBox Shell Text Widget]))

(set! *warn-on-reflection* true)

;; ================================================================ Listener

(defn listener ^Listener [f] (reify Listener (handleEvent [_ e] (f e))))

(defn on
  "Listener for an SWT event type (SWT/Selection, SWT/Modify, ...)."
  [^Widget w type f]
  (.addListener w (int type) (listener f))
  w)

(defn async! [^Display d f] (.asyncExec d ^Runnable f))

(defn timer! [^Display d ms f] (.timerExec d (int ms) ^Runnable f))

(defn busy
  "Run f with the busy cursor (blocks the UI like KeePass when
   opening/saving). Returns the result or rethrows."
  [^Display d f]
  (let [result (volatile! nil) error (volatile! nil)]
    (BusyIndicator/showWhile d ^Runnable (fn [] (try (vreset! result (f)) (catch Throwable t (vreset! error t)))))
    (when-let [^Throwable t @error] (throw t))
    @result))

(defn background!
  "Run f in a background thread, then (done result error) in the UI thread."
  [^Display d f done]
  (let [^Runnable r (bound-fn []
                      (let [[res e] (try [(f) nil] (catch Throwable t [nil t]))]
                        (when-not (.isDisposed d) (async! d #(done res e)))))]
    (doto (Thread. r)
      (.setDaemon true)
      (.start))))

;; ================================================================ Layout

(defn grid
  "GridLayout with n columns. opts: :margin :mh :mv :spacing :hs :vs :equal"
  ^GridLayout [n & {:keys [margin mh mv spacing hs vs equal]}]
  (let [l (GridLayout. (int n) (boolean equal))]
    (when margin (set! (.-marginWidth l) (int margin)) (set! (.-marginHeight l) (int margin)))
    (when mh (set! (.-marginWidth l) (int mh)))
    (when mv (set! (.-marginHeight l) (int mv)))
    (when spacing (set! (.-horizontalSpacing l) (int spacing)) (set! (.-verticalSpacing l) (int spacing)))
    (when hs (set! (.-horizontalSpacing l) (int hs)))
    (when vs (set! (.-verticalSpacing l) (int vs)))
    l))

(defn gd
  "GridData. opts: :fill (:h :v :both) :grab (:h :v :both) :span :w :h :align :valign :indent :exclude"
  ^GridData [& {:keys [fill grab span w h align valign indent vindent exclude]}]
  (let [g (GridData.)]
    (when (#{:h :both} fill) (set! (.-horizontalAlignment g) SWT/FILL))
    (when (#{:v :both} fill) (set! (.-verticalAlignment g) SWT/FILL))
    (when (#{:h :both} grab) (set! (.-grabExcessHorizontalSpace g) true))
    (when (#{:v :both} grab) (set! (.-grabExcessVerticalSpace g) true))
    (when span (set! (.-horizontalSpan g) (int span)))
    (when w (set! (.-widthHint g) (int w)))
    (when h (set! (.-heightHint g) (int h)))
    (when indent (set! (.-horizontalIndent g) (int indent)))
    (when vindent (set! (.-verticalIndent g) (int vindent)))
    (case align :end (set! (.-horizontalAlignment g) SWT/END) :center (set! (.-horizontalAlignment g) SWT/CENTER) nil)
    (case valign :top (set! (.-verticalAlignment g) SWT/TOP) :center (set! (.-verticalAlignment g) SWT/CENTER) nil)
    (when exclude (set! (.-exclude g) true))
    g))

(defn layout-data! [^Control c data] (.setLayoutData c data) c)

(defn show!
  "Show/hide a control and take it out of the layout."
  [^Control c visible?]
  (let [^GridData g (or (.getLayoutData c) (gd))]
    (set! (.-exclude g) (not visible?))
    (.setLayoutData c g)
    (.setVisible c (boolean visible?))
    (.layout (.getParent c) true true)
    c))

(defn composite ^Composite [^Composite parent layout & [data]]
  (let [c (Composite. parent SWT/NONE)]
    (.setLayout c layout)
    (when data (.setLayoutData c data))
    c))

(defn label ^Label [^Composite parent text & [data style]]
  (let [l (Label. parent (int (or style SWT/NONE)))]
    (.setText l (str text))
    (when data (.setLayoutData l data))
    l))

(defn wrap-label
  "Multi-line hint text that wraps with the dialog."
  ^Label [^Composite parent text & [w span]]
  (label parent text (gd :fill :h :grab :h :w (or w 400) :span (or span 1)) SWT/WRAP))

(defn text ^Text [^Composite parent value & {:keys [style data password multi read-only]}]
  (let [t (Text. parent (int (bit-or SWT/BORDER
                                     (if password SWT/PASSWORD 0)
                                     (if multi (bit-or SWT/MULTI SWT/V_SCROLL SWT/WRAP) SWT/SINGLE)
                                     (if read-only SWT/READ_ONLY 0)
                                     (or style 0))))]
    (.setText t (str value))
    (.setLayoutData t (or data (gd :fill :h :grab :h)))
    t))

(defn button ^Button [^Composite parent text f & {:keys [style data image]}]
  (let [b (Button. parent (int (or style SWT/PUSH)))]
    (.setText b (str text))
    (when image (.setImage b ^Image image))
    (when data (.setLayoutData b data))
    (when f (on b SWT/Selection (fn [_] (f))))
    b))

(defn check ^Button [^Composite parent text selected & [data]]
  (doto (button parent text nil :style SWT/CHECK :data data) (.setSelection (boolean selected))))

(defn radio ^Button [^Composite parent text selected f & [data]]
  (let [b (button parent text nil :style SWT/RADIO :data data)]
    (.setSelection b (boolean selected))
    (on b SWT/Selection (fn [_] (when (.getSelection b) (f))))
    b))

(defn combo ^Combo [^Composite parent items selected & [data]]
  (let [c (Combo. parent (int (bit-or SWT/DROP_DOWN SWT/READ_ONLY)))]
    (.setItems c ^"[Ljava.lang.String;" (into-array String items))
    (.select c (int (max 0 (.indexOf ^java.util.List (vec items) selected))))
    (when data (.setLayoutData c data))
    c))

(defn text-of ^String [^Text t] (.getText t))

;; ================================================================ Fonts and colors

(defn bold-font ^Font [^Display d ^Control c & [delta]]
  (let [^FontData fd (aget ^"[Lorg.eclipse.swt.graphics.FontData;" (.getFontData (.getFont c)) 0)]
    (Font. d (.getName fd) (int (+ (.getHeight fd) (or delta 0))) SWT/BOLD)))

(defn color ^Color [^Display d r g b] (Color. d (int r) (int g) (int b)))

;; ================================================================ Icons

(def ^:private icon-cache (atom {}))

(defn- load-png ^ImageData [path]
  (when-let [r (io/resource path)]
    (with-open [^InputStream in (io/input-stream r)] (ImageData. in))))

(defn icon
  "Icon from resources/icons: 16 px; big true = 32 px blue, :white = 32 px
   white (dialog header). HiDPI via the @2x variant. Images live as long as
   the display."
  ^Image [^Display d nm & [big]]
  (let [k [nm big]
        suffix (case big (nil false) "" :white "-w32" "-32")]
    (or (@icon-cache k)
        (let [base (str "icons/" nm suffix)
              base (if (io/resource (str base ".png")) base (str "icons/key" suffix))
              img (Image. d (reify ImageDataProvider
                              (getImageData [_ zoom]
                                (cond
                                  (>= zoom 200) (load-png (str base "@2x.png"))
                                  (= zoom 100) (load-png (str base ".png"))
                                  :else nil))))]
          (swap! icon-cache assoc k img)
          img))))

(defn image-from-bytes
  "Custom KeePass icon (PNG/JPEG/GIF/BMP/ICO) -> Image in 16x16, nil if unreadable."
  ^Image [^Display d ^bytes data]
  (try
    (let [id (ImageData. (ByteArrayInputStream. data))
          id (if (or (not= 16 (.-width id)) (not= 16 (.-height id))) (.scaledTo id 16 16) id)]
      (Image. d id))
    (catch Throwable _ nil)))

;; ================================================================ Message boxes

(defn message!
  "kind: :info :warn :error"
  [^Shell shell kind title msg]
  (let [mb (MessageBox. shell (int (bit-or SWT/OK (case kind :error SWT/ICON_ERROR :warn SWT/ICON_WARNING SWT/ICON_INFORMATION))))]
    (.setText mb (str title))
    (.setMessage mb (str msg))
    (.open mb)
    nil))

(defn confirm?
  [^Shell shell title msg]
  (let [mb (MessageBox. shell (int (bit-or SWT/YES SWT/NO SWT/ICON_QUESTION)))]
    (.setText mb (str title))
    (.setMessage mb (str msg))
    (= SWT/YES (.open mb))))

;; ================================================================ Dialogs (KeePass style)

(defn center! [^Shell s ^Shell parent]
  (let [^Rectangle pb (if parent (.getBounds parent) (.getBounds (.getPrimaryMonitor (.getDisplay s))))
        ^Point sz (.getSize s)]
    (.setLocation s (int (+ (.-x pb) (quot (- (.-width pb) (.-x sz)) 2)))
                  (int (+ (.-y pb) (max 0 (quot (- (.-height pb) (.-y sz)) 2)))))))

(defn run-modal!
  "Event loop until the dialog is closed."
  [^Shell s]
  (let [d (.getDisplay s)]
    (.open s)
    (while (not (.isDisposed s))
      (when-not (.readAndDispatch d) (.sleep d)))))

(def banner-height 60)

(defn banner
  "Dialog header like KeePass (BannerFactory, style \"Dark\"): horizontal
   gradient from (160,160,176) to (16,16,32), white icon, bold title
   (12 pt) and one line of explanation (9 pt)."
  ^Canvas [^Composite parent icon-name title sub]
  (let [d (.getDisplay parent)
        c (Canvas. parent SWT/DOUBLE_BUFFERED)
        start (color d 160 160 176)
        end (color d 16 16 32)
        white (.getSystemColor d SWT/COLOR_WHITE)
        ^FontData fd (aget ^"[Lorg.eclipse.swt.graphics.FontData;" (.getFontData (.getFont parent)) 0)
        f-title (Font. d (.getName fd) 12 SWT/BOLD)
        f-sub (Font. d (.getName fd) 9 SWT/NORMAL)
        img (icon d (or icon-name "entry") :white)
        text (atom [title sub])]
    (.setLayoutData c (gd :fill :h :grab :h :h banner-height))
    (on c SWT/Paint
        (fn [^Event e]
          (let [^GC gc (.-gc e)
                r (.getClientArea c)
                [t s] @text]
            (.setForeground gc start)
            (.setBackground gc end)
            (.fillGradientRectangle gc 0 0 (.-width r) (.-height r) false)
            (.drawImage gc img 12 (quot (- banner-height 32) 2))
            (.setForeground gc white)
            (.setFont gc f-title)
            (.drawText gc (str t) 56 10 true)
            (.setFont gc f-sub)
            (.drawText gc (str s) 64 34 true))))
    (on c SWT/Dispose (fn [_] (.dispose f-title) (.dispose f-sub) (.dispose start) (.dispose end)))
    (.setData c "set-text" (fn [t s] (reset! text [t s]) (.redraw c)))
    c))

(defn dialog
  "Builds a modal dialog. opts: {:title :icon-name :heading :sub :width}.
   (body-fn composite) fills the content and may return a map (ends up
   under :ctx). buttons: [[\"OK\" (fn [dlg]) :default] ...]; f nil = close,
   :left = align left. Returns dlg {:shell :body :ctx :buttons {text Button}}."
  [^Shell parent {:keys [title icon-name heading sub width]} body-fn buttons]
  (let [d (.getDisplay parent)
        s (Shell. parent (int (bit-or SWT/DIALOG_TRIM SWT/APPLICATION_MODAL SWT/RESIZE)))
        _ (.setText s (str title))
        _ (.setLayout s (grid 1 :margin 0 :spacing 0))
        _ (when icon-name (.setImage s (icon d icon-name)))
        white (.getSystemColor d SWT/COLOR_LIST_BACKGROUND)
        dlg (atom {:shell s})]
    (when heading
      (swap! dlg assoc :banner (banner s icon-name heading sub)))
    (let [body (composite s (grid 1 :margin 12) (gd :fill :both :grab :both))
          ctx (body-fn body)
          _ (label s "" (gd :fill :h :grab :h) (bit-or SWT/SEPARATOR SWT/HORIZONTAL))
          bar (composite s (grid (count buttons) :mh 12 :mv 10 :hs 6) (gd :fill :h :grab :h))
          btns (into {}
                     (for [[txt f & flags] buttons]
                       (let [left? (some #{:left} flags)
                             b (button bar txt (fn [] (if f (f @dlg) (.close s)))
                                       :data (gd :w 88 :grab (when left? :h) :align (when-not left? :end)))]
                         (when (some #{:default} flags) (.setDefaultButton s b))
                         [txt b])))]
      (when-let [first-right (some (fn [[txt _ & flags]] (when-not (some #{:left} flags) txt)) buttons)]
        ;; everything right-aligned: the first right button takes up the free space
        (let [^GridData g (.getLayoutData ^Button (btns first-right))]
          (when-not (some (fn [[_ _ & flags]] (some #{:left} flags)) buttons)
            (set! (.-grabExcessHorizontalSpace g) true)
            (set! (.-horizontalAlignment g) SWT/END))))
      (swap! dlg assoc :body body :ctx ctx :buttons btns)
      (.pack s)
      (let [^Point sz (.getSize s)]
        (.setSize s (int (max (.-x sz) (or width 0))) (.-y sz)))
      (center! s parent)
      @dlg)))

(defn close! [{:keys [^Shell shell]}] (when-not (.isDisposed shell) (.close shell)))

(defn error-text
  "Message for the user from an exception."
  [^Throwable e]
  (or (not-empty (ex-message e)) (str (.getSimpleName (class e)))))

(defn field-row
  "Caption + control in a 2-column form."
  [^Composite form caption make]
  (label form caption (gd :valign :center))
  (make form))

(defn shorten [s n] (let [s (str s)] (if (> (count s) n) (str (subs s 0 (dec n)) "…") s)))

(defn first-line [s] (first (str/split-lines (str s))))
