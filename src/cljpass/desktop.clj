(ns cljpass.desktop
  "Desktop UI (SWT) laid out like KeePass 2.x: menu, toolbar with quick
   search, group tree, entry list, entry view and status bar. Dialogs live in
   cljpass.desktop.dialogs / .start.

   The UI calls cljpass.service directly - no local HTTP server, no
   browser. (The web UI under resources/ui stays as the basis for a Firefox
   add-on, see cljpass.web.)

   All texts come from the i18n catalogs (area desktop); the language can be
   switched live via View > Language."
  (:require [clojure.string :as str]
            [cljpass.broker :as broker]
            [cljpass.channel :as channel]
            [cljpass.rotate :as rotate]
            [cljpass.crypto :as c]
            [cljpass.desktop.dialogs :as dlg]
            [cljpass.desktop.start :as start]
            [cljpass.desktop.ui :as ui]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.local :as local]
            [cljpass.service :as svc])
  (:import [java.time LocalDateTime]
           [org.eclipse.swt SWT]
           [org.eclipse.swt.custom CTabFolder CTabFolder2Adapter CTabFolderEvent CTabItem SashForm StyleRange StyledText]
           [org.eclipse.swt.dnd ByteArrayTransfer Clipboard DND DragSource DragSourceEvent DragSourceListener DropTarget
            DropTargetEvent DropTargetListener TextTransfer Transfer]
           [org.eclipse.swt.graphics Cursor Image Point Rectangle]
           [org.eclipse.swt.program Program]
           [org.eclipse.swt.widgets Composite Control Display Event Label Menu MenuItem Shell Table TableColumn
            TableItem Text ToolBar ToolItem Tree TreeItem]))

(set! *warn-on-reflection* true)

;; ================================================================ State

(def ^:private doc-defaults
  "State of one database (tab). state holds that of the active tab, the
   others keep theirs in docs."
  {:mode :server :entries [] :folder "" :search "" :filter nil :sort [:title 1] :selected nil :selection []
   :org "" :file "" :link nil :me nil :display-name nil :defaults {} :standalone-allowed true
   :pending 0 :conflicts 0 :online true :last-sync nil :folder-icons {} :locked true :status-msg nil
   :default-username "" :groups [] :recycle-bin nil :recycle-bin-enabled false :passwords {} :offline-copy nil})

(def ^:private locked-ui {:passwords {} :locked true :entries [] :selected nil})

(defonce ^:private state
  (atom (merge doc-defaults
               {:show-toolbar true :show-details true
                :search-opts {:case false :regex false}
                :columns [:title :username :password :url :notes] :show-passwords false})))

;; Open databases like the tabs in KeePass: {:list [{:session :ui}] :active i}.
;; Tab 0 is the main database (server or the file of local mode), the
;; others are further KeePass files (File > Open in new tab, AutoOpen).
(defonce ^:private docs (atom {:list [] :active 0}))

(defonce ^:private w (atom {})) ; widgets and app context

(defn- st [] @state)
(defn- local? [] (= :standalone (:mode (st))))
(defn- display ^Display [] (:display @w))
(defn- shell ^Shell [] (:shell @w))
(defn- session [] (get-in @docs [:list (:active @docs) :session]))
(defn- extra? [] (pos? (:active @docs)))
(defn- app
  "Context for the dialogs, with the session of the active tab."
  [] (assoc (:app @w) :session (session)))

;; Access for an LLM session (cljpass.broker): reading is a preference,
;; writing is switched on by hand and off again on every lock.
(defonce ^:private agent-access (atom {:read true :write false}))

(defn- agent-off! []
  (channel/close-all!)
  (swap! agent-access assoc :write false))

(def ^:private kp-icons
  "KeePass standard icons (IconID 0-68) -> our own drawings (like resources/ui/app.js)."
  ["key" "world" "warn" "server" "folder" "user" "gear" "entry" "world" "identity"
   "entry" "camera" "user" "key" "energy" "printer" "star" "cd" "monitor" "mail"
   "gear" "clipboard" "entry" "monitor" "energy" "mail" "disk" "drive" "entry" "console"
   "console" "printer" "box" "console" "gear" "monitor" "archive" "bank" "drive" "history"
   "mail" "entry" "drive" "del" "entry" "warn" "info" "box" "folder" "folderOpen"
   "box" "lockOpen" "lock" "check" "edit" "thumb" "book" "list" "user" "tool"
   "home" "star" "tux" "feather" "apple" "wiki" "money" "cert" "phone"])

(def ^:private custom-images (atom {}))

(defn- kp-image
  "Image for a KeePass icon {:id n :custom {:uuid :data-url}}."
  ^Image [icon fallback]
  (or (when-let [{:keys [uuid data-url]} (:custom icon)]
        (or (@custom-images uuid)
            (when-let [[_ b64] (re-find #"^data:image/[a-z-]+;base64,(.+)$" (str data-url))]
              (when-let [img (ui/image-from-bytes (display) (c/unb64 b64))]
                (swap! custom-images assoc uuid img)
                img))))
      (ui/icon (display) (if icon (get kp-icons (:id icon) fallback) fallback))))

;; ================================================================ Clipboard

(defn- format-transfer
  "Extra format for the Windows clipboard (like KeePass): not in the history
   (Win+V), not in the cloud, ignored by clipboard managers."
  ^Transfer [^String nm]
  (let [id (Transfer/registerType nm)]
    (proxy [ByteArrayTransfer] []
      (getTypeIds [] (int-array [id]))
      (getTypeNames [] (into-array String [nm])))))

(defonce ^:private clip-formats
  (delay (when (local/windows?)
           [(format-transfer "ExcludeClipboardContentFromMonitorProcessing")
            (format-transfer "CanIncludeInClipboardHistory")
            (format-transfer "CanUploadToCloudClipboard")])))

(def clear-seconds
  "Clear the clipboard after ... seconds (Tools > Options)."
  (atom 12))

(defn- set-status! [msg]
  (swap! state assoc :status-msg msg)
  (when-let [^Label l (:st-msg @w)] (when-not (.isDisposed l) (.setText l (str msg)) (.pack l) (.layout (.getParent l) true))))

(defn copy-text!
  "Put a value on the clipboard; clear it after clear-seconds - but only if it is still there.
   label names the copied value in the status bar (already translated)."
  [^String v label]
  (let [cb (Clipboard. (display))
        extra @clip-formats
        zero (byte-array 4)]
    (try
      (.setContents cb
                    (object-array (concat [v] (map (constantly zero) extra)))
                    ^"[Lorg.eclipse.swt.dnd.Transfer;" (into-array Transfer (concat [(TextTransfer/getInstance)] extra)))
      (finally (.dispose cb)))
    (let [n (atom @clear-seconds)
          tick (fn tick []
                 (if (pos? @n)
                   (do (set-status! (i18n/t :desktop/copied-clearing {:what label :n @n}))
                       (swap! n dec)
                       (ui/timer! (display) 1000 tick))
                   (let [cb (Clipboard. (display))]
                     (try
                       (when (= v (.getContents cb (TextTransfer/getInstance)))
                         (.clearContents cb))
                       (finally (.dispose cb)))
                     (set-status! ""))))]
      (tick))))

;; ================================================================ Rendering

(declare render! render-list! render-menu! refresh! lock! boot! actions update-actions! auto-open!
         open-in-tab! close-doc! render-tabs! rotate-entry!)

(defn- selected-entry [] (let [{:keys [entries selected]} (st)] (first (filter #(= selected (:id %)) entries))))

(defn- selected-ids
  "All selected entries (multi-selection). The selection only counts while
   it contains the current entry - whoever sets :selected thereby selects
   exactly one entry."
  []
  (let [{:keys [selection selected]} (st)]
    (cond (nil? selected) []
          (some #{selected} selection) (vec selection)
          :else [selected])))

(defn- selected-entries []
  (let [ids (set (selected-ids))] (filter #(ids (:id %)) (:entries (st)))))

(def ^:private with-me "\u0000with-me")
(def ^:private by-me "\u0000by-me")

(defn- norm-folder [f] (str/join "/" (remove str/blank? (map str/trim (str/split (str f) #"/")))))

(defn- match-folder [f]
  (fn [e]
    (cond
      (= f with-me) (not= "owner" (:permission e))
      (= f by-me) (and (= "owner" (:permission e)) (:shared e))
      :else (= (str f) (norm-folder (:folder e))))))

(defn- in-bin?
  "Is the folder inside the recycle bin (local mode)?"
  [f]
  (let [b (:recycle-bin (st)) f (norm-folder f)]
    (boolean (and b (or (= f b) (str/starts-with? f (str b "/")))))))

(defn- prefixes [f]
  (let [parts (str/split (norm-folder f) #"/")]
    (when-not (str/blank? (first parts))
      (for [i (range 1 (inc (count parts)))] (str/join "/" (take i parts))))))

(defn- all-groups
  "All groups: from the entries' folders and (local mode) the empty ones too.
   Parents before children, the recycle bin last."
  []
  (let [{:keys [entries groups]} (st)
        ps (sort (distinct (concat (mapcat (comp prefixes :folder) entries) (mapcat prefixes groups))))]
    (concat (remove in-bin? ps) (filter in-bin? ps))))

(defn- current-group
  "The group selected in the tree (nil for the top level and filters)."
  []
  (let [f (:folder (st))]
    (when-not (or (str/blank? f) (str/starts-with? f "\u0000")) f)))

(defn- expiry-time
  "Expiry as local date/time (date only: start of day), nil if none."
  ^LocalDateTime [e]
  (dlg/expires->local (:expires e)))

(defn- expired? [e]
  (when-let [t (expiry-time e)] (not (.isAfter t (LocalDateTime/now)))))

(defn- expiring?
  "Expires within the next 7 days (KeePass: Expiring Entries)."
  [e]
  (when-let [t (expiry-time e)] (and (not (expired? e)) (not (.isAfter t (.plusDays (LocalDateTime/now) 7))))))

(defn- matcher
  "Search like the KeePass quick search: title, user name, URL, notes,
   group, tags and unprotected custom fields. Options: case sensitive,
   regular expression. Several words must all occur."
  [search {:keys [case regex]}]
  (let [q (str/trim (str search))]
    (when-not (str/blank? q)
      (let [hay (fn [e] (str/join "\n" (concat (map #(str (get e %)) [:title :username :url :notes :folder])
                                               (:tags e) (:fields e))))]
        (if regex
          (let [p (try (re-pattern (str (when-not case "(?iu)") q)) (catch Exception _ nil))]
            (if p (fn [e] (boolean (re-find p (hay e)))) (constantly false)))
          (let [norm (if case identity str/lower-case)
                words (str/split (norm q) #"\s+")]
            (fn [e] (let [h (norm (hay e))] (every? #(str/includes? h %) words)))))))))

(defn- filter-pred
  "Filter from the Find menu: :expired, :expiring, [:tag t], [:ids label-key #{id}]."
  [f]
  (cond
    (nil? f) (constantly true)
    (= f :expired) expired?
    (= f :expiring) expiring?
    (= :tag (first f)) #(some #{(second f)} (:tags %))
    (= :ids (first f)) #(contains? (nth f 2) (:id %))
    :else (constantly true)))

(defn- searching? [] (some? (matcher (:search (st)) (:search-opts (st)))))

(defn- visible
  "Entries of the list. Like KeePass a group shows only its own entries; the
   quick search covers the whole database, its hits ordered by group."
  []
  (let [{:keys [entries folder search sort filter search-opts]} (st)
        m (matcher search search-opts)
        [k dir] sort
        rows (->> entries
                  (clojure.core/filter (if (and m (not (#{with-me by-me} folder))) (constantly true) (match-folder folder)))
                  ;; like KeePass: do not search the recycle bin unless it is selected
                  (clojure.core/remove #(and (:recycled %) (not (in-bin? folder))))
                  (clojure.core/filter (filter-pred filter))
                  (clojure.core/filter #(or (nil? m) (m %))))]
    (cond->> (cond->> (sort-by #(str/lower-case (str (get % k))) rows)
               (neg? dir) reverse)
      m (sort-by #(str/lower-case (norm-folder (:folder %)))))))

(defn- all-tags [] (sort-by str/lower-case (distinct (mapcat :tags (:entries (st))))))

(declare render-tree-items!)

(defn- render-tree! []
  (let [^Tree tree (:tree @w)
        {:keys [org folder folder-icons locked]} (st)
        _ (.setRedraw tree false)
        _ (.removeAll tree)
        ;; like KeePass: no groups and a grayed-out, disabled tree while locked
        _ (.setEnabled tree (not locked))
        _ (.setBackground tree (when locked (.getSystemColor (display) SWT/COLOR_WIDGET_BACKGROUND)))]
    (if locked
      (.setRedraw tree true)
      (render-tree-items! tree org folder folder-icons))))

(defn- render-tree-items! [^Tree tree org folder folder-icons]
  (let [root (TreeItem. tree SWT/NONE)
        nodes (atom {"" root})
        sel (atom nil)]
    (.setText root (str org))
    (.setImage root (ui/icon (display) "vault"))
    (.setData root "")
    (doseq [path (all-groups)]
      (let [parent (@nodes (norm-folder (str/join "/" (butlast (str/split path #"/")))) root)
            it (TreeItem. ^TreeItem parent SWT/NONE)
            fi (get folder-icons path)]
        (.setText it ^String (last (str/split path #"/")))
        (.setData it path)
        (.setImage it (if (and fi (or (:custom fi) (not (#{48 49} (:id fi))))) (kp-image fi "folder") (ui/icon (display) "folder")))
        (swap! nodes assoc path it)))
    (when-not (local?)
      (doseq [[p nm ic] [[with-me (i18n/t :desktop/shared-with-me) "shared"] [by-me (i18n/t :desktop/shared-by-me) "share"]]]
        (let [it (TreeItem. tree SWT/NONE)]
          (.setText it ^String nm) (.setData it p) (.setImage it (ui/icon (display) ic))
          (swap! nodes assoc p it))))
    (doseq [[_ ^TreeItem it] @nodes] (when (pos? (.getItemCount it)) (.setExpanded it true)))
    (reset! sel (@nodes folder root))
    (.setSelection tree ^TreeItem @sel)
    (.setRedraw tree true)))

(defn- color-of
  "KeePass color \"#RRGGBB\" -> SWT color (nil for default)."
  [h]
  (when-let [[_ r g b] (re-matches #"#([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})" (str h))]
    (ui/color (display) (Integer/parseInt r 16) (Integer/parseInt g 16) (Integer/parseInt b 16))))

(def ^:private all-columns
  "Columns of the entry list (View > Columns): [key title-key width cell]."
  [[:title :desktop/col-title 220 #(let [x (:title %)] (if (str/blank? x) (i18n/t :desktop/no-title) x))]
   [:username :desktop/col-username 150 #(str (:username %))]
   [:password :desktop/col-password 110 #(if (:show-passwords (st)) (get-in (st) [:passwords (:id %)] "") "********")]
   [:url :desktop/col-url 200 #(str (:url %))]
   [:notes :desktop/col-notes 180 #(ui/first-line (:notes %))]
   [:folder :desktop/col-group 140 #(str (:folder %))]
   [:tags :desktop/col-tags 120 #(str/join ", " (:tags %))]
   [:expires :desktop/col-expires 130 #(dlg/fmt-expires (:expires %))]
   [:modified :desktop/col-modified 130 #(dlg/fmt-date (:modified %))]
   [:attachments :desktop/col-attachments 70 #(let [n (:attachments % 0)] (if (pos? n) (str n) ""))]])

(defn- columns [] (let [ks (set (:columns (st)))] (filter #(ks (first %)) all-columns)))

(defn- column-at
  "Key of the column under a click in the list; nil outside the rows
   (KeePass: ListView.HitTest, a Table reports no column)."
  [^Table t ^Point p]
  (when-let [^TableItem it (.getItem t p)]
    (first (keep-indexed (fn [i [k]]
                           (let [^Rectangle r (.getBounds it (int i))]
                             (when (and (>= (.-x p) (.-x r)) (< (.-x p) (+ (.-x r) (.-width r)))) k)))
                         (columns)))))

(defn- build-columns!
  "Recreate the table columns from the choice (a click sorts)."
  []
  (let [^Table table (:table @w)]
    (doseq [^TableColumn c (.getColumns table)] (.dispose c))
    (doseq [[k txt wd] (columns)]
      (let [col (TableColumn. table SWT/NONE)]
        (.setText col (i18n/t txt)) (.setWidth col (int wd))
        (ui/on col SWT/Selection
               (fn [_]
                 (swap! state update :sort (fn [[k0 dir]] [k (if (= k0 k) (- dir) 1)]))
                 (.setSortColumn table col)
                 (.setSortDirection table (int (if (pos? (second (:sort (st)))) SWT/UP SWT/DOWN)))
                 (render-list!)))))))

(defn- render-list! []
  (let [^Table t (:table @w)
        rows (visible)
        sel (set (selected-ids))
        gray (.getSystemColor (display) SWT/COLOR_DARK_GRAY)
        ;; search hits: a small heading with the group above each block (KeePass)
        rows (if (searching?)
               (mapcat (fn [es] (cons {::group (norm-folder (:folder (first es)))} es))
                       (partition-by #(norm-folder (:folder %)) rows))
               rows)]
    (.setRedraw t false)
    (.removeAll t)
    (.setEnabled t (not (:locked (st))))
    (.setBackground t (when (:locked (st)) (.getSystemColor (display) SWT/COLOR_WIDGET_BACKGROUND)))
    (doseq [e rows]
      (if-let [g (::group e)]
        (doto (TableItem. t SWT/NONE)
          ;; like KeePass (PwGroup.GetFullPath(true, false)): without the top group,
          ;; whose name only heads the entries directly in it
          (.setText (if (str/blank? g) (str (:org (st))) (str/join " \u2192 " (str/split g #"/"))))
          (.setFont ^org.eclipse.swt.graphics.Font (:group-font @w))
          (.setForeground (.getSystemColor (display) SWT/COLOR_LINK_FOREGROUND)))
      (let [it (TableItem. t SWT/NONE)]
        (.setText it ^"[Ljava.lang.String;" (into-array String (map (fn [[_ _ _ cell]] (str (cell e))) (columns))))
        (.setImage it (int 0) (if (:kdbx-database e) (ui/icon (display) "vault") (kp-image (:icon e) "key")))
        (.setData it (:id e))
        (when-let [c (color-of (get-in e [:colors :fg]))] (.setForeground it c))
        (when-let [c (color-of (get-in e [:colors :bg]))] (.setBackground it c))
        (when (or (not (#{"update" "owner"} (:permission e))) (expired? e)) (.setForeground it gray)))))
    ;; indices, not (into-array TableItem ...): that class literal makes native-image
    ;; initialize SWT's Win32 layer at build time
    (.setSelection t (int-array (keep-indexed (fn [i e] (when (and (:id e) (sel (:id e))) i)) rows)))
    (.setRedraw t true)))

;; ---------------------------------------------------------------- URLs as links

(declare open-url! launch-url!)

(def ^:private link-schemes
  "Schemes a URL in a text needs to become a link. KeePass knows more
   (UrlUtil.IsKnownScheme: callto, file, ftp, ldap, mailto, tel ...),
   cljpass opens only http(s) (see launch-url!)."
  #{"http" "https"})

(defn- uri-char?
  "A character a URL may contain (UrlUtil.IsUriChar)."
  [ch]
  (let [c (int ch)]
    (and (<= (int \!) c (int \~)) (not (#{\" \< \> \\ \^ \` \{ \| \}} ch)))))

(defn- scheme-char?
  "A character a scheme may contain (UrlUtil.IsUriSchemeChar)."
  [ch]
  (let [c (int ch)]
    (or (<= (int \A) c (int \Z)) (<= (int \a) c (int \z)) (<= (int \0) c (int \9))
        (#{\+ \- \.} ch))))

(defn- url-end
  "End of the URL that starts at start (UrlUtil.GetUrlLength): URL
   characters, without a sentence mark at the end - unless the URL is
   quoted or braced."
  ^long [^String s ^long start]
  (let [n (.length s)
        i (long (loop [i start] (if (and (< i n) (uri-char? (.charAt s i))) (recur (inc i)) i)))]
    (if (and (< i n) (#{\" \> \}} (.charAt s i)))
      i
      (loop [i i] (if (and (> i start) (#{\! \, \. \: \; \?} (.charAt s (dec i)))) (recur (dec i)) i)))))

(defn- urls-in
  "The URLs in a text, like the entry view of KeePass
   (UIUtil.RtfLinkifyUrls): a known scheme before a colon, then URL
   characters. [[start end] ...]"
  [^String s]
  (loop [off 0 found []]
    (let [sep (.indexOf s (int \:) (int off))]
      (if (neg? sep)
        found
        (let [start (loop [i sep] (if (and (pos? i) (scheme-char? (.charAt s (dec i)))) (recur (dec i)) i))
              end (long (if (link-schemes (str/lower-case (subs s start sep))) (url-end s start) -1))]
          (if (> end off)
            (recur end (conj found [start end]))
            (recur (inc sep) found)))))))

;; Links of the entry view: [[start end action] ...], the first match wins.
(defonce ^:private details-links (atom []))

(defn- link-at
  "The action of the link at the offset of a click, nil if there is none."
  [^long offset]
  (when-not (neg? offset)
    (some (fn [[start end f]] (when (and (<= (long start) offset) (< offset (long end))) f)) @details-links)))

(defn- link-style!
  "Show start..end as a link (KeePass: UIUtil.RtfSetSelectionLink)."
  [^StyledText d ^long start ^long end]
  (let [r (StyleRange.)]
    (set! (.-start r) (int start))
    (set! (.-length r) (int (- end start)))
    (set! (.-foreground r) (.getSystemColor (display) SWT/COLOR_LINK_FOREGROUND))
    (set! (.-underline r) true)
    (set! (.-underlineStyle r) (int SWT/UNDERLINE_LINK))
    (.setStyleRange d r)))

(defn- render-details! []
  (let [^StyledText d (:details @w)
        e (selected-entry)
        n (count (selected-ids))]
    (reset! details-links [])
    (cond
      (nil? e) (.setText d "")
      (> n 1) (.setText d (i18n/t :desktop/details-multi {:n n}))
      :else
      (let [modified (dlg/fmt-date (:modified e))
            perm (dlg/perm-label (:permission e))
            rows (cond-> [[(i18n/t :desktop/col-group) (let [f (:folder e)] (if (str/blank? f) (:org (st)) f))]
                          [(i18n/t :desktop/col-title) (:title e)]
                          [(i18n/t :desktop/col-username) (:username e)]
                          [(i18n/t :desktop/col-password) "********"]
                          [(i18n/t :desktop/col-url) (:url e)]
                          [(i18n/t :desktop/col-modified) (if-let [b (:modified-by e)]
                                                            (i18n/t :desktop/modified-by {:date modified :user b})
                                                            (str modified))]]
                   (not (str/blank? (:expires e))) (conj [(i18n/t :desktop/col-expires) (dlg/fmt-expires (:expires e))])
                   (seq (:tags e)) (conj [(i18n/t :desktop/col-tags) (str/join ", " (:tags e))])
                   (pos? (:attachments e 0)) (conj [(i18n/t :desktop/col-attachments) (str (:attachments e))])
                   (:otp e) (conj ["TOTP" (i18n/t :desktop/totp-configured)])
                   (not (local?)) (conj [(i18n/t :desktop/your-permission)
                                         (if (:shared e) (i18n/t :desktop/permission-shared {:permission perm}) (str perm))]))
            sb (StringBuilder.)
            ranges (atom [])
            links (atom [])
            url-label (i18n/t :desktop/col-url)]
        (doseq [[i [k v]] (map-indexed vector (remove (comp str/blank? str second) rows))]
          (when (pos? i) (.append sb ", "))
          (let [start (.length sb)]
            (.append sb (str k ": "))
            (swap! ranges conj [start (+ 1 (count k))])
            (let [value-start (.length sb)]
              (.append sb (str v))
              ;; the URL field is a link, whatever it looks like (KeePass: fSetLink)
              (when (= k url-label) (swap! links conj [value-start (.length sb) open-url!])))))
        (doseq [warning (:warnings e)] (.append sb (str "\n" (i18n/t :desktop/warning {:text warning}))))
        (when-not (str/blank? (:notes e)) (.append sb (str "\n\n" (:notes e))))
        (let [text (str sb)]
          (.setText d text)
          (doseq [[s n] @ranges]
            (let [r (StyleRange.)]
              (set! (.-start r) (int s)) (set! (.-length r) (int n)) (set! (.-fontStyle r) SWT/BOLD)
              (.setStyleRange d r)))
          ;; the URL field first, it wins over an address found in the text
          (reset! details-links
                  (into @links (map (fn [[a b]] [a b #(launch-url! (subs text a b))]) (urls-in text))))
          (doseq [[a b] @details-links] (link-style! d a b)))))))

(defn- render-status! []
  (let [{:keys [entries selected online last-sync pending conflicts link file me display-name org locked offline-copy]} (st)
        n (count (visible))
        ^Label cnt (:st-count @w) ^Label sync (:st-sync @w) ^Label user (:st-user @w)]
    (.setText cnt (cond locked ""
                        selected (i18n/t :desktop/status-selected {:selected (count (selected-ids)) :n n})
                        :else (i18n/tn :desktop/entry-count n)))
    (.setToolTipText cnt (let [f (:filter (st))]
                           (cond (nil? f) nil
                                 (= f :expired) (i18n/t :desktop/filter-expired)
                                 (= f :expiring) (i18n/t :desktop/filter-expiring)
                                 (= :tag (first f)) (i18n/t :desktop/filter-tag {:tag (second f)})
                                 :else (i18n/t :desktop/filter-other {:name (i18n/t (second f))}))))
    (.setText sync (cond locked (i18n/t :desktop/locked)
                         (local?) (str/join " - " (cond-> [(i18n/t :desktop/status-local)]
                                                    (:enabled offline-copy) (conj (i18n/t (case (:state offline-copy)
                                                                                            :offline :desktop/status-copy-offline
                                                                                            :error :desktop/status-copy-error
                                                                                            :desktop/status-copy-synced)))
                                                    (:pending offline-copy) (conj (i18n/t :desktop/status-copy-pending))
                                                    link (conj (i18n/t :desktop/status-link-requested))))
                         :else (str/join " - " (cond-> [(i18n/t (if online :desktop/online :desktop/offline))]
                                                 last-sync (conj (i18n/t :desktop/status-last-sync
                                                                         {:time (subs (str (java.time.LocalTime/now)) 0 5)}))
                                                 (pos? pending) (conj (i18n/tn :desktop/status-pending pending))
                                                 (pos? conflicts) (conj (i18n/tn :desktop/status-conflicts conflicts))))))
    (when-not locked
      (let [{:keys [read write]} @agent-access
            n (count (channel/list-channels))]
        (.setText sync (str (.getText sync) " - "
                            (i18n/t (cond write :desktop/agent-status-write read :desktop/agent-status-read :else :desktop/agent-status-off))
                            (when (pos? n) (str " - " (i18n/tn :desktop/agent-status-channels n)))))))
    (.setToolTipText sync (when (and (local?) (not locked)) (:error offline-copy)))
    (.setText user (cond locked "" (local?) (str file) :else (str (or display-name me) " @ " org)))
    (.layout ^Composite (.getParent cnt) true)))

(defn- render-title! []
  (let [{:keys [locked file org]} (st)
        nm (if (local?) (when-not (str/blank? file) (fs/file-name file)) (not-empty org))]
    (.setText (shell) (cond (nil? nm) "cljpass"
                            locked (str nm " [" (i18n/t :desktop/locked) "] - cljpass")
                            :else (str nm " - cljpass")))))

(defn- render-banner! []
  (let [^Composite b (:banner @w)
        ^Label l (:banner-text @w)
        {:keys [link locked]} (st)]
    (when-let [^org.eclipse.swt.widgets.Button bb (:banner-button @w)]
      (.setText bb (i18n/t :desktop/withdraw-request)))
    (if (or locked (not (local?)) (nil? link))
      (ui/show! b false)
      (do (.setText l (case (:state link)
                        :pending (i18n/t :desktop/link-pending {:server (:server link) :fingerprint (:fingerprint link)})
                        :offline (i18n/t :desktop/link-offline {:server (:server link)})
                        :ready (i18n/t :desktop/link-ready)
                        (i18n/t :desktop/link-error {:error (:error link)})))
          (ui/show! b true)))))

;; ================================================================ Actions

(defn- fail! [e] (dlg/fail! (app) e))

(defn- call [f] (dlg/call (app) f))

(defn- copy-field! [field label]
  (when-let [e (selected-entry)]
    (let [v (call #(svc/get-field (session) (:id e) field))]
      (when (dlg/ok? v) (copy-text! v label)))))

(defn- copy-otp! []
  (when-let [e (selected-entry)]
    (let [r (call #(svc/otp (session) (:id e)))]
      (when (dlg/ok? r) (copy-text! (:code r) (i18n/t :desktop/totp-copied-label {:seconds (:remaining r)}))))))

(defn- show-report! [kind]
  (let [r (call #(svc/password-report (session)))]
    (when (dlg/ok? r)
      (let [dup? (= kind :duplicates)
            ids (set (if dup? (apply concat (:duplicates r)) (:weak r)))]
        (swap! state assoc :filter [:ids (if dup? :desktop/report-duplicates :desktop/report-weak) ids] :folder "" :selected nil)
        (render!)
        (set-status! (cond
                       (empty? ids) (i18n/t (if dup? :desktop/report-duplicates-none :desktop/report-weak-none))
                       dup? (i18n/tn :desktop/report-duplicates-found (count ids) {:groups (count (:duplicates r))})
                       :else (i18n/tn :desktop/report-weak-found (count ids))))))))

(defn- change-master-key! []
  (when (dlg/master-key-dialog (app))
    (set-status! (i18n/t :desktop/master-key-changed))))

(defn- db-settings! []
  (when (dlg/db-settings-dialog (app))
    (refresh!)
    (set-status! (i18n/t :desktop/db-settings-saved))))

(defn- launch-url!
  "Open a URL in the browser (KeePass: WinUtil.OpenUrl), without a scheme
   as https."
  [url]
  (let [u (str/trim (str url))
        u (if (re-find #"^[a-zA-Z][a-zA-Z0-9+.-]*:" u) u (str "https://" u))]
    (if (re-find #"^(?i)https?:" u)
      (Program/launch u)
      (ui/message! (shell) :warn (i18n/t :desktop/open-url) (i18n/t :desktop/open-url-only-http)))))

(defn- open-url! []
  (when-let [e (selected-entry)] (launch-url! (:url e))))

(defn- edit-entry! [id & [tab]]
  (when-let [r (dlg/entry-dialog (app) id tab)]
    (let [[kind v] r]
      (case kind
        :saved (do (swap! state assoc :selected v) (refresh!) (set-status! (i18n/t (if id :desktop/entry-saved :desktop/entry-added))))
        :duplicate (let [nid (call #(svc/duplicate-entry (session) v))]
                     (when (dlg/ok? nid) (swap! state assoc :selected nid) (refresh!)))))))

(declare delete-entries!)

(defn- delete-entry! []
  (when-let [e (if (> (count (selected-ids)) 1) (do (delete-entries!) nil) (selected-entry))]
    (when (or (and (local?) (:recycle-bin-enabled (st)) (not (:recycled e)))
              (ui/confirm? (shell) (i18n/t :desktop/delete-entry)
                           (str (i18n/t (if (local?) :desktop/confirm-delete-entry-final :desktop/confirm-delete-entry)
                                        {:title (:title e)})
                                (when (:shared e) (str "\n\n" (i18n/t :desktop/confirm-delete-entry-shared))))))
      (let [r (call #(svc/delete-entry (session) (:id e)))]
        (when (dlg/ok? r)
          (swap! state assoc :selected nil)
          (refresh!)
          (set-status! (i18n/t (if (= :recycled r) :desktop/entry-recycled :desktop/entry-deleted))))))))

(defn- duplicate! []
  (when-let [e (selected-entry)]
    (let [nid (call #(svc/duplicate-entry (session) (:id e)))]
      (when (dlg/ok? nid) (swap! state assoc :selected nid) (refresh!) (set-status! (i18n/t :desktop/entry-duplicated))))))

(defn- note-sync! [r]
  (when r
    (if (:standalone r)
      (let [{:keys [merged error]} (:offline-copy r)]
        (when (:offline-copy r) (swap! state assoc :offline-copy (:offline-copy r)))
        (cond merged (set-status! (i18n/t :desktop/copy-merged merged))
              error (set-status! error)
              (:reloaded r) (set-status! (i18n/t :desktop/file-reloaded))))
      (do (swap! state assoc :online (not (false? (:online r))) :last-sync (System/currentTimeMillis))
          (when (pos? (get-in r [:push :conflicts] 0))
            (ui/message! (shell) :warn (i18n/t :desktop/synchronize) (i18n/tn :desktop/sync-conflicts (get-in r [:push :conflicts]))))
          (when (pos? (get-in r [:push :rejected] 0))
            (ui/message! (shell) :warn (i18n/t :desktop/synchronize) (i18n/tn :desktop/sync-rejected (get-in r [:push :rejected]))))
          (when-let [l (seq (:log r))] (set-status! (last l)))))))

(defn- sync-now! []
  (let [r (call #(svc/sync-now (session)))]
    (when (dlg/ok? r)
      (note-sync! r)
      (refresh!)
      (when-not (local?) (set-status! (i18n/t (if (:online r) :desktop/synced :desktop/server-unreachable)))))))

(defn- save-now!
  "File > Save. Every change is written right away; this pushes an offline
   copy to the share now and takes over external changes (server: sync)."
  []
  (let [r (call #(svc/sync-now (session)))]
    (when (dlg/ok? r)
      (note-sync! r)
      (refresh!)
      (set-status! (i18n/t (cond (not (local?)) (if (:online r) :desktop/synced :desktop/server-unreachable)
                                 (:online r) :desktop/saved
                                 :else :desktop/saved-offline))))))

(defn- finish-connect! []
  (let [r (call #(svc/finish-connect! (session)))]
    (when (dlg/ok? r)
      (ui/message! (shell) :info (i18n/t :desktop/connected-title)
                   (str (i18n/t :desktop/connect-merged {:created (:created r) :updated (:updated r)})
                        (when (pos? (:copied r)) (str ", " (i18n/t :desktop/connect-copied {:n (:copied r)})))
                        (when (pos? (:deleted r)) (str ", " (i18n/t :desktop/connect-deleted {:n (:deleted r)}))) "."
                        "\n\n" (i18n/t :desktop/connect-backup {:file (:file r)})))
      (swap! state assoc :link nil)
      (boot!))))

(defn- note-link! [link]
  (swap! state assoc :link (when (local?) link))
  (render-banner!)
  (render-status!)
  (when (= :ready (:state link)) (ui/async! (display) finish-connect!)))

(defn- connect! []
  (when-let [l (dlg/connect-dialog (app) (merge (:defaults (st)) {:user (or (get-in (st) [:defaults :user]) (local/default-user))}))]
    (note-link! l)))

(defn- disconnect! []
  (when-let [r (dlg/disconnect-dialog (app) (:file (st)))]
    (set-status! (i18n/tn :desktop/disconnected (:count r)))
    (boot!)))

(defn- sync-file! []
  (when-let [r (dlg/sync-file-dialog (app))]
    (refresh!)
    (set-status! (i18n/t :desktop/file-synced {:added (:added r) :updated (:updated r) :deleted (:deleted r)}))))

(defn- toggle-offline-copy! []
  (let [on (not (get-in (st) [:offline-copy :enabled]))
        r (call #(svc/set-offline-copy! (session) on))]
    (when (dlg/ok? r)
      (swap! state assoc :offline-copy r)
      (refresh!)
      (set-status! (i18n/t (if on :desktop/offline-copy-on :desktop/offline-copy-off))))))

(defn- import! []
  (when-let [r (dlg/import-dialog (app))]
    (refresh!)
    (set-status! (i18n/tn :desktop/imported (:imported r)))))

(defn- export! [& [fmt]]
  (when-let [r (dlg/export-dialog (app) fmt)]
    (set-status! (i18n/tn :desktop/exported (:count r) {:file (:file r)}))))

(defn- open-other! [create]
  (svc/lock! (session))
  (swap! state merge locked-ui)
  (render!)
  (when (start/open-file-dialog (app) {:file (when-not create (:file (st))) :create create :extra (extra?)})
    (boot!)))

(defn- group-msg
  "Status text after renaming/moving a group; what-key names the action."
  [r what-key]
  (str (i18n/t what-key)
       (when (pos? (:updated r 0)) (str " - " (i18n/tn :desktop/entries-changed (:updated r))))
       (when (pos? (:skipped r 0)) (str ", " (i18n/tn :desktop/skipped-no-permission (:skipped r))))))

(defn- parent-of [g] (str/join "/" (butlast (str/split g #"/"))))

(defn- add-group! []
  (let [parent (or (current-group) "")
        n (dlg/group-name-dialog (app) {:title (i18n/t :desktop/add-group) :heading (i18n/t :desktop/add-group)
                                            :sub (i18n/t :desktop/in-group {:group (if (str/blank? parent) (:org (st)) parent)})})]
    (when n
      (let [p (call #(svc/add-group! (session) parent n))]
        (when (dlg/ok? p)
          (swap! state assoc :folder p :filter nil :selected nil)
          (refresh!)
          (set-status! (i18n/t :desktop/group-added)))))))

(defn- rename-group! []
  (when-let [g (current-group)]
    (when-let [n (dlg/group-name-dialog (app) {:title (i18n/t :desktop/rename-group) :heading (i18n/t :desktop/rename-group) :sub g
                                                   :value (last (str/split g #"/"))})]
      (let [r (call #(svc/rename-group! (session) g n))]
        (when (dlg/ok? r)
          (swap! state assoc :folder (:path r))
          (refresh!)
          (set-status! (group-msg r :desktop/group-renamed)))))))

(defn- move-group-to! [g target]
  (let [r (call #(svc/move-group! (session) g target))]
    (when (dlg/ok? r)
      (swap! state assoc :folder (:path r))
      (refresh!)
      (set-status! (group-msg r :desktop/group-moved)))))

(defn- move-group! []
  (when-let [g (current-group)]
    (let [targets (remove #(or (= % g) (str/starts-with? % (str g "/"))) (all-groups))]
      (when-let [t (dlg/choose-group-dialog (app) {:title (i18n/t :desktop/move-group) :heading (i18n/t :desktop/move-group) :sub g
                                                       :groups (vec targets) :root-name (:org (st)) :current (parent-of g)})]
        (move-group-to! g t)))))

(defn- delete-group! []
  (when-let [g (current-group)]
    (let [final? (or (not (:recycle-bin-enabled (st))) (in-bin? g))
          n (count (filter #(let [f (norm-folder (:folder %))] (or (= f g) (str/starts-with? f (str g "/")))) (:entries (st))))]
      (when (or (not final?)
                (ui/confirm? (shell) (i18n/t :desktop/delete-group)
                             (if (pos? n)
                               (i18n/tn :desktop/confirm-delete-group-entries n {:group g})
                               (i18n/t :desktop/confirm-delete-group {:group g}))))
        (let [r (call #(svc/delete-group! (session) g))]
          (when (dlg/ok? r)
            (swap! state assoc :folder (if (:recycled r) (:path r) (parent-of g)) :selected nil)
            (refresh!)
            (set-status! (i18n/t (if (:recycled r) :desktop/group-recycled :desktop/group-deleted)))))))))

(defn- group-icon! []
  (when-let [g (current-group)]
    (when-let [i (dlg/icon-dialog (app) (get-in (st) [:folder-icons g :id] 48))]
      (when (dlg/ok? (call #(svc/set-group-icon! (session) g i)))
        (refresh!)
        (set-status! (i18n/t :desktop/group-icon-changed))))))

(defn- empty-bin! []
  (when (ui/confirm? (shell) (i18n/t :desktop/empty-bin) (i18n/t :desktop/confirm-empty-bin))
    (let [n (call #(svc/empty-recycle-bin! (session)))]
      (when (dlg/ok? n)
        (swap! state assoc :selected nil)
        (refresh!)
        (set-status! (i18n/tn :desktop/bin-emptied n))))))

(defn- bulk-msg
  "Status text after a bulk change; what-key is a counted key ({n} entries ...)."
  [r what-key]
  (str (i18n/tn what-key (:updated r))
       (when (pos? (:skipped r 0)) (str ", " (i18n/tn :desktop/skipped-no-permission (:skipped r))))))

(defn- move-entries-to! [ids folder]
  (let [r (call #(svc/move-entries! (session) ids folder))]
    (when (dlg/ok? r)
      (refresh!)
      (set-status! (bulk-msg r (if (in-bin? folder) :desktop/entries-recycled :desktop/entries-moved))))))

(defn- move-entries! []
  (when-let [ids (not-empty (selected-ids))]
    (when-let [t (dlg/choose-group-dialog (app) {:title (i18n/t :desktop/move-to-group) :heading (i18n/t :desktop/move-to-group)
                                                     :sub (i18n/tn :desktop/entry-count (count ids))
                                                     :groups (vec (all-groups)) :root-name (:org (st))
                                                     :current (current-group)})]
      (move-entries-to! ids t))))

(defn- tag-entries! []
  (when-let [ids (not-empty (selected-ids))]
    (when-let [t (dlg/tags-dialog (app) {:count (count ids) :tags (vec (all-tags))})]
      (let [r (call #(svc/tag-entries! (session) ids t))]
        (when (dlg/ok? r) (refresh!) (set-status! (bulk-msg r :desktop/entries-changed)))))))

(defn- delete-entries! []
  (let [es (selected-entries)
        n (count es)
        final (remove #(and (local?) (:recycle-bin-enabled (st)) (not (:recycled %))) es)]
    (when (and (pos? n)
               (or (empty? final)
                   (ui/confirm? (shell) (i18n/t :desktop/delete-entries)
                                (str (if (= (count final) n)
                                       (i18n/t :desktop/confirm-delete-entries {:n n})
                                       (i18n/t :desktop/confirm-delete-entries-partial {:n n :final (count final)}))
                                     (when (some :shared final) (str "\n\n" (i18n/t :desktop/confirm-delete-entries-shared)))))))
      (let [r (call #(svc/delete-entries! (session) (map :id es)))]
        (when (dlg/ok? r)
          (swap! state assoc :selected nil)
          (refresh!)
          (set-status! (str/join ", " (remove nil? [(when (pos? (:recycled r)) (i18n/t :desktop/n-recycled {:n (:recycled r)}))
                                                    (when (pos? (:deleted r)) (i18n/t :desktop/n-deleted {:n (:deleted r)}))
                                                    (when (pos? (:skipped r)) (i18n/t :desktop/n-skipped-owner {:n (:skipped r)}))]))))))))

(defn- select-all! []
  (let [rows (visible)]
    (when (seq rows)
      (swap! state assoc :selection (mapv :id rows) :selected (or (some #{(:selected (st))} (map :id rows)) (:id (first rows))))
      (render-list!) (render-details!) (update-actions!) (render-status!))))

(defn- load-passwords!
  "Fetch the passwords for the list (only when shown)."
  []
  (if (and (:show-passwords (st)) (not (:locked (st))))
    (let [r (call #(svc/passwords (session) (map :id (:entries (st)))))]
      (when (dlg/ok? r) (swap! state assoc :passwords r)))
    (swap! state assoc :passwords {})))

(defn- save-prefs! [k v]
  (try (local/update-prefs! #(assoc % k v))
       (catch Exception e (set-status! (i18n/t :desktop/prefs-not-saved {:error (ex-message e)})))))

(defn- toggle-column! [k]
  (swap! state update :columns (fn [cs] (let [cs (if (some #{k} cs) (vec (remove #{k} cs)) (conj (vec cs) k))]
                                          (if (empty? cs) [:title] cs))))
  (save-prefs! :columns (:columns (st)))
  (build-columns!)
  (render-list!))

(defn- toggle-passwords! []
  (swap! state update :show-passwords not)
  (save-prefs! :show-passwords (:show-passwords (st)))
  (when (and (:show-passwords (st)) (not (some #{:password} (:columns (st)))))
    (toggle-column! :password))
  (load-passwords!)
  (render-list!))

(defn- apply-options! [{:keys [idle-minutes clipboard-seconds]}]
  (when idle-minutes
    (swap! w assoc :idle-seconds (* 60 idle-minutes))
    (doseq [d (:list @docs)] (svc/set-idle! (:session d) (* 60 idle-minutes))))
  (when clipboard-seconds (reset! clear-seconds (max 1 clipboard-seconds))))

(defn- options! []
  (let [p (local/load-prefs)]
    (when-let [o (dlg/options-dialog (app) {:idle-minutes (:idle-minutes p 5) :clipboard-seconds (:clipboard-seconds p 12)})]
      (local/update-prefs! #(merge % o))
      (apply-options! o)
      (set-status! (i18n/t :desktop/options-saved)))))

(defn- open-recent! [f]
  (svc/lock! (session))
  (swap! state merge locked-ui)
  (render!)
  (when (start/open-file-dialog (app) {:file f :extra (extra?)})
    (boot!)))

(defn- set-filter! [f folder]
  (swap! state assoc :filter f :folder folder :selected nil)
  (render!))

(defn- set-language!
  "View > Language: nil = automatic (operating system), else \"en\"/\"de\".
   Stores the choice and rebuilds all texts of the main window live."
  [lang]
  (when (not= lang (:lang-choice (st)))
    (swap! state assoc :lang-choice lang)
    (try (local/update-prefs! #(if lang (assoc % :lang lang) (dissoc % :lang)))
         (catch Exception e (set-status! (i18n/t :desktop/prefs-not-saved {:error (ex-message e)}))))
    (i18n/set-lang! (or lang (i18n/os-lang) i18n/default-lang))
    ;; after the menu has closed: render! replaces the menu bar
    (ui/async! (display) #(when-not (.isDisposed (shell))
                            (build-columns!)
                            (render!)))))

(defn- ctrl
  "Shortcut text shown in menus and tooltips, e.g. Ctrl+O / Strg+O."
  [k]
  (i18n/t :desktop/key-ctrl {:key k}))

(defn- actions
  "All actions: {key {:label :icon :key (display text) :accel (SWT) :on bool :run fn}}.
   :sub (fn [] [[text f checked] ...]) builds a submenu, :radio makes its items radio items."
  []
  (let [e (selected-entry)
        {:keys [locked link standalone-allowed]} (st)
        open (not locked)
        can-edit (and e (#{"update" "owner"} (:permission e)))
        owner (and e (= "owner" (:permission e)))
        g (current-group)
        n (count (selected-ids))
        one (and e (= 1 n))
        t i18n/t]
    {:open-tab {:label (t :desktop/open-in-tab) :icon "folderOpen" :run open-in-tab!}
     :close-tab {:label (t :desktop/close-tab) :key (ctrl "W") :accel (+ SWT/MOD1 (int \W)) :on (extra?)
                 :run #(close-doc! (:active @docs))}
     :new {:label (t :desktop/new) :icon "vault" :on (or (local?) locked) :run #(open-other! true)}
     :open {:label (t :desktop/open) :icon "folderOpen" :key (ctrl "O") :accel (+ SWT/MOD1 (int \O)) :on (or (local?) locked) :run #(open-other! false)}
     :unlock {:label (t (if locked :desktop/unlock-workspace :desktop/lock-workspace)) :icon "lock" :key (ctrl "L")
              :accel (+ SWT/MOD1 (int \L)) :run #(if (:locked (st)) (boot!) (lock!))}
     :import {:label (t :desktop/import) :icon "import" :on open :run import!}
     :export {:label (t :desktop/export) :icon "export" :on open :run export!}
     :print {:label (t :desktop/print) :icon "printer" :key (ctrl "P") :accel (+ SWT/MOD1 (int \P)) :on open :run #(export! :html)}
     :sync-file {:label (t :desktop/sync-with-file) :icon "conflict" :on (and open (local?)) :run sync-file!}
     :offline-copy {:label (t :desktop/offline-copy) :on (and open (local?)) :check (boolean (get-in (st) [:offline-copy :enabled]))
                    :run toggle-offline-copy!}
     :master-key {:label (t :desktop/change-master-key) :icon "lock" :on (and open (local?)) :run change-master-key!}
     :db-settings {:label (t :desktop/database-settings) :icon "gear" :on (and open (local?)) :run db-settings!}
     :save {:label (t :desktop/save) :icon "disk" :key (ctrl "S") :accel (+ SWT/MOD1 (int \S)) :on open :run save-now!}
     :sync {:label (t (if (local?) :desktop/reload :desktop/synchronize)) :icon "sync" :key "F5" :accel SWT/F5 :on open :run sync-now!}
     :connect {:label (t :desktop/connect-to-server) :icon "share" :on (and open (local?) (not (extra?)) (not= :pending (:state link)) (not= :offline (:state link))) :run connect!}
     :disconnect {:label (t :desktop/disconnect-from-server) :icon "export" :on (and open (not (local?)) (not (extra?)) standalone-allowed) :run disconnect!}
     :exit {:label (t :desktop/exit) :key (ctrl "Q") :accel (+ SWT/MOD1 (int \Q)) :run #(.close (shell))}
     :user {:label (t :desktop/copy-username) :icon "user" :key (ctrl "B") :on (boolean (and e (seq (:username e))))
            :run #(copy-field! "username" (t :desktop/col-username))}
     :pw {:label (t :desktop/copy-password) :icon "key" :key (ctrl "C") :on (boolean e) :run #(copy-field! "password" (t :desktop/col-password))}
     :url {:label (t :desktop/open-url) :icon "url" :key (ctrl "U") :on (boolean (and e (seq (:url e)))) :run open-url!}
     :urlcopy {:label (t :desktop/copy-url) :icon "clipboard" :on (boolean (and e (seq (:url e)))) :run #(copy-field! "url" "URL")}
     :otp {:label (t :desktop/copy-totp) :icon "history" :key (ctrl "T") :on (boolean (and e (:otp e))) :run copy-otp!}
     :add {:label (t :desktop/add-entry) :icon "add" :key (ctrl "I") :accel (+ SWT/MOD1 (int \I)) :on open :run #(edit-entry! nil)}
     :edit {:label (t (if (or can-edit (nil? e)) :desktop/edit-entry :desktop/view-entry)) :icon "edit" :key (t :desktop/key-enter)
            :on (boolean one) :run #(edit-entry! (:id e))}
     :dup {:label (t :desktop/duplicate-entry) :icon "dup" :key (ctrl "K") :on (boolean one) :run duplicate!}
     :del {:label (t (if (> n 1) :desktop/delete-entries :desktop/delete-entry)) :icon "del" :key (t :desktop/key-del)
           :on (boolean (or owner (> n 1))) :run delete-entry!}
     :move {:label (t :desktop/move-to-group-menu) :icon "folderOpen" :on (boolean e) :run move-entries!}
     :tag {:label (t :desktop/edit-tags) :icon "list" :on (boolean e) :run tag-entries!}
     :select-all {:label (t :desktop/select-all) :key (ctrl "A") :on open :run select-all!}
     :share {:label (t :desktop/share) :icon "share" :key (ctrl "E") :on (boolean (and e (not (local?)))) :run #(edit-entry! (:id e) :share)}
     :history {:label (t :desktop/history) :icon "history" :on (boolean e) :run #(edit-entry! (:id e) :history)}
     ;; Changing the password AT THE TARGET: only where the entry declares a
     ;; changer this machine knows (cljpass.rotate) - and only for someone
     ;; who may write the new one back.
     :rotate {:label (t :desktop/rotate-entry) :icon "key"
              :on (boolean (and one can-edit (rotate/rotatable? e)))
              :run rotate-entry!}
     :group-add {:label (t :desktop/add-group-menu) :icon "folder" :on (and open (local?)) :run add-group!}
     :group-edit {:label (t :desktop/rename-group-menu) :icon "edit" :on (boolean (and open g)) :run rename-group!}
     :group-move {:label (t :desktop/move-group-menu) :icon "folderOpen" :on (boolean (and open g)) :run move-group!}
     :group-del {:label (t (if (and g (in-bin? g)) :desktop/delete-group-permanently :desktop/delete-group)) :icon "del"
                 :on (boolean (and open g (local?) (not= g (:recycle-bin (st))))) :run delete-group!}
     :group-icon {:label (t :desktop/change-icon) :icon "gear" :on (boolean (and open g (local?))) :run group-icon!}
     :empty-bin {:label (t :desktop/empty-bin) :icon "del" :on (boolean (and open (local?) (:recycle-bin (st)))) :run empty-bin!}
     :find {:label (t :desktop/find) :icon "list" :key (ctrl "F") :accel (+ SWT/MOD1 (int \F)) :on open
            :run #(let [^Text s (:search @w)] (.setFocus s) (.selectAll s))}
     :all {:label (t :desktop/show-all-entries) :icon "list" :on open :run #(set-filter! nil "")}
     :expired {:label (t :desktop/show-expired-entries) :icon "history" :on open :run #(set-filter! :expired "")}
     :expiring {:label (t :desktop/show-expiring-entries) :icon "warn" :on open :run #(set-filter! :expiring "")}
     :tags {:label (t :desktop/entries-with-tag) :icon "list" :on (and open (boolean (seq (all-tags))))
            :sub (fn [] (for [tg (all-tags)] [tg #(set-filter! [:tag tg] "")]))}
     :duplicates {:label (t :desktop/duplicate-passwords) :icon "dup" :on open :run #(show-report! :duplicates)}
     :weak {:label (t :desktop/weak-passwords) :icon "warn" :on open :run #(show-report! :weak)}
     :case {:label (t :desktop/case-sensitive) :check (get-in (st) [:search-opts :case])
            :run #(do (swap! state update-in [:search-opts :case] not) (render-list!) (render-status!))}
     :regex {:label (t :desktop/regular-expression) :check (get-in (st) [:search-opts :regex])
             :run #(do (swap! state update-in [:search-opts :regex] not) (render-list!) (render-status!))}
     :with-me {:label (t :desktop/shared-with-me) :icon "shared" :on (and open (not (local?))) :run #(set-filter! nil with-me)}
     :by-me {:label (t :desktop/shared-by-me) :icon "share" :on (and open (not (local?))) :run #(set-filter! nil by-me)}
     :toolbar {:label (t :desktop/show-toolbar) :check (:show-toolbar (st))
               :run #(do (swap! state update :show-toolbar not) (ui/show! (:toolbar-row @w) (:show-toolbar (st))))}
     :details {:label (t :desktop/show-entry-view) :check (:show-details (st))
               :run #(do (swap! state update :show-details not)
                         (let [^SashForm sf (:vsash @w)]
                           (.setMaximizedControl sf (when-not (:show-details (st)) ^Control (:table @w)))))}
     :on-top {:label (t :desktop/always-on-top) :check false
              :run #(ui/message! (shell) :info (t :desktop/view) (t :desktop/on-top-window-manager))}
     :columns {:label (t :desktop/columns) :icon "list"
               :sub (fn [] (for [[k txt] all-columns] [(t txt) #(toggle-column! k) (boolean (some #{k} (:columns (st))))]))}
     :show-pw {:label (t :desktop/show-passwords) :check (:show-passwords (st)) :run toggle-passwords!}
     ;; language names stay in their own language
     :language {:label (t :desktop/language) :icon "world" :radio true
                :sub (fn [] (let [cur (:lang-choice (st))]
                              [[(t :desktop/language-automatic) #(set-language! nil) (nil? cur)]
                               ["English" #(set-language! "en") (= "en" cur)]
                               ["Deutsch" #(set-language! "de") (= "de" cur)]]))}
     :options {:label (t :desktop/options) :icon "gear" :run options!}
     :agent-read {:label (t :desktop/agent-read) :check (:read @agent-access)
                  :run #(do (swap! agent-access update :read not)
                            (when-not (:read @agent-access) (agent-off!))
                            (local/update-prefs! (fn [m] (assoc m :agent-read (:read @agent-access))))
                            (render-menu!) (render-status!))}
     :agent-write {:label (t :desktop/agent-write) :check (:write @agent-access) :on (and open (:read @agent-access))
                   :run #(do (swap! agent-access update :write not) (render-menu!) (render-status!))}
     :agent-close {:label (t :desktop/agent-close-channels {:n (count (channel/list-channels))}) :icon "lock"
                   :on (boolean (seq (channel/list-channels)))
                   :run #(do (channel/close-all!) (render-menu!) (render-status!))}
     :recent {:label (t :desktop/open-recent) :icon "folderOpen" :on (boolean (and (or (local?) locked) (seq (svc/recent-files))))
              :sub (fn [] (for [f (svc/recent-files)] [f #(open-recent! f)]))}
     :gen {:label (t :desktop/password-generator) :icon "gen" :run #(dlg/generator (app) false)}
     :conflicts {:label (t :desktop/conflicts-and-queue) :icon "conflict" :on (and open (not (local?)))
                 :run #(do (dlg/conflicts-dialog (app) (into {} (map (juxt :id :title)) (:entries (st)))) (refresh!))}
     :about {:label (t :desktop/about) :icon "vault"
             :run #(dlg/about-dialog (app) (cond (:locked (st)) (t :desktop/about-locked)
                                                     (local?) (t :desktop/about-local {:file (:file (st))})
                                                     :else (t :desktop/about-server {:user (:me (st)) :org (:org (st))})))}}))

(defn- menus []
  [[(i18n/t :desktop/menu-file) (if (or (local?) (:locked (st)))
                                  [:open :open-tab :recent :new :close-tab :- :save :- :export :print :- :import :sync-file :offline-copy :- :db-settings :master-key :- :connect :- :sync :- :unlock :exit]
                                  [:open-tab :close-tab :- :save :- :import :export :print :- :sync :- :disconnect :- :unlock :exit])]
   [(i18n/t :desktop/menu-group) [:group-add :group-edit :group-icon :group-move :group-del :- :empty-bin]]
   [(i18n/t :desktop/menu-entry) [:user :pw :otp :url :urlcopy :- :add :edit :dup :del :- :move :tag :select-all :- :share :history :- :rotate]]
   [(i18n/t :desktop/menu-find) [:find :case :regex :- :all :expired :expiring :tags :- :duplicates :weak :- :with-me :by-me]]
   [(i18n/t :desktop/menu-view) [:toolbar :details :- :columns :show-pw :- :language]]
   [(i18n/t :desktop/menu-tools) [:gen :- :options :- :agent-read :agent-write :agent-close :- :conflicts]]
   [(i18n/t :desktop/menu-help) [:about]]])

(def ^:private toolbar-keys [:open :save :sync :- :add :- :user :pw :url :urlcopy :- :share :gen :- :unlock])

(defn- build-menu-items! [^Menu m ks acts]
  (doseq [k ks]
    (if (= k :-)
      (MenuItem. m SWT/SEPARATOR)
      (let [{:keys [label icon key accel on check run sub radio]} (acts k)
            it (MenuItem. m (int (cond sub SWT/CASCADE (some? check) SWT/CHECK :else SWT/PUSH)))]
        (.setText it (str label (when key (str "\t" key))))
        (when accel (.setAccelerator it (int accel)))
        (when icon (.setImage it (ui/icon (display) icon)))
        (when (some? check) (.setSelection it (boolean check)))
        (.setEnabled it (not (false? on)))
        (if sub
          (let [sm (Menu. m)
                xs (sub)]
            (doseq [[txt f checked] xs]
              (let [si (MenuItem. sm (int (cond radio SWT/RADIO (some? checked) SWT/CHECK :else SWT/PUSH)))]
                (.setText si (str txt))
                (when (some? checked) (.setSelection si (boolean checked)))
                ;; radio items also fire when they get deselected
                (ui/on si SWT/Selection (fn [_] (when (or (not radio) (.getSelection si)) (f))))))
            (when (empty? xs)
              (doto (MenuItem. sm SWT/PUSH) (.setText (i18n/t :desktop/menu-none)) (.setEnabled false)))
            (.setMenu it sm))
          (ui/on it SWT/Selection (fn [_] (run))))))))

(defn- render-menu! []
  (let [acts (actions)
        old (.getMenuBar (shell))
        bar (Menu. (shell) SWT/BAR)]
    (doseq [[title ks] (menus)]
      (let [top (MenuItem. bar SWT/CASCADE)
            m (Menu. (shell) SWT/DROP_DOWN)]
        (.setText top title)
        (.setMenu top m)
        ;; determine enabled state again on opening (the selection may have changed)
        (ui/on m SWT/Show (fn [_]
                            (doseq [^MenuItem i (.getItems m)] (.dispose i))
                            (build-menu-items! m ks (actions))))
        (build-menu-items! m ks acts)))
    (.setMenuBar (shell) bar)
    (when old (.dispose old))))

(defn- render-toolbar! []
  (let [^ToolBar tb (:toolbar @w)
        acts (actions)]
    (.setMessage ^Text (:search @w) (i18n/t :desktop/search-placeholder))
    (doseq [^ToolItem i (.getItems tb)] (.dispose i))
    (doseq [k toolbar-keys]
      (if (= k :-)
        (ToolItem. tb SWT/SEPARATOR)
        (let [{:keys [label icon key on run]} (acts k)
              it (ToolItem. tb SWT/PUSH)]
          (.setImage it (ui/icon (display) (if (and (= k :unlock) (:locked (st))) "lockOpen" icon)))
          (.setToolTipText it (str (str/replace label "..." "") (when key (str " (" key ")"))))
          (.setEnabled it (not (false? on)))
          (ui/on it SWT/Selection (fn [_] (run))))))
    (.pack tb)
    (.layout ^Composite (:toolbar-row @w) true)))

(defn- update-actions!
  "After a selection change: enable/disable the toolbar items."
  []
  (let [acts (actions)
        ^ToolBar tb (:toolbar @w)]
    (doseq [[k ^ToolItem it] (map vector (remove #{:-} toolbar-keys) (remove #(zero? (bit-and (.getStyle ^ToolItem %) SWT/PUSH)) (.getItems tb)))]
      (.setEnabled it (not (false? (:on (acts k))))))))

(defn render! []
  (.setEnabled ^Text (:search @w) (not (:locked (st))))
  (render-tabs!)
  (render-title!)
  (render-menu!)
  (render-toolbar!)
  (render-banner!)
  (render-tree!)
  (render-list!)
  (render-details!)
  (render-status!))

(defn- context-menu! [^Control c ks]
  (let [m (Menu. c)]
    (ui/on m SWT/Show (fn [_]
                        (doseq [^MenuItem i (.getItems m)] (.dispose i))
                        (build-menu-items! m ks (actions))))
    (.setMenu c m)))

;; ================================================================ Data

(defn refresh!
  "Reload and show the entries."
  []
  (let [r (call #(svc/list-entries (session)))]
    (when (dlg/ok? r)
      (let [{:keys [entries]} r
            s (session)]
        (swap! state (fn [m]
                       (assoc m
                              :entries entries
                              :folder-icons (into {} (map (juxt :folder :icon)) (:folder-icons r))
                              :org (or (:org r) (i18n/t :desktop/vault-default-name))
                              :mode (or (:mode r) (:mode m))
                              :file (or (:file r) (:file m))
                              :offline-copy (:offline-copy r)
                              :me (:user r) :display-name (:display-name r)
                              :default-username (or (:default-username r) "")
                              :groups (vec (:groups r))
                              :recycle-bin (:recycle-bin r)
                              :recycle-bin-enabled (boolean (:recycle-bin-enabled r))
                              :selected (when (some #(= (:selected m) (:id %)) entries) (:selected m))
                              :selection (let [ids (set (map :id entries))] (filterv ids (:selection m))))))
        (when-not (local?)
          (swap! state assoc :pending (svc/pending-count s) :conflicts (count (svc/conflicts s))))
        (doseq [err (:errors r)] (set-status! (i18n/t :desktop/entry-unreadable {:error (:error err)})))
        (when (:show-passwords (st)) (load-passwords!))
        (render!)))))

(defn- lock-all!
  "Locks every tab (KeePass: Lock Workspace)."
  []
  (doseq [d (:list @docs)] (svc/lock! (:session d)))
  (swap! docs update :list (fn [l] (mapv #(update % :ui merge locked-ui) l)))
  (swap! state merge locked-ui)
  (render!))

(defn lock! []
  (agent-off!)
  (lock-all!)
  (set-status! (i18n/t :desktop/workspace-locked)))

(declare boot!)

(defn- setup!
  "First start without automatic enrollment: file or server?"
  [app st]
  (case (start/setup-dialog app st)
    :local-new (when (start/open-file-dialog app {:file (:file st) :create true}) (boot!))
    :local-open (when (start/open-file-dialog app {:file nil}) (boot!))
    :server (when (start/enroll-dialog app st) (boot!))
    (when-not (.isDisposed (shell)) (.close (shell)))))

(defn boot!
  "Determine the state and continue accordingly (setup, open, wait, list)."
  []
  (let [app (app)
        st (when-not (.isDisposed (shell))
             (try (ui/busy (display) #(svc/status (session))) (catch Throwable e (fail! e) nil)))]
    (when st
      (swap! state assoc :mode (or (:mode st) :server) :file (or (:file st) (:file (st)))
             :defaults (or (:defaults st) {}) :standalone-allowed (not (false? (:standalone-allowed st))))
      (case (:state st)
        :not-enrolled
        (if-let [auto (svc/auto-enroll-config)]
          ;; org.edn with {:kerberos true}: set up with the Windows logon, without any input
          (let [ok (try (ui/busy (display) #(svc/enroll! (session) auto)) true
                        (catch Throwable e (fail! e) false))]
            (if ok
              (boot!)
              (setup! app st)))
          (setup! app st))

        :locked
        (do (swap! state assoc :passwords {} :locked true :entries [])
            (render!)
            (if (local?)
              (when (start/open-file-dialog app {:file (:file st) :extra (extra?)}) (boot!))
              (when (dlg/ok? (call #(svc/unlock! (session)))) (boot!))))

        :pending
        (do (swap! state assoc :locked true)
            (render!)
            (if (start/pending-dialog app (:fingerprint st) (:kerberos st)) (boot!) (when-not (.isDisposed (shell)) (.close (shell)))))

        :active
        (let [unlocked (:locked @state) s (session)]
          (swap! state assoc :locked false :me (:user st))
          (note-sync! (:sync st))
          (refresh!)
          (note-link! (:link st))
          (.setFocus ^Table (:table @w))
          ;; only when it was just opened or unlocked, not after every boot!
          (when unlocked (ui/async! (display) #(auto-open! s))))))))

;; ================================================================ Tabs and AutoOpen

(defn- doc-ui
  "State of tab i (that of the active tab is in state)."
  [i]
  (if (= i (:active @docs)) (select-keys (st) (keys doc-defaults)) (get-in @docs [:list i :ui])))

(defn- tab-title [{:keys [mode file org]}]
  (or (not-empty (if (= :standalone mode) (when-not (str/blank? file) (fs/file-name file)) org)) "cljpass"))

(defn- render-tabs!
  "Tab bar above the list - only shown with more than one database."
  []
  (when-let [^CTabFolder f (:tabs @w)]
    (let [n (count (:list @docs))]
      (doseq [[i ^CTabItem it] (map-indexed vector (.getItems f))]
        (let [u (doc-ui i)]
          (.setText it ^String (cond-> (tab-title u) (:locked u) (str " [" (i18n/t :desktop/locked) "]")))
          (.setToolTipText it (str (when (= :standalone (:mode u)) (:file u))))
          (.setImage it (ui/icon (display) (if (:locked u) "lock" "vault")))))
      (when (< (:active @docs) (.getItemCount f)) (.setSelection f (int (:active @docs))))
      (when (not= (> n 1) (.getVisible f))
        ;; only the tab bar: the folder has no content of its own (the hint is
        ;; the content height, the layout adds the tabs)
        (set! (.-heightHint ^org.eclipse.swt.layout.GridData (.getLayoutData f)) 0)
        (ui/show! f (> n 1))))))

(defn- switch-doc!
  "Makes tab i the active one: its state moves into state."
  [i]
  (let [{:keys [active list]} @docs]
    (when (and (not= i active) (< -1 i (count list)))
      (swap! docs #(-> % (assoc-in [:list active :ui] (select-keys (st) (keys doc-defaults))) (assoc :active i)))
      (swap! state merge (get-in @docs [:list i :ui]))
      (.setText ^Text (:search @w) (str (:search (st))))
      (render!))))

(defn- idle-seconds [] (or (:idle-seconds @w) (* 60 (:idle-minutes (local/load-prefs) 5))))

(defn- add-doc!
  "New tab (locked) for the session sess of a further file. Returns its index."
  [sess]
  (CTabItem. ^CTabFolder (:tabs @w) (int (if (seq (:list @docs)) SWT/CLOSE SWT/NONE)))
  (swap! docs update :list conj {:session sess
                                 :ui (assoc doc-defaults :mode :standalone :file (or (svc/session-file sess) ""))})
  (render-tabs!)
  (dec (count (:list @docs))))

(defn- close-doc!
  "Closes tab i (not the main database) and locks its session."
  [i]
  (when (and (pos? i) (< i (count (:list @docs))))
    (when (= i (:active @docs)) (switch-doc! (dec i)))
    (svc/lock! (get-in @docs [:list i :session]))
    (swap! docs (fn [d] (cond-> (update d :list #(into (subvec % 0 i) (subvec % (inc i))))
                          (> (:active d) i) (update :active dec))))
    (.dispose (.getItem ^CTabFolder (:tabs @w) (int i)))
    (render!)))

(defn- open-in-tab!
  "File > Open in new tab: a further KeePass file beside the current database."
  []
  (let [prev (:active @docs)
        i (add-doc! (svc/new-session {:idle-seconds (idle-seconds)}))]
    (switch-doc! i)
    (if (start/open-file-dialog (app) {:extra true})
      (boot!)
      (do (close-doc! i) (switch-doc! prev)))))

(defn- same-file? [a b]
  (and (not (str/blank? a)) (not (str/blank? b))
       (let [a (fs/absolutize a) b (fs/absolutize b)]
         (if (local/windows?) (.equalsIgnoreCase ^String a b) (= a b)))))

(defn- doc-of-file [file]
  (first (keep-indexed (fn [i d] (when (same-file? file (svc/session-file (:session d))) i)) (:list @docs))))

(defn- open-auto-item!
  "Opens the database of one AutoOpen entry of session src in a tab, like
   KeeAutoExec: without a stored master key, or with a wrong one, the unlock
   dialog asks for it. An already open file is not opened twice (a locked
   tab is unlocked). Returns the error text or nil."
  [src {:keys [id title label]}]
  (try
    (let [t (ui/busy (display) #(svc/auto-open-target src id))
          prev (:active @docs)
          existing (when-not (:skip t) (doc-of-file (:file t)))]
      ;; the main database (tab 0) is unlocked the normal way
      (when-not (or (:skip t) (= 0 existing)
                    (and existing (not (svc/locked? (get-in @docs [:list existing :session])))))
        (let [i (or existing (add-doc! (svc/new-session {:idle-seconds (idle-seconds)})))
              s (get-in @docs [:list i :session])
              opened (or (and (not (:prompt t))
                              (try (ui/busy (display) #(svc/open-extra-file! s (select-keys t [:file :password :keyfile])))
                                   true
                                   (catch Throwable e
                                     (when-not (= :kdbx-bad-key (:type (ex-data e)))
                                       (when-not existing (close-doc! i))
                                       (throw e))
                                     false)))
                         (do (switch-doc! i)
                             (swap! state assoc :file (:file t))
                             (render-tabs!)
                             (start/open-file-dialog (app) {:file (:file t) :extra true})))]
          (cond
            opened (do (switch-doc! i)
                       (boot!)
                       (when (:restore-focus t) (switch-doc! prev)))
            existing (do (render-tabs!) (switch-doc! prev))
            :else (do (close-doc! i) (switch-doc! prev)))))
      nil)
    (catch Throwable e
      (str (if (str/blank? title) label title) ": " (ui/error-text e)))))

(defn- auto-open!
  "AutoOpen (like the KeePass plugin KeeAutoExec, see cljpass.autoopen):
   after the database of session src has been unlocked, open the files of
   its AutoOpen group in tabs. Opened files can open further ones; each file
   is opened only once."
  [src]
  (when-not (or (.isDisposed (shell)) (svc/locked? src))
    (let [items (try (filterv :auto (svc/auto-open-items src))
                     (catch Throwable e (set-status! (ui/error-text e)) []))
          errors (vec (keep #(open-auto-item! src %) items))]
      (when (seq errors)
        (ui/message! (shell) :warn (i18n/t :desktop/auto-open) (str/join "\n\n" errors))))))

;; ================================================================ Drag and drop

(defonce ^:private dnd-transfer (delay (format-transfer "cljpass/intern")))

(defn- drop-target-path
  "Folder path of the tree node under the mouse pointer, or nil (no target)."
  [^DropTargetEvent e]
  (when-let [^TreeItem it (when (instance? TreeItem (.-item e)) (.-item e))]
    (let [p (str (.getData it))]
      (when-not (str/starts-with? p "\u0000") p))))

(defn- droppable? [drag target]
  (and target
       (case (:kind drag)
         :entries true
         :group (and (not= target (parent-of (:path drag)))
                     (not= target (:path drag)) (not (str/starts-with? target (str (:path drag) "/"))))
         false)))

(defn- dnd!
  "Drag entries from the list and groups in the tree onto a group (like
   KeePass). The data stays in the process; only a marker in a private
   format is transferred, which other programs do not accept."
  [^Table table ^Tree tree]
  (let [drag (atom nil)
        types ^"[Lorg.eclipse.swt.dnd.Transfer;" (into-array Transfer [@dnd-transfer])
        source (fn [^Control c start]
                 (doto (DragSource. c DND/DROP_MOVE)
                   (.setTransfer types)
                   (.addDragListener
                    (reify DragSourceListener
                      (dragStart [_ e] (let [d (start e)] (reset! drag d) (set! (.-doit ^DragSourceEvent e) (boolean d))))
                      (dragSetData [_ e] (set! (.-data ^DragSourceEvent e) (byte-array [1])))
                      (dragFinished [_ _] (reset! drag nil))))))
        over (fn [^DropTargetEvent e]
               (set! (.-feedback e) (int (bit-or DND/FEEDBACK_SELECT DND/FEEDBACK_SCROLL DND/FEEDBACK_EXPAND)))
               (set! (.-detail e) (int (if (droppable? @drag (drop-target-path e)) DND/DROP_MOVE DND/DROP_NONE))))]
    ;; GTK reports the selection only on release: take the row under the pointer or the table selection
    (source table (fn [^DragSourceEvent e]
                    (let [under (some-> (.getItem table (Point. (.-x e) (.-y e))) .getData)
                          sel (into [] (keep #(.getData ^TableItem %)) (.getSelection table))
                          ids (if (and under (not (some #{under} sel))) [under] sel)]
                      (when (seq ids) {:kind :entries :ids ids}))))
    (source tree (fn [^DragSourceEvent e]
                   (when-let [^TreeItem it (.getItem tree (Point. (.-x e) (.-y e)))]
                     (let [p (str (.getData it))]
                       (when-not (or (str/blank? p) (str/starts-with? p "\u0000")) {:kind :group :path p})))))
    (doto (DropTarget. tree DND/DROP_MOVE)
      (.setTransfer types)
      (.addDropListener
       (reify DropTargetListener
         (dragEnter [_ e] (over e))
         (dragOver [_ e] (over e))
         (dragOperationChanged [_ e] (over e))
         (dragLeave [_ _])
         (dropAccept [_ e] (over e))
         (drop [_ e]
           (let [d @drag target (drop-target-path e)]
             (when (droppable? d target)
               ;; run after the drag has ended (dialogs, rebuilding the tree)
               (ui/async! (display) #(case (:kind d)
                                       :entries (move-entries-to! (:ids d) target)
                                       :group (move-group-to! (:path d) target)))))))))))

;; ================================================================ Window

(defn- build! ^Shell [^Display d sess]
  (let [s (Shell. d SWT/SHELL_TRIM)
        _ (.setText s "cljpass")
        _ (.setImages s ^"[Lorg.eclipse.swt.graphics.Image;" (into-array [(ui/icon d "vault") (ui/icon d "vault" true)]))
        _ (.setLayout s (ui/grid 1 :margin 0 :spacing 0))
        ;; toolbar + quick search
        trow (ui/composite s (ui/grid 2 :mh 2 :mv 2) (ui/gd :fill :h :grab :h))
        tb (ToolBar. trow (int (bit-or SWT/FLAT SWT/RIGHT)))
        search (Text. trow (int (bit-or SWT/SEARCH SWT/ICON_SEARCH SWT/ICON_CANCEL SWT/BORDER)))
        _ (.setLayoutData search (ui/gd :align :end :grab :h :w 220))
        ;; notice about the requested server connection
        banner (ui/composite s (ui/grid 3 :mh 8 :mv 4) (ui/gd :fill :h :grab :h :exclude true))
        _ (.setVisible banner false)
        _ (.setBackground banner (ui/color d 234 244 252))
        bicon (ui/label banner "")
        _ (.setImage bicon (ui/icon d "sync"))
        btext (ui/label banner "" (ui/gd :fill :h :grab :h))
        bbutton (ui/button banner (i18n/t :desktop/withdraw-request)
                           #(when (dlg/ok? (call (fn [] (svc/cancel-connect! (session)))))
                              (note-link! nil) (set-status! (i18n/t :desktop/request-withdrawn))))
        ;; tabs: one per open database (shown from the second one on)
        tabs (CTabFolder. s (int (bit-or SWT/TOP SWT/FLAT)))
        _ (.setLayoutData tabs (ui/gd :fill :h :grab :h :exclude true))
        _ (.setVisible tabs false)
        _ (.setSimple tabs false)
        ;; tree | list / entry view
        hsash (SashForm. s SWT/HORIZONTAL)
        _ (.setLayoutData hsash (ui/gd :fill :both :grab :both))
        tree (Tree. hsash (int (bit-or SWT/BORDER SWT/SINGLE)))
        vsash (SashForm. hsash SWT/VERTICAL)
        table (Table. vsash (int (bit-or SWT/BORDER SWT/FULL_SELECTION SWT/MULTI)))
        details (StyledText. vsash (int (bit-or SWT/BORDER SWT/MULTI SWT/V_SCROLL SWT/WRAP SWT/READ_ONLY)))
        _ (.setWeights hsash (int-array [22 78]))
        _ (.setWeights vsash (int-array [78 22]))
        _ (.setHeaderVisible table true)
        group-font (ui/bold-font d table -1)
        _ (.setMargins details 4 4 4 4)
        ;; status bar
        sbar (ui/composite s (ui/grid 4 :mh 6 :mv 2 :hs 16) (ui/gd :fill :h :grab :h))
        st-count (ui/label sbar "" (ui/gd :w 160))
        st-sync (ui/label sbar "")
        st-msg (ui/label sbar "" (ui/gd :fill :h :grab :h))
        st-user (ui/label sbar "" (ui/gd :align :end))
        app {:session sess :shell s :display d
             :local? local? :folder #(let [f (:folder (st))] (if (str/starts-with? f "\u0000") "" f))
             :me #(:me (st))
             :default-username #(:default-username (st))
             :groups #(vec (remove in-bin? (all-groups)))
             :icon-image kp-image
             :on-locked #(ui/async! d (fn [] (swap! state assoc :passwords {} :locked true :entries []) (render!) (boot!)))
             :copy-text! copy-text!}]
    (.setForeground st-msg (.getSystemColor d SWT/COLOR_LIST_SELECTION))
    (reset! w {:display d :shell s :session sess :app app :tabs tabs :toolbar tb :toolbar-row trow :search search
               :banner banner :banner-text btext :banner-button bbutton :tree tree :table table :group-font group-font :details details :vsash vsash
               :st-count st-count :st-sync st-sync :st-msg st-msg :st-user st-user})
    (build-columns!)
    ;; ------------------------------------------------ Events
    (ui/on tabs SWT/Selection (fn [_]
                                (switch-doc! (.getSelectionIndex tabs))
                                (when (:locked (st)) (ui/async! d boot!))))
    (ui/on s SWT/Deiconify (fn [_] (when (and (:locked (st)) (empty? (.getShells s))) (ui/async! d boot!))))
    (.addCTabFolder2Listener tabs (proxy [CTabFolder2Adapter] []
                                    (close [^CTabFolderEvent e]
                                      (set! (.-doit e) false)
                                      (let [i (.indexOf tabs ^CTabItem (.-item e))]
                                        (ui/async! d #(close-doc! i))))))
    (ui/on search SWT/Modify (fn [_] (swap! state assoc :search (.getText search)) (render-list!) (render-status!)))
    (ui/on search SWT/KeyDown (fn [^Event e] (when (#{(int SWT/CR) SWT/ARROW_DOWN} (.-keyCode e))
                                               (.setFocus table)
                                               (when-let [i (first (keep-indexed (fn [i ^TableItem it] (when (.getData it) i)) (.getItems table)))]
                                                 (.select table (int i))
                                                 (swap! state assoc :selected (.getData (.getItem table (int i))) :selection [(.getData (.getItem table (int i)))])
                                                 (render-details!) (update-actions!) (render-status!)))))
    (ui/on tree SWT/Selection (fn [^Event e]
                                (let [^TreeItem it (.-item e)]
                                  (swap! state assoc :folder (str (.getData it)) :filter nil :selected nil)
                                  (render-list!) (render-details!) (update-actions!) (render-status!))))
    (ui/on table SWT/Selection (fn [^Event e]
                                 (doseq [[i ^TableItem it] (map-indexed vector (.getItems table))]
                                   (when (and (nil? (.getData it)) (.isSelected table (int i))) (.deselect table (int i))))
                                 (let [ids (into [] (keep #(.getData ^TableItem %)) (.getSelection table))
                                       cur (some-> ^TableItem (.-item e) .getData)]
                                   (swap! state assoc :selection ids
                                          :selected (cond (some #{cur} ids) cur (seq ids) (first ids) :else nil)))
                                 (render-details!) (update-actions!) (render-status!)))
    ;; a double click acts on the column clicked (KeePass:
    ;; OnPwListMouseDoubleClick): the URL column opens the URL, every other
    ;; one edits the entry
    (let [url-click (atom false)]
      (ui/on table SWT/MouseDown (fn [_] (reset! url-click false)))
      (ui/on table SWT/MouseDoubleClick
             (fn [^Event e]
               (reset! url-click (boolean (and (= :url (column-at table (Point. (.-x e) (.-y e))))
                                               (seq (:url (selected-entry))))))
               (when @url-click (open-url!))))
      (ui/on table SWT/DefaultSelection
             (fn [_] (if @url-click
                       (reset! url-click false)
                       (when-let [e (selected-entry)] (edit-entry! (:id e)))))))
    ;; a URL in the entry view is a link, a click opens it
    (let [hand (.getSystemCursor d SWT/CURSOR_HAND)
          link (fn [^Event e] (link-at (.getOffsetAtPoint details (Point. (.-x e) (.-y e)))))
          pressed (atom nil)]
      (ui/on details SWT/MouseDown (fn [^Event e] (reset! pressed (when (= 1 (.-button e)) (link e)))))
      (ui/on details SWT/MouseUp (fn [^Event e]
                                   (let [f @pressed]
                                     (reset! pressed nil)
                                     (when (and f (identical? f (link e))) (f)))))
      (ui/on details SWT/MouseMove (fn [^Event e] (.setCursor details ^Cursor (when (link e) hand)))))
    (ui/on table SWT/KeyDown
           (fn [^Event e]
             (let [ctrl (not (zero? (bit-and (.-stateMask e) SWT/MOD1)))
                   k (Character/toLowerCase (int (bit-and (.-keyCode e) 0xffff)))
                   acts (actions)
                   run (fn [a] (when-not (false? (:on (acts a))) ((:run (acts a)))) (set! (.-doit e) false))]
               (cond
                 (= (.-keyCode e) (int SWT/DEL)) (run :del)
                 (and ctrl (= k (int \b))) (run :user)
                 (and ctrl (= k (int \c))) (run :pw)
                 (and ctrl (= k (int \u))) (run :url)
                 (and ctrl (= k (int \k))) (run :dup)
                 (and ctrl (= k (int \t))) (run :otp)
                 (and ctrl (= k (int \a))) (run :select-all)
                 (and ctrl (= k (int \e))) (run :share)))))
    (context-menu! table [:user :pw :otp :url :urlcopy :- :add :edit :dup :del :- :move :tag :- :share :history])
    (dnd! table tree)
    (context-menu! tree [:group-add :group-edit :group-icon :group-move :group-del :empty-bin :- :add :- :all :expired :expiring :tags])
    ;; activity for the idle lock
    (doseq [t [SWT/KeyDown SWT/MouseDown]]
      (.addFilter d (int t) (ui/listener (fn [_] (doseq [x (:list @docs)] (svc/touch! (:session x)))))))
    ;; check the idle lock
    ((fn idle-check []
       (ui/timer! d 15000 (fn []
                            (when-not (.isDisposed s)
                              ;; like KeePass: the whole workspace locks
                              (when (seq (filterv #(svc/check-idle! (:session %)) (:list @docs)))
                                (agent-off!)
                                (lock-all!)
                                (set-status! (i18n/t :desktop/locked-idle)))
                              (idle-check))))))
    ;; background sync (server) or checking the file for changes (local)
    ((fn bg-sync []
       (ui/timer! d 60000
                  (fn []
                    (when-not (.isDisposed s)
                      (if (or (:locked (st)) (seq (.getShells s)))
                        (bg-sync)
                        (let [cur (session) main? (not (extra?))]
                          (ui/background! d
                                        #(binding [svc/*background* true]
                                           [(svc/sync-now cur) (when (and main? (local?)) (:link (svc/status cur)))])
                                        (fn [[r link] e]
                                          (when (and (not e) (identical? cur (session)) (not (:locked (st))) (empty? (.getShells s)))
                                            (note-sync! r)
                                            (refresh!)
                                            (when (and main? (local?)) (note-link! link)))
                                          (bg-sync))))))))))
    (.setSize s 1100 720)
    (ui/center! s nil)
    s))

(defn smoke!
  "Self-test for CI (also as native binary): opens the most important
   dialogs one after another, closes each after ms and then exits."
  [ms]
  (let [app (app)
        close-top (fn [] (ui/timer! (display) ms
                                    #(when-let [^Shell dl (last (filter (fn [^Shell x] (.isVisible x)) (.getShells (shell))))]
                                       (.close dl))))]
    (doseq [f [#(dlg/generator app false)
               #(edit-entry! nil)
               #(when-let [e (first (visible))] (edit-entry! (:id e)))
               #(dlg/connect-dialog app {})
               #(dlg/sync-file-dialog app)
               #(dlg/db-settings-dialog app)
               #(dlg/tags-dialog app {:count 2 :tags ["a" "b"]})
               #(dlg/icon-dialog app 3)
               #(dlg/import-dialog app)
               #(dlg/options-dialog app {:idle-minutes 5 :clipboard-seconds 12})
               #(dlg/export-dialog app :xsl)
               #(dlg/group-name-dialog app {:title "Self-test" :heading (i18n/t :desktop/add-group) :sub "Self-test"})
               #(dlg/choose-group-dialog app {:title "Self-test" :heading (i18n/t :desktop/move-group) :sub "Self-test"
                                             :groups (vec (all-groups)) :root-name "Self-test" :current ""})
               #(dlg/totp-dialog (shell) "Self-test")
               #(dlg/about-dialog app "Self-test")]]
      (close-top)
      (f))
    (println "UI self-test: OK")
    (.close (shell))))

;; ================================================================ LLM session (cljpass.broker)

(defn- ui-sync
  "(f) on the UI thread, result or exception back to the calling thread."
  [^Display d f]
  (let [r (promise)]
    (.syncExec d ^Runnable (fn [] (deliver r (try [:ok (f)] (catch Throwable t [:err t])))))
    (let [[k v] @r] (if (= k :err) (throw v) v))))

(defn- to-front! []
  (let [^Shell s (shell)]
    (.setMinimized s false)
    (.forceActive s)))

(defn- approve-channel! [{:keys [title target minutes changed-by-agent]}]
  (to-front!)
  (ui/confirm? (shell) (i18n/t :desktop/agent-approve-title)
               (str (i18n/t :desktop/agent-approve-text {:title title :target target :minutes minutes})
                    (when changed-by-agent (str "\n\n" (i18n/t :desktop/agent-approve-changed))))))

(defn- ask-human!
  "A prompt of ssh that cljpass does not answer itself (TOTP, host key,
   jump host). The answer goes to ssh, never to the session."
  [{:keys [prompt target title]}]
  (to-front!)
  (if (re-find #"(?i)\(yes/no" prompt)
    (if (ui/confirm? (shell) (i18n/t :desktop/agent-prompt-title) (str (i18n/t :desktop/agent-prompt-for {:title title :target target}) "\n\n" prompt))
      "yes" "no")
    (let [result (atom nil)
          dlg (ui/dialog (shell) {:title (i18n/t :desktop/agent-prompt-title) :icon-name "lock"
                                  :heading (i18n/t :desktop/agent-prompt-title)
                                  :sub (i18n/t :desktop/agent-prompt-for {:title title :target target}) :width 460}
                         (fn [^Composite body]
                           (ui/wrap-label body (str prompt) 420)
                           (let [t (ui/text body "" :password true)]
                             (.setFocus t)
                             {:t t}))
                         [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}] (reset! result (.getText ^Text (:t ctx))) (ui/close! d)) :default]
                          [(i18n/t :dialogs/cancel) nil]])]
      (ui/run-modal! (:shell dlg))
      @result)))

(defn- approve-rotation!
  "A password change AT THE TARGET, from the menu or from the session: the
   human sees entry, target and changer before anything runs."
  [{:keys [title host changer probe]}]
  (to-front!)
  (ui/confirm? (shell) (i18n/t :desktop/rotate-title)
               (i18n/t (if probe :desktop/rotate-approve-probe :desktop/rotate-approve-text)
                       {:title title :host host :changer changer})))

(defn- ask-code!
  "The one-time code that releases a change (cljpass.rotate). It is typed
   here, by a human with the authenticator - the session never sees one."
  [{:keys [title host]}]
  (to-front!)
  (let [result (atom nil)
        dlg (ui/dialog (shell) {:title (i18n/t :desktop/rotate-code-title) :icon-name "lock"
                                :heading (i18n/t :desktop/rotate-code-title)
                                :sub (i18n/t :desktop/rotate-code-for {:title title :host host}) :width 420}
                       (fn [^Composite body]
                         (let [t (ui/text body "" :password true)]
                           (.setFocus t)
                           {:t t}))
                       [[(i18n/t :dialogs/ok) (fn [{:keys [ctx] :as d}] (reset! result (.getText ^Text (:t ctx))) (ui/close! d)) :default]
                        [(i18n/t :dialogs/cancel) nil]])]
    (ui/run-modal! (:shell dlg))
    @result))

(defn- rotate-ctx
  "The way a rotation reaches the human: dialogs on the UI thread, the
   changer itself on a thread of its own."
  [^Display d]
  {:session (session)
   :exec (fn [f] (ui-sync d f))
   :approve! (fn [info] (ui-sync d #(approve-rotation! info)))
   :ask-code (fn [info] (ui-sync d #(ask-code! info)))})

(defn rotate-entry!
  "Entry > Change password at the target. Runs in the background: a web UI
   round trip through a jump host takes seconds, and the dialogs need the
   UI thread meanwhile."
  []
  (when-let [e (selected-entry)]
    (let [d (display)]
      (set-status! (i18n/t :desktop/rotate-running {:title (:title e)}))
      (ui/background!
       d
       (fn [] (rotate/rotate! (rotate-ctx d) (:id e) nil))
       (fn [r err]
         (refresh!)
         (if err
           (fail! err)
           (ui/message! (shell) (if (= "ok" (:state r)) :info :warn)
                        (i18n/t :desktop/rotate-title) (rotate/summary r))))))))

(defn- start-broker! [^Display d sess]
  (swap! agent-access assoc :read (not (false? (:agent-read (local/load-prefs)))) :write false)
  (try
    (broker/start! {:session sess :access agent-access
                    :exec (fn [f] (ui-sync d f))
                    :on-change #(ui/async! d (fn [] (when-not (or (.isDisposed (shell)) (:locked (st)))
                                                       (refresh!))))
                    :approve! (fn [info] (ui-sync d #(approve-channel! info)))
                    :approve-rotation! (fn [info] (ui-sync d #(approve-rotation! info)))
                    :ask-human! (fn [info] (ui-sync d #(ask-human! info)))})
    (catch Throwable e
      (set-status! (i18n/t :desktop/agent-unavailable {:error (.getMessage e)}))
      nil)))

(defn start!
  "Starts the UI and blocks until the window is closed.
   opts: {:idle-seconds (else from the options) :smoke ms :session s :on-start (fn [shell])}
   :smoke closes after ms (CI), :session/:on-start for tests."
  [{:keys [idle-seconds smoke session on-start]}]
  ;; language first: every text below is created in it
  (i18n/set-lang! (local/preferred-lang))
  (swap! state assoc :lang-choice (i18n/normalize (:lang (local/load-prefs))))
  (Display/setAppName "cljpass")
  (let [d (or (Display/getCurrent) (Display.))
        prefs (local/load-prefs)
        sess (or session (svc/new-session {:idle-seconds (or idle-seconds (* 60 (:idle-minutes prefs 5)))}))
        _ (reset! clear-seconds (max 1 (:clipboard-seconds prefs 12)))
        _ (swap! state merge (select-keys prefs [:columns :show-passwords]))
        s (build! d sess)]
    (swap! w assoc :idle-seconds idle-seconds)
    (reset! docs {:list [] :active 0})
    (add-doc! sess)
    (swap! state assoc :locked true)
    (render!)
    (.open s)
    (when smoke (ui/timer! d smoke #(when-not (.isDisposed s) (.dispose s))))
    (ui/async! d boot!)
    (when on-start (ui/async! d #(on-start s)))
    (let [b (when-not smoke (start-broker! d sess))]
      (try
        (while (not (.isDisposed s))
          (when-not (.readAndDispatch d) (.sleep d)))
        (finally (when b ((:stop b))))))
    (doseq [x (:list @docs)] (svc/lock! (:session x)))
    (.dispose d)))
