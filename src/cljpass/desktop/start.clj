(ns cljpass.desktop.start
  "Start dialogs: setup (file or server), open or create a database (like
   KeyPromptForm/KeyCreationForm in KeePass) and waiting for approval."
  (:require [clojure.string :as str]
            [cljpass.desktop.dialogs :as dlg]
            [cljpass.desktop.ui :as ui]
            [cljpass.fs :as fs]
            [cljpass.i18n :as i18n]
            [cljpass.service :as svc])
  (:import [org.eclipse.swt SWT]
           [org.eclipse.swt.widgets Button Composite Display Shell Text]))

(set! *warn-on-reflection* true)

(defn- password-row
  "Password field with a *** button (toggle plain text) like in KeePass."
  [^Composite f caption]
  (ui/label f caption)
  (let [row (ui/composite f (ui/grid 2 :margin 0 :hs 4) (ui/gd :fill :h :grab :h))
        state (atom {:masked true})
        mk (fn [masked value]
             (let [t (ui/text row value :password masked)] (.moveAbove t nil) t))
        t (atom (mk true ""))]
    (ui/button row "***" (fn []
                           (let [^Text old @t v (.getText old)]
                             (swap! state update :masked not)
                             (.dispose old)
                             (reset! t (mk (:masked @state) v))
                             (.layout row true)
                             (.setFocus ^Text @t)))
               :data (ui/gd :w 36))
    t))

(defn- value [t] (.getText ^Text @t))

(defn open-file-dialog
  "Open a database (create = create a new one). Returns true on success.
   extra = in a further tab (cljpass.service/open-extra-file!)."
  [app {:keys [file create extra]}]
  (let [ok (atom false)
        d (ui/dialog
           (:shell app)
           {:title (i18n/t (if create :desktop/create-database :desktop/open-database)) :icon-name (if create "vault" "lock")
            :heading (i18n/t (if create :desktop/create-database :desktop/open-database))
            :sub (if create (i18n/t :desktop/create-database-sub) (or (some-> file fs/file-name) ""))
            :width 520}
           (fn [^Composite body]
             (let [f (ui/composite body (ui/grid 2 :margin 0 :hs 10 :vs 6) (ui/gd :fill :both :grab :both))
                   _ (ui/label f (i18n/t :desktop/label-file))
                   file-t (dlg/file-field f (or file "") (if create :save :open) true)
                   pw (password-row f (i18n/t :desktop/label-master-password))
                   pw2 (when create (password-row f (i18n/t :desktop/label-repeat)))
                   _ (ui/label f (i18n/t :desktop/label-key-file))
                   kf (dlg/file-field f "" :open false)
                   err (doto (ui/label f "" (ui/gd :span 2 :fill :h :grab :h))
                         (.setForeground (.getSystemColor ^Display (:display app) SWT/COLOR_RED)))]
               (if (str/blank? file) (.setFocus file-t) (.setFocus ^Text @pw))
               {:file file-t :pw pw :pw2 pw2 :kf kf :err err}))
           [[(i18n/t :desktop/ok) (fn [{:keys [ctx] :as d}]
                    (let [{:keys [^Text file pw pw2 kf ^org.eclipse.swt.widgets.Label err]} ctx]
                      (cond
                        (and create (not= (value pw) (value pw2))) (.setText err (i18n/t :desktop/passwords-do-not-match))
                        (and (str/blank? (value pw)) (str/blank? (.getText ^Text kf))) (.setText err (i18n/t :desktop/password-or-key-file-required))
                        :else
                        (try
                          (ui/busy (:display app)
                                   #((if extra svc/open-extra-file! svc/open-file!) (:session app) {:file (str/trim (.getText file)) :password (value pw)
                                                                   :keyfile (dlg/read-keyfile kf) :create (boolean create)}))
                          (reset! ok true)
                          (ui/close! d)
                          (catch Throwable e (.setText err (ui/error-text e)) (.layout (.getParent err) true))))))
             :default]
            [(i18n/t :desktop/cancel) nil]])]
    (ui/run-modal! (:shell d))
    @ok))

(defn enroll-dialog
  "Set up server mode. Returns true on success."
  [app st]
  (let [ok (atom false)
        defaults (:defaults st)
        d (ui/dialog
           (:shell app)
           {:title (i18n/t :desktop/enroll-title) :icon-name "vault" :heading (i18n/t :desktop/enroll-title)
            :sub (i18n/t :desktop/enroll-sub) :width 540}
           (fn [^Composite body]
             (let [f (ui/composite body (ui/grid 2 :margin 0 :hs 10 :vs 6) (ui/gd :fill :both :grab :both))
                   server (do (ui/label f (i18n/t :desktop/label-server)) (ui/text f (or (:server defaults) "")))
                   hash (do (ui/label f (i18n/t :desktop/label-org-hash)) (ui/text f (or (:org-hash defaults) "")))
                   user (do (ui/label f (i18n/t :desktop/label-username)) (ui/text f (or (:user st) "")))
                   krb (ui/check f (i18n/t :desktop/label-kerberos) (true? (:kerberos defaults)) (ui/gd :span 2))
                   err (doto (ui/label f "" (ui/gd :span 2 :fill :h :grab :h))
                         (.setForeground (.getSystemColor ^Display (:display app) SWT/COLOR_RED)))]
               (ui/wrap-label f (i18n/t :desktop/enroll-keys-note) 460 2)
               {:server server :hash hash :user user :krb krb :err err}))
           [[(i18n/t :desktop/enroll-button) (fn [{:keys [ctx] :as d}]
                            (let [{:keys [^Text server ^Text hash ^Text user ^Button krb ^org.eclipse.swt.widgets.Label err]} ctx]
                              (try
                                (ui/busy (:display app) #(svc/enroll! (:session app) {:server (str/trim (.getText server))
                                                                                     :org-hash (str/trim (.getText hash))
                                                                                     :user (str/trim (.getText user))
                                                                                     :kerberos (.getSelection krb)}))
                                (reset! ok true)
                                (ui/close! d)
                                (catch Throwable e (.setText err (ui/error-text e)) (.layout (.getParent err) true)))))
             :default]
            [(i18n/t :desktop/cancel) nil]])]
    (ui/run-modal! (:shell d))
    @ok))

(defn setup-dialog
  "First start: local file or server? Returns :local-new, :local-open,
   :server or nil."
  [app st]
  (let [allow-local (not (false? (:standalone-allowed st)))
        choice (atom (if (or (get-in st [:defaults :server]) (not allow-local)) :server :local-open))
        result (atom nil)
        d (ui/dialog
           (:shell app)
           {:title (i18n/t :desktop/setup-title) :icon-name "vault" :heading (i18n/t :desktop/setup-title)
            :sub (i18n/t :desktop/setup-sub) :width 540}
           (fn [^Composite body]
             (let [opt (fn [k title text enabled]
                         (let [b (ui/radio body title (= k @choice) #(reset! choice k))]
                           (.setEnabled b enabled)
                           (.setFont b (ui/bold-font (:display app) b))
                           (ui/layout-data! (ui/wrap-label body text 460) (ui/gd :fill :h :grab :h :indent 22 :w 460))))]
               (opt :local-open (i18n/t :desktop/setup-local-open) (i18n/t :desktop/setup-local-open-text) allow-local)
               (opt :local-new (i18n/t :desktop/setup-local-new) (i18n/t :desktop/setup-local-new-text) allow-local)
               (opt :server (i18n/t :desktop/setup-server) (i18n/t :desktop/setup-server-text) true)))
           [[(i18n/t :desktop/next) (fn [d] (reset! result @choice) (ui/close! d)) :default]
            [(i18n/t :desktop/exit) nil]])]
    (ui/run-modal! (:shell d))
    @result))

(defn pending-dialog
  "Waiting for approval: shows the fingerprint (with Kerberos only for
   reference) and checks every 5 s.
   Returns true as soon as the device is approved."
  [app fingerprint kerberos]
  (let [ok (atom false)
        d (ui/dialog
           (:shell app)
           {:title (i18n/t :desktop/pending-title) :icon-name "user" :heading (i18n/t :desktop/pending-title)
            :sub (i18n/t :desktop/pending-sub) :width 520}
           (fn [^Composite body]
             ;; with Kerberos the admin needs no code; it is shown only for queries
             (ui/wrap-label body (i18n/t (if kerberos :desktop/pending-kerberos-note :desktop/pending-code-note)) 460)
             (let [fp (ui/text body fingerprint :read-only true)]
               (.setFont fp (ui/bold-font (:display app) fp 4)))
             (ui/wrap-label body (i18n/t :desktop/pending-auto-close) 460))
           [[(i18n/t :desktop/exit) nil]])
        ^Shell s (:shell d)
        check (fn check []
                (when-not (.isDisposed s)
                  (ui/background! (:display app)
                                  #(binding [svc/*background* true] (svc/status (:session app)))
                                  (fn [st _]
                                    (when-not (.isDisposed s)
                                      (if (= :active (:state st))
                                        (do (reset! ok true) (.close s))
                                        (ui/timer! (:display app) 5000 check)))))))]
    (ui/timer! (:display app) 2000 check)
    (ui/run-modal! s)
    @ok))
