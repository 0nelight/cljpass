(ns screenshots
  "Screenshots of the desktop UI (in English) under Xvfb:
   CLJPASS_LANG=en xvfb-run -a clojure -M:swt-linux -i dev/screenshots.clj -e \"(screenshots/run \\\"doc/screenshots\\\")\""
  (:require [cljpass.desktop :as desktop]
            [cljpass.desktop.dialogs :as dlg]
            [cljpass.desktop.ui :as ui]
            [cljpass.fs :as fs]
            [cljpass.local :as local]
            [cljpass.service :as svc])
  (:import [org.eclipse.swt SWT]
           [org.eclipse.swt.graphics GC Image ImageData ImageLoader Rectangle]
           [org.eclipse.swt.widgets Display Shell]))

(defn shot! [^Display d ^Shell s file]
  (let [^Rectangle b (.getBounds s)
        gc (GC. d)
        img (Image. d (.-width b) (.-height b))]
    (.copyArea gc img (.-x b) (.-y b))
    (.dispose gc)
    (let [l (ImageLoader.)]
      (set! (.-data l) (into-array ImageData [(.getImageData img)]))
      (.save l ^String file SWT/IMAGE_PNG))
    (.dispose img)
    (println "Screenshot:" file) (flush)))

(defn- later [^Display d ms f] (.timerExec d (int ms) ^Runnable f))

(defn- top-dialog [^Shell s] (last (filter #(.isVisible ^Shell %) (.getShells s))))

(defn run [out]
  (fs/create-dirs out)
  (binding [local/*home* (str (fs/create-temp-dir))]
    (let [file (str (fs/path (fs/create-temp-dir) "Company.kdbx"))
          s (svc/new-session {})]
      (svc/open-file! s {:file file :password "m" :create true :kdf {:kdf :aes :rounds 1000}})
      (doseq [[t u f n url] [["Firewall" "admin" "" "Main firewall" "https://fw.example.local"]
                             ["VPN" "alice" "" "" "https://vpn.example.local"]
                             ["Wi-Fi guests" "" "" "Change monthly" ""]
                             ["Router" "admin" "Network" "" "https://192.0.2.1"]
                             ["Switch floor 1" "admin" "Network/Switches" "" ""]
                             ["Online banking" "company123" "Finance" "TAN via app" "https://bank.example"]
                             ["Mail server" "postmaster" "" "" "https://mail.example.local"]
                             ["Domain admin" "Administrator" "Server/Windows" "Emergency only" ""]]]
        (svc/save-entry s {:title t :username u :password "Secret!2026" :folder f :notes n :url url}))
      (let [d (Display.)]
        (desktop/start!
         {:session s
          :on-start
          (fn [^Shell main]
            (later d 1500
                   (fn []
                     (shot! d main (str out "/desktop-main.png"))
                     ;; entry dialog (modal) - screenshot from a timer
                     (later d 1200 #(let [^Shell dl (top-dialog main)]
                                      (shot! d dl (str out "/desktop-entry.png"))
                                      (.close dl)))
                     (let [id (:id (first (:entries (svc/list-entries s))))]
                       (dlg/entry-dialog (:app @@#'desktop/w) id))
                     (later d 1200 #(let [^Shell dl (top-dialog main)]
                                      (shot! d dl (str out "/desktop-generator.png"))
                                      (.close dl)))
                     (dlg/generator (:app @@#'desktop/w) false)
                     (later d 1200 #(let [^Shell dl (top-dialog main)]
                                      (shot! d dl (str out "/desktop-connect.png"))
                                      (.close dl)))
                     (dlg/connect-dialog (:app @@#'desktop/w) {:server "https://pw.example.local" :user "alice"})
                     (svc/lock! s)
                     (later d 1500 #(let [^Shell dl (top-dialog main)]
                                      (shot! d dl (str out "/desktop-open.png"))
                                      (.close dl)
                                      (later d 300 (fn [] (.close main)))))
                     (#'desktop/boot!))))})))))

(defn run-server
  "Server mode: a real server, alice shares with admin; screenshots from alice's view."
  [out]
  (require 'cljpass.admin 'cljpass.identity 'cljpass.server)
  (let [admin-ns (the-ns 'cljpass.admin) idn (the-ns 'cljpass.identity) srv (the-ns 'cljpass.server)
        port (with-open [ss (java.net.ServerSocket. 0)] (.getLocalPort ss))
        url (str "http://127.0.0.1:" port)
        stop ((ns-resolve srv 'start!) {:db (str (fs/path (fs/create-temp-dir) "s.db")) :port port :bind "127.0.0.1" :init-token "t"})
        homes (into {} (for [u ["admin" "alice"]] [u (str (fs/create-temp-dir))]))
        admin-ident ((ns-resolve idn 'new-identity) "admin")
        {:keys [org-hash]} ((ns-resolve admin-ns 'init-org!) url "t" "Example Ltd" admin-ident)
        sa (svc/new-session {}) sal (svc/new-session {})]
    (binding [local/*home* (homes "admin")]
      (local/save-identity! admin-ident :file)
      (local/save-config! {:server url :org-hash org-hash :user "admin"})
      (svc/unlock! sa))
    (let [{:keys [fingerprint]} (binding [local/*home* (homes "alice")]
                                  (svc/enroll! sal {:server url :org-hash org-hash :user "alice" :protector :file}))]
      (binding [local/*home* (homes "admin")]
        (svc/sync-now sa)
        (svc/with-ctx sa #((ns-resolve admin-ns 'approve!) % admin-ident "alice" {:fingerprint fingerprint :display-name "Alice Berger"}))))
    (binding [local/*home* (homes "alice")]
      (svc/sync-now sal)
      (let [id (svc/save-entry sal {:title "Firewall" :username "root" :password "x" :folder "Network" :url "https://fw"})]
        (svc/set-acl sal id [{:principal "u:alice" :permission "owner"} {:principal "u:admin" :permission "read"}])
        (svc/save-entry sal {:title "Private" :username "alice" :password "y"})
        (let [d (Display.)]
          (desktop/start!
           {:session sal
            :on-start
            (fn [^Shell main]
              (later d 1500
                     (fn []
                       (shot! d main (str out "/desktop-server.png"))
                       (later d 1500 #(let [^Shell dl (top-dialog main)]
                                        (shot! d dl (str out "/desktop-share.png"))
                                        (.close dl)
                                        (later d 300 (fn [] (.close main)))))
                       (#'desktop/edit-entry! id :share))))}))))
    (stop)))
