(ns build
  "clojure -T:build uber    -> target/cljpass.jar
   clojure -T:build native  -> target/cljpass(.exe)   (GraalVM native-image on the PATH)
   clojure -T:build native :quick true  -> faster, less optimized (CI)

   The desktop UI uses SWT; the build picks the matching JAR for the
   build system (Windows, macOS, Linux) itself.
   On Windows two files are produced:
   - cljpass.exe  Windows program (double-click, no console window)
   - cljpass.com  the same binary as a console program; cmd/PowerShell
                    pick the .com automatically for \"cljpass ...\", so
                    the output of the commands is visible (like devenv.com)."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.build.api :as b])
  (:import [java.io RandomAccessFile]
           [java.util.zip ZipFile]))

(def class-dir "target/classes")
(def uber-file "target/cljpass.jar")

(def os-name (.toLowerCase (System/getProperty "os.name")))
(def windows? (.startsWith os-name "windows"))
(def mac? (.startsWith os-name "mac"))

(def swt-alias
  (cond windows? :swt-win
        mac? (if (= "aarch64" (System/getProperty "os.arch")) :swt-mac :swt-mac-x64)
        :else :swt-linux))

(def basis (delay (b/create-basis {:project "deps.edn" :aliases [swt-alias]})))

(defn clean [_] (b/delete {:path "target"}))

(defn uber [_]
  (clean nil)
  (b/copy-dir {:src-dirs ["resources"] :target-dir class-dir})
  (b/compile-clj {:basis @basis
                  :ns-compile '[cljpass.main]
                  :class-dir class-dir
                  :compile-opts {:direct-linking true}
                  :bindings {#'clojure.core/*warn-on-reflection* true}})
  (b/uber {:class-dir class-dir :uber-file uber-file :basis @basis :main 'cljpass.main})
  (println "Done:" uber-file))

;; ---------------------------------------------------------------- SWT for native-image

(defn- swt-jar []
  (or (first (filter #(re-find #"org\.eclipse\.swt\.(win32|gtk|cocoa)" %) (:classpath-roots @basis)))
      (throw (ex-info "SWT JAR not on the classpath" {}))))

(def ^:private swt-skip
  ;; unused; would pull in AWT or browser engines.
  ;; do NOT exclude: internal/ole (Windows: Display and clipboard need COM)
  ["org/eclipse/swt/awt/" "org/eclipse/swt/browser/" "org/eclipse/swt/opengl/"
   "org/eclipse/swt/internal/webkit/" "org/eclipse/swt/internal/opengl/" "org/eclipse/swt/internal/mozilla/"])

(defn- jni-config
  "SWT calls back into Java via JNI (callbacks, structs). For that, all
   classes of the SWT JAR are registered completely."
  [out]
  (with-open [z (ZipFile. ^String (swt-jar))]
    (let [classes (->> (enumeration-seq (.entries z))
                       (map #(.getName ^java.util.zip.ZipEntry %))
                       (filter #(and (str/starts-with? % "org/eclipse/swt/") (str/ends-with? % ".class")))
                       (remove (fn [n] (some #(str/starts-with? n %) swt-skip)))
                       (map #(-> % (subs 0 (- (count %) 6)) (str/replace "/" "."))))]
      (io/make-parents out)
      (spit out (str "[\n"
                     (str/join ",\n" (concat (for [c classes]
                                               (str "{\"name\":\"" c "\",\"allDeclaredFields\":true,"
                                                    "\"allDeclaredMethods\":true,\"allDeclaredConstructors\":true}"))
                                             ["{\"name\":\"java.lang.Throwable\",\"methods\":[{\"name\":\"addSuppressed\",\"parameterTypes\":[\"java.lang.Throwable\"]}]}"]))
                     "\n]\n"))
      (count classes))))

(defn- pe-subsystem!
  "Sets the subsystem in the PE header of an .exe (2 = Windows GUI, 3 = console)."
  [file subsystem]
  (with-open [f (RandomAccessFile. (io/file file) "rw")]
    (.seek f 0x3C)
    (let [pe (Integer/reverseBytes (.readInt f))]
      (.seek f pe)
      (when-not (= 0x50450000 (.readInt f)) (throw (ex-info "Not a PE file" {:file file})))
      ;; optional header starts after signature (4) + COFF header (20); subsystem at +68
      (.seek f (+ pe 24 68))
      (.writeShort f (Short/reverseBytes (short subsystem))))))

(defn native
  "Builds the standalone binary. Clojure namespaces are initialized at
   build time (fast startup). Everything that must be random per process
   (random generator, memory keys) is therefore only created at run time
   (delay)."
  [{:keys [quick]}]
  (uber nil)
  (let [jni "target/native/jni-config.json"
        n (jni-config jni)
        exe (if windows? "native-image.cmd" "native-image")
        args (cond-> [exe "-jar" uber-file
                      "-o" "target/cljpass"
                      "--no-fallback"
                      "--initialize-at-build-time=clojure,cljpass"
                      "--enable-url-protocols=http,https"
                      "-H:+UnlockExperimentalVMOptions"
                      (str "-H:JNIConfigurationFiles=" jni)
                      ;; web UI (ui/), icons, SWT libraries and stylesheets.
                      ;; Separate options without | ^ ( ): on Windows native-image.cmd
                      ;; runs through cmd.exe, which splits on these characters.
                      "-H:IncludeResources=ui/.*"
                      "-H:IncludeResources=icons/.*"
                      "-H:IncludeResources=swt.*[.]dll"
                      "-H:IncludeResources=libswt.*[.]so"
                      "-H:IncludeResources=libswt.*[.]jnilib"
                      "-H:IncludeResources=libswt.*[.]dylib"
                      "-H:IncludeResources=org/eclipse/swt/internal/.*[.]css"
                      "-H:IncludeResources=org/eclipse/swt/internal/Library[.]class"
                      "--report-unsupported-elements-at-runtime"
                      "-march=compatibility"
                      "-J-Xmx6g"]
               ;; fast build without full optimization (CI smoke test)
               quick (conj "-Ob"))
        _ (println "SWT:" (swt-jar) "-" n "classes registered for JNI")
        {:keys [exit]} (b/process {:command-args args})]
    (when-not (zero? exit) (throw (ex-info "native-image failed" {:exit exit})))
    (when windows?
      (io/copy (io/file "target/cljpass.exe") (io/file "target/cljpass.com"))
      (pe-subsystem! "target/cljpass.exe" 2)
      (println "Done: target/cljpass.exe (GUI) and target/cljpass.com (console)"))
    (when-not windows? (println "Done: target/cljpass"))))
