(ns cljpass.test-runner
  "clojure -M:test [ns ...] - ohne Argumente alle Test-Namespaces."
  (:require [clojure.test :as t]))

(def all-nss '[cljpass.crypto-test cljpass.vault-test cljpass.service-test cljpass.web-test cljpass.standalone-test
               cljpass.cli-test cljpass.kdbx-test cljpass.parity-test cljpass.groups-test cljpass.exchange-test cljpass.generator-test cljpass.settings-test cljpass.i18n-test cljpass.kerberos-test cljpass.autoopen-test cljpass.offline-test cljpass.agent-test cljpass.rotate-test])

(defn -main [& args]
  (let [nss (if (seq args) (map symbol args) all-nss)]
    (apply require nss)
    (let [{:keys [fail error]} (apply t/run-tests nss)]
      (shutdown-agents)
      (System/exit (if (pos? (+ fail error)) 1 0)))))
