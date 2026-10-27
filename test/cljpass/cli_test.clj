(ns cljpass.cli-test
  (:require [clojure.test :refer [deftest is]]
            [cljpass.cli :as cli]))

(def ^:private table
  [{:cmds ["gui"] :fn identity :coerce {:port :long}}
   {:cmds ["approve"] :fn identity :args->opts [:user]}
   {:cmds ["group"] :fn identity :args->opts (cons :group (repeat :members)) :coerce {:members []}}
   {:cmds [] :fn identity}])

(deftest dispatch
  (is (= {:opts {:port 8080 :browser false} :args []} (cli/dispatch table ["gui" "--port" "8080" "--no-browser"])))
  (is (= {:opts {:port 1} :args []} (cli/dispatch table ["gui" "--port=1"])))
  (is (= {:opts {:user "alice" :fingerprint "ab-cd" :display-name "Alice B"} :args []}
         (cli/dispatch table ["approve" "alice" "--fingerprint" "ab-cd" "--display-name" "Alice B"])))
  (is (= {:opts {:group "it" :members ["bob" "carol"]} :args []} (cli/dispatch table ["group" "it" "bob" "carol"])))
  (is (= {:opts {:group "it"} :args []} (cli/dispatch table ["group" "it"])))
  (is (= {:opts {} :args []} (cli/dispatch table [])))
  (is (= {:opts {:x true} :args ["foo"]} (cli/dispatch table ["foo" "--x"])))
  (is (thrown? Exception (cli/dispatch table ["gui" "--port" "abc"]))))
