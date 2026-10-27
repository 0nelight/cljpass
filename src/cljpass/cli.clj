(ns cljpass.cli
  "Subcommands and options, behaves like babashka.cli/dispatch as far as
   needed:
     --key value | --key=value | --flag (true) | --no-flag (false)
   Table: [{:cmds [\"approve\"] :fn f :args->opts [:user] :coerce {:port :long :members []}}]"
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n]))

(defn- coerce [spec v]
  (case spec
    :long (or (parse-long (str v)) (throw (i18n/error :core/cli-number-expected {:value v} {:type :usage})))
    v))

(defn- add-opt [opts coercions k v]
  (let [spec (get coercions k)]
    (if (vector? spec)
      (update opts k (fnil conj []) v)
      (assoc opts k (coerce spec v)))))

(defn parse
  "args -> {:opts {} :args [positional arguments that were not assigned]}"
  [args {:keys [coerce args->opts]}]
  (loop [[a & more :as xs] args
         opts {}
         pos []
         slots (seq args->opts)]
    (cond
      (empty? xs) {:opts opts :args pos}

      (str/starts-with? a "--")
      (let [[k v] (str/split (subs a 2) #"=" 2)]
        (cond
          v (recur more (add-opt opts coerce (keyword k) v) pos slots)
          (str/starts-with? k "no-") (recur more (assoc opts (keyword (subs k 3)) false) pos slots)
          (and (seq more) (not (str/starts-with? (first more) "--")))
          (recur (rest more) (add-opt opts coerce (keyword k) (first more)) pos slots)
          :else (recur more (assoc opts (keyword k) true) pos slots)))

      slots (recur more (add-opt opts coerce (first slots) a) pos (next slots))
      :else (recur more opts (conj pos a) slots))))

(defn dispatch
  "Picks the entry with the longest matching :cmds prefix and calls
   (f {:opts :args})."
  [table args & [{global-coerce :coerce}]]
  (let [args (vec args)
        entry (->> table
                   (filter (fn [{:keys [cmds]}] (= cmds (take (count cmds) args))))
                   (sort-by (comp - count :cmds))
                   first)]
    (when-not entry (throw (i18n/error :core/cli-unknown-command nil {:type :usage})))
    ((:fn entry) (parse (drop (count (:cmds entry)) args)
                        {:coerce (merge global-coerce (:coerce entry))
                         :args->opts (:args->opts entry)}))))
