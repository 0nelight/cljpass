(ns cljpass.negotiate
  "HTTP POST with the Windows logon (Kerberos via SPNEGO, \"Negotiate\"),
   for enrollment without any input (doc/FORMAT.md §8.1).

   Windows gets the Kerberos ticket itself (SSPI); the JDK cannot do that in
   the native binary. Therefore, like DPAPI and ADSI, via PowerShell and
   .NET HttpWebRequest with UseDefaultCredentials."
  (:require [clojure.string :as str]
            [cljpass.i18n :as i18n]
            [cljpass.proc :as proc]))

(def ^:private ps-post
  "$ErrorActionPreference='Stop'
   [Console]::InputEncoding=[Text.Encoding]::UTF8
   [Console]::OutputEncoding=[Text.Encoding]::UTF8
   [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072
   $b=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd())
   $r=[Net.HttpWebRequest]::Create($env:CLJPASS_URL)
   $r.Method='POST'; $r.ContentType='application/json; charset=utf-8'
   $r.UseDefaultCredentials=$true; $r.AllowAutoRedirect=$false; $r.Timeout=20000
   $r.ContentLength=$b.Length
   try{
     $s=$r.GetRequestStream(); $s.Write($b,0,$b.Length); $s.Close()
     $resp=$r.GetResponse()
   }catch [Net.WebException]{
     $resp=$_.Exception.Response
     if(-not $resp){[Console]::Error.Write($_.Exception.Message); exit 2}
   }
   $sr=New-Object IO.StreamReader($resp.GetResponseStream(),[Text.Encoding]::UTF8)
   [Console]::Out.Write([string][int]$resp.StatusCode + \"`n\" + $sr.ReadToEnd())")

(defn- powershell-post [url ^String body]
  (let [{:keys [exit out err]} (proc/run ["powershell.exe" "-NoProfile" "-NonInteractive" "-Command" ps-post]
                                         body {:env {"CLJPASS_URL" url}})]
    (if (zero? exit)
      (let [[status body] (str/split (str out) #"\n" 2)]
        {:status (parse-long (str/trim status)) :body (or body "")})
      (throw (ex-info (i18n/t :core/server-unreachable {:detail (str/trim (str err))})
                      {:type :offline :msg :core/server-unreachable :params {:detail (str/trim (str err))}})))))

(def ^:dynamic *post*
  "(fn [url body-string] -> {:status :body}). Replaceable in tests (JGSS
   initiator instead of the Windows logon)."
  powershell-post)

(defn post [url body] (*post* url body))
