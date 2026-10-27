(ns cljpass.clipboard
  "Clipboard like KeePass (Windows):
   - formats ExcludeClipboardContentFromMonitorProcessing,
     CanIncludeInClipboardHistory=0 and CanUploadToCloudClipboard=0:
     no entry in the history (Win+V), no cloud sync, clipboard managers
     ignore the content.
   - After `seconds` it is cleared - but only if our value is still in it.
   The value goes to PowerShell via stdin, never via the command line."
  (:require [cljpass.local :as local]
            [cljpass.proc :as proc]))

(def clear-seconds 12)

(def ^:private ps-copy
  "Add-Type -AssemblyName System.Windows.Forms
   $v=[Console]::In.ReadToEnd()
   $d=New-Object System.Windows.Forms.DataObject
   $d.SetText($v,[System.Windows.Forms.TextDataFormat]::UnicodeText)
   $z=New-Object IO.MemoryStream(,[byte[]](0,0,0,0))
   $d.SetData('ExcludeClipboardContentFromMonitorProcessing',$true)
   $d.SetData('CanIncludeInClipboardHistory',$z)
   $d.SetData('CanUploadToCloudClipboard',(New-Object IO.MemoryStream(,[byte[]](0,0,0,0))))
   [System.Windows.Forms.Clipboard]::SetDataObject($d,$true)
   Start-Sleep -Seconds $env:CLJPASS_CLEAR_SECONDS
   if([System.Windows.Forms.Clipboard]::GetText() -ceq $v){[System.Windows.Forms.Clipboard]::Clear()}
   $v=$null")

(defn native? [] (local/windows?))

(defn copy!
  "Copies `value` to the Windows clipboard (asynchronously, clears itself)."
  [^String value]
  (proc/spawn! ["powershell.exe" "-NoProfile" "-NonInteractive" "-STA" "-WindowStyle" "Hidden"
                "-Command" ps-copy]
               value {:env {"CLJPASS_CLEAR_SECONDS" (str clear-seconds)}})
  true)
