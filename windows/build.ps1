# Builds target\cljpass.exe (GUI) and target\cljpass.com (console),
# standalone with GraalVM native-image.
# Requirements: GraalVM for JDK 21 (native-image on the PATH) and the
# Visual Studio Build Tools (C++). The script downloads the Clojure tools
# itself (deps.exe from borkdude/deps.clj). Run in the project folder:
#   powershell -ExecutionPolicy Bypass -File windows\build.ps1
param([string]$DepsVersion = "1.12.6.1673")
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot)

if (!(Get-Command native-image -ErrorAction SilentlyContinue)) {
  throw "native-image not found - install GraalVM and add bin\ to the PATH"
}
$dl = "target\dl"
New-Item -ItemType Directory -Force $dl | Out-Null
if (!(Test-Path "$dl\deps.exe")) {
  Invoke-WebRequest "https://github.com/borkdude/deps.clj/releases/download/v$DepsVersion/deps.clj-$DepsVersion-windows-amd64.zip" -OutFile "$dl\deps.zip"
  Expand-Archive "$dl\deps.zip" $dl -Force
}

& "$dl\deps.exe" -T:build native
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
Write-Host "Done: target\cljpass.exe (GUI), target\cljpass.com (console)"
