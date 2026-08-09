# Push CPH2521 GhostLock build and run a TIMED test only (default 45s).
# Usage:
#   .\push_and_test.ps1
#   .\push_and_test.ps1 -TimeoutSec 60 -Kphys 0xa8000000 -Shift 0

param(
  [int]$TimeoutSec = 45,
  [string]$Kphys = "0xa8000000",
  [int]$Shift = 0
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "ghostlock-cph2521"
if (-not (Test-Path $Bin)) { throw "Missing $Bin — run build_cph2521.ps1 first" }

$devs = adb devices | Select-String "`tdevice$"
if (-not $devs) { throw "No adb device in 'device' state. Fix USB debugging first." }

Write-Host "Device:"
adb devices -l
adb shell "uname -r; getprop ro.build.display.id; id; getenforce"

adb shell "mkdir -p /data/local/tmp/a; killall -9 e 2>/dev/null; true"
adb push $Bin /data/local/tmp/a/e
adb shell "chmod 755 /data/local/tmp/a/e; ls -la /data/local/tmp/a/e"

$envLine = "KPHYS=$Kphys"
if ($Shift -ne 0) { $envLine += " PSELECT_SHIFT=$Shift" }

Write-Host ""
Write-Host "=== Running timed exploit ($TimeoutSec s) with $envLine ===" -ForegroundColor Yellow
Write-Host "Wrong shift / layout can soft-panic the phone. Cable stays connected for logs." -ForegroundColor Yellow
Write-Host ""

adb shell "timeout ${TimeoutSec}s sh -c '$envLine /data/local/tmp/a/e' 2>&1; echo EXIT:$?"
Write-Host ""
Write-Host "Post-run check:"
adb shell "echo alive; uname -r; pidof e || echo no-e" 2>&1
