# Minimal ADB recovery ONLY.
#
# DO NOT use USB PnP disable/enable, root-hub power cycle, or host-controller
# bounce from automation - on this host that often leaves the phone
# undetected until a MANUAL cable replug.
#
# Safe actions only:
#   - adb kill-server / start-server
#   - diagnose PnP (read-only)
#   - wait briefly for device after user replug
#
# Usage:
#   .\adb_usb_recover.ps1
#   .\adb_usb_recover.ps1 -WaitSec 30
param(
  [int]$WaitSec = 30
)

$ErrorActionPreference = "Continue"
Write-Host "=== ADB recover (server only - NO USB power/PnP thrash) ===" -ForegroundColor Yellow
Write-Host "If stale: unlock phone and MANUAL unplug/replug USB cable." -ForegroundColor DarkYellow

function Get-AdbDeviceLines {
  return @(adb devices 2>$null | Where-Object { $_ -match "`tdevice$" })
}

function Test-AdbShell {
  if ((Get-AdbDeviceLines).Count -lt 1) { return $false }
  $token = "ADB_OK_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
  $out = adb shell "echo $token" 2>&1 | Out-String
  return ($out -match [regex]::Escape($token))
}

function Restart-AdbServer {
  try { adb kill-server 2>$null | Out-Null } catch {}
  Start-Sleep -Milliseconds 500
  try { adb start-server 2>$null | Out-Null } catch {}
  Start-Sleep -Milliseconds 800
}

function Show-Diag {
  Write-Host "--- adb devices ---"
  adb devices -l 2>&1 | ForEach-Object { Write-Host $_ }
  Write-Host "--- Oppo USB (read-only) ---"
  Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -match 'VID_22D9' -or $_.FriendlyName -match 'ADB|MTP|OPPO' } |
    Format-Table Status, FriendlyName, Service -AutoSize |
    Out-String | Write-Host
}

if (Test-AdbShell) {
  Write-Host "OK: adb shell works" -ForegroundColor Green
  Show-Diag
  adb shell "echo ALIVE; cat /proc/sys/kernel/random/boot_id; cat /proc/uptime"
  Write-Host "If last fire softbooted/stale/spray-hung: run .\post_softboot_hardboot.ps1 (adb reboot) before next fire." -ForegroundColor DarkYellow
  exit 0
}

Write-Host "1) adb server restart only..."
Restart-AdbServer
Show-Diag
if (Test-AdbShell) {
  Write-Host "OK after adb server restart" -ForegroundColor Green
  adb shell "echo ALIVE; cat /proc/sys/kernel/random/boot_id; cat /proc/uptime"
  exit 0
}

Write-Host "2) waiting up to ${WaitSec}s for MANUAL replug (no USB thrash)..."
$t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt $WaitSec) {
  if (Test-AdbShell) {
    Write-Host "OK: device appeared" -ForegroundColor Green
    Show-Diag
    adb shell "echo ALIVE; cat /proc/sys/kernel/random/boot_id; cat /proc/uptime"
    exit 0
  }
  Start-Sleep -Seconds 2
}

Write-Host "FAIL: still no adb shell" -ForegroundColor Red
Show-Diag
Write-Host "ACTION: physical unplug/replug (or power-button reboot). Do not run USB PnP power scripts." -ForegroundColor Yellow
exit 1
