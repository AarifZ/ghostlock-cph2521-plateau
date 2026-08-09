# After softboot / spray hang / stale ADB: clean test boot via adb reboot only.
# NO USB hub/host power cycle, NO PnP disable/enable thrash.
#
# Usage:
#   .\post_softboot_hardboot.ps1
#   .\post_softboot_hardboot.ps1 -WaitForUserSec 180
#
# Exit codes:
#   0 = clean boot ready (new boot_id, low uptime, boot_completed=1)
#   2 = never got adb shell (need manual replug)
#   3 = reboot did not take / boot not clean
param(
  [int]$MaxUptimeSec = 60,
  [int]$WaitForUserSec = 120,
  [int]$BootWaitSec = 150
)

$ErrorActionPreference = "Continue"
Write-Host "=== post-softboot hardboot (adb reboot only, no USB thrash) ===" -ForegroundColor Yellow

function Test-Shell {
  $token = "ADB_OK_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
  $out = adb shell "echo $token" 2>&1 | Out-String
  return ($out -match [regex]::Escape($token))
}

function Get-BootInfo {
  $bid = (adb shell "cat /proc/sys/kernel/random/boot_id" 2>&1 | Out-String).Trim()
  $up  = (adb shell "cat /proc/uptime" 2>&1 | Out-String).Trim()
  $bc  = (adb shell "getprop sys.boot_completed" 2>&1 | Out-String).Trim()
  if ($bid -match '([0-9a-fA-F-]{36})') { $bid = $Matches[1] } else { $bid = "" }
  $uptime = 99999.0
  if ($up -match '([\d.]+)') { $uptime = [double]$Matches[1] }
  if ($bc -match '([01])') { $bc = $Matches[1] } else { $bc = "" }
  return [pscustomobject]@{ BootId = $bid; Uptime = $uptime; BootCompleted = $bc }
}

function Wait-Shell {
  param([int]$Sec, [string]$Why)
  Write-Host $Why -ForegroundColor DarkYellow
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalSeconds -lt $Sec) {
    if (Test-Shell) { return $true }
    Start-Sleep -Seconds 2
  }
  return (Test-Shell)
}

$devs = @(adb devices 2>$null | Where-Object { $_ -match "`tdevice$" })
if ($devs.Count -lt 1) {
  Write-Host "No device listed - adb server restart only..."
  try { adb kill-server 2>$null | Out-Null } catch {}
  Start-Sleep -Milliseconds 600
  try { adb start-server 2>$null | Out-Null } catch {}
  Start-Sleep -Seconds 1
}

if (-not (Test-Shell)) {
  $ok = Wait-Shell -Sec $WaitForUserSec -Why "ADB down. Unlock + MANUAL unplug/replug. Waiting ${WaitForUserSec}s..."
  if (-not $ok) {
    Write-Host "FAIL: no adb shell - manual replug required" -ForegroundColor Red
    adb devices -l
    exit 2
  }
}

$before = Get-BootInfo
if (-not $before.BootId) {
  Write-Host "FAIL: shell responded but boot_id unreadable - not rebooting blind" -ForegroundColor Red
  adb devices -l
  adb shell "cat /proc/sys/kernel/random/boot_id; cat /proc/uptime" 2>&1
  exit 2
}
Write-Host ("BEFORE reboot: boot_id={0} uptime={1:n1}s boot_completed={2}" -f $before.BootId, $before.Uptime, $before.BootCompleted)

Write-Host "adb reboot (must change boot_id)..."
$reb = adb reboot 2>&1 | Out-String
if ($reb.Trim()) { Write-Host $reb }
Start-Sleep -Seconds 8

$t0 = Get-Date
$after = $null
while (((Get-Date) - $t0).TotalSeconds -lt $BootWaitSec) {
  if (Test-Shell) {
    $info = Get-BootInfo
    if ($info.BootId -and $info.BootCompleted -eq "1") {
      $after = $info
      if ($info.BootId -ne $before.BootId) { break }
      if (($info.Uptime -lt 90) -and ($info.Uptime -lt $before.Uptime)) { break }
    }
  }
  Start-Sleep -Seconds 2
}

if ((-not $after) -or (-not $after.BootId)) {
  Write-Host "No clean shell after reboot window - try MANUAL replug once, then re-run" -ForegroundColor Yellow
  $ok2 = Wait-Shell -Sec 90 -Why "Waiting after possible USB drop..."
  if (-not $ok2) {
    Write-Host "FAIL: no shell after reboot" -ForegroundColor Red
    exit 3
  }
  $after = Get-BootInfo
}

Write-Host ("AFTER: boot_id={0} uptime={1:n1}s boot_completed={2}" -f $after.BootId, $after.Uptime, $after.BootCompleted)

$newBoot = ($after.BootId -and ($after.BootId -ne $before.BootId))
$lowUp = ($after.Uptime -le $MaxUptimeSec)
$bcOk = ($after.BootCompleted -eq "1")

if ($newBoot -and $bcOk -and ($lowUp -or ($after.Uptime -lt 120))) {
  Write-Host "CLEAN BOOT READY (boot_id changed)" -ForegroundColor Green
  adb shell "killall -9 e 2>/dev/null; true" 2>$null | Out-Null
  exit 0
}

if (-not $newBoot) {
  Write-Host "FAIL: boot_id UNCHANGED - adb reboot did not take. Run: adb reboot" -ForegroundColor Red
  exit 3
}

Write-Host "Boot changed but uptime/boot_completed not ideal - check manually" -ForegroundColor DarkYellow
exit 3
