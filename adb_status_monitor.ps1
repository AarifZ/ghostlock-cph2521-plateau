# ADB status monitor for CPH2521 softboot recovery.
# Prints ONE line per state change (for Grok monitor / log tail).
# Softboot: ADB dies without a clean reboot — when device returns, optionally
# issue `adb reboot` so the next exploit shot has a hard-boot window.
#
# Usage:
#   .\adb_status_monitor.ps1
#   .\adb_status_monitor.ps1 -AutoHardRebootOnSoftboot
#   .\adb_status_monitor.ps1 -AutoHardRebootOnSoftboot -MaxUptimeForClean 50
#
# Stop:
#   Set-Content (Join-Path $StatusDir stop) "1"
#   or kill the process.

param(
  [int]$PollSec = 3,
  [int]$OfflineGraceSec = 8,
  [int]$MaxUptimeForClean = 50,
  [switch]$AutoHardRebootOnSoftboot,
  [int]$MaxHardReboots = 20,
  [string]$StatusDir = "C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus\logs\adb_monitor"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $StatusDir | Out-Null
$stopFile = Join-Path $StatusDir "stop"
$statusFile = Join-Path $StatusDir "status.txt"
$logFile = Join-Path $StatusDir "monitor.log"
if (Test-Path $stopFile) { Remove-Item $stopFile -Force -ErrorAction SilentlyContinue }

function Emit([string]$event, [string]$detail = "") {
  $line = if ($detail) { "{0} {1}" -f $event, $detail } else { $event }
  $ts = Get-Date -Format "HH:mm:ss"
  $full = "[$ts] $line"
  # stdout = monitor event (keep short, one line)
  Write-Output $line
  [Console]::Out.Flush()
  try {
    Set-Content -Path $statusFile -Value $full -Encoding utf8
    Add-Content -Path $logFile -Value $full
  } catch {}
}

function Get-DeviceState {
  $devs = cmd /c "adb devices 2>nul" | Out-String
  if ($devs -notmatch "\tdevice(\s|$)") {
    if ($devs -match "\toffline" -or $devs -match "\trecovery" -or $devs -match "\tsideload") {
      return @{ State = "weird"; Uptime = -1; Boot = ""; Raw = $devs }
    }
    return @{ State = "offline"; Uptime = -1; Boot = ""; Raw = $devs }
  }
  $up = (cmd /c "adb shell cat /proc/uptime 2>nul" | Out-String).Trim()
  $bc = (cmd /c "adb shell getprop sys.boot_completed 2>nul" | Out-String).Trim()
  if (-not $up) {
    return @{ State = "stale"; Uptime = -1; Boot = $bc; Raw = $devs }
  }
  $secs = -1.0
  try { $secs = [double]($up.Split()[0]) } catch {}
  if ($bc -ne "1") {
    return @{ State = "booting"; Uptime = $secs; Boot = $bc; Raw = $up }
  }
  return @{ State = "online"; Uptime = $secs; Boot = $bc; Raw = $up }
}

$prev = "init"
$offlineSince = $null
$sawOffline = $false
$hardReboots = 0
$lastRebootAt = [datetime]::MinValue
$cleanAnnounced = $false

Emit "MONITOR_START" ("poll={0}s auto_hard={1} clean_lt={2}s status={3}" -f $PollSec, [bool]$AutoHardRebootOnSoftboot, $MaxUptimeForClean, $StatusDir)

while ($true) {
  if (Test-Path $stopFile) {
    Emit "MONITOR_STOP" "stop_file"
    break
  }

  $s = Get-DeviceState
  $st = $s.State

  if ($st -eq "offline" -or $st -eq "stale" -or $st -eq "weird") {
    if ($prev -eq "online" -or $prev -eq "booting" -or $prev -eq "clean") {
      $offlineSince = Get-Date
      $sawOffline = $true
      $cleanAnnounced = $false
      Emit "ADB_DROP" ("was={0} softboot_suspect=1" -f $prev)
    } elseif ($null -eq $offlineSince) {
      $offlineSince = Get-Date
    } else {
      $offSec = [int]((Get-Date) - $offlineSince).TotalSeconds
      if ($offSec -ge $OfflineGraceSec -and ($offSec % 30) -lt $PollSec) {
        Emit "ADB_OFFLINE" ("for={0}s" -f $offSec)
      }
    }
    $prev = "offline"
    Start-Sleep -Seconds $PollSec
    continue
  }

  if ($st -eq "booting") {
    if ($prev -ne "booting") {
      Emit "BOOTING" ("uptime={0:N1}" -f $s.Uptime)
    }
    $prev = "booting"
    $cleanAnnounced = $false
    Start-Sleep -Seconds $PollSec
    continue
  }

  # online + boot_completed
  if ($prev -eq "offline" -or $prev -eq "init" -or $prev -eq "booting") {
    Emit "ADB_ONLINE" ("uptime={0:N1} saw_offline={1}" -f $s.Uptime, [int]$sawOffline)
  }

  if ($sawOffline -and $AutoHardRebootOnSoftboot) {
    # Softboot recovery: device is back but we want a hard cycle for clean shots
    $cooldown = ((Get-Date) - $lastRebootAt).TotalSeconds -gt 45
    if ($hardReboots -lt $MaxHardReboots -and $cooldown) {
      if ($s.Uptime -gt $MaxUptimeForClean) {
        Emit "HARD_REBOOT" ("reason=softboot_recovery uptime={0:N1} n={1}" -f $s.Uptime, ($hardReboots + 1))
        cmd /c "adb reboot" 2>$null | Out-Null
        $hardReboots++
        $lastRebootAt = Get-Date
        $sawOffline = $false
        $prev = "rebooting"
        $offlineSince = Get-Date
        Start-Sleep -Seconds $PollSec
        continue
      }
    }
  }

  if ($s.Uptime -ge 0 -and $s.Uptime -le $MaxUptimeForClean) {
    if (-not $cleanAnnounced) {
      Emit "CLEAN_WINDOW" ("uptime={0:N1} hard_reboots={1}" -f $s.Uptime, $hardReboots)
      $cleanAnnounced = $true
    }
    $prev = "clean"
  } else {
    # Emit STALE only once on leaving clean/init — never every poll
    if ($prev -eq "clean" -or ($prev -eq "online" -and -not $cleanAnnounced -and $prev -ne "stale")) {
      if ($prev -ne "stale") {
        Emit "STALE_WINDOW" ("uptime={0:N1}" -f $s.Uptime)
      }
    }
    $prev = "stale"
    $cleanAnnounced = $false
  }

  $sawOffline = $false
  $offlineSince = $null
  Start-Sleep -Seconds $PollSec
}

Emit "MONITOR_EXIT"
