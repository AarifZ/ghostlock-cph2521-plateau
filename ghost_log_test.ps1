# GhostLock durable on-device logging + test runner (CPH2521)
#
# Why: soft reboot kills ADB mid-run. Logs flushed to /sdcard survive.
#
# Usage:
#   .\ghost_log_test.ps1                        # CLEAN BOOT ONLY (default)
#   .\ghost_log_test.ps1 -Shift -2
#   .\ghost_log_test.ps1 -Shift 2 -SimpleLayout
#   .\ghost_log_test.ps1 -PullOnly              # after reboot: post-collect + pull
#   .\ghost_log_test.ps1 -CleanOnly
#   .\ghost_log_test.ps1 -DeployOnly            # push scripts+binary, no run
#   .\ghost_log_test.ps1 -AdbHost 192.168.1.108 -AdbPort 5555
#   .\ghost_log_test.ps1 -AllowStaleBoot        # override: allow high uptime (not recommended)
#
# CLEAN BOOT ONLY (default):
#   - boot_completed=1
#   - uptime seconds <= MaxUptimeSec (default 45)
#   - waits for HARD reboot if device is stale / post-softboot
#   - after exploit softboot: PULL LOGS ONLY (never auto re-run)
#
# Never uses adb kill-server.

param(
  [string]$Kphys = "0xa8000000",
  [string]$Shift = "",
  [switch]$SimpleLayout,
  [switch]$PullOnly,
  [switch]$CleanOnly,
  [switch]$DeployOnly,
  [switch]$NoClean,
  [switch]$AllowStaleBoot,
  [string]$AdbHost = "192.168.1.108",
  [int]$AdbPort = 5555,
  [int]$MaxUptimeSec = 45,
  [int]$MaxWaitShellSec = 120,
  [int]$MaxWaitCleanBootSec = 900,
  [int]$ExploitWaitSec = 90,
  [int]$PostRebootWaitSec = 180,
  [string]$HostLogDir = "C:\Users\LENOVO\Temp\grok-cph2521-quest\device_pulls"
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "ghostlock-cph2521"
$Scripts = Join-Path $Root "device_scripts"
$RemoteDir = "/data/local/tmp"
$RemoteBin = "/data/local/tmp/a/e"
$RemoteLogDir = "/sdcard/ghostlock_logs"

New-Item -ItemType Directory -Force -Path $HostLogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostMeta = Join-Path $HostLogDir ("session_{0}_host.txt" -f $stamp)

function HLog([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss.fff"), $msg
  Write-Host $line
  Add-Content -Path $hostMeta -Value $line
}

function Get-WifiSerial {
  if ($AdbHost -and $AdbPort -gt 0) { return "${AdbHost}:${AdbPort}" }
  return $null
}

function Connect-WifiAdb {
  $ws = Get-WifiSerial
  if (-not $ws) { return $false }
  # soft: never kill-server; just connect
  $out = adb connect $ws 2>&1 | Out-String
  HLog ("adb connect $ws : " + ($out -replace '\s+', ' ').Trim())
  return ($out -match 'connected to|already connected')
}

function Get-Serial {
  # Prefer Wi-Fi serial when connected and healthy
  $ws = Get-WifiSerial
  if ($ws) {
    foreach ($line in (adb devices 2>$null)) {
      if ($line -match [regex]::Escape($ws) + '\s+device') { return $ws }
    }
  }
  foreach ($line in (adb devices 2>$null)) {
    if ($line -match '^(\S+)\s+device') { return $Matches[1] }
  }
  return $null
}

function Get-UptimeSec {
  param([string]$Serial)
  $up = adb -s $Serial shell "cat /proc/uptime" 2>$null | Out-String
  if ($up -match '^\s*([0-9]+(?:\.[0-9]+)?)') {
    return [double]$Matches[1]
  }
  return -1
}

function Get-BootCompleted {
  param([string]$Serial)
  $bc = (adb -s $Serial shell "getprop sys.boot_completed" 2>$null | Out-String).Trim()
  return ($bc -eq "1")
}

function Wait-Shell {
  param([int]$TimeoutSec = 120)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $lastConnect = [datetime]::MinValue
  while ((Get-Date) -lt $deadline) {
    # periodically (re)connect Wi-Fi ADB (survives USB loss; dies on soft reboot until adbd tcp is back)
    if ($AdbHost -and ((Get-Date) - $lastConnect).TotalSeconds -ge 5) {
      [void](Connect-WifiAdb)
      $lastConnect = Get-Date
    }
    $s = Get-Serial
    if (-not $s) { Start-Sleep -Milliseconds 800; continue }
    $r = adb -s $s shell "echo SHELL_OK; getprop sys.boot_completed" 2>$null | Out-String
    if ($r -match 'SHELL_OK') {
      $bc = ""
      if ($r -match '(?m)^1\s*$') { $bc = "1" }
      HLog "shell ready serial=$s boot_completed~=$bc"
      return $s
    }
    HLog "serial=$s listed but shell not ready yet..."
    Start-Sleep -Milliseconds 800
  }
  return $null
}

# Wait until shell is up AND uptime is low (clean boot window).
# Soft reboot also resets uptime - user must HARD reboot after softboot
# before the next test. We detect "just softbooted" only by refusing
# to chain tests; each test invocation requires uptime <= MaxUptimeSec.
function Wait-CleanBoot {
  param(
    [int]$TimeoutSec = 900,
    [int]$MaxUp = 45
  )
  HLog "CLEAN BOOT ONLY: need boot_completed=1 and uptime<=${MaxUp}s (HARD reboot if stale)"
  Write-Host ""
  Write-Host ">>> If phone is already up with HIGH uptime: do a FULL HARD REBOOT now."
  Write-Host ">>> After softboot from a test: HARD REBOOT again before next test."
  Write-Host ">>> Waiting for clean window (uptime <= ${MaxUp}s)..."
  Write-Host ""

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $lastConnect = [datetime]::MinValue
  $lastNote = [datetime]::MinValue
  while ((Get-Date) -lt $deadline) {
    if ($AdbHost -and ((Get-Date) - $lastConnect).TotalSeconds -ge 5) {
      [void](Connect-WifiAdb)
      $lastConnect = Get-Date
    }
    $s = Get-Serial
    if (-not $s) {
      if (((Get-Date) - $lastNote).TotalSeconds -ge 10) {
        HLog "waiting for device (USB or Wi-Fi $AdbHost`:$AdbPort)..."
        $lastNote = Get-Date
      }
      Start-Sleep -Seconds 2
      continue
    }
    $r = adb -s $s shell "echo SHELL_OK" 2>$null | Out-String
    if ($r -notmatch 'SHELL_OK') {
      HLog "serial=$s listed but shell not ready..."
      Start-Sleep -Seconds 1
      continue
    }
    if (-not (Get-BootCompleted -Serial $s)) {
      HLog "serial=$s shell OK but boot_completed!=1 yet..."
      Start-Sleep -Seconds 1
      continue
    }
    $up = Get-UptimeSec -Serial $s
    if ($up -lt 0) {
      HLog "could not read uptime on $s"
      Start-Sleep -Seconds 1
      continue
    }
    if ($up -le $MaxUp) {
      HLog ("CLEAN BOOT window OK serial={0} uptime={1:n1}s (limit {2}s)" -f $s, $up, $MaxUp)
      return $s
    }
    if (((Get-Date) - $lastNote).TotalSeconds -ge 8) {
      HLog ("STALE/SOFT boot serial={0} uptime={1:n1}s > {2}s - HARD REBOOT required" -f $s, $up, $MaxUp)
      $lastNote = Get-Date
    }
    Start-Sleep -Seconds 2
  }
  return $null
}

function Deploy-All {
  param([string]$Serial)
  if (-not (Test-Path $Bin)) { throw "Missing binary: $Bin - run build_cph2521.ps1 first" }
  if (-not (Test-Path $Scripts)) { throw "Missing $Scripts" }

  # After hard reboot wait for emulated storage before logging
  adb -s $Serial shell "i=0; while [ `$i -lt 40 ]; do mkdir -p /data/local/tmp/a /data/local/tmp/ghostlock_run /storage/emulated/0/ghostlock_logs /sdcard/ghostlock_logs 2>/dev/null; if touch /storage/emulated/0/ghostlock_logs/.w 2>/dev/null || touch /sdcard/ghostlock_logs/.w 2>/dev/null; then rm -f /storage/emulated/0/ghostlock_logs/.w /sdcard/ghostlock_logs/.w 2>/dev/null; echo STOR_OK; exit 0; fi; i=`$((i+1)); sleep 0.5; done; echo STOR_FAIL" 2>$null | ForEach-Object { HLog "storage: $_" }

  $pushBin = adb -s $Serial push $Bin $RemoteBin 2>&1 | Out-String
  HLog ("push bin: " + ($pushBin -replace '\s+', ' ').Trim())

  foreach ($name in @("collect_log.sh", "run_ghost_test.sh", "post_reboot_collect.sh")) {
    $local = Join-Path $Scripts $name
    $remote = "$RemoteDir/$name"
    $p = adb -s $Serial push $local $remote 2>&1 | Out-String
    HLog ("push $name : " + ($p -replace '\s+', ' ').Trim())
  }

  adb -s $Serial shell "chmod 755 $RemoteBin $RemoteDir/collect_log.sh $RemoteDir/run_ghost_test.sh $RemoteDir/post_reboot_collect.sh" 2>$null | Out-Null
  HLog "deploy done"
}

function Invoke-Clean {
  param([string]$Serial)
  HLog "cleaning on-device logs..."
  adb -s $Serial shell "sh /data/local/tmp/collect_log.sh clean" 2>&1 | ForEach-Object { HLog "  $_" }
}

function Invoke-Pull {
  param([string]$Serial, [string]$Tag = "pull")
  $dest = Join-Path $HostLogDir ("{0}_{1}" -f $stamp, $Tag)
  New-Item -ItemType Directory -Force -Path $dest | Out-Null

  # Best-effort post-reboot crumbs first
  adb -s $Serial shell "sh /data/local/tmp/post_reboot_collect.sh" 2>&1 | ForEach-Object { HLog "post: $_" }

  HLog "pulling $RemoteLogDir -> $dest"
  adb -s $Serial pull $RemoteLogDir $dest 2>&1 | ForEach-Object { HLog "  $_" }

  # Also copy host-readable summary if present
  $ghost = Get-ChildItem -Path $dest -Recurse -Filter "ghost_log.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($ghost) {
    HLog "=== ghost_log.txt tail ==="
    Get-Content $ghost.FullName -Tail 80 -ErrorAction SilentlyContinue | ForEach-Object { HLog "LOG: $_" }
    Copy-Item $ghost.FullName (Join-Path $HostLogDir ("ghost_log_{0}_{1}.txt" -f $stamp, $Tag)) -Force
  } else {
    HLog "no ghost_log.txt found in pull"
  }

  # kernel hints
  $hints = Get-ChildItem -Path $dest -Recurse -Filter "kernel_hints.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($hints) {
    HLog "=== kernel_hints.txt tail ==="
    Get-Content $hints.FullName -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { HLog "HINT: $_" }
  }

  HLog "pull complete: $dest"
  return $dest
}

function Invoke-Test {
  param([string]$Serial)

  # Host already cleaned when CLEAN path runs; do not re-clean inside once.sh
  # (second clean races the collector / can wipe early lines).
  $exports = @("export KPHYS=$Kphys", "export GHOST_BIN=$RemoteBin", "export CLEAN=0")
  if ($Shift -ne "") { $exports += "export PSELECT_SHIFT=$Shift" }
  if ($SimpleLayout) { $exports += "export PSELECT_SIMPLE_LAYOUT=1" }
  $envLine = $exports -join "; "

  HLog "starting on-device test: $envLine"
  HLog "logs live on device at $RemoteLogDir (survive ADB drop if fsynced)"

  # Fire-and-forget on device so host ADB drop cannot kill the test.
  # run_ghost_test.sh tees to /sdcard and syncs near pselect lines.
  $marker = "/data/local/tmp/ghostlock_run/test_running"
  $doneMark = "/data/local/tmp/ghostlock_run/test_done"
  $once = "/data/local/tmp/ghostlock_run/once.sh"
  adb -s $Serial shell "rm -f $marker $doneMark; mkdir -p /data/local/tmp/ghostlock_run /sdcard/ghostlock_logs" 2>$null | Out-Null

  # Write a small launcher on-device (avoids nasty host quoting)
  $onceBody = @(
    '#!/system/bin/sh'
    $envLine
    "touch $marker"
    'sh /data/local/tmp/run_ghost_test.sh > /sdcard/ghostlock_logs/run_console.txt 2>&1'
    ('echo $? > ' + $doneMark)
    ('rm -f ' + $marker)
  ) -join "`n"
  $onceLocal = Join-Path $HostLogDir ("once_{0}.sh" -f $stamp)
  Set-Content -Path $onceLocal -Value $onceBody -Encoding ascii -NoNewline
  # ensure trailing newline
  Add-Content -Path $onceLocal -Value ""
  adb -s $Serial push $onceLocal $once 2>&1 | Out-Null
  adb -s $Serial shell "chmod 755 $once" 2>$null | Out-Null
  HLog "spawn once.sh on device"
  # Background: sleep 1 lets adb return while job continues
  adb -s $Serial shell "sh $once >/dev/null 2>&1 & sleep 1; echo SPAWNED" 2>&1 | ForEach-Object { HLog "spawn_out: $_" }
  Start-Sleep -Seconds 2

  $waited = 0
  $lost = $false
  while ($waited -lt $ExploitWaitSec) {
    Start-Sleep -Seconds 2
    $waited += 2
    $s2 = Get-Serial
    if (-not $s2) {
      HLog "device lost at +${waited}s (likely soft reboot) - will wait for return and pull"
      $lost = $true
      break
    }
    $st = adb -s $s2 shell "if [ -f $doneMark ]; then echo DONE; cat $doneMark; elif [ -f $marker ]; then echo RUN; else echo IDLE; fi; wc -c /sdcard/ghostlock_logs/ghost_log.txt 2>/dev/null; tail -3 /sdcard/ghostlock_logs/ghost_log.txt 2>/dev/null" 2>$null | Out-String
    if ($st -match 'DONE') {
      HLog "on-device test finished: $($st.Trim() -replace "`r|`n",' | ')"
      break
    }
    if (($waited % 10) -eq 0) {
      HLog "poll +${waited}s: $($st.Trim() -replace "`r|`n",' | ')"
    }
  }
  if (-not $lost -and $waited -ge $ExploitWaitSec) {
    HLog "exploit wait timeout ${ExploitWaitSec}s - pulling whatever was flushed"
  }

  # If still online, pull immediately
  Start-Sleep -Seconds 2
  if (Get-Serial) {
    $s3 = Wait-Shell -TimeoutSec 30
    if ($s3) {
      HLog "device still up - pull logs now"
      Invoke-Pull -Serial $s3 -Tag "live"
      return
    }
  }

  # Wait for reboot + shell, then pull
  HLog "waiting up to ${PostRebootWaitSec}s for post-reboot shell..."
  $s4 = $null
  $deadline = (Get-Date).AddSeconds($PostRebootWaitSec)
  while ((Get-Date) -lt $deadline) {
    $s4 = Wait-Shell -TimeoutSec 15
    if ($s4) {
      # prefer fresh boot: uptime often low after soft reboot
      $up = adb -s $s4 shell "cat /proc/uptime" 2>$null | Out-String
      HLog "post-reboot shell uptime=$($up.Trim())"
      break
    }
  }
  if ($s4) {
    # small settle so sdcard is mounted
    Start-Sleep -Seconds 3
    Invoke-Pull -Serial $s4 -Tag "post_reboot"
  } else {
    HLog "TIMEOUT waiting for post-reboot shell - reconnect USB and run: .\ghost_log_test.ps1 -PullOnly"
  }
}

# ---- main ----
HLog "ghost_log_test start Root=$Root MaxUptimeSec=$MaxUptimeSec AllowStaleBoot=$AllowStaleBoot"

if ($PullOnly) {
  $s = Wait-Shell -TimeoutSec $MaxWaitShellSec
  if (-not $s) { HLog "no shell"; exit 1 }
  Deploy-All -Serial $s  # ensure post_reboot script exists
  Invoke-Pull -Serial $s -Tag "pull_only"
  exit 0
}

# Deploy/CleanOnly: any shell is fine (no clean-boot gate)
if ($DeployOnly -or $CleanOnly) {
  $serial = Wait-Shell -TimeoutSec $MaxWaitShellSec
  if (-not $serial) {
    HLog "NO DEVICE/SHELL - USB and/or Wi-Fi adb connect $AdbHost`:$AdbPort"
    exit 1
  }
  Deploy-All -Serial $serial
  if ($CleanOnly) {
    Invoke-Clean -Serial $serial
    exit 0
  }
  HLog "deploy only - on device run:"
  HLog "  export KPHYS=$Kphys; sh /data/local/tmp/run_ghost_test.sh"
  exit 0
}

# --- exploit path: CLEAN BOOT ONLY by default ---
$serial = $null
if ($AllowStaleBoot) {
  HLog "WARNING: AllowStaleBoot set - running on whatever uptime is present"
  $serial = Wait-Shell -TimeoutSec $MaxWaitShellSec
} else {
  $serial = Wait-CleanBoot -TimeoutSec $MaxWaitCleanBootSec -MaxUp $MaxUptimeSec
}

if (-not $serial) {
  HLog "NO CLEAN BOOT WINDOW - hard reboot the phone, unlock, enable Wi-Fi ADB, retry"
  exit 1
}

# Final uptime gate right before run (race with aging)
$upNow = Get-UptimeSec -Serial $serial
if (-not $AllowStaleBoot -and $upNow -gt $MaxUptimeSec) {
  HLog ("ABORT: uptime drifted to {0:n1}s before run (limit {1}s) - hard reboot and retry" -f $upNow, $MaxUptimeSec)
  exit 2
}
HLog ("pre-run gate serial={0} uptime={1:n1}s shift={2} simple={3}" -f $serial, $upNow, $Shift, [bool]$SimpleLayout)

Deploy-All -Serial $serial

if (-not $NoClean) {
  Invoke-Clean -Serial $serial
}

# Re-check clean boot after deploy (deploy can take a few seconds)
$up2 = Get-UptimeSec -Serial $serial
if (-not $AllowStaleBoot -and $up2 -gt ($MaxUptimeSec + 15)) {
  HLog ("ABORT after deploy: uptime={0:n1}s too high - hard reboot for a tighter window" -f $up2)
  exit 3
}

Invoke-Test -Serial $serial
HLog "done hostMeta=$hostMeta"
HLog "NEXT TEST requires HARD REBOOT (do not chain on softboot/stale uptime)"
