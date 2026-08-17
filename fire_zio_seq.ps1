# Same-boot: ZERO_NAME -> ZERO_OWNER -> ION_SAFE
# SAFETY: never auto-reboot in a loop. At most one reboot at start (opt-in).
# Usage:
#   .\fire_zio_seq.ps1
#   .\fire_zio_seq.ps1 -RebootFirst
param(
  [string]$Serial = "192.168.1.108:5555",
  [switch]$RebootFirst
)

$ErrorActionPreference = "Continue"
$ADB = "C:\Users\LENOVO\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$env:PATH = (Split-Path $ADB) + ";" + $env:PATH
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "zio_seq_$stamp"
$logdir = Join-Path $Root "logs\aarif_pull"
New-Item -ItemType Directory -Force -Path $logdir | Out-Null

function ShellOk {
  $tok = "P" + [guid]::NewGuid().ToString("N").Substring(0, 6)
  $o = & $ADB -s $Serial shell "echo $tok" 2>&1 | Out-String
  return ($o -match [regex]::Escape($tok))
}
function GetBid {
  $b = (& $ADB -s $Serial shell "cat /proc/sys/kernel/random/boot_id" 2>&1 | Out-String).Trim()
  if ($b -match '([0-9a-fA-F-]{36})') { return $Matches[1] }
  return ""
}
function GetUp {
  $up = (& $ADB -s $Serial shell "cat /proc/uptime" 2>&1 | Out-String).Trim()
  if ($up -match '([\d.]+)') { return [double]$Matches[1] }
  return 9999.0
}
function WaitShell([int]$MaxSec = 180) {
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalSeconds -lt $MaxSec) {
    $null = & $ADB connect $Serial 2>&1
    if (ShellOk) {
      $bc = (& $ADB -s $Serial shell "getprop sys.boot_completed" 2>&1 | Out-String).Trim()
      if ($bc -eq "1") { return $true }
    }
    Start-Sleep 3
  }
  return (ShellOk)
}
function FireStep([string]$EnvLine, [string]$Step) {
  Write-Host ("=== {0} {1} ===" -f $Step, $EnvLine) -ForegroundColor Yellow
  if (-not (ShellOk)) {
    Write-Host "no shell - abort step" -ForegroundColor Red
    return @{ Class = "OFFLINE"; Hit = ""; Pre = ""; Post = "" }
  }
  $pre = GetBid
  $up = GetUp
  Write-Host ("pre={0} up={1:n1}" -f $pre, $up)
  & $ADB -s $Serial shell "rm -f /sdcard/ghostlock/aarif/live_sync.log" 2>&1 | Out-Null

  $lines = New-Object System.Collections.Generic.List[string]
  [void]$lines.Add("#!/system/bin/sh")
  [void]$lines.Add("export MODE4_ONLY=1")
  foreach ($p in ($EnvLine -split '\s+')) {
    if ($p -match '^([A-Za-z0-9_]+)=(.*)$') {
      [void]$lines.Add(("export {0}={1}" -f $Matches[1], $Matches[2]))
    }
  }
  [void]$lines.Add("export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log")
  [void]$lines.Add("cd /data/local/tmp")
  [void]$lines.Add("/data/local/tmp/ghostlock-cph2521")
  [void]$lines.Add('echo EXIT=$?')
  $runner = Join-Path $logdir ($tag + "_" + $Step + ".sh")
  [System.IO.File]::WriteAllText($runner, (($lines -join "`n") + "`n"))
  & $ADB -s $Serial push $runner /data/local/tmp/run_lab.sh 2>&1 | Out-Null
  & $ADB -s $Serial shell "chmod 755 /data/local/tmp/run_lab.sh" 2>&1 | Out-Null

  $console = Join-Path $logdir ($tag + "_" + $Step + "_console.txt")
  & $ADB -s $Serial shell "sh /data/local/tmp/run_lab.sh" 2>&1 | Tee-Object -FilePath $console

  Start-Sleep 2
  $alive = ShellOk
  if (-not $alive) {
    Write-Host "shell down - wait reconnect (no reboot)" -ForegroundColor DarkYellow
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt 160) {
      $null = & $ADB connect $Serial 2>&1
      if (ShellOk) { $alive = $true; break }
      Start-Sleep 4
    }
  }
  $post = ""
  $hit = ""
  if ($alive) {
    $post = GetBid
    $lsPath = Join-Path $logdir ($tag + "_" + $Step + "_live_sync.log")
    & $ADB -s $Serial pull /sdcard/ghostlock/aarif/live_sync.log $lsPath 2>&1 | Out-Null
    if (Test-Path $lsPath) {
      $raw = Get-Content $lsPath -Raw
      if ($raw -match "errno=(\d+)") { $hit = "errno=" + $Matches[1] }
      if ($raw -match "FOPS_CFI_HIT") { $hit += " HIT" }
      if ($raw -match "cfi_write_ret=([-\d]+)") { $hit += " wr=" + $Matches[1] }
    }
  }
  $class = "OFFLINE"
  if ($alive -and $post -and $pre -and $post -ne $pre) { $class = "SOFTBOOT" }
  elseif ($alive -and $post -eq $pre) { $class = "ALIVE" }
  Write-Host ("{0} -> {1} {2}" -f $Step, $class, $hit) -ForegroundColor Cyan
  return @{ Class = $class; Hit = $hit; Pre = $pre; Post = $post }
}

# --- main: single pass, no reboot loop ---
Write-Host "=== fire_zio_seq SAFE mode (no auto-reboot loop) tag=$tag ===" -ForegroundColor Green

if ($RebootFirst) {
  if (-not (ShellOk)) { $null = & $ADB connect $Serial 2>&1 }
  if (ShellOk) {
    $before = GetBid
    Write-Host "one-shot reboot (RebootFirst) before=$before"
    & $ADB -s $Serial reboot 2>&1 | Out-Null
    Start-Sleep 14
  }
}

if (-not (WaitShell 180)) {
  Write-Host "FAIL: no shell - unlock phone / re-enable wireless ADB. NOT rebooting." -ForegroundColor Red
  exit 2
}

$boot = GetBid
$up = GetUp
Write-Host ("ready boot={0} up={1:n1}" -f $boot, $up)

& $ADB -s $Serial push (Join-Path $Root "ghostlock-cph2521") /data/local/tmp/ghostlock-cph2521 2>&1 | Out-Null
& $ADB -s $Serial shell "chmod 755 /data/local/tmp/ghostlock-cph2521; mkdir -p /sdcard/ghostlock/aarif" 2>&1 | Out-Null

$a = FireStep "MODE4_ZERO_NAME=1" "1_zero"
if ($a.Class -ne "ALIVE") {
  Write-Host "STOP: ZERO_NAME not ALIVE (class=$($a.Class)). No further steps, no reboot." -ForegroundColor Red
  Write-Output $tag
  exit 1
}

Start-Sleep 1
$b = FireStep "MODE4_ZERO_OWNER=1" "2_owner"
if ($b.Class -ne "ALIVE") {
  Write-Host "STOP: ZERO_OWNER not ALIVE (class=$($b.Class)). No reboot." -ForegroundColor Red
  Write-Output $tag
  exit 1
}

Start-Sleep 1
$c = FireStep "MODE4_ION_SAFE=1" "3_ion"
Write-Host ("DONE zero={0} owner={1} ion={2} {3}" -f $a.Class, $b.Class, $c.Class, $c.Hit) -ForegroundColor Green

@(
  "tag=$tag"
  "boot=$boot"
  "zero=$($a.Class)"
  "owner=$($b.Class)"
  "ion=$($c.Class)"
  "ion_hit=$($c.Hit)"
) | Set-Content (Join-Path $logdir ($tag + "_summary.txt"))
Write-Output $tag
