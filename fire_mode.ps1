# Fire a MODE4 experiment via network ADB. No git.
param(
  [Parameter(Mandatory = $true)][string]$ModeEnv,
  [string]$Serial = "192.168.1.108:5555",
  [string]$TagPrefix = "lab"
)

$ErrorActionPreference = "Continue"
$ADB = "C:\Users\LENOVO\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$env:PATH = (Split-Path $ADB) + ";" + $env:PATH
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$safe = ($ModeEnv -replace "[^A-Za-z0-9_]+", "_")
$tag = $TagPrefix + "_" + $safe + "_" + $stamp
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

if (-not (ShellOk)) {
  $null = & $ADB connect $Serial 2>&1
  Start-Sleep -Seconds 2
  if (-not (ShellOk)) { Write-Host "FAIL: no shell"; exit 2 }
}

$pre = GetBid
$up = (& $ADB -s $Serial shell "cat /proc/uptime" 2>&1 | Out-String).Trim()
Write-Host ("=== FIRE {0} ===" -f $tag) -ForegroundColor Yellow
Write-Host ("env={0} pre_boot={1} up={2}" -f $ModeEnv, $pre, $up)

& $ADB -s $Serial shell "mkdir -p /data/local/tmp /sdcard/ghostlock/aarif" 2>&1 | Out-Null
& $ADB -s $Serial shell "rm -f /sdcard/ghostlock/aarif/live_sync.log /sdcard/ghostlock/aarif/stage.txt /sdcard/ghostlock/aarif/proof.log" 2>&1 | Out-Null
& $ADB -s $Serial push (Join-Path $Root "ghostlock-cph2521") /data/local/tmp/ghostlock-cph2521 2>&1 | Out-Null
& $ADB -s $Serial shell "chmod 755 /data/local/tmp/ghostlock-cph2521" 2>&1 | Out-Null

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("#!/system/bin/sh")
$lines.Add("export MODE4_ONLY=1")
foreach ($part in ($ModeEnv -split '\s+')) {
  if ($part -match '^([A-Za-z0-9_]+)=(.*)$') {
    $lines.Add(("export {0}={1}" -f $Matches[1], $Matches[2]))
  }
}
$lines.Add("export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log")
$lines.Add("export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt")
$lines.Add("export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log")
$lines.Add("cd /data/local/tmp")
$lines.Add("/data/local/tmp/ghostlock-cph2521")
$lines.Add('echo EXIT=$?')
$runnerBody = ($lines -join "`n") + "`n"
$runner = Join-Path $logdir ($tag + "_runner.sh")
[System.IO.File]::WriteAllText($runner, $runnerBody)

& $ADB -s $Serial push $runner /data/local/tmp/run_lab.sh 2>&1 | Out-Null
& $ADB -s $Serial shell "chmod 755 /data/local/tmp/run_lab.sh" 2>&1 | Out-Null

$console = Join-Path $logdir ($tag + "_console.txt")
@(
  "tag=$tag"
  "env=$ModeEnv"
  "pre=$pre"
  "up=$up"
) | Set-Content -Path (Join-Path $logdir ($tag + "_meta.txt")) -Encoding utf8

& $ADB -s $Serial shell "sh /data/local/tmp/run_lab.sh" 2>&1 | Tee-Object -FilePath $console

Start-Sleep -Seconds 3
$alive = ShellOk
if (-not $alive) {
  Write-Host "shell down - waiting reconnect (softboot?)" -ForegroundColor DarkYellow
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalSeconds -lt 180) {
    $null = & $ADB connect $Serial 2>&1
    if (ShellOk) { $alive = $true; break }
    Start-Sleep -Seconds 5
  }
}

$post = ""
$up2 = ""
if ($alive) {
  $post = GetBid
  $up2 = (& $ADB -s $Serial shell "cat /proc/uptime" 2>&1 | Out-String).Trim()
  & $ADB -s $Serial pull /sdcard/ghostlock/aarif/live_sync.log (Join-Path $logdir ($tag + "_live_sync.log")) 2>&1 | Out-Null
  & $ADB -s $Serial pull /sdcard/ghostlock/aarif/stage.txt (Join-Path $logdir ($tag + "_stage.txt")) 2>&1 | Out-Null
  & $ADB -s $Serial pull /sdcard/ghostlock/aarif/proof.log (Join-Path $logdir ($tag + "_proof.log")) 2>&1 | Out-Null
}

$class = "UNKNOWN"
if ($post -and $pre -and $post -ne $pre) { $class = "SOFTBOOT" }
elseif ($alive -and $post -eq $pre) { $class = "ALIVE" }
elseif (-not $alive) { $class = "OFFLINE" }

Write-Host ("=== CLASS={0} pre={1} post={2} up_after={3} ===" -f $class, $pre, $post, $up2) -ForegroundColor Cyan
Write-Host "=== live_sync ===" -ForegroundColor Green
$ls = Join-Path $logdir ($tag + "_live_sync.log")
if (Test-Path $ls) { Get-Content $ls } else { Write-Host "(missing)" }
Write-Host ("TAG={0} CLASS={1}" -f $tag, $class)
@(
  "class=$class"
  "pre=$pre"
  "post=$post"
) | Set-Content -Path (Join-Path $logdir ($tag + "_classify.txt")) -Encoding utf8
Write-Output $tag
