# Keep WiFi ADB 192.168.1.2:5555 alive.
# USB 596666e9 is bootstrap only (tcpip 5555). Never exec exploit on USB.
# Silent while WiFi works. FAILED only if BOTH transports stay down 10 minutes.
$ErrorActionPreference = "Continue"
$adb = Join-Path $PSScriptRoot "adb_local.exe"
$wifi = "192.168.1.2:5555"
$usb = "596666e9"
$log = Join-Path $env:USERPROFILE ".grok\long-running-background-tasks\watch_adb_wifi.log"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
function L([string]$m) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format o), $m) }
function St([string]$s) {
  $o = & $adb -s $s get-state 2>&1 | Out-String
  if ($o -match '(?m)^device\s*$' -or $o.Trim() -eq "device") { return "device" }
  return $o.Trim()
}
$bothSince = $null
while ($true) {
  $w = St $wifi
  if ($w -ne "device") {
    & $adb connect $wifi 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $w = St $wifi
  }
  if ($w -eq "device") {
    $bothSince = $null
    Start-Sleep -Seconds 30
    continue
  }
  $u = St $usb
  if ($u -eq "device") {
    L "wifi down; USB bootstrap tcpip 5555"
    & $adb -s $usb tcpip 5555 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & $adb connect $wifi 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $w = St $wifi
    if ($w -eq "device") {
      $bothSince = $null
      L "wifi restored via USB"
      Start-Sleep -Seconds 30
      continue
    }
  }
  if ($null -eq $bothSince) { $bothSince = Get-Date; L "both down start" }
  $mins = ((Get-Date) - $bothSince).TotalMinutes
  if ($mins -ge 10) {
    Write-Host "FAILED: both USB and WiFi ADB down >10m; need user reconnect (Shizuku/USB)"
    L "FAILED both down 10m"
    exit 1
  }
  Start-Sleep -Seconds 30
}
