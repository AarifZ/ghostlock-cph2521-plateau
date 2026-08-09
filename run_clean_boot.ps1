# One-shot GhostLock test ONLY on a clean hard-boot window.
#
# Policy:
#   - Refuse uptime > MaxUptimeSec (default 45s)
#   - Wait for you to HARD reboot if device is stale / post-softboot
#   - After this test softboots: pull logs, then STOP (no auto re-run)
#
# Usage:
#   .\run_clean_boot.ps1
#   .\run_clean_boot.ps1 -Shift 0
#   .\run_clean_boot.ps1 -Shift 4
#   .\run_clean_boot.ps1 -Shift 0 -SimpleLayout
#   .\run_clean_boot.ps1 -MaxUptimeSec 60
#
# Wi-Fi ADB default: 192.168.1.108:5555
# After hard reboot, re-enable TCP if needed:
#   adb tcpip 5555
#   adb connect 192.168.1.108:5555

param(
  [string]$Shift = "0",
  [switch]$SimpleLayout,
  [int]$MaxUptimeSec = 45,
  [string]$AdbHost = "192.168.1.108",
  [int]$AdbPort = 5555,
  [string]$Kphys = "0xa8000000"
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $Root "ghost_log_test.ps1"

Write-Host ""
Write-Host "=============================================="
Write-Host " CLEAN BOOT ONLY - GhostLock CPH2521"
Write-Host "=============================================="
Write-Host " 1. HARD reboot the phone (full power cycle)."
Write-Host " 2. Unlock, wait for home + Wi-Fi."
Write-Host " 3. If needed: adb tcpip 5555 && adb connect ${AdbHost}:${AdbPort}"
Write-Host " 4. This script runs only while uptime <= ${MaxUptimeSec}s."
Write-Host " 5. After softboot: logs are pulled; HARD reboot again before next test."
Write-Host "=============================================="
Write-Host ""

$argsList = @(
  "-AdbHost", $AdbHost,
  "-AdbPort", $AdbPort,
  "-Kphys", $Kphys,
  "-MaxUptimeSec", $MaxUptimeSec,
  "-MaxWaitCleanBootSec", "1200",
  "-ExploitWaitSec", "160",
  "-PostRebootWaitSec", "300",
  "-MaxWaitShellSec", "180"
)
if ($Shift -ne "") { $argsList += @("-Shift", $Shift) }
if ($SimpleLayout) { $argsList += "-SimpleLayout" }

& powershell -ExecutionPolicy Bypass -File $runner @argsList
exit $LASTEXITCODE
