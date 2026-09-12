# CPH2521 network ADB (Shizuku auto 5555)

**Updated:** 2026-09-12 (IP moved; lab build still 16.0.5.1002). USB `596666e9` is **bootstrap only** (`tcpip 5555`). All exploit/push/shell on WiFi. Dual USB+WiFi → `error: closed`. Lab copy that worked this session: `adb_local.exe` in the repo root.

| Field | Value |
|-------|--------|
| Device | Oppo Reno 10 Pro+ CPH2521 |
| Transport | TCP (Shizuku auto-restart ADB) |
| Host | **192.168.1.2** (was 192.168.1.108) |
| Port | **5555** |
| Serial | **192.168.1.2:5555** |
| adb binary (working) | **`C:\Users\LENOVO\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe`** (v36, on PATH as `adb`) |
| adb Desktop copy | `C:\Users\LENOVO\Desktop\platform-tools\adb.exe` — **broken/silent** from agent (use winget path instead) |

## Connect (after reboot / softboot)

```powershell
$ADB = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
& $ADB connect 192.168.1.2:5555
& $ADB -s 192.168.1.2:5555 shell "getprop sys.boot_completed; cat /proc/uptime; cat /proc/sys/kernel/random/boot_id"
```

## Last user probe (2026-08-16)

| Field | Value |
|-------|--------|
| model | CPH2521 |
| uname | 5.10.236-android12-9-o-g74d132f4467a |
| boot_id | e8af1399-d122-4b1d-8b05-968eb9eee04e |
| uptime | ~7999 s (~2.2 h) — not a fresh boot |
| boot_completed | 1 |
| uid | 2000 shell |
| binary | `/data/local/tmp/ghostlock-cph2521` 133544 B (2026-08-09) |
| stage | `/data/local/tmp/ghostlock_run/stage.txt` (touched 2026-08-16) |
| aarif | `/sdcard/ghostlock/aarif/plateau_20260809_231813_*` |

## Policy

- Prefer this over USB thrash. USB serial `596666e9` only for `adb tcpip 5555` then `adb connect 192.168.1.2:5555`.
- After KP/softboot: WiFi first. After clean reboot, USB often returns and 5555 is dead until Shizuku / `tcpip`.
- After softboot: wait for connect, confirm **new boot_id** + `boot_completed=1` + uptime ≳ 2 min before fire.
- Quote remote `$(...)` in PowerShell or the host expands it.
- User confirmed connect works from their shell (2026-08-16). Watcher: `watch_adb_wifi.ps1`.

## Agent note

If the Grok terminal reports `IO Error: program not found`, the host cannot spawn processes — not an ADB PATH issue on the user’s machine.
