# CPH2521 network ADB (Shizuku auto 5555)

**Updated:** 2026-08-16

| Field | Value |
|-------|--------|
| Device | Oppo Reno 10 Pro+ CPH2521 |
| Transport | TCP (Shizuku auto-restart ADB) |
| Host | **192.168.1.108** |
| Port | **5555** |
| Serial | **192.168.1.108:5555** |
| adb binary (working) | **`C:\Users\LENOVO\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe`** (v36, on PATH as `adb`) |
| adb Desktop copy | `C:\Users\LENOVO\Desktop\platform-tools\adb.exe` — **broken/silent** from agent (use winget path instead) |

## Connect (after reboot / softboot)

```powershell
$ADB = "C:\Users\LENOVO\Desktop\platform-tools\adb.exe"
& $ADB connect 192.168.1.108:5555
& $ADB -s 192.168.1.108:5555 shell "getprop sys.boot_completed; cat /proc/uptime; cat /proc/sys/kernel/random/boot_id"
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

- Prefer this over USB thrash.
- After softboot: wait for connect, confirm **new boot_id** + `boot_completed=1` + low uptime before fire.
- User confirmed connect works from their shell (2026-08-16).

## Agent note

If the Grok terminal reports `IO Error: program not found`, the host cannot spawn processes — not an ADB PATH issue on the user’s machine.
