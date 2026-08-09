# ADB / softboot recovery (mandatory)

## Never do this (LOCKED)
- **USB PnP disable/enable thrash** (MTP/ADB/composite)
- **Root-hub / host-controller “power cycle”** from automation — on this PC it often leaves the phone **undetected** until **manual replug**
- Fire on high uptime after softboot
- Idle “thinking” loops instead of hardboot when shell is up

## Treat all of these as “need clean boot” (same recovery)

| Symptom | Typical cause |
|---------|----------------|
| Softboot mid-place / punch | stamp + erase path |
| Stuck long in **spray** / KS retry | KernelSnitch fail loop; ADB often dies |
| KS `mm_struct leak failed` ×N | flaky high-uptime or heap noise |
| ADB **stale** / `error: closed` / empty devices | softboot, spray wedge, or host ADB flake |

**Do not** keep firing on the same long-uptime / half-dead session.

## After softboot / spray hang / stale ADB

1. `adb kill-server` then `adb start-server` only (**no** USB PnP/power thrash)  
2. If still dead: **you** manual unplug/replug (or power-button reboot)  
3. When `adb shell` works: **`adb reboot`** for a **clean** test boot (uptime ≲ 60s)  
   - Prefer `.\post_softboot_hardboot.ps1` (must see **new boot_id**; exit 3 if reboot did not take)  
   - Agent **must** hardboot after a softboot/stale it caused, once shell is back  
   - If script fails: agent runs plain `adb reboot` and waits for new `boot_id` — do not claim CLEAN until id changes  
4. Only then fire again (`FOPS_MAX_ATTEMPTS=4` default for fires to avoid 12× spray grind)

```powershell
# safe: server only + wait for you
.\adb_usb_recover.ps1

# when shell works: hardboot without USB thrash
.\post_softboot_hardboot.ps1
```

Automation must **not** call `-PowerCycle`, host-controller bounce, or bulk PnP disable.

### What `post_softboot_hardboot.ps1` does
1. USB recover if shell dead  
2. `adb reboot`  
3. While booting: re-run USB recover if shell drops (not passive wait only)  
4. Require `boot_completed=1` and **uptime ≲ 45s**  

## If software USB cycle fails
Phone may show MTP/WinUsb **OK** but `adb devices` empty — phone USB stack wedged.

Then **you** must:
1. Physical unplug + replug USB cable, **or**  
2. Power-button hard reboot (hold power until off, then on)  
3. Unlock phone, confirm USB debugging / “File transfer” if prompted  
4. Re-run `.\adb_usb_recover.ps1` then `.\post_softboot_hardboot.ps1`  

## Clean-to-fire checklist
- [ ] `adb shell echo OK` works  
- [ ] `boot_completed=1`  
- [ ] `uptime` first field **≤ 45**  
- [ ] Prefer **new** `boot_id` vs pre-softboot  
- [ ] `killall -9 e` leftover exploit  
