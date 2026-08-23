# Next session pickup — 2026-08-24

**Read first:** this file, then `docs/Z29_UID0_CHECKPOINT_2026-08-24.md`, then `docs/Z15_SELINUX_PLAIN_PARK_2026-08-23.md`.  
**Supersedes:** `docs/NEXT_SESSION_2026-08-23.md`.

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` only.  
**Binary:** `ghostlock-cph2521` (rebuild `.\build_cph2521.ps1` if tree moved).

---

## ColorOS 15s kill (screenshot)

`logs/aarif_pull/Z29_coloros_security_warning.jpg`

Dialog on top of Shizuku (01:00, 2026-08-24):

> Security warning  
> An attempt by a malicious app to damage the system has been stopped. For security purposes, your device will restart in 15 seconds.

**Not a kernel panic.** Park/`pselect ret=5`/`enforce=0` can still be a **success**; ColorOS then force-restarts. Same family as Z14 `OplusCfThread`, but this is the **user-visible 15s reboot**. After it: WiFi ADB `192.168.1.108:5555` dead until Shizuku; USB `596666e9` for classify/fire. Do not USB-PnP.

---

## Policy (do not violate)

- No second GhostLock process on a park boot (**Z5**).
- No 8-byte NULL into `selinux_state` (**Z14**).
- No spray overlay / no wrap of `ffffff87/88/89` → P0 (**Z23, Z28** pre-select KP).
- No `fire_mode.ps1` (CRLF). Unix LF runner only.
- One data punch after park (**Z26 W3** KP).
- No JoinChang #31 post. No live git spam. Push only if user asks.

---

## Where uid0 actually is

Park is the product. Leak is **PMU type=8 `inst_retired`, x28** (unique, 64-aligned). **Z26:** `*(x28+0x790)` changed `comm` → that object is `task_struct`.

`*(task+0x780)=init_cred` **walks alive** (Z25, Z27, Z29) but **uid stays 2000**: `/proc/status` reads **real_cred +0x778**; child never answers `getuid()` (pipe 9999). BSS-zero cred panics (Z22/Z24).

**Next fire (fresh boot, uptime ≳ 2 min, one process):**

```
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8
MODE4_SWAP_NOCFI=1 MODE4_UID0=1
```

Push `ghostlock-cph2521` → `/data/local/tmp/gl_uid0` + `gl_run_uid0.sh`.

Code change still needed in tree if not already: **one** store `*(x28+TASK_REAL_CRED_OFF=0x778)=init_cred` (or parent x28 if it is already `ffffff80` P0 — then `getuid()` in-process). Prefer raw x28. **Do not wrap.**

Success: `status_uid=0` or `getuid_after_store=0`. If the 15s ColorOS dialog appears after that, kernel still won — log and stop that boot.

---

## ADB

| | |
|--|--|
| WiFi | `192.168.1.108:5555` Shizuku 13.6 |
| USB | `596666e9` |
| Host | WinGet `platform-tools\adb.exe` |
| After 15s ColorOS reboot | USB first; force-stop Shizuku if 5555 dead |

---

## Do not reopen

ION / PAD3 / dual-PI / swapped ashmem / `MODE4_ROOT` this cycle / JoinChang 6.12 `.write_iter` on 5.10.

---

## Logs

`logs/aarif_pull/Z15_plain_console.txt` … `Z29_cred_console.txt`  
`tools/leak_probe.c` — PMU probe, not a second GhostLock.
