# ColorOS 15s popup vs kernel root — 2026-08-29

**Question:** the phone shows *“An attempt by a malicious app to damage the system has been stopped… restart in 15 seconds.”* If we turn that detection off, do we reach root? Have we tried it?

**Short answer:** we already turned off the userspace package that *draws* that dialog (`com.oplus.stdsp`). Child `uid 0` then appeared for ~2 minutes **without** the 15s popup (Z33). That is not usable/persistent root. Punching the **ADB/shell** process still tripped ColorOS even with StdSP off (Z34). A Settings toggle has **not** been tried. Turning the dialog off does **not** create kernel R/W, does **not** load KernelSU, and does **not** disarm the kernel `sys_exit` ROOTGUARD hook.

---

## Two different “root stopped” mechanisms

| Layer | What | Who | What we did |
|-------|------|-----|-------------|
| **Userspace ColorOS** | 15s “Security warning” dialog, then reboot. Boot reason `reboot,malicious_app_try_to_root_devices`. | `com.oplus.stdsp` (StdSP Core, intercept activity `SystemSafeGuardInterceptActivity`) plus `com.oplus.safecenter`, `com.oplus.subsys`, `com.oplus.securityguard`. Same family as Z14 `OplusCfThread`. | **Tried** `pm disable-user` of StdSP as uid 2000. **Did not try** a ColorOS Settings toggle. |
| **Kernel ROOTGUARD** | `oplus_root_check_post_handler` on `sys_exit` **SIGKILLs** a process that drops uid/euid/gid/egid unless `g_boot_state` is nonzero (`is_unlocked` = `LDRB`+`RET`, any nz = orange). | Vendor module `oplus_security_guard.ko` (not GKI `cred.c`). `WHITE_LIST_SUPPORT` is userdebug-only. Killing `oplus_kevent` userspace does nothing. | Unhooked on-device by **leaf-NULL** `*__tracepoint_sys_exit.funcs = 0` (not T1 `tree_pc=0`). |

The popup is **not a kernel panic**. Classify:

| Symptom | Meaning |
|---------|---------|
| `pselect pre-select +1–10ms` then ADB gone | real punch KP / kernel SOFTBOOT |
| `pselect ret=5` then phone reboots ~15s later with this dialog | walk **lived**; ColorOS killed the boot |
| Screen off, adbd alive, SID flood in dmesg | Z14-style `initialized=0` — **do not repeat** (8-byte NULL into `selinux_state`) |
| `pselect ret=5`, no dialog, then silent reboot ~2 min, `sys.boot.reason=reboot` | Z33: child uid0 lived; another watchdog (not StdSP dialog) still reboots |

Screenshot: `logs/aarif_pull/Z29_coloros_security_warning.jpg`.

---

## What we actually tried

### 1. Disable StdSP (`com.oplus.stdsp`) — **tried, Z33**

```
pm disable-user --user 0 com.oplus.stdsp
```

as shell **uid 2000**. Disable **persisted** across reboot (`pm list packages -d`). Factory `/product/priv-app/StdSP` stayed listed; update APK `com.oplus.stdsp` 2.24.2.

Then same-process park + **child** cred punch (not the ADB shell):

```
UID0 status_uid=0 getuid=9999 self_uid=2000 who=child_x28
UID0 WIN child is root
```

- `ps`: `root 22522 gl_uid0`
- `/proc/22522/status`: uid/euid/fsuid **0**, caps `000001ffffffffff`, SELinux `u:r:kernel:s0`
- **No 15s Security warning.** Focus stayed on Shizuku.
- Reboot ~2 min later. `sys.boot.reason = reboot` (**not** `malicious_app_try_to_root_devices`).
- Parent `getuid()` stayed **2000**. Child never answered the pipe (`getuid=9999`).
- `suid`/`gid` looked like leftover pointer bits (`0xffffff89` / `0xe12899f8`) — not a clean `init_cred` copy.

**Log:** `logs/aarif_pull/Z33_stdsp_disabled_console.txt`, `Z33_stdsp_disabled_result.txt`.

So: turning the dialog off **did** let a kernel uid0 **child** live long enough to log WIN. It did **not** give an ADB root shell, persist, or KernelSU.

### 2. Same StdSP-off + **self** cred of the ADB/shell task — **tried, Z34, failed**

StdSP still disabled-user from Z33. Self `x28` + `*(task+0x780)=init_cred`. Walk `ret=5`, then session died **before** `getuid_after_store`.

After: `sys.boot.reason = reboot,malicious_app_try_to_root_devices`. StdSP **still** disabled. Running: safecenter, subsys, securityguard.

**Conclusion (Z34):** punching the **adb/shell** task cred trips ColorOS even with StdSP off. The 15s dialog is not “the only detection.”

**Log:** `logs/aarif_pull/Z34_selfcred_result.txt`.

### 3. In-exploit `uid0_mute_coloros()` — **tried as uid 2000 after park, insufficient**

`src/core/main.c` `uid0_mute_coloros()` `pm disable-user` + `am force-stop` of:

`com.oplus.exsystemservice`, `com.oplus.stdsp`, `com.oplus.safecenter`, `com.oplus.subsys`, `com.oplus.securityguard`, `com.coloros.phonemanager`.

Comment in tree: *stdsp-only was not enough (safecenter/subsys still ran).* `pm disable-user` as uid 2000 cannot disable privileged ColorOS packages that the shell does not own. Host `pm` of StdSP worked because that update APK is user-disableable.

**Hookcred gap:** `MODE4_NULL_STORE` `goto uid0_cred_punch` **skips** `uid0_mute_coloros()`. Leaf-NULL + self-cred fires never mute ColorOS in-process.

### 4. ColorOS **Settings** toggle — **not tried**

No lab fire used a user-visible Security / Privacy / “unauthorized access” / “root detection” switch. If one exists on ColorOS 16 (CPH2521 `16.0.5.1002`), it is the only remaining *userspace* experiment. It is **not** a substitute for kernel R/W.

---

## What turning the popup off cannot do

Even a perfect Settings mute would not:

1. **Disarm kernel ROOTGUARD.** That is `oplus_security_guard.ko` on `sys_exit`. Self-cred without hook-off / `g_boot_state` nz **SIGKILLs** on pselect return. Already unhooked via leaf-NULL on later boots.
2. **Create unlimited kernel R/W.** Swap still clobbers `fake_fops+8` (llseek). Opening swapped ashmem KPs. ZI ZERO_NAME (current route) KPs at `pselect place` ×2.
3. **Make `setenforce` work.** uid0 + Enforcing still hits SELinux MAC (`write` `/sys/fs/selinux/enforce` → errno **13**). Park is the data-only way we have to Permissive.
4. **Load KernelSU.** Dropping `su`/`ksud` into `/data/adb` without a kernel module / LKM path does not persist a root manager. `/data/adb` created 0700 so shell sees Permission denied unless umask/chmod happens as the uid0 process.
5. **Stop every reboot.** Z33 already had **no dialog** and still rebooted ~2 min later (`sys.boot.reason=reboot`). Something else (another userspace watchdog, or delayed kernel death) still kills the boot.

---

## Honest status of “did we reach root?”

| Claim | Evidence |
|-------|----------|
| Kernel **child** uid 0, ~2 min, Permissive, no 15s dialog | **Yes (Z33).** Logged `UID0 WIN child is root`. `/proc/pid/status` Uid 0. |
| Living **same-process** `getuid()==0` on the ADB shell | **Not in a pulled console line.** 24c41c5a self-cred walk `ret=5` then log ends at `waiter_pselect_returned` (same shape as Z34 death). Treat parent getuid=0 as **unconfirmed** until `getuid_after_store=0` is on disk. |
| Usable / persistent root (adb `id` uid=0, KernelSU, survive reboot) | **No.** |

---

## If the operator wants to try a Settings toggle anyway

Do it **before** the next fire, on a settled boot (uptime ≳ 2 min), **one** GhostLock process:

1. Settings: hunt Security / Privacy / system protection / unauthorized-access / “root” wording. Disable if present. Screenshot.
2. Confirm `pm list packages -d` still has `com.oplus.stdsp` (Z33 disable may still be on).
3. Prefer **Z33 geometry** (park + **child** cred, no wrap, no W3), not self-cred of adbd.
4. If child WIN again: persist **inside the uid0 child** immediately (umask 0, `chmod 0666` proof files, `mkdir /data/adb` 0777) — code already tries this on `self_uid==0`, **not** on child-only WIN.
5. Do **not** treat a missing popup as “root done.” Check `getuid()`, `/proc/self/status`, `getenforce`, and whether ADB still answers after 3+ minutes.

Kernel work that still has to happen regardless of the dialog: **unlimited kR/W** (fops swap without llseek clobber / first configfs pwrite on a pre-swap fd) so SELinux, both creds, `g_boot_state` physmap, and KSU are data-only.

See `docs/NEXT_SESSION_2026-08-29.md` and `docs/GLM_HANDOFF_PICKUP_2026-08-29.md`.
