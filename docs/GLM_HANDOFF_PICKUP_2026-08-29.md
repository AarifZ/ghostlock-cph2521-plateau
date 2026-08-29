# GLM handoff pickup — 2026-08-29

You are picking up GhostLock on **CPH2521** from Grok. The 2026-08-23 GLM pickup (`docs/GLM_HANDOFF_PICKUP_2026-08-23.md`) is **stale** for next-fire (it still says `fire_mode.ps1`, UMH/modprobe, two-fire oracle→swap). Read **this file first**, then `docs/NEXT_SESSION_2026-08-29.md`, then `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`, then `docs/HANDOFF_2026-08-29.md`.

**Do not fire** until the boot is ≳ 2 min old and ADB is stable. Last device state: post-ZI-2 kernel panic, boot `34b02354`, young, ADB flaky.

**Do not retry `MODE4_ZI`.** Both ZERO_NAME geometries KP’d at `pselect place`. ION never ran.

---

## Operator question you must not get wrong

> we were getting the popup for root attempt was stopped... but if we turn off that detection then it should reach the root i believe have we tried that?

**Answer in one breath:** the 15s “Security warning” is ColorOS **userspace** (`com.oplus.stdsp` / safecenter), not a kernel panic. We **did** disable StdSP with `pm disable-user` as uid 2000 (Z33). The popup **did not show**. A **child** then hit uid 0 for ~2 minutes (`UID0 WIN child is root`, `/proc/pid/status` Uid 0). The **ADB shell stayed uid 2000**. The phone still rebooted ~2 min later (`sys.boot.reason=reboot`, not `malicious_app`). Self-cred of the shell **still** popped even with StdSP off (Z34). A ColorOS **Settings** toggle has **not** been tried. Turning the dialog off does not create kR/W, does not `setenforce`, does not load KernelSU, and does not replace kernel ROOTGUARD (`oplus_security_guard` on `sys_exit` — already unhookable via leaf-NULL).

Full evidence table: `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`.

---

## Lab rules (from the operator — do not violate)

| Rule | Why |
|------|-----|
| Branch `research-master` only | user |
| No live git except checkpoints; no push unless asked | user |
| Unix LF `gl_run_*.sh` only | `fire_mode.ps1` CRLF / Permission denied |
| After KP: WiFi `192.168.1.108:5555` first | USB `596666e9` often dead; no PnP; one transport |
| No second GhostLock after **any** successful walk | Z5; later second-process park after oracle also KP |
| No 8-byte NULL into `selinux_state` | Z14 |
| No spray after park; no wrap `ffffff87/88/89`→P0 | Z16, Z23, Z28 |
| One data punch after park | Z26 W3 KP |
| No fire ≲ 2 min uptime | Z21 |
| No GBOOT to **module VA** | Z47 `STRICT_MODULE_RWX` |
| No kptr VALUE `0xffffff8100000000` | Z44 |
| No T1 `tree_pc=0` | KP |
| No ZI as currently routed | KP ×2 2026-08-29 |
| ~20 true-reboot budget | treat KP as expensive |
| Research only; this is the user’s device | |

Workspace: `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
Binary: `ghostlock-cph2521` **214880**. Push as `/data/local/tmp/gl_uid0`. NDK r27d `.\build_cph2521.ps1`.  
Host adb: WinGet `platform-tools\adb.exe`.

---

## What landed since the 2026-08-23 GLM session

GLM 2026-08-23 left: SLIDE oracle, SLIDE_SWAP, SWAP_NOCFI N5 ALIVE, `swap_probe` unrun in the 2-min window.

Grok / lab since then (keep; do not re-open):

| Result | Notes |
|--------|-------|
| Spray-free SLIDE | O29–O32 LANDED; sprayed young-boot oracle KP |
| Durable park | Z15 PLAIN-STORE `*selinux_state=P0(0x02BB0000)` |
| SWAP HOLD | N15 `fake_fops=ffffff8048240100` when snitch page is `ffffff80` |
| Second process after walk | **always KP** (generalized Z5) |
| In-process llseek repair | N14 KP |
| UMH | `STATIC_USERMODEHELPER_PATH=""` — modprobe path **dead** |
| ROOTGUARD RE | `oplus_security_guard.ko`; `g_boot_state` core+0x3000; `is_unlocked` any nz; module VA RO |
| GBOOT module VA punch | Z47 KP |
| Leaf-NULL `*sys_exit.funcs=0` | **lives** (`parent=funcs-8`). T1 `tree_pc=0` KP |
| User-PMU x28 | `pmu8_user_xk` under Enforcing; kernel-only EACCES |
| Child uid 0 | **Z33** logged WIN; ~2 min; StdSP disabled; no 15s dialog |
| Self-cred of adbd | Z34 died; ColorOS `malicious_app` even with StdSP off |
| Hookcred 24c41c5a | leaf-NULL + user-PMU + self-cred walk `ret=5`; console **truncated** before `getuid_after_store` — do **not** claim parent getuid=0 from that log |
| Compact waiter `{1,tree_r}` | fixed (historical ION stamped `tree_right=0`) |
| ZI ZERO_NAME | KP ×2; do not retry this route |
| Issue #31 update | posted comment `5456301814`; no owner reply |

---

## Tree facts GLM will touch

**LEAF-NULL** (`src/core/fops.c` `MODE4_NULL_STORE`):

```
tree_pc = (ztgt - 8) & ~3ULL;
tree_r = 0; tree_l = 0;
stack_lock = init_task+0x878;
```

**Compact words:** `{0,tree_pc} {1,tree_r} {2,tree_l} {6,stack_task} {7,stack_lock} {8,stack_prio} {9,stack_deadline}`.

**Hookcred skip-mute:** `uid0_cred_walk()` `MODE4_NULL_STORE` → `goto uid0_cred_punch` **skips** `uid0_mute_coloros()`. Fix if you fire hookcred.

**WIN persist** only runs when `self_uid==0 || euid==0`. Z33 child-only WIN never chmod’d `/data/adb` 0777. If you extend Z33, persist on `status_uid==0` **in the child**.

**ZI** (`gl_run_zi.sh`): phase1 ZERO_NAME now BSS lock prio=0 (was spray lock prio 200). Still KP at place. `g_mode4_chain_phase` is kept (was wrongly zeroed). **Do not fire.**

**User-PMU:** `perf_open_hw` tries `pmu8_user_xk` first (`exclude_user=0, exclude_kernel=1`). Count x28 only if IP is kernel (`>= 0xffffffc000000000`) and `task_ptr_ok`.

---

## Recommended first actions (in order)

1. **Do not fire.** Classify: `boot_id`, `uptime`, `getenforce`, `id`. If uptime < 120s or ADB flaky, wait or `adb reboot` and wait.
2. If the operator wants the Settings experiment: they hunt ColorOS Security/Privacy for an anti-tamper switch. You do not invent one. Screenshot. Then fire **Z33 geometry** (`gl_run_uid0.sh`), not ZI, not a second process.
3. If they want kernel progress instead: **code**, not ZI.
   - Call `uid0_mute_coloros()` on the NULL_STORE path (or document host `pm disable-user com.oplus.stdsp` before hookcred).
   - Write `getuid_after_store` to `/data/local/tmp/ghostlock_uid0` **inside `uid0_one_store` after pselect**, before `getuid()` / ColorOS can kill.
   - On `status_uid==0`, persist from the **child** (`G` pipe already there).
   - For kR/W: implement **pre-open ashmem fd → swap HOLD → pwrite that fd** (JoinChang #31 Q3). Do not `open()` after swap. Do not second process. Do not in-process repair that KPd (N14).
4. Rebuild, push `/data/local/tmp/gl_uid0`, Unix LF runner, `setsid`/`nohup` so ADB SIGHUP does not kill the fire.
5. Stop after two pre-select SOFTBOOTs in a row or if the phone is hot.

---

## Runners (Unix LF)

| Script | What |
|--------|------|
| `gl_run_uid0.sh` | park + cred (Z33 class). **Tracked.** |
| `gl_run_hookcred.sh` | leaf-NULL funcs then self cred. **Untracked.** |
| `gl_run_slide.sh` | spray-free SLIDE oracle. Untracked. |
| `gl_run_swap.sh` | SLIDE_SWAP NOCFI. **Stale `KASLR_SLIDE` in file — replace.** Untracked. |
| `gl_run_zi.sh` | ZERO→ION. **Banned this cycle.** Untracked. |
| `gl_run_park.sh` | park only. Untracked. |
| `gl_run_gboot.sh` | park then g_boot punch. **Do not punch module VA.** Tracked. |
| `gl_run_holdpark.sh` | park HOLD, no cred. Tracked. |

---

## Offsets (do not “rediscover”)

See table in `docs/NEXT_SESSION_2026-08-29.md`. Cred `0x780`, real_cred `0x778`, funcs P0 `ffffff802a950700`, `init_cred` P0 `ffffff802a7e0be0`, KPHYS `0xa8000000`.

---

## Issue #31

https://github.com/JoinChang/ghostlock-oneplus/issues/31  
Our update: `docs/ISSUE31_UPDATE_2026-08-28.md` (comment 5456301814). **Do not post again** unless the operator asks or the owner replies.

Owner already told us: errno 22 is configfs EINVAL; compact waiter; KPHYS 0xa8000000. Lab agrees. Remaining ask is **first pwrite without post-swap open**.

---

## Success / honesty

- `UID0 WIN child is root` **already happened** (Z33). That is not product root.
- Do not write “parent getuid=0” unless `/data/local/tmp/ghostlock_uid0` or console shows `getuid_after_store=0`.
- ColorOS 15s dialog after a kernel win = userspace reboot. Log it. Do not rewind a successful walk.
- Product root = ADB `id` uid=0 **or** a world-readable proof file **and** the boot still up after 3+ minutes **and** a persist story (`/data/adb` usable from shell, or KSU).
