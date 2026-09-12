# Next session pickup — 2026-08-29

> **SUPERSEDED 2026-09-12.** Read `docs/NEXT_SESSION_2026-09-12.md` and `docs/GLM_HANDOFF_PICKUP_2026-09-12.md`. Exact Z33 KPd; do not use this file’s next-fire. WiFi IP below was patched to `192.168.1.2`.

**Read first:** this file, then `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`, then `docs/GLM_HANDOFF_PICKUP_2026-08-29.md` / `docs/HANDOFF_2026-08-29.md`. Older: `docs/Z49_GBOOT_CHECKPOINT_2026-08-24.md`, `docs/Z29_UID0_CHECKPOINT_2026-08-24.md`, `docs/Z15_SELINUX_PLAIN_PARK_2026-08-23.md`.

**This file supersedes** `docs/NEXT_SESSION_2026-08-24.md` (GBOOT-as-next-fire is stale).

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` only. Do not leave. No live git except checkpoints. Do not push unless asked.  
**Binary:** `ghostlock-cph2521` **214880** bytes (ZI BSS-lock build, 2026-08-29 ~11:49). Rebuild `.\build_cph2521.ps1` (NDK r27d) if the tree moved.  
**Git tip:** `ea1e73f` docs: CPH2521 progress + guidance ask posted on JoinChang#31. Working tree has **uncommitted** `src/core/fops.c` + `src/core/main.c` + runners + tools — that *is* the lab binary.

---

## One-sentence status

Park is product. Leaf-NULL unhooks kernel ROOTGUARD. Child `uid 0` lived ~2 min when StdSP was disabled (Z33). Usable/persistent root is **not** done. ColorOS 15s dialog is userspace; turning it off already happened for StdSP and did **not** yield an ADB root shell. Do **not** fire ZI-as-routed. Do **not** fire on a boot ≲ 2 min.

---

## ColorOS popup (operator asked 2026-08-29)

**Tried:** `pm disable-user com.oplus.stdsp` as uid 2000 (Z33). Popup gone; child uid0 WIN; silent reboot ~2 min later. Self-cred of adbd still popped even with StdSP off (Z34, boot reason `malicious_app_try_to_root_devices`).

**Not tried:** ColorOS Settings anti-tamper toggle.

**Would a Settings mute “reach root”?** No by itself. Full answer: `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`.

---

## Policy (do not violate)

- No second GhostLock after **any** successful walk (Z5 park; later oracle+park **second process also KP**). Even if the process died and `enforce=0` persists.
- No 8-byte NULL into `selinux_state` (**Z14**).
- No spray after park. No wrap `ffffff87/88/89` → P0 (**Z23, Z28**).
- One data punch after park (**Z26** third walk KP).
- Unix **LF** runners only (`gl_run_*.sh`). **No** `fire_mode.ps1` (CRLF).
- No kptr VALUE `0xffffff8100000000` (**Z44**).
- No GBOOT punch to the **module VA** (**Z47** RO, `STRICT_MODULE_RWX`).
- Do not fire on boots ≲ 2 min (Z21, post-KP young boot).
- After **kernel panic / softboot: WiFi ADB `192.168.1.108:5555` first** (USB `596666e9` often dies). Do not USB-PnP. Dual USB+WiFi → `error: closed`; use **one** transport.
- After clean `adb reboot` / ColorOS 15s: USB usually returns; 5555 dead until Shizuku.
- No `logcat -c` if capturing popups.
- **Do not retry `MODE4_ZI` ZERO_NAME as currently routed** (both spray-lock and BSS-lock KP at `pselect place`; ION never ran).
- T1 `MODE4_NULL_STORE` with `tree_pc=0` is banned. Use **LEAF-NULL** (`parent=target-8`, left=right=0).
- Do not open swapped ashmem (N13/N14). Do not in-process llseek-null repair after swap.
- JoinChang #31: posted `docs/ISSUE31_UPDATE_2026-08-28.md` as comment `5456301814`. **No further owner reply.** Do not spam.

---

## Device last seen (do not fire until settled)

After ZI-2 KP (`zi_3c325838_bss_kp.txt`): boot **`34b02354`**, young (~50s), ADB flaky. Host copies under `logs/aarif_pull/`. Device console often `/data/local/tmp/hookcred_console.txt` or `zi_console.txt`. Push binary to `/data/local/tmp/gl_uid0` (not `ghostlock-cph2521` — Permission denied).

| | |
|--|--|
| WiFi | `192.168.1.2:5555` Shizuku (was `192.168.1.108`) — **use after softboot/KP** |
| USB | `596666e9` — classify/fire after clean reboot if 5555 is down |
| Host adb | WinGet `platform-tools\adb.exe` (not Desktop platform-tools) |

---

## Scoreboard (keep)

| Piece | Status | Evidence |
|-------|--------|----------|
| Compact waiter words 0–9, shift=0 | Works | JoinChang 5.10 + CPH |
| P0 data AAW | Works | boot_id write-proof |
| Spray-free SLIDE KASLR leak | Works | O29–O32 LANDED even at 4h uptime |
| Durable SELinux Permissive park | **Product** | Z15 PLAIN-STORE `*selinux_state=P0(0x02BB0000)`; Z50/Z51 |
| SWAP_NOCFI, never open | Survives | N3/N5; N15 HOLD `fake_fops=ffffff8048240100` when snitch is `ffffff80` |
| Swap clobbers `fake_fops+8` llseek | Always | `change_child` |
| Leaf-NULL `*sys_exit.funcs=0` | Lives | hookcred `pselect ret=5` (bbf055c4, 24c41c5a, 49f54684) |
| User-PMU `pmu8_user_xk` x28 leak under Enforcing | Works | 24c41c5a `x28n=256/256` |
| Child uid 0 ~2 min, no 15s popup | **Yes** | Z33 `UID0 WIN child is root` |
| Parent `getuid()==0` logged | **Unconfirmed** | 24c41c5a walk ret=5, console truncated |
| Usable / KSU / persist | **No** | MAC `setenforce` errno 13; UMH dead |
| ZI ZERO→ION | **KP ×2** | `zi_7239f288_kp.txt`, `zi_3c325838_bss_kp.txt` |

---

## Next fire (fresh boot, uptime ≳ 2 min, **one** process)

**Not ZI.** Pick **one**:

### A — Operator Settings mute (only if they find a toggle)

Then Z33 geometry, Unix LF:

```
# gl_run_uid0.sh (park + cred). StdSP should already be disabled-user.
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8
MODE4_SWAP_NOCFI=1 MODE4_UID0=1
KPHYS=0xa8000000 CORE_SEL=7
```

Success for this experiment: child `/proc/pid/status` Uid 0 **and** the boot still answers ADB after **>3 min**. Persist must run in the **child** (current WIN persist is gated on `self_uid==0`).

### B — Hookcred (kernel ROOTGUARD off, then self cred)

```
# gl_run_hookcred.sh
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 MODE4_NULL_STORE=1 MODE4_SWAP_NOCFI=1 MODE4_UID0=1
SLIDE_P0_TARGET=0xffffff802a950700 DATAONLY_TARGET=0x2950700
KPHYS=0xa8000000 CORE_SEL=7
```

**Fix before firing:** `uid0_mute_coloros()` is skipped on this path (`goto uid0_cred_punch`). Call it (or pre-disable StdSP on host) **before** the cred punch. Flush `getuid_after_store` to a file **before** anything else (console has died after `ret=5` twice).

### C — Best primitive (kR/W): spray-free SLIDE then SWAP_HOLD, never open

```
# 1) gl_run_slide.sh  → decode tools/slide_decode.py
# 2) same boot? NO — second process after a successful walk KPs.
#    Same process MODE4_ROOT two-phase, or fresh boot with KASLR_SLIDE=
# gl_run_swap.sh needs a live slide; current file has a stale KASLR_SLIDE.
MODE4_SLIDE_SWAP=1 KASLR_SLIDE=<decoded> MODE4_SWAP_NOCFI=1 MODE4_SWAP_HOLD=1
```

Then **first configfs pwrite on an ashmem fd opened before the swap** (JoinChang #31 Q3 — never landed). Repair llseek via that write. Do not `open()` after swap. Do not second GhostLock.

---

## Offsets cheat (CPH2521)

| Symbol | Image off | P0 |
|--------|-----------|-----|
| `selinux_state` | `0x02A793C8` | `ffffff802aa793c8` |
| `init_task` | `0x027CC000` | `ffffff802a7cc000` |
| `init_task+0x878` lock | | `ffffff802a7cc878` |
| `init_cred` | `0x027E0BE0` | `ffffff802a7e0be0` |
| `bss_tail` lock | `0x02BB9D00` | `ffffff802abb9d00` |
| PLAIN value | `0x02BB0000` | `ffffff802abb0000` |
| `ashmem_misc.fops` | `0x0291A8E8` | `ffffff802a91a8e8` |
| `__tracepoint_sys_exit` | `0x29506c0` | |
| `.funcs` (+0x40) | `0x2950700` | `ffffff802a950700` |
| `swapper_pg_dir` | | `ffffff802a491000` |
| KIMAGE | `0xffffffc008000000` | |
| KPHYS | `0xa8000000` delta `0x28000000` | |
| RAM | 12GB (`0x2c0000000`), phys_offset `0x80000000` | |
| task `real_cred` / `cred` / `comm` | `0x778` / `0x780` / `0x790` | |

`PSELECT_WAITER_WORD_SHIFT=0`. Compact words `{0,tree_pc} {1,tree_r} {2,tree_l} {6,task} {7,lock} {8,prio} {9,deadline}`.

---

## Do not reopen

ION / PAD3 / dual-PI / `MODE4_ROOT` this cycle unless C is chosen with HOLD / JoinChang 6.12 `.write_iter` on 5.10 / 8-byte NULL `selinux_state` / wrap to P0 / kptr DRAM VALUE / module-VA GBOOT / second GhostLock / ZI ZERO_NAME as routed / T1 `tree_pc=0` / sprayed oracle (young-boot O26–O28 KP).

---

## Logs / tools (gitignored under `logs/aarif_pull/`)

Z33 WIN, Z34 self-cred popup, hookcred `24c41c5a` / `49f54684` / `b9dc91de`, ZI KP `zi_7239f288_kp.txt` `zi_3c325838_bss_kp.txt`.  
Tools (untracked): `tools/ptrace_*.c`, `tools/enf_*.c`, `tools/kgsl_leak.c`. Park-safe probes, not a second GhostLock.
