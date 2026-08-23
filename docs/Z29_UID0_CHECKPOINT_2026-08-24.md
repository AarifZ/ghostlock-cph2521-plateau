# Checkpoint — CPH2521 uid0 path + ColorOS 15s kill (2026-08-24)

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` (do not leave)  
**Git tip at start of this cycle:** `6f47999` `Z15: durable SELinux Permissive park`  
**Binary:** `ghostlock-cph2521` **193072 bytes** (built 2026-08-24 ~00:58, then 193072 no-wrap Z29)  
**Device:** OPPO Reno 10 Pro+ **CPH2521** / OP56D3L1 / `5.10.236-android12-9-o-g74d132f4467a` locked BL  
**Pickup file:** `docs/NEXT_SESSION_2026-08-24.md`

---

## ColorOS “Security warning” (user screenshot)

**File:** `logs/aarif_pull/Z29_coloros_security_warning.jpg`  
**Original:** `C:\Users\LENOVO\Downloads\Screenshot_2026-08-24-01-00-41-46_bbcac0db4b62a7ada9c32b2fb09e1801.jpg`  
**When:** 2026-08-24 **01:00** local. Shizuku 13.6 (adb) visible behind the dialog.

Exact UI copy:

> **Security warning**  
> An attempt by a malicious app to damage the system has been stopped. For security purposes, your device will restart in **15 seconds**.  
> **Got it**

**What this is:** ColorOS / OPLUS userspace anti-tamper (same family as Z14 `OplusCfThread` SIGKILL `system_server`). **Not a kernel panic.** Kernel + UI are still up; ColorOS has decided the boot is compromised and forces a restart.

**What it explains:** many post-park “SOFTBOOTs” after `pselect ret=5` + `enforce=0` were **this 15s reboot**, not a cred-walk KP. Classify:

| Symptom | Meaning |
|---------|---------|
| `pselect pre-select +1–10ms` then ADB gone | real punch KP / kernel SOFTBOOT |
| `pselect ret=5` `enforce=0` then phone reboots ~15s later with this dialog | **park/cred lived; ColorOS killed the boot** |
| Screen off, adbd alive, `getpeercon` / SID flood in dmesg | Z14-style `initialized=0` (8-byte NULL into `selinux_state`) — do not repeat |

Do **not** treat the 15s dialog as proof that `init_cred` or x28 was wrong. It is an **userspace watchdog** after Permissive (and/or packet_socket / cred touch). `id` still `u:r:shell:s0` under park; ColorOS still notices.

---

## Product that works (keep)

**SELinux Permissive park (Z15, reproduced Z19–Z27, Z29):**

- **No heap spray.** Overlay BSS.
- W1 only-left PLAIN-STORE: `*selinux_state = P0(0x02BB0000)`  
  `0x02A793C8` = `&selinux_state` packed bools: disabled, **enforcing**, checkreqprot, **initialized**.  
  PLAIN-STORE keeps `initialized≠0`. **Never 8-byte NULL** (Z4/Z14 delayed death).
- Stack: `task=P0(init_task)=ffffff802a7cc000` `lock=P0(init_task+0x878)=ffffff802a7cc878` for W1.  
  Cred W2: `lock=P0(bss_tail)=ffffff802abb9d00` (W1 lock is dirty after park).
- `pselect ret=5` `enf_wrote=1` `getenforce=Permissive` `id` still `u:r:shell:s0`.

Fire (Unix **LF** runner, **not** `fire_mode.ps1` CRLF):

```
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8
MODE4_SWAP_NOCFI=1 MODE4_UID0=1
```

Host adb: WinGet `platform-tools\adb.exe`. WiFi `192.168.1.108:5555` Shizuku. USB serial **`596666e9`** when 5555 is dead. After ColorOS 15s reboot, 5555 is dead until Shizuku; USB is enough to fire. Force-stop Shizuku if 5555 wedged. **No USB PnP thrash.**

---

## uid0 gap (not closed)

**Leak:** after park, `armv8_pmuv3` **type=8** `inst_retired` (not `PERF_TYPE_HARDWARE`, errno 95). **x28** is per-task, 64-aligned, 256/256 votes. Parent ≠ child.

**Z26 comm canary:** `*(x28+0x790) = BSS marker` changed `/proc/child/comm` from `gl_uid0_child` to a NUL-prefixed blob (`task_comm=0x790`). That object **is `task_struct`**.

**Offsets (STRUCT_OFFSETS_5_10, Image-verified):**  
`real_cred=0x778` `cred=0x780` `comm=0x790` `pid=0x5C8`  
`init_cred` P0 `ffffff802a7e0be0` `init_user_ns` `ffffffc00a7df7f8` / P0 `ffffff802a7df7f8`

**VALUE:** `init_cred` (Z25/Z27/Z29 walks **lived**). BSS-zero cred (Z22/Z24) walked then **panicked** (`user_ns=NULL`). Z17 `init_cred` pre-select KP was **dirty W1 lock**; BSS-tail lock is OK.

**One data punch after park.** W1 park + W2 store lives. **W3 (second cred/comm follow-up) pre-select KP (Z26).**

**uid still 2000.** After `*(task+0x780)=init_cred`: `status_uid=2000` (status uses **real_cred** +0x778), child `getuid` pipe **9999** (child never answers `C`). Parent `getuid_after_store=2000` if we punched the child.

RAM: `MemTotal ≈ 11485536 kB` → round **12GB** (`0x2c0000000`). Direct map is 64GB (`ffffff80`…); x28 often `ffffff87/88/89`.

---

## Scoreboard (2026-08-23 night → 2026-08-24)

| Tag | What | Result |
|-----|------|--------|
| Z15 | PLAIN-STORE park | **product park** `enforce=0` stays up |
| Z17 | VALUE=`init_cred`, dirty lock | pre-select KP |
| Z18 | BSS-zero cred, shared perf VA | W2 lived, uid=2000 |
| Z19 | unique-set perf (SW clock) | 1-vote noise punch, uid=2000 |
| Z20 | HW PMU type=8, skip punch | park + leak_probe; **x28 unique** |
| Z21 | young boot ~39s | park pre-select SOFTBOOT |
| Z22 | BSS-zero into high x28+cred | W2 lived, then death |
| Z23 | nibble-strip `ffffff87`→`ffffff80` | pre-select KP |
| Z24 | BSS-zero `real_cred` | W2 lived, then death |
| Z25 | `init_cred` into high x28+cred | **W2 lived, park held**, uid=2000, getuid=9999 |
| Z26 | comm canary then cred W3 | **comm HIT**; W3 pre-select KP |
| Z27 | one-shot `init_cred` cred | W2 lived, park held, uid=2000 |
| Z28 | **wrap** high→`ffffff81` | **pre-select KP — never wrap** |
| Z29 | child x28 already P0 + cred | W2 lived, uid=2000, getuid=9999 |
| popup | ColorOS 15s restart | userspace kill after park, not KP |

Logs: `logs/aarif_pull/Z15_plain_console.txt` … `Z29_cred_console.txt`, screenshot above.  
`tools/leak_probe.c` — park-safe PMU probe (not GhostLock).

---

## Do not re-open / do not repeat

- Second GhostLock process on a park boot (**Z5**)
- 8-byte NULL into `selinux_state` (**Z14**)
- Spray overlay after park (**Z16**) or as W1 lock (**Z9–Z13**)
- `fire_mode.ps1` CRLF runners (Permission denied) — Unix LF `printf` / `gl_run_uid0.sh`
- `PERF_TYPE_HARDWARE` (95) — use sysfs type **8**
- Wrap/nibble-strip high alias to P0 (**Z23, Z28**)
- BSS-zero as `struct cred` (**Z22, Z24**)
- Second pselect data walk after park (**Z26 W3**)
- Swapped ashmem / ION / PAD3 / dual-PI
- GitHub JoinChang #31 follow-up unless user asks
- Live git spam — commit breakthroughs/checkpoints only; **do not push** unless asked

---

## Next fire (fresh boot, one process, uptime ≳ 2 min)

Same env as park. **One** cred-class store after W1:

1. Prefer **parent x28 if it is already `ffffff80`… in the 16GB P0 window** (Z27 saw `ffffff8035583780`) → `getuid()` in-process.  
2. Else **child raw x28** (high alias OK).  
3. Store **`*(task+0x778)=init_cred` (`real_cred`)** so `/proc/pid/status` Uid can move without the child pipe. (Z29 wrote **cred** `+0x780`; status stayed 2000.)  
4. Do **not** wrap. Do **not** W3.  
5. If ColorOS 15s dialog appears: park/cred **survived the kernel**; log it, do not “fix” the walk.

Stop: two pre-select SOFTBOOTs in a row; phone hot.

---

## Offsets cheat (CPH2521)

| Symbol | Image off | P0 |
|--------|-----------|-----|
| `selinux_state` | `0x02A793C8` | `ffffff802aa793c8` |
| `init_task` | `0x027CC000` | `ffffff802a7cc000` |
| `init_task+0x878` lock | | `ffffff802a7cc878` |
| `init_cred` | `0x027E0BE0` | `ffffff802a7e0be0` |
| `init_user_ns` | `0x027DF7F8` | `ffffff802a7df7f8` |
| `bss_tail` lock | `0x02BB9D00` | `ffffff802abb9d00` |
| PLAIN value | `0x02BB0000` | `ffffff802abb0000` |
| KIMAGE | `0xffffffc008000000` | |
| KPHYS | `0xa8000000` delta `0x28000000` | |
| KASLR | slide **0** on this device (P0 math) | |

`PSELECT_WAITER_WORD_SHIFT=0` in `build_cph2521.ps1`. NDK r27d.

---

## Uncommitted at handoff (must be in the next binary)

Working tree vs `6f47999`:

```
M  src/core/main.c     x28 PMU leak, uid0_cred_walk, no wrap, init_cred VALUE
M  src/core/fops.c     SLIDE_CRED VALUE=init_cred, BSS tail lock
M  ghostlock-cph2521
?? tools/leak_probe.c
?? gl_run_uid0.sh
?? docs/NEXT_SESSION_2026-08-24.md
?? docs/Z29_UID0_CHECKPOINT_2026-08-24.md
```

`util.c` `MODE4_UID0` fills `g_cred_copy` only on spray; spray is skipped so VALUE is `init_cred` (correct).
