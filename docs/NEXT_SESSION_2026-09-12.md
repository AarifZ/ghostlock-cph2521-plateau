# Next session pickup — 2026-09-12

**Read first:** this file, then `docs/GLM_HANDOFF_PICKUP_2026-09-12.md`, then `docs/HANDOFF_2026-09-12.md`. ColorOS popup answer is still `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`. Older 08-29 / 09-01 files are background, not next-fire.

**This file supersedes** `docs/NEXT_SESSION_2026-08-29.md` and the 09-01 “chain complete / 3 ranked experiments” tip (`743669e`).

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` only. Remote for this lab: `plateau` = `https://github.com/AarifZ/ghostlock-cph2521-plateau.git`. Do **not** push to `origin` (JoinChang) unless the operator asks.  
**Binary:** `ghostlock-cph2521` **226752** bytes. HOST_MD5 `46c058e3269e9d1a9fd8384f84cb0aea`. Push as `/data/local/tmp/gl_uid0` (not `ghostlock-cph2521` — Permission denied). Rebuild `.\build_cph2521.ps1` (NDK r27d).  
**Host adb:** workspace `adb_local.exe` (this session). WinGet `platform-tools\adb.exe` also fine. Desktop `platform-tools\adb.exe` is silent. Always `-s 192.168.1.2:5555` for shell/push/exploit.

---

## One-sentence status

Park is still product. Exact Z33 (park + high-alias child `+0x780`) **kernel-panicked** on 2026-09-12. `ROOTED` 25 NUL bytes is **not** a win. Usable/persistent root is not done. Next fire is **not** a blind Z33 retry. Recommended: **code a self-only gate, then same-process hookcred**. Do not fire ZI. Do not fire two GhostLock processes.

---

## Device last classified (2026-09-12 ~18:02 IST)

After Exact Z33 KP. **Re-classify before any fire** (`boot_id`, `uptime`, `getenforce`, `id`). Do not assume this boot is still live.

| | |
|--|--|
| Device | OPPO Reno 10 Pro+ CPH2521, slot `_b`, ColorOS 16.0.5.1002 EX01, locked BL |
| Kernel | `5.10.236-android12-9-o-g74d132f4467a` |
| Boot | `c2773f39-2b31-489a-b735-22af25bd7622` |
| Uptime then | ~224 s (settled). Enforcing. uid 2000 |
| Boot reason | `reboot` (not `malicious_app`) |
| StdSP | `pm list packages -d` still has `com.oplus.stdsp` |
| Walk on that boot | **none** (park died in the KP). A fire was allowed after settle |
| ADB | USB `596666e9` **and** WiFi `192.168.1.2:5555` were both `device` — drop USB before fire |

USB is **bootstrap only**: `adb -s 596666e9 tcpip 5555` then `adb connect 192.168.1.2:5555`. All exploit/push/shell on WiFi. Dual transports → `error: closed`. Watcher: `watch_adb_wifi.ps1` (FAILED only if both down >10 min; then need user / Shizuku / cable). Clean-reboot wait 2–3 min is enough. Do not fire ≲ 2 min (Z21).

---

## What happened this session (do not re-litigate)

### Exact Z33 fire (operator picked “1” then “Exact Z33”)

Runner `gl_run_parkchild.sh`: same-process W1 PLAIN park, W2 child cred, `UID0_PREFER_CHILD=1`, slot `+0x780`, no wrap.

- Binary pushed as `/data/local/tmp/gx693197935` (random name; `/data/local/tmp/gl_uid0` is the usual).
- Boot **`c5ad8ad0`**. Park landed (`ENF=0`).
- `self_x28=ffffff89c23e0000/252` (high alias, not used).
- `child_x28=ffffff88bb2ca500/114` `who=child_x28` (not `child_x28_p0`).
- Store: `*ffffff88bb2cac80 = ffffff802a7e0be0` (`init_cred`), PLAIN only-left.
- Stamp: `lock=ffffff802abb9d00` (bss_tail), `task=ffffff802a7cc000`, `prio=3`.
- Log ends: `pselect pre-select +2ms` then NULs. Kernel panic. New boot `c2773f39`.

Log: `logs/Z33_parkchild.txt` (also pulled as `logs/aarif_pull/Z33_parkchild_c5ad8ad0.txt`).

```
UID0 store child_cred slot=ffffff88bb2cac80 val=ffffff802a7e0be0
stack SLIDE_CRED PLAIN only-left: *ffffff88bb2cac80 = ffffff802a7e0be0 (init_cred) ...
pselect place tree=ffffff802a7e0be0 ... lock=ffffff802abb9d00 prio=0000000000000003
pselect pre-select +2ms
```

### `ROOTED` is not root

| File | After KP reboot |
|------|-----------------|
| `/data/local/tmp/ROOTED` | 25 **NUL** bytes, `root:root`, 0666. Not ASCII `uid=… status=…` |
| `/data/local/tmp/uid0_id.txt` | 0 bytes, uid 0, **gid `3140267136` = `0xBB2CA500`** (low 32 of that child x28) |
| `UID0 WIN` line | **absent** (log truncated at pre-select) |

Same messy pointer-bit gid shape as the original Z33 WIN (`suid`/`gid` leftover pointer bits). Crash debris. Do not call this a living uid0 shell.

Original Z33 (2026-08-24) **did** log `UID0 WIN child is root` with `who=child_x28` (also high alias) for ~2 min, then silent reboot. This retry of that geometry KPd in the walk. Blind retry = reboot-budget coin flip.

### P0-only child gate (same session, earlier)

Operator first landed on a P0-only HOLD (`gx744299392`, boot `3cee7fb6`, child `ffffff899400ca00`) that **never punched**. They then chose Exact Z33 (punch even if `ffffff88/89`). That punch KPd.

### JoinChang stock clone (same session)

Tree: `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-joinchang-stock`. Binary `/data/local/tmp/a/e`. **Do not grep that path** (pattern pipe can exec it).

- README lists CPH as offsets-extracted / feasible, **not** verified working.
- Path A (mode=4 fops swap): `pselect success=0` `step=33`.
- Path B W1: `success=0`. Path B W1 is **banned here** (8-byte `selinux_state`, Z4/Z14).
- Do not graft ROOTGUARD unhook onto Path B W1+W2 (that is three walks). Steal `pipe_physrw` only after a **living** swap.

### Hookcred this session

**Not fired.** Mute skip on `MODE4_NULL_STORE` **is already fixed** in `uid0_cred_walk()` (calls `uid0_mute_coloros()` before the punch). Proof flush on `getuid()==0` is in `fops.c`.

**Trap:** `gl_run_hookcred.sh` does **not** set `UID0_PREFER_CHILD`, but `uid0_cred_punch` still forks a child and, when self x28 is not P0, **falls through to the child**. On this phone self is typically `ffffff89`. That W2 is the same high-alias child punch that just KPd, after a different W1. **Do not fire hookcred until a self-only gate exists.**

---

## Policy (do not violate)

- No second GhostLock after **any** successful walk (Z5). `gl_run_chain.sh` is P1 then P2 — **do not run P2** if P1’s walk lived.
- No 8-byte NULL into `selinux_state` (Z14). No JoinChang Path B W1.
- No wrap `ffffff87/88/89` → P0 (Z23, Z28). Logged wrap `ffffff807b2ca500` must stay unused.
- One data punch after park (Z26 W3 KP). Child `LANDING_RETRY` default is **1**.
- Unix LF `gl_run_*.sh` only. No `fire_mode.ps1`.
- No kptr VALUE `0xffffff8100000000` (Z44). No GBOOT to **module VA** (Z47).
- No fire ≲ 2 min. No ZI as routed. No T1 `tree_pc=0`.
- No `MODE4_CRED_RIGHT` unless you are repeating the GLM 08-31 experiment (KPd 4/4, chains V–Y). Default cred shape is **PLAIN only-left** (Z25/Z27/Z29/Z33).
- JoinChang #31: already commented. Do not spam.
- PowerShell: quote remote `$(...)`. Never grep `/data/local/tmp/a/e`.
- Research only; this is the operator’s phone.

---

## Scoreboard (keep)

| Piece | Status | Evidence |
|-------|--------|----------|
| Compact waiter words 0–9, shift=0 | Works | JoinChang 5.10 + CPH |
| P0 data AAW | Works | boot_id write-proof |
| Spray-free SLIDE | Works | O29–O32 |
| Durable SELinux park | **Product** | Z15; this session W1 also landed |
| SWAP_NOCFI never-open | Survives | N3/N5/N15 |
| Swap clobbers `fake_fops+8` | Always | `change_child` |
| Leaf-NULL `*sys_exit.funcs=0` | Lives | hookcred ret=5 (24c41c5a, …) |
| User-PMU x28 under Enforcing | Works | this fire 252/252 self, 114/114 child |
| Child uid 0 ~2 min | **Yes once** | Z33 08-24. **09-12 retry KP** |
| Parent `getuid()==0` | **Unconfirmed** | never a durable on-disk `getuid_after_store=0` |
| Usable / KSU / persist | **No** | |
| JoinChang Path A on this phone | Miss | success=0 step=33 |
| Exact Z33 high-alias child `+0x780` | **KP 09-12** | `c5ad8ad0` pre-select +2ms |
| ZI ZERO_NAME | **Banned** | KP ×2 |

Offsets cheat: still the table in `docs/NEXT_SESSION_2026-08-29.md`. Cred: `/proc` Uid follows **real_cred** (`+0x778` in one table, `+0x780` in the 08-30 canary comment). Subjective `getuid()` is the qword before `comm` (`+0x788` per `util.c`). Z33 WIN was **status** Uid 0 with parent `getuid` 2000. Slot env: `UID0_SLOT`. Sweep: `{0x780, 0x788, 0x778, …}` with child retry=1 so sweep barely runs.

---

## Next fire (uptime ≳ 2 min, **one** process, one transport)

Operator asked for the plan, then handed off **before picking A/B/C**. Do not invent a fire.

### A — Hookcred, self-only (recommended)

1. **Code first.** Punch `self` only. No child fallback when self x28 is `ffffff87/88/89`. Optional: `UID0_PREFER_SELF=1` / refuse child unless `UID0_PREFER_CHILD`.
2. Rebuild, push `/data/local/tmp/gl_uid0`.
3. Disconnect USB from `adb devices` (or ignore it: never `-s 596666e9` for the fire).
4. `gl_run_hookcred.sh` via `adb -s 192.168.1.2:5555` `setsid`/`nohup`.
5. Success: on-disk `getuid_after_store=0` **and** ADB up after 3+ min. Fail: W2 miss → hook off, still uid 2000, **no second process**.

High-alias **self** punches historically **missed** (CapEff stayed 0), they did not panic. High-alias **child** just panicked. That is why the gate matters.

StdSP is already disabled-user. Mute is already called on this path.

### B — Retry Exact Z33

`gl_run_parkchild.sh` as-is. One 08-24 WIN, one 09-12 KP. Only if the operator wants to spend another reboot on the same stamp.

### C — Park-only

`gl_run_holdpark.sh` / `gl_run_park.sh`. Durable Permissive. Not uid 0.

### Not this cycle unless operator names it

- `gl_run_chain.sh` (two processes).
- `gl_run_root.sh` / `MODE4_ROOT` sprayed swap (young-boot / spray KP history).
- JoinChang Path B. Wrap to P0. ZI. GBOOT module VA.

kR/W still the product gap: pre-open ashmem fd → swap HOLD → first configfs pwrite on **that** fd (JoinChang #31 Q3). Never landed.

---

## Code in this tree vs `743669e`

| File | What |
|------|------|
| `src/core/fops.c` | Cred default PLAIN only-left; `MODE4_CRED_RIGHT=1` for GLM only-right. Child landing retry default **1**, self **2**. Proof file if `getuid()==0`. |
| `src/core/main.c` | `UID0_PREFER_CHILD`; child auto-G on status Uid 0 / `uid0_go`; write `ROOTED`; `uid0_go` on child-only WIN; `UID0_SLOT`. |
| `src/core/util.c` | Slot candidates `0x780,0x788,0x778,…`; self query uses `getuid()`. |
| `gl_run_parkchild.sh` | Exact Z33 runner. |
| `gl_run_hookcred.sh` | Same-process leaf-NULL + cred (**needs self-only gate**). |
| `gl_run_chain.sh` | **Two-process — do not use after a live W1.** |
| `watch_adb_wifi.ps1` | WiFi keep-alive. |

---

## Do not reopen

ION / PAD3 / dual-PI / sprayed young-boot oracle / 8-byte NULL selinux / wrap to P0 / kptr DRAM VALUE / module-VA GBOOT / second GhostLock / ZI / T1 `tree_pc=0` / opening swapped ashmem / in-process llseek repair / `MODE4_CRED_RIGHT` as the default.
