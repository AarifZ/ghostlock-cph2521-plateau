# GhostLock CPH2521 — full session context

**Date saved:** 2026-08-09 (redirect note 2026-08-16)  
**Purpose:** Resume after token budget / context loss. Single source of truth for state, policy, scoreboard, env flags, and next moves.  
**Do not change default plateau** on `main` / consumer path. Research is opt-in env only.

**2026-08-16 port study redirect:** see `docs/PORT_STUDY_AND_REDIRECT_2026-08-16.md`.  
Thesis: stop CHAIN/ZERO_NAME as primary; prove 5.10 aristotle only-left store with write-proof first; cfi22 = swap not applied.

---

## 1. Target

| Field | Value |
|-------|--------|
| Device | Oppo Reno 10 Pro+ **CPH2521** |
| Kernel | **5.10.236** (Android 12 build, locked bootloader) |
| CVE / name | GhostLock (**CVE-2026-43499**) |
| Goal | fops write → **uid0** |
| Plateau definition of success today | `success=1`, **cfi errno=22**, process **ALIVE** (no fops redirect yet) |
| Breakthrough definition | **cfi ≠ 22** (real write path) then uid0 |

Workspace:  
`C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus\`

Binary: `ghostlock-cph2521` (~132–133 KB)

---

## 2. Exploit chain (what we control)

1. **Three-futex EDEADLK (−35)** primes UAF on `pi_blocked_on` / waiter.
2. **pselect reclaim** overlays forged `rt_mutex_waiter` (stack words via shift).
3. **sched_setattr (setprio)** → `rt_mutex_adjust_pi` → **`adjust_prio_chain`**.
4. Inside chain (Linux 5.10):  
   **`dequeue` (`rb_erase`) → update prio → `enqueue` (re-walk tree)**.
5. Write primitive = **`rb_erase` only-right / leaf / root** stores into forged tree geometry.
6. Desired end state: **`*ashmem_misc.fops = fake_fops`** (or direct fops slot write), then CFI punch write succeeds (not errno 22), escalate.

**CPH2521 shift:** `PSELECT_SHIFT=-2` (measured; shift=0 softboots at overlay).

---

## 3. Hard policies (LOCKED — do not violate)

### ADB / USB
- **No USB PnP thrash**, no host-controller “power cycle”, no MTP disable/enable spam.
- ADB recover: **`adb kill-server` + `adb start-server` only**, then **manual replug** if empty.
- Softboot / stale ADB / spray hang → when shell returns: **`adb reboot`** for clean boot (prefer `post_softboot_hardboot.ps1`). Must see **new `boot_id`**.
- Fire only when: shell OK, `boot_completed=1`, **uptime ≲ 45–60s**, preferably fresh `boot_id`.
- `FOPS_MAX_ATTEMPTS=4` default on research fires (avoid 12× spray grind).

### Softboot vs ADB drop (detection bug fixed)
- **ADB drop ≠ softboot.** Shell can die while **same `boot_id`** continues.
- Truth: **`/proc/sys/kernel/random/boot_id`** change = real reboot/softboot class event.
- Stage truth: **`PROOF` lines** in durable stage log (`stage.txt` / `ghostlock_logs`).
- Earlier “3/3 softboot” on ZERO_NAME was **wrong** (ADB stale); re-fire showed **post_setattr + cfi22 + same boot**.

### Default binary path
- **No research env flags** = plateau packing (inert / survive → cfi22). Never break that as default.
- All breakthrough stamps are **opt-in** `MODE4_*` env flags.

---

## 4. Git / branches

| Branch / remote | Notes |
|-----------------|--------|
| `main` @ `10b8a50` | Plateau: restore survive→cfi errno=22 (consumer delay fix). Local may be ahead 2. |
| `research/cph2521-zero-name-standalone` @ `9d06f31` | **Current worktree** — MODE4_CHAIN + ZERO_NAME path |
| Remote push | Standalone orphan history to `https://github.com/AarifZ/ghostlock-cph2521-plateau` branch `research/cph2521-zero-name-write-path-2026-08-09` (commits include ZERO_NAME + CHAIN). Origin main push was 403 earlier. |
| Plateau remote tracking | standalone tracks plateau research branch |

Key commits (conceptual):
- Plateau restore: consumer delay / inert stamp ALIVE cfi22
- ZERO_NAME + proof markers + write-path map
- `MODE4_CHAIN`: same-process phase1 ZERO_NAME then phase2 ION_SAFE

---

## 5. Scoreboard (facts as of last clean fires)

| Path | Survive setprio? | Stage last | cfi | Notes |
|------|------------------|------------|-----|--------|
| **Plateau default** | yes | full route | **22** | ALIVE; no redirect |
| **MODE4_ZERO_NAME** | **YES (confirmed)** | `post_setattr ret=0` → cfi22 → route return | **22** (expected) | Leaf parent=MISC−16 → **`*name=0`** |
| Classic parent=MISC−8 + erase | **no** | `pre_setattr` only | — | Softboot in setprio / erase |
| Classic NO_CONSUMER / PRIO_MATCH | yes | no erase | 22 | Proves erase geometry is the killer |
| ION_ROOT | no / no erase | often no write | — | wait_lock at name≠0 blocks |
| ION_SAFE (after ZERO, separate fire) | **no** (so far) | `pre_setattr` only | — | Softboot |
| MODE4_CHAIN phase1 | flaky | sometimes full ZERO, once died pre only | — | After successful ZERO, CHAIN re-fire softbooted at phase1 |
| MODE4_CHAIN phase2 | never reached live | — | — | Need phase1 survive then ION |
| ION_FOPS right=write_jt | softboot | — | — | **right must be spray**, not .text JT |
| ROOT_SPRAY right=fake_fops | softboot | — | — | re-enqueue walks fops as tree unless rb-leaf head |
| E2 / REF_LEFT / TOP_LEFT / A53 stamp | softboot class or rejected | — | — | Softboot-class stamps banned for default |

**UAF:** EDEADLK **35** reliable when chain primed.

**Not achieved:** `*MISC = fake_fops` while ALIVE; cfi≠22; uid0.

---

## 6. Best advance: ZERO_NAME

### Geometry
- `parent_color = ashmem_misc − 16` (name field; aligned `& ~3`)
- `right=0`, `left=0` → **leaf only-right/leaf erase** → `*(name) = 0`
- `prio=200`, deadline set, `LOCK_OWNER0` style owner=0 packing where applied
- Open-all FDs (same as classic open-all family)

### Why it matters
- First **surviving erase AAW** next to ashmem_misc (name slot).
- Zeros **wait_lock** used as spinlock identity at **MISC−8** for ION root erase.
- Proves softboot is **not** “any store near misc” — it is **MISC−8 parent / fops-slot geometry** and/or re-enqueue after root write.

### Confirmed stage (example from clean fire)
```
pre_setattr
post_setattr ret=0 errno=0
cfi_on_punch_enter
cfi_open_ok
cfi_write_ret=-1 errno=22
route_threads_returned
```
Same `boot_id`, full process return.

### After ZERO success, CHAIN on same boot
- CHAIN phase1 re-does ZERO geometry; stage stopped at **`pre_setattr` only** + **new boot_id** (true softboot).
- Interpretation: flaky second erase, or CHAIN packing (`FOPS_RB_LEAF` / spray) interaction, or name already 0 changing tree walk.

---

## 7. ION / CHAIN design (not proven alive)

### ION_SAFE / ION_ROOT
- `lock = MISC − 8` (waiters root pointer at that spinlock-shaped word)
- `parent=1` (null parent black), `right=fake_fops`, `left=0`
- Root erase: `*MISC = fake_fops` (desired redirect)
- **Requires** `*(u32*)(MISC−8) == 0` (ZERO_NAME first)
- ION_SAFE / CHAIN: `fake_fops[0:0x18]` prepared as **valid black rb leaf** so post-erase re-enqueue does not walk garbage

### MODE4_CHAIN (same process)
1. Phase 1: ZERO_NAME (`g_mode4_chain_phase == 1`)
2. Phase 2: ION_SAFE (`g_mode4_chain_phase == 2`)  
Same process so name-zero persists without second full softboot cycle.

Code: `src/core/fops.c` (stamp branches + chain phase), `src/core/util.c` (rb-leaf fops, prio packing).

---

## 8. Linux 5.10 source insight (why classic dies)

Source walk: `docs/KERNEL_5_10_RTMUTEX_WRITE_PATH.md`

```
adjust_prio_chain: dequeue(rb_erase) → prio update → enqueue(re-walk)
```

Failure modes seen:
1. **Classic only-right** parent=MISC−8, right=value → stores into fops path but dies in setprio (PROOF last = pre_setattr). Not just CFI after write.
2. **Root write** `*waiters = fake_fops` then enqueue walks fops as rb → die unless rb-leaf head.
3. **right = CFI JT in .text** → `rb_set_parent` into RO text → softboot.
4. **owner = fake_task|1** + become top → setprio(fake_task) softboot → prefer **LOCK_OWNER0**.
5. **owner=0** + stack becomes top → `wake_up_process(init_task)` if task stamped init_task.

ZERO_NAME avoids putting MISC−8 as parent of erased node; only zeros name leaf.

---

## 9. Env flags (research only)

| Flag | Role |
|------|------|
| `MODE4_ZERO_NAME=1` | Leaf erase `*name=0`; survive setprio |
| `MODE4_ION_SAFE=1` | Root `*MISC=fake_fops` + rb-leaf fops |
| `MODE4_ION_ROOT=1` | Same root idea (earlier naming) |
| `MODE4_CHAIN=1` | Phase1 ZERO then phase2 ION_SAFE same process |
| `MODE4_LOCK_OWNER0=1` | owner=0 packing |
| `MODE4_FOPS_RB_LEAF=1` | Explicit rb-leaf head on fake_fops |
| `MODE4_PROOF=1` | Durable PROOF markers in stage |
| `MODE4_CFI_ON_PUNCH=1` | CFI probe during punch window |
| `PSELECT_SHIFT=-2` | CPH default measured |
| `PSELECT_ROUTE_DELAY_USEC` | Consumer delay (plateau ≥100–150ms class) |
| `FOPS_MAX_ATTEMPTS=4` | Cap spray/route grind |
| Default none of MODE4_* | **Plateau** |

Softboot-class (do not use as default; research only if intentional):  
classic MISC−8 erase, E2 inverted, dual REF_LEFT, A53_STAMP, ION without zeroed wait_lock, right=.text JT.

---

## 10. Key source files

| Path | Role |
|------|------|
| `src/core/fops.c` | MODE4 stamps, ZERO/ION/CHAIN, pselect overlay |
| `src/core/util.c` | fake_fops zeroed table, rb-leaf, spray prio, LOCK_OWNER0 |
| `src/core/main.c` | EDEADLK owner path, PROOF / CFI_ON_PUNCH |
| `src/core/common.h` | `durable_proof_log`, pselect constants |
| `src/devices/cph2521/offsets.h` | Device offsets + shift note |
| `docs/KERNEL_5_10_RTMUTEX_WRITE_PATH.md` | Source map of write path |
| `docs/RESEARCH_CHECKPOINT_2026-08-09.md` | Short checkpoint |
| `docs/ADB_SOFTBOOT_RECOVERY.md` | Recovery SOP |
| `logs/OPTION2_ZERO_NAME_AND_ION_SAFE.md` | Option-2 writeup |
| `logs/ZERO_STAB_AND_CHAIN_2026-08-09.md` | Stability + CHAIN notes |
| `logs/PROOF1_WRITE_VS_ERASE.md` | Die in setprio vs after CFI |
| `post_softboot_hardboot.ps1` | Clean reboot (boot_id must change) |
| `adb_usb_recover.ps1` | Server-only recover + wait |

Durable stage on device (typical):  
`/storage/emulated/0/ghostlock_logs/stage.txt` or `/data/local/tmp/stage.txt` (confirm on fire).

---

## 11. Experiment matrix summary (letter series)

| Exp | Intent | Result class |
|-----|--------|--------------|
| Plateau / delay150 | Survive, cfi22 | ALIVE plateau |
| A53 / classic mapped | Samsung-like stamp | Rejected / softboot |
| B PI classic | PI parent MISC | Softboot / mixed |
| E / E2 | Main spray / inverted | Softboot class |
| F timeout/delay | Timing | Softboot when erase-like |
| G REF_LEFT | only-left *MISC | Softboot |
| H OWNER_UNLOCK | Unlock path | Softboot |
| I EDEADLK | Prove UAF | **35 proven** |
| J ION_ROOT | Root *MISC | No live redirect |
| L/M open-all E2 | FD packing | Softboot |
| N/N1b ION_FOPS | fops slot | Softboot (JT/right lessons) |
| O NO_CONSUMER classic | No erase | ALIVE |
| P PRIO_MATCH | Early-out adjust | ALIVE |
| Q–Y classic erase variants | Leaf/safe/nop/zeroed fops | Softboot if erase MISC−8 |
| W ROOT_SPRAY | Root to spray lock | Softboot (re-enqueue) |
| ZERO_NAME | *name=0 | **ALIVE** |
| ION_SAFE after zero | Root after name | Softboot pre_setattr |
| CHAIN | same-proc zero+ion | Phase1 flaky softboot after prior zero |

---

## 12. Session fires 2026-08-09 (post-CONTEXT / replug)

Working tree: `research/cph2521-zero-name-standalone` @ `9d06f31`, binary `ghostlock-cph2521` 132968.

### Results (boot_id + stage truth)

| Fire | Stamp | Last PROOF | boot_id | Class |
|------|--------|------------|---------|--------|
| T1 r1 | ZERO_NAME + LOCK_OWNER0 + PROOF + CFI_ON_PUNCH | **pre_setattr only** | changed | **true softboot** |
| T1 r2 | same | **pre_setattr only** | changed | **true softboot** |
| Plateau | default inert + delay 150ms + PROOF + CFI | post_setattr + **cfi errno=22** + route return | **same** | **ALIVE plateau** |
| T1 r3 | ZERO_NAME again clean boot | **pre_setattr only** | changed | **true softboot** |

**Plateau still holds.** ZERO_NAME is **not stable this session: 0/3 post_setattr, 3/3 softboot at setprio**.

Earlier session logs still show prior ZERO success (post_setattr + cfi22) — treat ZERO as **flaky / packaging-sensitive**, not banked.

### ADB note
Plateau run dropped ADB during **W1 spray KS fail loop** but **same boot_id** — ADB drop ≠ softboot. Prefer kill after fops phase when probing.

### Current device (after T1 r3 softboot)
- New boot after softboot recovery; do not fire again without hardboot + plan.
- CHAIN **not** attempted this session (ZERO must be stable first).

---

## 13. Immediate next tests (when ADB clean)

Order (few, high signal):

1. **Clean boot checklist**  
   `boot_id`, uptime≤45, push binary if needed, clear stage.

2. **T1 — ZERO_NAME only** (reconfirm)  
   ```
   MODE4_ZERO_NAME=1 MODE4_LOCK_OWNER0=1 MODE4_PROOF=1 MODE4_CFI_ON_PUNCH=1
   FOPS_MAX_ATTEMPTS=4
   ```  
   Expect: EDEADLK 35, post_setattr, cfi22, same boot_id.

3. **T2 — MODE4_CHAIN alone on fresh boot** (do not fire ZERO first)  
   Let phase1 zero then phase2 ion in one process.  
   Classify with boot_id + stage (phase markers if logged).

4. **If T1 OK and T2 dies phase1:** treat CHAIN packing (rb-leaf) as suspect; try ZERO then **separate** ION_SAFE only after confirming stage, or patch CHAIN to skip re-ZERO if already zeroed / single spray.

5. **If ION dies at pre_setattr with wait_lock supposedly 0:**  
   - Prove name still 0 (hard without read primitive)  
   - Try root right = **spray leaf not fops table** (value still need fops later)  
   - Or classic only-right with parent=MISC−8 **after** name zero (risky)  
   - Re-read Ghidra `rb_erase` + ashmem_misc layout for wait_lock vs name

6. **Do not** thrash USB; on softboot → hardboot script → clean fire only.

---

## 14. What “breakthrough” looks like in logs

```
PROOF ... post_setattr ret=0
PROOF ... cfi_write_ret=... errno=0   # or ≠22
# and/or success with uid0 / root markers
same boot_id as pre-fire
```

Partial breakthrough: post_setattr on ION/CHAIN phase2 **ALIVE** even if cfi still 22 (proves *MISC redirect path survived erase — then fix fake_fops / CFI JT).

---

## 15. Anti-goals / rejected paths

- Softboot-class stamps as new default  
- USB recover thrash  
- Claiming softboot from ADB drop alone  
- right = kernel .text JT  
- Putting MISC on main tree as walkable rb node without knowing walk  
- Burning long spray loops on high uptime after softboot  

---

## 16. Resume checklist for next agent / session

1. Read **this file** + `logs/ZERO_STAB_AND_CHAIN_2026-08-09.md` + `docs/ADB_SOFTBOOT_RECOVERY.md`  
2. `adb devices` → if empty: server restart once, then **user replug**  
3. `adb reboot` if uptime high / last event softboot  
4. Confirm branch + binary size  
5. Fire **T1 ZERO** only; log boot_id before/after + stage  
6. One CHAIN or ION_SAFE attempt; hardboot if softboot  
7. Update scoreboard in this file or `ZERO_STAB_AND_CHAIN_*.md`  

---

*End of CONTEXT.md — saved to preserve weekly token / session continuity.*
