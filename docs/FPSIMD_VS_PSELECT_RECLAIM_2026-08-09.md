# FPSIMD / rt_sigreturn reclaim vs CPH pselect (map)

**Date:** 2026-08-09  
**Context:** BuSung #160 (“pselect dead on Samsung 5.15”) + Meowkis claim that FPSIMD works on 5.10; map to CPH2521 GhostLock.

## Correction first (attribution)

| Source | What they actually use for reclaim |
|--------|-------------------------------------|
| **johnny-salz/root-my-galaxy-clean** (A53, `5.10.237`) | **`pselect`**, not FPSIMD. Full shell root + KSU live-load proven on SM-A536E. |
| **Meowkis Root-My-Galaxy-Payloads `writer`** | **`src/sigreturn.c`** + `tools/test_sigreturn_overlap.c` — **rt_sigreturn + FPSIMD** path for Samsung where pselect layout fails. |
| **Issue #160** | pselect dead on **Samsung 5.15.189**; pivot to FPSIMD. “johnny FPSIMD on 5.10” is **mis-attributed** (johnny A53 = pselect success). |

So: **5.10 can do pselect** (A53 + your CPH plateau). FPSIMD is an **alternate reclaim**, not “the 5.10 method”.

---

## Shared chain (all ports)

```text
1) UAF prime     FUTEX_CMP_REQUEUE_PI → EDEADLK (-35)
2) Waiter free   remove_waiter clears wrong pi_blocked_on
3) RECLAIM       <<< only this stage differs
4) Consumer      sched_setattr → adjust_prio_chain → rb_erase / setprio
5) AAW + CFI     fake fops / ashmem / configfs / cred
```

CPH2521 already has **1, 2, 3 (pselect), 4 (plateau)** working. Stuck on **5** (live fops redirect).

---

## Reclaim A — pselect `fd_set` (your path + A53)

### Mechanism
Large `pselect6(nfds≈320, in/out/ex, …)` copies kernel stack `fd_set` words over the freed `rt_mutex_waiter` on the waiter thread stack. Userspace controls those words.

### Geometry comparison

| | **CPH2521 (yours)** | **A53 johnny (working root)** |
|--|---------------------|-------------------------------|
| Kernel | 5.10.236 Oppo | 5.10.237 Samsung A53 |
| NFDS | 320 | 320 |
| Placement | **`PSELECT_SHIFT=-2`** waiter-word map | **No shift** (raw word indices) |
| Classic stamp | Via MODE4 + tree/task/lock fields | `write[1]=target-8`, `write[2]=value`, `ex[2]=init_task`, `ex[3]=fake_lock` |
| Default plateau | inert tree → **cfi22 ALIVE** | N/A (they go for real write) |
| A53 stamp on CPH | **SOFTBOOT** (`MODE4_A53_STAMP` rejected) | Native layout → works on A53 |

Your `fops.c` already documents A53 layout as experiment-only:

```c
/* Samsung poc.c setup_stamp (no shift):
 *   write_set[1] = target-8; write_set[2] = value;
 * This is NOT the same as our shift=-2 waiter-word map. */
```

### Why #160 fails on Samsung 5.15
Compiler stack frame for `pselect` **does not** put `fd_set` on the UAF waiter. Not “bug patched” — **reclaim miss**. 6.x often lines up; 5.15.189 Samsung does not.

### Why you should keep pselect on CPH
Plateau proves reclaim hits: `EDEADLK`, place, `post_setattr`, `success=1`, cfi22. That is the opposite of #160.

---

## Reclaim B — rt_sigreturn + FPSIMD (Meowkis writer)

Sources (fetched):  
`Meowkis/Root-My-Galaxy-Payloads@writer` → `src/sigreturn.c`, `tools/test_sigreturn_overlap.c`

### Mechanism
1. Same GhostLock UAF (waiter thread still has dangling `pi_blocked_on` into its stack).
2. Install `SA_SIGINFO` handler for `SIGUSR1` on waiter.
3. `tgkill` waiter → signal delivery builds **signal frame** with **`fpsimd_context`** (`FPSIMD_MAGIC`) holding V-reg save area.
4. Handler finds magic in `ucontext`, **`memcpy` fake waiter into `fpsimd->vregs + 0x18`** (0x58 bytes).
5. **`rt_sigreturn`** restores FPSIMD state → kernel writes Vregs back into a **stack region that overlaps the freed waiter**.
6. Arm consumer (`sched_setattr` / punch) as usual.

### Fake waiter blob (sigreturn.c)

```text
+0x00  fake_w0          (list/rb depending on layout comment)
+0x08  0
+0x10  0                (rb parent black / null parent style)
+0x18  0                rb_right
+0x20  0                rb_left
+0x28  init_task        task
+0x30  fake_lock        lock
+0x38  prio=3
+0x40..0x57 zeros
```

Overlap test expects panic markers if consumer walks forged `lock`/`task` (proof of overlap, not root).

### Pros vs pselect
| | FPSIMD | pselect |
|--|--------|---------|
| Depends on `fd_set` stack layout | **No** | **Yes** (OEM/compiler fragile) |
| Needs signal + FPSIMD context | **Yes** | No |
| Control of full waiter object | Byte-accurate blob in Vregs | Word map via shift |
| Proven full root on A53 5.10 | No (pselect did) | **Yes** (johnny) |
| Proven on CPH2521 | **Not tested** | **Yes** (plateau) |
| SVE path | May miss FPSIMD magic | N/A |

---

## Side-by-side pipeline map

```text
                 ┌──────────────────┐
                 │  EDEADLK UAF     │  same
                 └────────┬─────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
   pselect reclaim                  FPSIMD reclaim
   (CPH shift=-2)                   (sigreturn Vregs+0x18)
   johnny A53 no-shift              Meowkis writer
          │                               │
          └───────────────┬───────────────┘
                          ▼
                 sched_setattr / adjust
                          │
                          ▼
                 rb_erase / AAW stamp
                          │
                          ▼
                 fops / CFI / root
```

**Only the middle box changes.** Stamps (ZERO_NAME, ION_SAFE, classic MISC−8) still need correct **field layout relative to the reclaimed waiter**, not relative to `fd_set` words — FPSIMD places a **contiguous 0x58 waiter**, which may actually make stamp packing **cleaner** than multi-set shift mapping.

---

## Implications for CPH2521

| Question | Answer |
|----------|--------|
| Should we drop pselect because of #160? | **No.** CPH pselect works. |
| Is FPSIMD required for 5.10? | **No.** A53 rooted with pselect on 5.10.237. |
| When would FPSIMD help on CPH? | (1) Future build breaks shift; (2) want byte-stable waiter for classic erase without fd_set shift bugs; (3) research second channel if softboot is place-related not erase-related. |
| Does FPSIMD fix cfi22 / softboot classic erase? | **Not by itself.** After reclaim you still hit the same `adjust` / MISC geometry problems. A53 proves a **different stamp layout** can root on 5.10; that is more relevant than FPSIMD for your wall. |
| Best borrow from A53 | Not FPSIMD — their **post-reclaim write target + workqueue/UMH root path + first-page-only fake fops** after order-3 reclaim. Their classic `target-8` stamp softboots **on CPH**; do not paste blindly. |

---

## Practical research order (CPH)

1. **Keep** plateau pselect as ground truth reclaim.  
2. **Optional smoke:** port `test_sigreturn_overlap.c` alone (markers only) on clean boot — proves FPSIMD overlap without full stamp (expect softboot if markers poison lock walks).  
3. **If implementing FPSIMD route:** after overlap proven, stamp with same field values as current ZERO/ION packing, still `LOCK_OWNER0` / prio rules.  
4. **Higher ROI than FPSIMD:** understand why **A53 classic stamp roots on Samsung 5.10** but softboots on CPH under shift=-2 (layout mismatch), and keep working **ION/ZERO write path**.

---

## Local reference copies

| File | Path |
|------|------|
| johnny poc (pselect A53) | `logs/ref_johnny/poc.c` |
| johnny target | `logs/ref_johnny/target.h` |
| Meowkis FPSIMD | `logs/ref_fpsimd/sigreturn.c` |
| Meowkis overlap test | `logs/ref_fpsimd/test_sigreturn_overlap.c` |

---

## One-line summary

**#160 says pselect reclaim fails on Samsung 5.15; your Oppo 5.10 already has pselect reclaim. Johnny’s 5.10 A53 root is still pselect. FPSIMD (Meowkis) is a solid Plan-B reclaim with a contiguous waiter blob — worth a careful smoke test, not a reason to abandon the CPH plateau path.**
