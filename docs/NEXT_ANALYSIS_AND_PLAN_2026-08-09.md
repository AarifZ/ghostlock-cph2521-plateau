# Multi-source analysis + what we can do (2026-08-09)

Sources: Ghidra lab project, Image xxd, binwalk, kallsyms, phone stage/runlog, exploit source.

## 1. Binwalk / Image (not the bottleneck)

```text
binwalk kernel → ARM64 Image, ~45MB, 4k pages (expected)
```

| Object | Image fact | Exploit use |
|--------|------------|-------------|
| `ashmem_fops` | `.write` @ +0x18 = **0** | explains cfi **errno=22** if fops not redirected |
| `ashmem_misc+0x10` | ptr = `ashmem_fops` | **correct write target** for mode4 |
| `configfs_bin_file_operations` | `.read`/`.write` = bin CFI JTs at +0x10/+0x18 | already wired in 5.10 fake_fops |
| CFI JTs | open/ioctl/write_bin match live logs | offsets **OK** |

**Conclusion:** binwalk/static layout confirms offsets; does **not** show a missing symbol that blocks landing.

## 2. Ghidra — when the write can fire

`remove_waiter(lock, waiter)`:

1. Always (if enqueued): `rb_erase(waiter, lock+8)` → **main** node @ +0  
2. Only if was top: `rb_erase(waiter+0x18, owner+0x880)` → **pi** node  

Only xref: `rt_mutex_start_proxy_lock` (deadlock unwind).

GhostLock UAF: after that path, stack waiter is freed but a dangling pointer remains; **pselect** reclaims it; later PI/setprio (consumer punch) walks forged memory.

**Plateau implication:**

| Stamp | Erase? | On-device |
|-------|--------|----------|
| Main classic MISC (A) | Would be erase path | **softboot** |
| PI classic (B) | Only if top + PI erase | survive, **cfi22** (erase likely not PI) |
| Inert (default) | nothing useful erased | survive, **cfi22** |

## 3. Phone logs (what actually runs)

```text
after_cmp_requeue_pi
waiter_after_requeue_enter_pselect
pselect success=1
cfi open OK, pwrite errno=22
route_threads_returned
```

- Calls are the **right** route (requeue → pselect → CFI).  
- Not stuck in wrong syscall.  
- ADB can die without reboot (same boot_id); retest without reboot is fine if process killed first.

## 4. Linux / exploit logic (not “wrong open()”)

Mode4 goal:  
`*(ashmem_misc + 0x10) = fake_fops` via `rb_erase` only-right write.

CFI probe is correct: open ashmem + pwrite.  
22 = still real ashmem_fops.

DeepSeek “missing configfs iter” is a **naming** issue; CPH already uses bin `.read`/`.write` JTs.

## 5. What we can do next (priority order)

### Keep (stable platform)

- Plateau default: inert packing, `PSELECT_ROUTE_DELAY_USEC=150000`  
- Retest: kill `/data/local/tmp/a/e`, same boot OK for B-like experiments  
- Proof: always log `boot_id` + uptime before/after  

### Research (no phone risk)

1. **Ghidra:** walk `rt_mutex_adjust_prio_chain` + `rt_mutex_setprio` for **which fields** of `pi_blocked_on` waiter are used after UAF (may not be full main erase).  
2. **Trace which rb node** consumer punch hits (setprio vs second remove_waiter).  
3. Diff Samsung A53 timing (when stamp vs when erase) vs our select+150ms.  

### On-device experiments (one variable, env-gated)

| ID | Idea | Goal |
|----|------|------|
| **C** | PI classic (B) + **only** prio games to force top (stack prio 0 / W0 out of waiters tree) | Fire PI erase without main MISC |
| **D** | After route success, **second** punch burst / longer delay matrix (not stamp change) | See if late erase ever lands write |
| **E** | Minimal main stamp that is **not** MISC (e.g. only-right with parent in spray page) | Avoid softboot, still classic write shape |
| **F** | `MODE4_NO_CONSUMER` vs consumer-only isolation on B | Confirm write path needs punch |

**Do not re-open without new theory:** A (main MISC), A53_STAMP, pi_waiters under fake_task, DIG MISC.

### Not worth now

- Hunting more kallsyms for “missing” iter names  
- Full Auto Analyze of whole kernel  
- selinux_disabler without write (same primitive)  
- Switching CVE until GhostLock write path is exhausted  

## 6. Success criteria (when something beats plateau)

Must have **all** of:

1. Device alive (same boot_id or clean return)  
2. `success=1` (or documented exception)  
3. **`cfi write` errno ≠ 22** (ideally 0 / short write)  
4. Retest once without reboot  

Then: SELinux / UMH / physrw — not before.

## 7. Suggested immediate session plan

1. Ghidra: decompile `rt_mutex_setprio` + `rt_mutex_adjust_prio_chain` (UAF use sites).  
2. Design **exp E** (non-MISC parent for main only-right) or tighten **exp C** (top PI).  
3. One clean boot or same-boot kill+fire; one variable.  
4. Log to `logs/expX_*.txt` + boot_id meta.  
