# Clone-swap breakthrough plan (2026-08-16, collaborator agent)

**TL;DR:** Offline RE + walk analysis show our fake table and only-left geometry
were already correct, and the docs' "re-enqueue walks W0.left=MISC" blocker model
does not match what the code actually packs. The MISC softboot has exactly two
live explanations left: (a) the walk crashes on something we have not modeled, or
(b) **the swap lands and post-swap system ashmem traffic through our half-shell
table panics the kernel** while `sched_setattr` is still returning (last PROOF =
pre_setattr — which cannot distinguish these). New `MODE4_CLONE_FOPS` /
`MODE4_CLONE_CFG` tables turn that question into ONE decisive fire.

---

## 1. New verified facts (boot.img Image RE, kallsyms cross-check)

Boot img v4, kernel 48 MB at page 4096; `_text = 0xffffffc008000000`; file
offset == kallsyms offset. JT stub = `bti c; b <target>` decoded by script.

| Check | Result |
|-------|--------|
| `off_configfs_read_iter` (0x0182FCF8) | **→ `configfs_read_bin_file`** (misleading name, correct stub) |
| `off_configfs_bin_write_iter` (0x01830218) | **→ `configfs_write_bin_file`** (correct) |
| ashmem ioctl/open/mmap/noop_llseek stubs | all decode to the right functions |
| `target.h` fops slot constants (ioctl@0x50, compat@0x58, mmap@0x60, open@0x70, release@0x80) | **match real `ashmem_fops` dump exactly** (GKI layout, shifted +8 vs mainline) |
| `configfs_bin_file_operations` real table | `.read`=0x0182FCF8, `.write`=0x01830218 — our constants are the real slots |

Real `ashmem_fops` dump (for the clone):

```
+0x00 owner      = 0
+0x08 llseek     = ashmem_llseek.cfi_jt        = 0x0181FEF8
+0x10 read       = 0        +0x18 write     = 0
+0x20 read_iter  = ashmem_read_iter.cfi_jt  = 0x01822948
+0x28 write_iter = 0
+0x50 ioctl      = 0x01837928   +0x58 compat = 0x01837930
+0x60 mmap       = 0x01822A68   +0x70 open   = 0x01831488
+0x80 release    = 0x01831490   (everything else 0)
```

**Conclusion: wrong-symbol / wrong-slot theories are dead. The fake table
construction was already correct.** (`off_ashmem_llseek` / `off_ashmem_read_iter`
added to offsets so we can clone it bit-exact.)

## 2. Corrected walk model (why the stale doc model is wrong)

The docs say only-left `left=MISC` dies because "re-enqueue walks W0.left=MISC".
But the actual ARISTOTLE/WRITE_PROOF packing (util.c) keeps **W0.main =
(1,0,0) empty black leaf** and puts the write geometry on the **stack waiter's
main-tree words** (+ W0.pi). Under that packing, per the 5.10 rb_erase Case-2
trace (aristotle RTMUTEX_WALK_DISASM_ANALYSIS.md §(a), device+QEMU proven on the
same kernel generation):

1. `*MISC = parent_color` — the AAW (single store).
2. `__rb_change_child` only COMPARES `fake_fops+8/+0x10` against the erased node
   (no match ⇒ no store) — never dereferences them.
3. No rebalance/rotation in Case-2 (child recolored black in place).
4. Re-enqueue walks from root fake_w0 (prio 100 < waiter 139) into fake_w0's
   NULL right child — **never touches MISC**.
5. owner=1 ⇒ prerequeue_top_waiter == top_waiter (both fake_w0) ⇒ no
   wake_up_process ⇒ clean return.

Nothing after the store reads or writes the miscdevice neighborhood. So the
walk itself cannot explain why boot_id (identical packing) survives and MISC
dies — **unless the walk is not what dies.**

## 3. Two live hypotheses for the MISC softboot

- **H-A — the swap LANDS, then the box dies through our own table.** After
  `*MISC = fake_fops`, every Android ashmem open/ioctl/mmap goes through the
  fake table. Current rb_leaf table: open/mmap/ioctl/release real (safe),
  read/llseek NULL (safe) — but `.write` = configfs stub, and
  `MODE4_OPEN_ALL`-era tables had stray slots. A panic on another CPU while
  `sched_setattr` returns ⇒ last PROOF = pre_setattr — exactly our signature.
  Timing feels tight, but this is the ONLY structural difference between the
  two targets left standing.
- **H-B — racy trigger.** The EDEADLK-dangling is racy (aristotle measured the
  same: "sometimes survives, most runs cleared"); a mis-overlaid waiter faults
  anywhere. ZERO_NAME went "ALIVE" → "3/3 softboot" → "flaky" across sessions —
  our left=MISC sample may be 1–2 fires total. Single-fire "reject" verdicts on
  this primitive are not statistics.

## 4. New code (built, uncommitted on research-master)

- `MODE4_CLONE_FOPS=1` — fake_fops = **bit-exact clone of real ashmem_fops**
  (all slots above). The `*MISC` swap is a semantic NO-OP: if the walk is clean,
  the device MUST stay ALIVE with same boot_id and full stage.
- `MODE4_CLONE_CFG=1` — clone + `.read`/`.write` = configfs bin JTs
  (verified stubs). This is the full-compat attack table: system traffic keeps
  using real slots; fresh opens get `FMODE_CAN_WRITE` (write≠0) so the cfi
  pwrite reaches `configfs_write_bin_file` instead of EINVAL.
- Both bypass the rb_leaf shell (`+0x00=0` owner is a valid "black, no-parent"
  rb head; JTs at +8/+0x10 are compare-only in Case-2 — same as aristotle's own
  table, which is not a shell).

## 5. Fire plan (ordered, minimal boots)

**T0 — control (no research env).** Expect success=1 cfi22 ALIVE. Gates everything.

**T1 — boot_id regression with the new binary.**
`MODE4_WRITE_PROOF=1 MODE4_ONLY=1` (+ bootid target default env as before).
Expect landed=1 ALIVE, EXIT=0. Proves the new table code path didn't break the
proven primitive.

**T2 — DECISIVE: pure-clone swap on MISC.**
`MODE4_WRITE_PROOF=1 MODE4_CLONE_FOPS=1 WRITE_PROOF_SHAPE=left MODE4_ONLY=1 FOPS_MAX_ATTEMPTS=1`
(only-left parent=fake_fops right=0 left=MISC; value is the clone table).
- **ALIVE, same boot_id, post_setattr logged** ⇒ H-A CONFIRMED in reverse: the
  walk + swap are clean; every earlier softboot was the table/traffic side.
  Proceed straight to T3.
- **Softboot at pre_setattr** ⇒ H-A dead for the walk window; the crash IS in
  the walk/overlay. Then: re-fire T2 twice more on clean boots (rule out H-B
  race); if deterministic, the next suspect is trigger/overlay fidelity
  (aristotle's EDEADLK-vs-cleanup race), not geometry.

**T3 — attack table.**
`MODE4_WRITE_PROOF=1 MODE4_CLONE_CFG=1 WRITE_PROOF_SHAPE=left MODE4_ONLY=1 FOPS_MAX_ATTEMPTS=1`
Swap lands with full-compat table. Immediately after setprio returns:
fresh `open("/dev/ashmem", O_RDWR)` + 1-byte `pwrite` (existing cfi stage):
- errno ≠ 22 (or EFBIg/EFAULT/anything) ⇒ **swap is LIVE — cfi22 plateau broken.**
- Still 22 ⇒ swap not in effect on the probe fd: log the fake table words via
  live_sync (payload readback) and re-verify MISC P0 alias on this boot.

**T4 — after cfi≠22:** configfs read/write primitive → pipe physrw → cred → uid0
(existing code paths; aristotle pipe.c reference).

Rules kept: fresh boot_id + uptime ≤ 60 s per fire; `FOPS_MAX_ATTEMPTS=1` for all
MISC fires (no second walk on a mutated overlay); no USB thrash; hardboot script
between softboots; cool-down between fires (overheating history).

## 6. Why clone tables are safe for the walk (and the system)

- Case-2 change_child only compares parent's child words against the erased
  node — clone's llseek JT / 0 never match the stack waiter, so no store fires.
- +0x00 (owner=0) reads as rb "black, parent NULL" — any accidental parent walk
  terminates. (The old rb_leaf shell did the same job; the clone is strictly
  more compatible afterwards.)
- Post-swap system behavior with CLONE_FOPS is byte-identical to stock ashmem
  (it IS stock ashmem). With CLONE_CFG, only `.read`/`.write` differ — ashmem
  read/write are unused by Android (mmap/ioctl path), and our own probe is the
  only writer.

---

## SESSION RESULT (2026-08-16 late — fired by collaborator agent, see logs/CLONE_FIRES_2026-08-16_LATE.md)

- **T2 clone-swap DECISIVE FIRE LANDED THE WALK: T2f = first-ever `post_setattr
  ret=0` on only-left `left=&ashmem_misc.fops`** (clone table, owner=1, W0 leaf).
  The "MISC geometry softboots in-walk" blocker is DEAD — historical softboots
  were the reclaim race (tonight bootid-target crashed 4/5 identically).
- New product blocker: kernel dies in the first post-swap `open()` ~4 ms after
  the walk (cfi_before_open logged, cfi_open_ok never). With a bit-exact clone
  this points at **fake_fops→sprayed-page placement/lifetime**, not geometry.
- Build A/B (old vs new binary): no difference — race is per-boot lottery.
- Verified offline this session: JT stubs decode correctly (configfs bin
  read/write), fops slot layout matches real table, miscdevice+0x10 = &ashmem_fops.
- Updated fire order for next good session: probe-less CLONE_FOPS → placement
  oracle (scratch+recv) → CLONE_CFG for cfi≠22.
