# QEMU CFI validation + 5.10 slot ground truth — 2026-08-22

## What was proven (QEMU, real CPH2521 kernel Image, nokaslr)

Manual-swap harness (`qemu_cph/cfitest.py` + `rsp.py` RSP client):
spray → RSP pokes `ashmem_misc.fops = <real sprayed table>` → guest runs
`try_cfi_stage` (CFI_TEST mode). Result:

```
cfi write ret=35          ← configfs_write_bin_file copied 35 bytes to
                             binwrite_target — ARBITRARY WRITE WORKS
file: f_op=<real table> f_mode CAN_WRITE=1 CAN_READ=1
private_data blob at name+0xb exactly as designed (bin_buffer+size visible)
```

- kCFI passes with genuine `.cfi_jt` pointers in every slot. **CFI is not
  a blocker.**
- errno 22 root-caused at instruction level: `vfs_write+0x30` loads
  `file->f_mode` (+0x44): bit1=FMODE_WRITE else -EBADF, **bit18=
  FMODE_CAN_WRITE else -EINVAL**. Stamped in do_dentry_open AFTER ->open
  from `f_op->write || f_op->write_iter`. ⇒ errno22 with a fresh O_RDWR fd
  means the swap did NOT land (or table slots empty) — it never meant
  "CFI blocked".

## 5.10 ground truth (Image disassembly / dumps)

- Real `configfs_bin_file_operations`: `.read=configfs_read_bin_file.cfi_jt`
  @+0x10, `.write=configfs_write_bin_file.cfi_jt` @+0x18, everything else 0.
  **On 5.10 the configfs bin fns are `.read`/`.write` style (never converted
  to `_iter`). Putting them in iter slots = kCFI panic** (QEMU-verified:
  "CFI failure (target: configfs_write_bin_file.cfi_jt)").
  JoinChang's `write_iter` arrangement is 6.x-only. Our offsets already
  pointed at these JTs (kallsyms names).
- `configfs_buffer`: private_data@file+0xd8, page+0x10, mutex 0x20..0x50,
  needs_read_fill+0x50, read_in_progress+0x54 (must be 0), write_in_progress
  +0x55, bin_buffer+0x58, bin_buffer_size+0x60 (32-bit, bounds the copy),
  cb_max_size+0x64 (only read on the vmalloc growth path — skipped when
  size ≥ pos+len).
- `ashmem_area.name` @ +0xb (SET_NAME memcpy dest `add x0, x19, #0xb`)
  ⇒ ASHMEM_NAME_PREFIX_LEN=11 confirmed. Default name "dev/ashmem/".
- Read primitive on 5.10 must use a SMALL pos (JoinChang's huge
  ASHMEM_PREFIX_COUNT-derived pos fails the 32-bit size bound) —
  `configfs_read_once` now uses pos=0x1000, bin_buffer=target-pos.

## Code changes

- `put_fake_fops_table`: 5.10 = configfs JTs in `.read/.write` (+0x10/+0x18),
  iters zero; rb_leaf shell keeps +0x10 = 0 (guard added); CLONE_CFG same.
- `MODE4_JOINCHANG=1`: arms W0.pi write shape {parent=fake_fops,
  right=MISC_P0, left=0} + fake_task.pi_waiters→&W0.pi (compact 5.10 offsets
  pi_tree@0x18 from build defines). rb_erase right-child-only path writes
  `child->__rb_parent_color = pc` → `*MISC_FOPS = fake_fops`, red ⇒ no
  rebalance.
- `do_one_write` mode4: post-walk `try_cfi_stage` now unconditional
  (verifies + restores ashmem_misc.fops).
- `CFI_TEST` QEMU mode + `QEMU_INIT` mknod/KPHYS auto-setup +
  `RECLAIM_DELAY_MS` knob.

## Device fires today (3, all softboot — stopped per policy)

| Tag | Env | Signature |
|-----|-----|-----------|
| JC1 | MODE4_JOINCHANG=1 | walk clean, NO cfi markers (gated off), softboot AFTER process exit |
| JC2 | MODE4_JOINCHANG=1 + unconditional cfi | cfi_open_ok → pwrite errno22 (swap NOT landed at open) → softboot after exit |
| WPS1 | WRITE_PROOF+WPROOF_SPRAY | softboot DURING pselect (before walk output) |

## Open problem (sharply defined)

**Heap placement**: in QEMU the reclaim frag lands ~0x31bf00 BELOW the
leaked base (wide-scan verified; base page = live mm slab, never freed).
JC2 errno22 + WPS1 mid-walk crash are consistent with the same miss on
device (fake_fops → uncontrolled page). The WPROOF_SPRAY MSG_PEEK oracle
exists but its fire softbooted — needs QEMU-grade analysis of the
KernelSnitch free/reclaim choreography (per-cpu partial lists, RCU-delayed
mmdrop) before more device cycles.

## QEMU harness notes

- `qemu_cph/cfitest.py`: boots, waits for "CFI_TEST armed", RSP-pokes
  MISC.fops (wide-scans for the ioctl-JT anchor and repokes at the REAL
  table if the reclaim missed), breakpoints write_bin JT, inspects the
  file struct, resumes.
- lldb.exe on this host is broken (0xC0000135) — use `rsp.py` (raw GDB
  RSP: read/write mem, Z0 breakpoints, p-reg reads).
- Static guest build: `build_qemu_static.ps1` (-static -ldl; dynamic binary
  can't exec in the initramfs).

## Afternoon addendum — placement forensics (QEMU, kscan tooling)

`qemu_cph/kscan.py` (RSP scan for the per-run `fake_w0` marker = every payload
copy's lock signature) gives a per-run payload page map:

- No churn, RECLAIM_SENDS=24 → **12 order-0 payload pages** bracketing base
  (base−0x4000 and base−0x8000 adjacent!) but **never base itself**;
  base+0x100 stays mm residue in every run.
- Disassembly of `skb_page_frag_refill`: alloc call has `mov w2, wzr` —
  **order-0**. The "order-2 LIFO freelist" theory is dead; frags are 4K
  chunks. The −0xE80 geometry packs lock@+0 / table@+0x100 / W0@+0x300 /
  task@+0x400 into the first 4K, so order-0 claims align when they happen.
- Root cause: the emptied mm slab page **never leaves SLUB** (active cpu
  slab or per-cpu partial; cpu_partial≈13 for 0x3c0 objects) → never
  reaches the buddy → no order-0 storm can split it.
- MM_CHURN v1 (256 post-close holder forks+kills): did NOT free base —
  the spill discards displaced the frag claims instead. Needs the correct
  sequence: exhaust base's freelist to force a deactivate while empty,
  then spill with base as the oldest chain entry (discarded last =
  freshest = first split by the order-0 storm).
- SNDBUF_KB env added (reclaim socket sndbuf).

Next session: iterate the choreography in kscan until
`BASE IS PAYLOAD: True`, then device: WPROOF_SPRAY oracle, then
MODE4_JOINCHANG (post-swap chain already QEMU-proven).

## Session 2 addendum — storm + copy-A + the breakpoint fix

- COPYA (default on): one memcpy duplicates the frag-region structure
  cluster into skb_buf[0..0x500) — kmalloc-4096 linear heads are also
  order-0 claims, so ANY linear/frag object landing at base carries the
  geometry (values identical: lock/table/W0/task are base-derived).
- 512-send storm (SO_SNDBUFFORCE 32MB + 8 sockets): 164 pages claimed,
  consecutive runs of adjacent 4K pages visible in scans — base still
  unclaimed; SLUB chain stays 13(13)/node 0/slabs 47 through everything.
- Close-order reorder (memfd_leak FIRST, then all pre/post/spray) +
  +6 prepare-kill spill trigger: chain count unmoved — trigger racy.
- **Breakpoints were never broken: the QEMU gdb port 1234 TIME_WAIT made
  launches silently fail. With a fresh port, a single __mmdrop Z0 bp
  produced 53k stops in 70s.** Next session: trace __mmdrop + discard_slab
  + frag-refill against the armed base to see exactly which frozen/parked
  page base is and when pages actually discard — then target its release.

## Device oracle fire (WPS2, evening)

MODE4_WRITE_PROOF+WPROOF_SPRAY with the full new choreography (COPYA,
64 sends / 8 sockets, reordered closes): SOFTBOOT mid-walk at the marker
write — same signature as WPS1. Two identical crashes at the
`*(fake_fops+0x90)` write moment ⇒ heap placement misses on real hardware
too (stray qword + tree walk into a foreign page). Placement is the
blocker on BOTH platforms; stop device fires until the QEMU trace
(now working) pins base's SLUB state and its release path.

## Session 3 (2026-08-23 early AM) — interleaved reclaim + device rolls

- PREPARE_DEADLINE_S env (smp8 TCG needs >180s per attempt).
- INTERLEAVED RECLAIM: kill micro-batches (KILL_BATCH) with immediate
  ring claims (RING_BATCH) — page that empties is claimed within
  batch-microseconds at the PCP head instead of sitting stealable in the
  buddy for seconds. smp8 win trajectory: 0/4 → 1/4 (KB=4/RB=8) →
  2/4 (KB=2/RB=8/CYCLES=4). Remaining smp8 miss class: flags=0x8080
  (base re-claimed by the mm cache as a fresh slab — next cycle's forks
  beat the rings).
- Device rolls (interleaved build, MODE4_RETRY=5):
  JC12 softboot after 2 SURVIVED retry attempts (errno22 no-swap each);
  JC13 swap landed + bad table (crash at open); JC14 ALIVE with
  survived attempts (errno22); JC15 not fired (device rebooting).
  vs previous session: 0/8 boots survived a miss → now most boots
  survive misses and retry in-place.
- Next: target the 0x8080 class (frees that the NEXT cycle's forks
  re-claim — perhaps fork holders BEFORE the kills of the previous
  cycle freed, i.e., single continuous holder pool with rolling
  kill/claim), tune smp8 to ≥3/4, then device.

## Session 4 (2026-08-23 morning) — CPU limiting investigation (user idea)

- CORE_SEL env + QUIESCE_MAX loadavg gate shipped; afftest.c on-device
  probe produced GROUND TRUTH: pin(7) can succeed then EINVAL 2s later
  — Android demotes long-running background procs to restricted
  cpusets; Cpus_allowed_list FLUCTUATES per-second (0-7 ↔ single core
  "6"); prime core hotplugs online/offline at idle.
- pin_to_core hardened: multi-try loop (requested core down to 0, then
  highest-allowed down) — EINVAL aborts eliminated (JC30/31 ran the
  full flow).
- KEY RECON INSIGHT (untested): the cpuset bounce migrates us between
  cpus mid-run — per-CPU SLUB partial lists and PCPs split the reclaim
  choreography across multiple cpus' allocator state. QEMU-TCG keeps
  us on one vcpu; the device bounces. THIS may be the real device-vs-
  QEMU placement gap. Next: re-pin every batch / cpu-agnostic design.
- JC30-31: full-flow runs (no EINVAL), 1 survived errno22 attempt,
  walk-crash class persists; placement still 0 on device.
