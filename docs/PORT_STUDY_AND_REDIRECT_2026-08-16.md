# Port study → CPH2521 redirect (2026-08-16)

**Goal:** Stop drifting through stamp experiments. Align research with ports that **already root** on the same CVE, especially the closest 5.10 line.

**Policy unchanged:** default binary path stays **plateau** (inert / survive → `success=1`, `cfi errno=22`, ALIVE). Research is opt-in env only. Softboot-class stamps banned as default. ADB = kill/start-server + manual replug; truth = `boot_id` + durable stage.

---

## 1. What every working PoC does (same chain)

| Stage | All ports |
|-------|-----------|
| 1 | KASLR / identity (slide, boot_id, nfulnl, or assume+verify) |
| 2 | Futex PI UAF → pselect reclaim of `rt_mutex_waiter` |
| 3 | `sched_setattr` → `adjust_prio_chain` → **`rb_erase` AAW** |
| 4 | **`*ashmem_misc.fops = fake_fops`** (one clean store) |
| 5 | configfs-shaped R/W through swapped fops |
| 6 | pipe physrw → patch cred / SELinux / seccomp |
| 7 | su / KernelSU install (optional persistence) |

Shared engineering habits (we under-used these):

- **O_SYNC / fsync** per diagnostic line so logs survive panic.
- **Write-proof before fops swap** (scratch / boot_id / enforcing).
- **Stop multi-stage root spray until `landed=1`.**
- Device `target.h` is sacred; wrong MISC vs FOPS table is a silent cfi22 forever.

---

## 2. Per-repo findings

### 2.1 `yijiacloud/GhostLock-OPPO-PCKM00` — 4.14.180 OPPO PCKM00

- Full userspace `LD_PRELOAD` chain; ~97% reliability claim.
- Waiter packing is **4.14-shaped** (`shift≈+2` style word map; `in[2]=fake_w0`, task/lock/prio in out/ex).
- fake_fops: **legacy `.read` / `.write`** = `configfs_read_bin_file` / `configfs_write_bin_file` (no `_iter`).
- Logging: `/sdcard/Download/log_*.txt` with forced sync.
- **Takeaway for us:** structure and logging, not stamp geometry. 4.14 `rt_mutex_waiter` / fops layout ≠ 5.10.

### 2.2 `yijiacloud/ghostlock-cve-2026-43499-4.19-k40` — 4.19.x K40-class

- Same framework as NebuSec / 4.14 port; big `adaptation-4.19.patch`.
- Simple stack overlay (`in[0]=fake_w0`, ex = task/lock/prio).
- `CFGOPS_4_19_STYLE`: configfs methods in **`.read`/`.write` slots**.
- `ASHMEM_MISC_FOPS = miscdevice.fops` (+0x10) — same rule we already have.
- Slide stage logged as `UNVERIFIED` until proven on-device.
- **Takeaway:** 4.19 is intermediate; still not our dequeue/enqueue 5.10 walk. Good reference for “MISC is the pointer field, not the table.”

### 2.3 `soralis0912/CVE-2026-43499-aristotle-apk` + `iAhtasham/aristotle-root` — **5.10.136** (closest)

**Primary reference for CPH2521 (5.10.236).** Same generation, same bug class, working root on device + deep disasm (`RTMUTEX_WALK_DISASM_ANALYSIS.md`).

#### Proven walk geometry (device + QEMU)

Stack overlay (pselect fdset, **shift = −2**):

| waiter word | field | value |
|-------------|--------|--------|
| 2 | `tree.__rb_parent_color` | **fake_fops** (write value) |
| 3 | `tree.rb_right` | **0** |
| 4 | `tree.rb_left` | **&ashmem_misc.fops** (write target) |
| … | task / lock / prio | INIT_TASK / fake_lock / prio≠task |

`rb_erase` hits **only-left, no-right** →  
`*(&ashmem_misc.fops) = fake_fops`  
(single store; no recolor panic if parent page is spray).

Heap `fake_lock`:

- `waiters` / leftmost → `fake_w0`
- **`owner = 1`** (NULL owner + HAS_WAITERS) → clean exit after write, skip fragile fake-task setprio path

Heap `fake_w0` (waiters root node): main tree empty black leaf; PI tree may carry write shape for PI paths — **the stack overlay main tree is what dequeues for the AAW.**

#### Write / CFI lessons (directly maps to our cfi22)

1. **`success=1` ≠ store landed.** It only means `sched_setattr` returned 0.
2. **`cfi errno=22` after open of real ashmem** = `vfs_write` **`FMODE_CAN_WRITE` missing** because **fops swap never applied** on that fd (real ashmem has no `.write` / often no write_iter that sets the flag the way we probe).
3. If swap **had** landed with **wrong method pointers**, they would see panic / non-EINVAL, not stable 22.
4. aristotle fix for methods: put **`configfs_read_bin_file.cfi_jt` / `configfs_write_bin_file.cfi_jt` in `.read`/`.write`**, **zero `_iter`**. Their earlier `_iter` / table-as-func bugs match class of mistakes.
5. **Write-proof first** (default in their tree):
   - scratch qword in sprayed page + sk_buff recv
   - or `sysctl_bootid` / SELinux enforcing
   - **Do not attempt fops swap until walk_wrote=1.**

#### Reclaim / trigger

- Frame-sum on 5.10: **`PSELECT_WAITER_WORD_SHIFT = −2`** (matches our measured shift).
- EDEADLK requeue path can leave dangling `pi_blocked_on` without SIGALRM; they also document race where pointer is cleared → `walks=0`. Continuous **pselect slice re-arm** + consumer burst is how they keep the window open.
- Optional SIGALRM path exists in older duchamp lore when cleanup clears pi_blocked_on too early — use only if write-proof shows walks=0.

### 2.4 `fusiondrive/CVE-2026-43499-S24U6.1.x` — **404**

Repo missing. Closest public 6.1 Samsung line:

- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) + Payloads (S24 / S24U / S25U, kernels 6.1.x)
- Same IonStack/NebuSec ancestry; 6.1 has different `rt_mutex` / fops / pipe details.

**Takeaway:** useful later for pipe/root stages; **not** the stamp model for CPH 5.10. Do not chase 6.1-only stamps on 5.10.

---

## 3. Where we strayed (honest scoreboard)

| Direction | Why it felt right | Why it stalled |
|-----------|-------------------|----------------|
| Plateau inert | Survive setprio + cfi22 ALIVE | Correct **sanity**; not a write path |
| Classic only-right parent=MISC−8 | NebuSec / many ports | Softboot in setprio on CPH; re-enqueue / lock identity |
| ZERO_NAME → ION CHAIN3 | Survive erase near misc; unlock wait_lock | Multi-phase; flaky; never proven past p1; **no working 5.10 port does this** |
| REF_LEFT dual main+pi | aristotle-shaped only-left | Softboot **at pre-select** (not post-erase) — packing/FD/owner differ from full aristotle |
| REF_LEFT_PI only | Survive | PI erase path not the main dequeue that does the AAW |
| A53 / E2 / TOP_LEFT / JT as right | Other devices | Softboot-class on CPH |

**What is proven on CPH:**

- UAF primes: EDEADLK **35** reliable.
- Shift **−2** survives overlay; shift 0 softboots.
- Plateau: full route, `post_setattr`, cfi22, ALIVE.
- ZERO_NAME: surviving leaf store to name (not the fops slot).
- **Not proven:** any `*MISC = fake_fops` while ALIVE; any cfi ≠ 22; uid0.

---

## 4. Redirected research plan (ordered, freeze-friendly)

### Tier 0 — Never break (main / default)

- No `MODE4_*` → plateau packing only.
- ADB softboot policy as in `CONTEXT.md`.
- Durable stage under `/sdcard/ghostlock/aarif/` (O_SYNC style).

### Tier 1 — Diagnostics only (must pass before stamp wars)

Implement / re-enable **one** of (aristotle order):

1. **SCRATCH write-proof**  
   Overlay `tree_left = page_base+SCRATCH`, value = magic; after route, sk_buff recv / page readback.  
   - landed → walk reaches dequeue.  
   - not landed + success=1 → early-exit or wrong overlay content (not “need ZERO then ION”).

2. **boot_id / enforcing proof** (static alias target)  
   Separates “store works” vs “data_addr / MISC offset wrong”.

Gate: **no fops-target fire counts as progress until write-proof has a clean positive or a clean negative with full PROOF log.**

### Tier 2 — Single aristotle-faithful stamp (research env)

One env family, e.g. `MODE4_ARISTOTLE=1`, that sets **together** (do not mix half of CHAIN):

| Piece | Value |
|-------|--------|
| shift | −2 |
| stack main tree | parent=fake_fops, right=0, left=MISC (only-left) |
| stack lock | fake_lock |
| fake_lock.owner | **1** (not fake_task\|1, not 0-unless tested) |
| heap W0 main | empty black leaf (1,0,0) |
| fake_fops methods | verify CPH configfs bin table: prefer **`.read`/`.write` CFI JT** of bin file ops; **zero `_iter` unless table says otherwise** |
| consumer | short delay + multi-walk; optional pselect re-slice |
| FD open policy | match aristotle (timerfd / selected bits), not random OPEN_ALL experiments |
| max attempts | small (≤4) |

If this softboots at **pre-select**, fix reclaim/FD/owner — do **not** invent ZERO_NAME again.  
If ALIVE + write-proof negative, dump overlay words and re-check MISC = **miscdevice.fops**, not ashmem_fops table.

### Tier 3 — Only after landed=1

1. Fix fake_fops text slots against real CPH `configfs_bin_file_operations` dump (CFI JT).
2. CFI punch → expect non-22 or clear panic class.
3. pipe physrw → cred (copy aristotle/4.19 pipe stage, re-offset for CPH).
4. Then SELinux spray / su — never before.

### Tier 4 — Deprioritize / archive

- MODE4_CHAIN / ZERO_NAME / ZERO_OWNER / ION_SAFE as **primary** path.
- Classic MISC−8 only-right as default write.
- right = .text JT.
- 6.1 S24U stamps until 5.10 write-proof is green.
- Multi-hour stamp matrix without a write oracle.

---

## 5. CPH-specific checks to re-verify from kernel image

1. **`off_ashmem_misc_fops`** = `&ashmem_misc.fops` (+0x10), not table base. (aristotle had a long silent cfi22 from exactly this.)
2. **configfs bin fops** — dump real table: which of `.read`/`.write`/`.read_iter`/`.write_iter` are non-NULL and which CFI JT addresses.
3. Our `put_fake_fops_table` today wires `CONFIGFS_*_ITER` symbols into **`.read`/`.write`** under `GHOSTLOCK_KERNEL_5_10` — names may be wrong even if slots are right; rename/verify like aristotle `CONFIGFS_READ_BIN` / `WRITE_BIN`.
4. `data_addr()` / `P0_KERNEL_PHYS_LOAD` delta — bootid proof separates this from “walk dead.”

---

## 6. Recommended next session (minimal)

1. Keep plateau binary as control fire (confirm ALIVE cfi22 after any code change).
2. Port **write-proof only** (no MISC target) on research branch; one clean boot fire; pull aarif log.
3. If proof positive → one aristotle-faithful only-left stamp + owner=1.
4. If proof negative with walks≥1 → overlay content / shift ±1 diagnostic, not CHAIN3.
5. Update scoreboard only with: `walks`, `walk_wrote`, `boot_id`, last PROOF, cfi errno.

---

## 7. One-line thesis

> **We are not stuck on “need a multi-phase wait_lock zero.” We are stuck on proving the 5.10 only-left rb_erase store lands (aristotle model), while treating cfi22 as “swap not applied,” and we strayed into ZERO/ION/CHAIN because classic MISC−8 softboots — which is a different geometry than the working 5.10 ports use.**

---

## 8. Links

| Kernel | Repo |
|--------|------|
| 4.14 | https://github.com/yijiacloud/GhostLock-OPPO-PCKM00 |
| 4.19 | https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40 |
| 5.10 APK | https://github.com/soralis0912/CVE-2026-43499-aristotle-apk |
| 5.10 exploit | https://github.com/iAhtasham/aristotle-root (fork of soralis0912/aristotle-root) |
| S24U 6.1 link | **404** — use BuSung Root-My-Galaxy / Payloads for 6.1 class |
| Upstream | NebuSec CyberMeowfia IonStack CVE-2026-43499 |
