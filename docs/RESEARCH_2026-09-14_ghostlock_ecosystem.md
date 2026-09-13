# GhostLock Ecosystem Research — 2026-09-14 (full-day sweep)

Recall document from an exhaustive search of every public GhostLock chain,
the original NebuSec writeups, and adjacent Android root chains. Sources in
the final section. All raw files cached in /tmp/research (session-lifetime).

---

## 0. THE CAMPAIGN-DEFINING FINDINGS (read this first)

1. **NebuSec part II explains our "+0x780 fortress" with their own
   constraint equations.** The canonical GhostLock write targets
   `lock = target-8` and treats the qwords after it as an rt_mutex. The
   kernel READS those neighbors BEFORE writing:
   ```
   *(u32*)(target-8)  must read as UNLOCKED spinlock (low 4 bytes 0)
   *(u64*)(target+8)  must be benign (rb_leftmost)
   *(u64*)(target+16) & ~1 must be 0 (owner NULL/NULL|HAS_WAITERS)
   ```
   For target = task+0x780 (cred), target-8 = task+0x778 holds the
   real_cred POINTER → reads as a LOCKED spinlock → trylock fails → walk
   exits WITHOUT writing. **The fortress is the primitive's structural
   constraint, not OPPO magic.** Nobody can hit +0x780 with the root-form
   store. (popsicle's change_child form hits it differently but panics
   our 5.10 — 5/5 measured.)

2. **NebuSec's Android 17 root NEVER swaps the cred pointer.** Part III:
   escalate to unlimited kernel R/W (pipe_buffer.page), then patch the
   ORIGINAL cred object's fields in place (uids=0, all 5 cap sets=FULL,
   securebits=0, seccomp cleared, TIF_SECCOMP cleared) + SELinux sid swap
   + enforcing=0. Our ORACLE_CAPS concept was right; it needs a real R/W
   primitive, not one-shot constrained writes.

3. **polygraphene's Samsung S26 chain is the endgame template for
   hard-vendor devices** (DEFEX/KDP = kernel memory NOT writable even as
   root): ONE write → selinux_enforcing=0; ONE write → pipe_buffer.flags
   |= PIPE_BUF_FLAG_CAN_MERGE (dirty-pipe-like); splice had planted the
   target file's page-cache pages into the pipes; pipe write() now
   appends INTO THE FILE'S PAGE CACHE (dm-verity blind — RAM only);
   `setprop ctl.start vendor.modprobe` executes the overwritten content.
   No KASLR needed (kernelsnitch + linearmap addresses), no ashmem, no
   cred write, no CFI issue (data-only, no function pointers).

4. **"Aristotle" is a Xiaomi device codename** (au/KDDI XIG04, MTK,
   Android 12, 5.10.136-android12) — the 5.10 PORT of the verified
   popsicle exploit (x-spy/CVE-2026-43499-popsicle, Xiaomi 17, 6.12).
   Our fork's "MODE4_ARISTOTLE" env naming descends from this lineage.

---

## 1. Lineage map (who forked whom)

```
NebuSec/CyberMeowfia (IonStack: CVE-2026-10702 Firefox JIT + GhostLock)
 │  original authors; $92k bounty; Android 17 demo
 ├─ x-spy/CVE-2026-43499-popsicle   Xiaomi 17/Pro/Ultra, 6.12.23, VERIFIED,
 │  │                               direct-root (cred→init_cred + selinux flip)
 │  └─ soralis0912/...-aristotle    Xiaomi XIG04, 5.10.136-android12 (OUR
 │                                  KERNEL FAMILY) — full port doc, unverified
 │                                  on device (build step pending)
 ├─ polygraphene/CyberMeowfia       Samsung 6.12 (S26): selinux + PIPE-FLAG
 │  │                               dirty-pipe file overwrite + vendor.modprobe
 │  ├─ BuSung-dev/Root-My-Galaxy    Samsung one-click (S25U etc, 6.6/6.12),
 │  │  └─ -Payloads                 + kernelsu.ko build w/ kdp-rkp-defex patch
 │  ├─ diabl0w/ghostlock-q8q        Z Fold 8 Ultra — io_submit() primer!
 │  └─ snothin/ghostlock-s26        S26 follow-up (polygraphene endorses)
 ├─ JoinChang/ghostlock-oneplus     OnePlus/Oppo table; OUR fork's base;
 │  │                               CPH2521 = "pending device test"
 │  └─ PeronGH/ghostlock-selinux-disabler  W1-only (enforcing=0 via
 │                                  fake_right=page+0x100, kaslr_slide=0!)
 ├─ pubglite55/oppo-ghostlock       OPPO Find N2, 5.10.236 (OUR EXACT
 │  │                               kernel build family!) — stuck at CFI/
 │  │                               write primitive (same walls as us)
 │  └─ Thiasap/oppo-pgem10-ghostlock Find X6 Pro, 5.15, PAC blocks SLIDE
 │                                  (futex frame 0xA70 > pselect 0x620)
 ├─ Colorful-glassblock/duchamp-root Xiaomi K70e, 6.1.138-android14
 ├─ NothingFumo/ghostlock-aresin    POCO F3 GT, 4.14.186, data-only physmap
 │                                  overwrite, device PANICS (accepted)
 ├─ hmascs/KSuRoot 3.0              one-click APK; on-device kallsyms→
 │  │                               movz/movk re-patching payload builder;
 │  │                               vivo/iQOO variant (vr.ko anti-su bypass);
 │  │                               6.6+ needs no ADB
 └─ others: 2932796375github OPPO-MT6835 (PLS120 5.15: all leaks blocked,
    MTE+freelist-hardened — negative result doc), ASUS i005, Xiaomi x200,
    theVakhovskeIsTaken (Vivo PD2405), MhmRdd (Moto G05), localhosts-A
    (Redmi K80 Ultra), CakesTwix checker
```

Unrelated family (no kernel memory corruption):
`LSPosed/LSPromise` = CVE-2026-49881 (Telecom serviceClassExists logic bug
→ code in system_server) + `V4bel/dirtyfrag` CVE-2026-43284 (xfrm-ESP
page-cache write) → patch libc/libc++/vendor lib → init → vendor_modprobe
→ kernel module → permissive. 100% success, Pixel 10/Android 17 only.

---

## 2. The write primitive — all known forms

### 2a. Canonical (NebuSec part II, used for boot_id KASLR + ashmem fops)
Root-replacement store: fake waiter is a SINGLE-CHILD ROOT (pc=NULL) in
lock->waiters; erasing it writes the child pointer into
lock->waiters.rb_node. With lock = target-8: ***(u64*)target = W0_BASE**
(the value is always OUR sprayed page address). Constraints §0.1.
The write VALUE is limited to a kernel address we control — that's why
"fops = fake table" and "enforcing = page+0x100 (byte0=0)" are the
canonical uses.

### 2b. popsicle shape-0 (read oracle)
W0.pi/ghost-tree = {pc=Q, right=0, left=B}: erase writes B into *(Q+8)
(change_child) AND *(B)=Q (store-1) → boot_id.data=Q → read /proc/.../
boot_id = [Q]=wanted, [Q+8]=B (B = proof-of-fire oracle). Reads DESTROY
Q+8 (writes B there). Verified 6.12. aristotle uses it to read
__per_cpu_offset → entry_task = CURRENT TASK (no perf/x28 needed!).

### 2c. popsicle shape-1 (the cred write; VERIFIED 6.12 ONLY)
{pc=target-8, right=VALUE, left=0} → Case 1a: store-1 corrupts
VALUE+0 (init_cred.usage — harmless), store-2 = *(target)=VALUE.
**Panics our 5.10.236 5/5 (V-Y chains + our fire-2 heap-carrier).**
popsicle stamps this on BOTH ghost trees (main+pi) AND heap W0.pi;
ghost task=fake_task, prio=FAKE_WAITER_PRIO=130 (equal to W0 → ghost
never top-waiter; the write fires in the UAF cleanup's remove_waiter,
NOT top-waiter processing). aristotle 5.10 word table:
```
{0 parent}{1 right}{2 left}{3 parent}{4 right}{5 left}{6 fake_task}
{7 fake_lock}{8 130}{9 0}
```
NOTE: geometry at words 0-2 REQUIRES shift>=0 — negative shift drops
words 0/1 (unplaceable) and the main-tree geometry never lands. Our
device overlay is shift=-2 (empirically) → the popsicle dual-tree stamp
CANNOT work as-is on our device. (aristotle sweeps shift 0..7.)

### 2d. Our fire-6 form (pi-clean left, parent on OUR page)
{pi_parent=fake_fops(our page), pi_right=0, pi_left=target}: erase
store-1 = *(target)=fake_fops. LANDED (misc.fops ✓, real_cred+0x778 ✓).
Only proven-surviving direct-write form on CPH2521.

### 2e. polygraphene pipe-flag write (data-only, vendor-hardening-proof)
Constrained write → pipe_buffer.flags |= PIPE_BUF_FLAG_CAN_MERGE. Exact
geometry from poly_util.c (PAGE_PAYLOAD_PIPE_FLAG):
```
write_pc    = fake_pipe_flag + PIPE_BUF_FLAG_CAN_MERGE   // VALUE=page|CAN_MERGE
write_right = 0
write_left  = pipebuf_page_base + PIPE_BUFFER_FLAGS_OFF  // TARGET=&flags
```
= ONLY-LEFT Case 2 store-1, PARENT ON OUR SPRAYED PAGE — **identical to
our fire-6 proven-surviving form**. Erase does *(flags)=page|CAN_MERGE.
Their SELINUX payload is {pc=enforcing-8, right=page+0x100, left=0} (the
6.12 store-2 form — panics our 5.10); we do the SAME RESULT with our
surviving left-form: pc=page+0x100 (byte0=0), left=&enforcing →
*(enforcing)=page+0x100 → enforcing byte = 0. PeronGH confirms the
page+0x100 encoding works (byte0=0=off, byte1=1 tolerated).
Then: splice(target_file→pipe) pre-seeded the pipe with the file's
page-cache page; write(pipe, data) appends INTO THE FILE (page cache =
RAM; dm-verity/AVB only verify disk reads!). Result: arbitrary file
overwrite, no kernel mem writes needed after this point.

### 2f. NebuSec pipe_buffer.page R/W (Android 17 part III)
configfs-constrained write → pipe_buffer.page = arbitrary physmap page
(VMEMMAP_STRICT_OFF on Android → vmemmap base = phys + fixed delta) →
unlimited kernel read/write via pipe read/write. Then patch cred FIELDS.

---

## 3. The Android endgames (ranked for hard vendors)

1. **polygraphene pipe-flag + vendor.modprobe** (S26-proven, KDP/DEFEX
   immune): selinux=0 write → pipe CAN_MERGE flag write → overwrite the
   file that `ctl.start vendor.modprobe` consumes (kernelsu.ko / config)
   → module loads → full root. Needs: kernelsnitch pipe address, a
   modprobe init service on the device, kernel module loading enabled.
2. **NebuSec pipe_buffer.page R/W + in-place cred field patch** (A17-
   proven): uid/gid=0, 5×cap sets=FULL, securebits=0, seccomp=0,
   TIF_SECCOMP cleared, task_security osid/sid→kernel sid, enforcing=0.
   NEVER touches task->cred pointer → fortress irrelevant.
3. **popsicle direct cred swap** (6.12-proven, 5.10-panics): real_cred
   then cred → init_cred, followup enforcing=0 (same child), then FULL
   SELINUX POLICY RELOAD (/sys/fs/selinux/load) + embedded su daemon.
4. **UMH injection** — blocked on Android (CONFIG_STATIC_USERMODEHELPER);
   JoinChang's workqueue/system_unbound_wq variant exists as alternative.
5. **ASHMEM fops swap → configfs r/w** (our fire-6 landed the swap!) —
   the NebuSec step before 2f; kCFI-safe because read_iter/write_iter
   signatures match configfs handlers (.cfi_jt stubs on our kernel).

---

## 4. CPH2521-specific knowledge assembled

- Same kernel family as pubglite55/oppo-ghostlock (Find N2, 5.10.236):
  they verified trigger+spray+KASLR but are stuck at exactly our wall.
- PGEM10 (5.15) PAC lesson: if futex frame > pselect frame, SLIDE is
  impossible. OUR overlay WORKS (shift=-2 measured) → no PAC problem.
- selinux-disabler (OnePlus 5.10-era): enforcing write works with
  fake_right = page+0x100 and kaslr_slide=0 (our logs confirm slide=0).
- aristotle 5.10.136 offsets vs ours: real_cred=0x778/cred=0x780 IDENTICAL;
  pi_waiters=0x880/pi_top=0x890/blocked_on=0x898 vs OURS 0xA00/0xA10/0xA18
  (vendor config drift — our Image-measured values stand). Waiter layout
  identical (10 words, task@0x30 lock@0x38 prio@0x40 deadline@0x48).
- Task leak without perf: popsicle reads __per_cpu_offset[cpu] then the
  percpu entry_task slot via the shape-0 oracle (2b) — works under
  SELinux where perf is EACCES. Our perf/x28 leak also works.
- q8q (Z Fold 8): if select-based overlay ever fails to align, io_submit()
  is a working alternative primer (different kernel stack frame).
- RANDOMIZE_KSTACK_OFFSET drops success to 1/8 (part II) — our overlay is
  deterministic → RKCO off on our build. MTE (KASAN_HW_TAGS) needs tag
  brute-force (popsicle's kernelsnitch method) — our device: MTE off
  (mte disabled in polygraphene log style; our kernel 5.10 GKI-era).
- ABL cmdline injection (Qualcomm!): `fastboot oem set-gpu-preemption 0
  androidboot.selinux=permissive` (patched on newer ABLs; HyperOS 2/3
  era affected; Reno 10 Pro+ = SM8475 Qualcomm — worth ONE test if we
  ever enter fastboot; zero-risk, may just reject).
- Vivo vr.ko anti-su: vendor kernel MODULE reverts root — OPPO's
  equivalent is userspace (oplus_kevent/anti_root, we already mute) +
  the kernel-side revert we saw on dualwrite — much weaker than RKP.

---

## 5. Other chains catalogued (context, not our path)

- **DirtyFrag (V4bel)**: splice pins read-only page-cache page into skb
  frag; ESP in-place crypto STOREs 4 controlled bytes (replay_esn seq_hi)
  into the page. CVE-2026-43284 (xfrm) exploitable on Android but only
  from system_server/network_stack/netd (SELinux neverallow for apps) →
  LSPromise pairs it with the Telecom system_server bug (Android 17
  only). Not reachable from our shell context.
- **DirtyPipe (CVE-2022-0847)**: our 5.10.236 is patched (fixed in
  5.10.102). polygraphene's pipe-flag trick is the GhostLock-powered
  re-implementation of it.
- **CVE-2025-21479 + IMQSNative/MQSAS service call** (Xiaomi): system
  service command injection → temp root. Xiaomi-only.

---

## 6. Recommended plan for CPH2521 (post-research)

**Phase A — polygraphene template on our kernel (BOTH writes in our
fire-6 proven left-form, parent on sprayed page):**
1. W1: enforcing=0 — {pc=page+0x100, left=&selinux_enforcing} →
   *(enforcing)=page+0x100 (byte0=0). PeronGH-proven encoding; our
   off_selinux_enforcing=0x02A793C8. Detector: /sys/fs/selinux/enforce
   reads '0'. Survivable, no fortress involved.
2. W2: pipe CAN_MERGE — {pc=page+PIPE_FLAG_OFF+0x10, left=&pipe_buffer.
   flags} → *(flags)=page|CAN_MERGE (polygraphene-exact). Needs
   kernelsnitch pipe address (our fork has kernelsnitch; retries OK).
3. splice(pre-chosen file)→pipes, write payload via pipe → file
   overwritten in page cache (dm-verity blind). Candidate targets on
   ColorOS need enumeration (vendor.modprobe config / uid-0-loaded lib /
   init-triggered binary). VERIFY kernel module loading feasibility
   before betting on kernelsu.ko; the LSPromise file-target logic
   (libc/libc++/vendor lib + crash_dump domain dance) is the model.
**Phase B (fallback) — NebuSec pipe_buffer.page R/W + cred-field patch:**
ashmem fops swap (fire-6 landed once) → configfs r/w → vmemmap math →
pipe_buffer.page = arbitrary page → in-place cred FIELD patch (uids=0,
5×caps=FULL, seccomp cleared, TIF_SECCOMP, sid swap). NEVER touches the
cred pointer. Fortress irrelevant.
Both phases need ZERO writes to task->cred. The +0x780 war is over.

---

## 7. Sources (fetched + cached)

- nebusec.ai/research/ionstack-part-2/ (write primitive + constraints)
- nebusec.ai/research/ionstack-part-3/ (Android 17 root recipe)
- github.com/x-spy/CVE-2026-43499-popsicle (+ source, cloned)
- github.com/soralis0912/CVE-2026-43499-aristotle (+ ARISTOTLE_CVE43499_PORT.md, cloned)
- github.com/polygraphene/CyberMeowfia (main.c/root.c pipe-flag phases)
- github.com/diabl0w/ghostlock-q8q (io_submit primer note)
- github.com/BuSung-dev/Root-My-Galaxy(-Payloads) (kernelsu.ko samsung patch)
- github.com/pubglite55/oppo-ghostlock (Find N2 5.10.236 status)
- github.com/Thiasap/oppo-pgem10-ghostlock (PAC blocker analysis)
- github.com/2932796375github/CVE-2026-43499_OPPO-MT6835 (negative result)
- github.com/PeronGH/ghostlock-selinux-disabler (W1 exact form)
- github.com/NothingFumo/ghostlock-aresin (4.14 physmap data-only)
- github.com/Colorful-glassblock/duchamp-root (6.1 K70e)
- github.com/hmascs/KSuRoot (payload builder, vivo vr.ko bypass)
- github.com/LSPosed/LSPromise + github.com/V4bel/dirtyfrag write-up
- github.com/lokey0905/rootWithoutUnlockBootloaderList (ABL injection)
- github.com/JoinChang/ghostlock-oneplus (our fork's base)
