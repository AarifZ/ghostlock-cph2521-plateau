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

---

# ADDENDUM (same day, evening): multi-agent correlation — THE PLAN IS NOW EVIDENCE-CLOSED

Three agents + device enumeration + offline checks. Sources: agent reports
(cached /tmp/research/{jc,users}), upstream JoinChang @ fa877c4 source,
JoinChang issues #9/#16/#21/#31/#44/#46/#50, RMG/IonStack docs, our fire
ledger (1575 logs mined).

## A. THE TWIN-DEVICE PROOF: 5.10.236-android12-9 IS ROOTABLE

- **Galaxy Z Fold4 SM-F9360: SAME KMI as CPH2521 (5.10.236-android12-9),
  waipio SoC family, kernel_phys_load=0xa8000000 — DEVICE-TESTED ROOT 3×**
  (RMG docs/SM-F9360-F9360ZCSAIZF1.md; KSU "Working LKM Jailbreak mode").
- Galaxy S22 Ultra 5.10.226: hardware-verified `uid=0 context=u:r:kernel:s0`
  + KernelSU-Next insmod (sarabpal-dev/IonStack-S22U; QEMU harness).
- Galaxy A53 5.10.237: rooted from PURE APP domain.
- OnePlus 10 Pro (issue #16, same KMI as ours): JoinChang's pselect engine
  KP's — but OUR fork already walks (shift=-2 overlay proven), so we are
  past the point where that twin is stuck.

## B. THE CONFIGFS-ON-5.10 BUG — AND THE FIX (source-verified)

JoinChang commit 17b6ec4 (xperia1iv, 5.10): mainline 5.10
`configfs_file_operations` uses **plain .read/.write**
(configfs_read_file @ fops+0x10, configfs_write_bin_file @ +0x18) — NOT
.read_iter/.write_iter (6.x-era). JoinChang's fake table points the _iter
slots at iter-compiled functions → on 5.10 VFS either never dispatches or
misdispatches → errno 22 / broken. OUR FORK INHERITED THE SAME TABLE.
**Fix: point fake fops .read(+0x10)→configfs_read_file .cfi_jt stub and
.write(+0x18)→configfs_write_bin_file .cfi_jt stub for 5.10.** New Image
offsets to extract: both stubs + verify CFG_* configfs_buffer field
offsets (upstream constants tuned for GKI 6.x 48-byte mutex; our 5.10
needs BTF/disasm verification of struct configfs_buffer:
{count@0,pos@8,page@16,ops@24,mutex@32,needs_read_fill@80,bin_buffer@88,
bin_buffer_size@96,cb_max_size@100}).

## C. THE UMH IS DEAD ON OUR DEVICE (config-verified) — replacement known

CONFIG_STATIC_USERMODEHELPER=y PATH="" → call_usermodehelper_exec_async
forces path="" → execve fails. Workqueue injection (umh_root.c) calls the
same dead end. JoinChang issue #31's own conclusion: skip UMH entirely.
Replacement endgame (NebuSec part III + issue #31 recipe):
**configfs r/w → pipe_physrw → 1-byte enforcing=0 (no adjacent bytes) →
ROOTGUARD unhook (sys_exit tracepoint funcs → probestub; we already
landed the leaf-NULL variant) → walk init_task→child → patch cred FIELDS
in place (uids=0, 5×caps=FULL, seccomp cleared, sid→kernel) → child
executes .ghostlock_root.sh (ksud late-load already coded in main.c).**

## D. WHY PREVIOUS ATTEMPTS STALLED (correlated, all cited in agent report)

1. Selinux W1: SOLVED (Z15 value 0xffffff802abb0000 keeps `initialized`
   byte ≠0; the 8-byte-NULL form zeroes it → SID flood → ~100s death —
   independently confirmed by JoinChang fa877c4 on Xperia: __randomize_layout).
2. Walk budget 2/boot: park+W2 max (Z5/Z26 3rd-walk KP). The new plan
   needs **ONE walk total** (fops swap); everything after is userspace.
3. Fire-6 ambiguity (errno 22 = configfs EINVAL vs unswapped): the honest
   re-verification = canary write into OUR OWN PAGE + readback compare
   (JoinChang try_cfi_stage step 1 — our fork has it) — unambiguous.
4. Every landed fops swap clobbered fake_fops+0x08 (llseek) via
   change_child: repair_fake_fops_llseek exists — must run right after.
5. ROOTGUARD (oplus_root_check_post_handler sys_exit): the vivo vr.ko
   Option-B pattern (funcs[].func → tracepoint probestub, address-
   fingerprinted) is the clean surgical variant of our landed leaf-NULL.

## E. THE CHAIN (every link cited; ONE walk; no cred-pointer writes)

0. OFFLINE (no fire): extract configfs_read_file/configfs_write_bin_file
   .cfi_jt stubs from our Image; verify configfs_buffer offsets vs our
   kernel (BTF absent on our build → capstone on do_configfs_open/
   configfs_write_bin_file disasm — same method as aristotle port §3).
1. Walk 1: fops swap (fire-6 surviving form + JoinChang mode-4 W0 arming:
   fake_task.pi_waiters root=leftmost=&W0.pi, W0.pi={pc=fake_fops(page),
   right=&misc.fops, left=0}) → *(misc.fops)=fake_fops (aligned, no color
   bit). prio=0, sprayed-page lock, shift=-2. [fire-6 + Z15 precedent]
2. Userspace: open /dev/ashmem<boot_id> (fake .open=real ashmem_open;
   fire-6's open SURVIVED — the only open-survivor ever), ASHMEM_SET_NAME
   blob → configfs_buffer forged in asma->name.
3. Canary write→readback on our page (honest swap proof).
4. repair llseek; pipe_physrw install (code exists; drain64/reclaim16 +
   kmalloc-2k gate + marker scan — JoinChang geometry).
5. 1-byte enforcing=0; ROOTGUARD probe-redirect; task walk; cred FIELD
   patch (uids/caps/seccomp/sid) — NebuSec Android-17 recipe verbatim.
6. Child uid=0 → .ghostlock_root.sh → ksud late-load --kmi android12-5.10
   (module build needed for non-GKI vermagic 5.10.236-android12-9-o-g74d…
   — OPPO kernel source + KernelSU-next LKM, no-LTO per Z Fold4 lesson;
   even without the module: durable root shell + permissive until reboot).

## F. Fall-back ladder (if a rung fails, next rung — all userspace-verifiable)

- configfs slots wrong → polygraphene 2-walk pipe-flag plan (bugreportd,
  dumpstate page-cache overwrite; CONFIG_MODULES=y + NO MODULE_SIG
  verified on device — unsigned .ko loadable once root).
- pipe slab never lands → S22U "exp32" compat-child or SIGRETURN writer
  (proven alternates on same-KMI-class devices).
- ColorOS permissive death timer (15s–15min) → mute list (uid0_mute_
  coloros) + do steps 4-6 immediately; park value keeps initialized≠0.

## G. Confidence (per rung, evidence-weighted)

swap walk+open survive 0.6 (1/1 fire-6) → configfs@5.10-fixed-slots 0.6
(source-verified fix, untested offsets) → physrw 0.6 (code complete,
twin-device proven, our slab unknown) → cred-field patch 0.9 (NebuSec-
proven, no pointers) → **joint ≈ 0.2 first run, ≈ 0.5 within 3-4 runs**
(independent verifiable rungs, each retry cheap after walk 1).

---

# ADDENDUM 2: OFFLINE EXTRACTION COMPLETE (all verified, no rebuild needed)

## Verified against our Image (kallsyms.txt + disasm of kernel_Image.bin)

1. **Configfs stubs — already correct in offsets.h (mislabeled):**
   - off_configfs_read_iter = 0x0182FCF8 = **configfs_read_bin_file.cfi_jt**
   - off_configfs_bin_write_iter = 0x01830218 = **configfs_write_bin_file.cfi_jt**
   (kallsyms: ffffffc00982fcf8/0x01830218 targets 0x6b0d0c/0x6b0f84)
2. **Real table configfs_bin_file_operations @ RVA 0x21756a0** uses PLAIN
   .read(+0x10)=read_bin stub, .write(+0x18)=write_bin stub — 5.10 style.
   configfs_file_operations @ 0x2175580 likewise (.read/.write = the
   non-bin variants). Our kernel HAS no _iter configfs dispatch.
3. **Slot placement already correct in our binary**: put_fake_fops_table's
   GHOSTLOCK_KERNEL_5_10 branch puts the stubs in FOPS_READ_OFF(0x10)/
   FOPS_WRITE_OFF(0x18) under clone_cfg — the fix predates this session.
4. **configfs_buffer layout VERIFIED from configfs_write_bin_file@0x6b0f84
   + read_bin_file@0x6b0d0c disasm** (matches target.h constants exactly):
   - mutex @ +0x20 (add x19,x24,#0x20 → mutex_lock)
   - read_in_progress @ +0x54, write_in_progress @ +0x55
   - needs_read_fill @ +0x50 (read fn: ldr w8,[x26,#0x50]; cbz → skip refill)
   - bin_buffer @ +0x58 (88), bin_buffer_size @ +0x60 (96, ldrsw),
     cb_max_size @ +0x64 (100, ldrsw)
   - file->private_data @ file+0xd8 (fake .open=real ashmem_open ✓)
   - Write bounds path `pos+count <=? bin_buffer_size → copy at
     bin_buffer+pos` confirmed = the end_offset==bin_buffer_size trick.
5. **KASLR slide=0 confirmed by our own landing history** (real_cred lands
   100% at data_addr(KIMAGE+off) — impossible with nonzero slide). The old
   gl_run_swap.sh KASLR_SLIDE=0x2892200000 was a miscalc; in-flow
   leak_kernel_base cross-checks anyway.

## Device-run plan (user executes when ready) — ONE process run:

Env: MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 MODE4_CLONE_CFG=1
     KPHYS=0xa8000000 CORE_SEL=7 PSELECT_SHIFT=-2 UID0_NO_SYNCLOG=1
Binary: /data/local/tmp/gl_jc2b (already on device, md5 a883b3a3...)
MUST NOT set: UID0_DIRECT, MODE4_CRED_PI, MODE4_SLIDE_CRED,
MODE4_SWAP_NOCFI (all divert to dead paths).

Auto-flow after the swap walk: try_cfi_stage → canary write+readback
(honest proof) → fops readback → boot_id restore → KASLR leak →
install_pipe_physrw (probe strings verify) → install_child_root →
UMH (fails: STATIC_UMH_PATH="") → fallback install_android_root
(find_task_by_tgid → cred FIELD patches).

Known 3rd-act risk: ROOTGUARD (oplus sys_exit hook) may SIGKILL the
rooted child on exit unless g_boot_state flipped — if the chain lands
but the child dies at exec, that is the NEXT targeted fix (Z49 g_boot_state
work + vr.ko-style probe redirect via physrw). Even that outcome = first
proven full primitive chain on this device.
