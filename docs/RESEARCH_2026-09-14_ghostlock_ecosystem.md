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

## Fire result (fl090020, user-approved device run): WALK CRASH at pselect

Env: MODE4_ONLY=1 SLIDE_SWAP=1 CLONE_CFG=1 KPHYS/CORE_SEL/PSELECT_SHIFT=-2.
Device rebooted ~60s in (bootreason "reboot"). Log (67 lines): spray ok
(attempt 4), EDEADLK trigger ok, stamp logged verbatim as fire-6
(`stack SLIDE_SWAP pi-only: *misc.fops=fake_fops (clean) main=all-zero
lock=spray`, prio=0) — pselect entered, never returned.

**Critical reinterpretation of fire-6's "stable" evidence:** fire-6 ran
BEFORE the fdset pi-words fix — its ghost pi words were ZERO (never
reached the waiter), so what survived was a pi-disarmed walk; the swap
itself landed via the AUTO-WRITE_PROOF phase's W0-classic arming
({pc=MISC-8|1, right=fake_fops, left=0}, owner=1). With the writer FIXED,
the ghost pi words are now live — and the pi-armed walk crashed 1/1.
Matrix with fixed writer: ghost-pi-left@prio=0 → KP (this fire +
CRED_PI-L0 before it); ghost-pi-left@prio=1 → clean but NO store
(CRED_PI r219140). The ghost-pi delivery requires top-waiter status
(prio=0) which also drives the deeper processing that kills the box
(setprio(owner) class, docs/KERNEL_5_10_RTMUTEX_WRITE_PATH.md).

**Next candidate geometries (no fire until one is chosen):**
1. W0-ONLY REPLICATION of fire-6's actual landing path: ghost = pure
   benign carrier (pi words ZERO deliberately — the JoinChang words_compact
   verbatim), W0.pi classic armed by the auto-phase, owner=1. Matches the
   only historically-landed swap; our MODE4_JC2 stamp already IS the
   benign carrier — combine with the auto-phase's W0 classic arming and
   NO ghost-pi geometry. (MODE4_JOINCHANG=1 arms pi_waiters→W0.pi as the
   upstream mode-4 does.)
2. prio/owner isolation sweep for the pi-armed form (prio=1 + owner=1).

## Fires fl090020 + fl091910 postmortem (W0-replication attempts 1-2)

Both died AT pselect entry. Postmortem findings:
1. **Env mistake found:** the auto WRITE_PROOF phase overrides the payload
   target to BOOTID (default) — "mode4 ARISTOTLE W0.pi only-left
   parent=fake_fops right=0 left=bootid". NEITHER fire actually armed the
   W0-classic misc.fops form (use_classic requires WRITE_PROOF_TARGET=fops).
   Both walks were bootid-proof shapes with today's ghost stamps.
2. Ghost pi-armed vs carrier: BOTH crashed → ghost pi words are NOT the
   kill variable (isolated cleanly).
3. **Common element of both crashes absent from every historical 5.10
   survivor: ghost task=fake_task(spray page).** Survivors used
   task=init_task P0 (ttwu no-op). Spray quality was shaky both boots
   (KernelSnitch 2-3 retries; PM page = 0xffffff87 high alias).
4. Corrected replication (jc2c build):
   - WRITE_PROOF_TARGET=fops → auto-phase arms W0-classic {pc=MISC-8|1,
     right=fake_fops, left=0} = fire-6's landing form, ONE walk
   - MODE4_JC2 carrier hardened: task=init_task(P0) instead of fake_task
     (decouples the walk's first deref from spray quality)
   - env: MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 MODE4_CLONE_CFG=1 MODE4_JC2=1
     WRITE_PROOF_TARGET=fops KPHYS=0xa8000000 CORE_SEL=7 PSELECT_SHIFT=-2
     UID0_NO_SYNCLOG=1 → /data/local/tmp/gl_jc2c
Device: 4 reboots today — fire only on explicit user go.

## Fire fl094501 postmortem + jc2d build (v4 corrections)

fl094501 (jc2c, fresh boot, WRITE_PROOF_TARGET=fops): still target=bootid —
**MODE4_SLIDE_SWAP=1 force-overrides the target** (main.c ~3386, "target
unused by stamp"). Carrier line confirmed task=init_task P0 — walk STILL
crashed → task=fake_task theory dead too.

Three-fire matrix (all died at pselect entry):
- fl090020: pi-armed stamp + P0 page(ffffff803adf...) → crash
- fl091910: carrier + fake_task + HIGH page(ffffff87f86c...) → crash
- fl094501: carrier + init_task + HIGH page(ffffff87816f...) → crash
Reading: fire 1 = pi-armed kill (known class); fires 2+3 = **high-alias
spray pages** (Z23/Z28 alias-wrap KP class; ~32GB physmap offset, beyond
DRAM). O-era survivors (45-55%) match fl094501's shape but never showed
high-alias pages in their logs.

jc2d fixes:
1. SPRAY_ALIAS_MAX gate (default 0xffffff8400000000): high-alias spray
   pages rejected + retried in prepare_good_kernel_page.
2. Correct arming env (no SLIDE_SWAP override):
   MODE4_ONLY=1 MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops
   MODE4_CLONE_CFG=1 MODE4_JC2=1 KPHYS=0xa8000000 CORE_SEL=7
   PSELECT_SHIFT=-2 UID0_NO_SYNCLOG=1 FOPS_MAX_ATTEMPTS=24 → gl_jc2d
   → W0-classic {pc=MISC-8|1, right=fake_fops} on a low-alias page,
   ghost = init_task carrier, owner=1, cfi stage auto-follows.

## Fire fl095612 (jc2d) — PERFECT ARMING, STILL KP: matrix complete

Log confirms every intended element for the first time:
`WRITE_PROOF fops target=fops addr=ffffff802a91a8e8` ✓
`mode4 ARISTOTLE W0.pi classic parent=MISC-8|1 right=fake_fops left=0` ✓
(fire-6's landing form) `owner=1 waiters=W0` ✓ low-alias page
(ffffff8056178000, first-attempt spray, no KS retry) ✓
→ kernel_panic,oops at pselect entry. 56-line log, died at pre-select.

**Final 6-fire matrix (today+JC2): every controllable variable exonerated.**
| fire | ghost stamp | task | W0 form | page | result |
|------|------------|------|---------|------|--------|
| JC2-f2 | carrier | fake_task | mode2 {tgt-8,init_cred} | P0 | KP |
| fl090020 | pi-armed | fake_task | only-left@bootid | P0 | KP |
| fl091910 | carrier | fake_task | only-left@bootid | HIGH | KP |
| fl094501 | carrier | init_task | only-left@bootid | HIGH | KP |
| fl095612 | carrier | init_task | **classic@misc** | **LOW** | KP |
(plus CRED_PI-L0 left-pi@prio0 KP from 09-13)

Ghost stamp, task ptr, W0 geometry, target, owner, page alias: ALL varied,
ALL die at pselect entry on the current binary. The kill is NOT in any of
these variables — it is in the base route flow of the current codebase
(consumer sched_setattr cadence / thread timing / delay rotation) OR in
boot-state changes since the O-era.

## NEXT: regression test (needs user go)
/data/local/tmp/ghostlock-compact = the 08-22 O-era binary (walks survived
45-55%, bootid proofs landed). Replay on a fresh boot:
  MODE4_ONLY=1 MODE4_WRITE_PROOF=1 KPHYS=0xa8000000 (its era env)
- survives → current binary route regressed → git bisect the route changes
  (route_done timeout, detached threads, delay rotation, consumer changes)
- also KP → the device/kernel state itself changed since Aug 22 (the
  August walk results are no longer reproducible — different problem
  class entirely, likely needing a fresh trigger-timing campaign).

## prio=1 A/B result (fl101255, jc2e): KP — the debug concludes

Config fully verified in log: W0-classic@misc ✓ owner=1 ✓ carrier prio=1
stamped ✓ page ffffff8835b18000. Died at pselect like all others.
(The alias-gate run fl100706 timed out at spray — every page this boot
was high-alias; gate disabled; ALSO NOTE: clean userspace exit, no KP,
device untouched — a failed spray is harmless.)

## THE COHERENT PICTURE (all evidence, 8 KP boots today + history)

| walk class | W0.pi | result |
|---|---|---|
| r219140 (09-13, fixed writer) | INERT {1,0,0} | CLEAN (but no write — ghost-pi delivery) |
| O-era O18-O32 (08-22) | armed only-left | 45-55% survive (documented coin flip) |
| fire-6 (08-30, writer-bug era) | armed classic@misc | survived (won its flip) |
| today's 6 (all variants) | armed (bootid/misc/mode2) | 6/6 KP |

**The W0-erase-with-real-geometry is an inherent ~50/50 survival lottery
on this kernel** — matching the O-era's own 45-55% stats AND the Z Fold4
twin's "per-boot volatility, re-run after reboot" note. Every deterministic
geometry bug (pi-armed ghost, store-2, prio classes, arming env, spray
ordering) has been fixed and eliminated; what remains is the coin flip
that the O-era always accepted and the 09-13 single-fire discipline was
never designed for. 6 tails in a row ≈ 1.6% — improbable but the odds
may be worse than 50% on recent boots.

## THE DECISION POINT (for user)
The fl101255 config is verified correct end-to-end (arming, target,
table, carrier, canary follow-through). Each boot = independent flip.
Options:
A) Continue 1-fire-per-approval with this exact config — each approval
   is one coin flip; expected land within a few boots (if odds ~50%).
B) User-authorized limited re-roll loop of THIS EXACT config only
   (fastflip-style, e.g. 4-6 rolls with 10-min settle between reboots)
   — re-introduces the O-era's acceptance of the lottery, bounded.
No code changes pending — the chain behind the walk (canary → configfs →
physrw → cred-field patch) is verified and waiting.

## 10-ROLL CAMPAIGN (rolls 1-6 used, 12 KPs total) — DIAGNOSTIC CONCLUSION

Rolls 1-5 (classic/only-left, prio 0/1, spray/inittask878 locks, wchan
guard ACTIVE and passing, CPU0/1 pinning, 2min-uptime protocol,
MM_STRUCT_SZ=0x3c0): all KP at the same point.
**Roll 6 = MODE4_NO_CONSUMER=1 (no sched_setattr punch at all):**
```
pselect post-select +1508ms ret=0          ← THE STAMPED WINDOW IS SAFE
route_done wait TIMEOUT (waiter wedged)    ← wedged post-select
[device KP'd later in the teardown]
```
**Conclusion:** the killer is ANY PI walk through the STAMPED ghost —
whether triggered by the consumer punch (mid-select KP in rolls 1-5) or
by the waiter's own exit/teardown (roll 6). The stamp content arms a
walker-lethal ghost on current boot states. Root structural cause: at
shift=-2 the fdset writer CANNOT stamp waiter words 0/1 (tree_entry
pc/right — unplaceable, negative global word), so the walk's
rt_mutex_dequeue runs on the ghost's ORIGINAL (uncontrolled) tree
linkage — a boot-state lottery that has gone 12-for-12 lethal since
midday (the August 45-55% era is gone with current boot states).

**The ecosystem's documented answer for exactly this class: a writer
that stamps the FULL waiter.** q8q (Z Fold 8) switched to io_submit();
S918B uses MCAST (setsockopt stamping at fixed depth 0x98); iQOO Z9 uses
SIGRETURN/SVE frames. All stamp words 0-9 coherently — no uncontrolled
linkage. That is the next build (not more rolls: rolls 7-10 with the
fdset writer would burn 4 reboots for no new information).

Remaining budget: 4 rolls — PARKED pending the writer swap or user
direction. All findings committed.

## 10-ROLL CAMPAIGN FINAL (rolls 7-10 = the breakthrough arc)

- Roll 7 (jc2g, shift-0 full 10-word carrier, tree/pi zeros): **WALK
  SURVIVED** — flow completed, device alive, proof missed (landed=0).
  F9360 same-KMI alignment ("waiter qword 0 overlaps first fd-set
  qword") CONFIRMED on our device. The August "-2" was a bug-era
  misattribution — at -2 words landed 2 off and NOTHING we stamped ever
  controlled the waiter; the "45-55% lottery" was our stamps scattered
  across wrong fields.
- Roll 8 (tree_left=W0 to preserve root): KP — the W0 top-waiter
  processing stage is lethal (independent of W0.task: init_task raw VA
  or fake_task P0 both die, rolls 8-9).
- Roll 10 (jc2j: swap on ghost's OWN pi words, tree {0,0,0} root case):
  **SURVIVED THE FULL FLOW** — cfi stage ran postwalk, process exited
  cleanly, boot stayed usable. Swap did not land (cfi step=1 errno=22
  wr=-1) — the ghost-pi erase didn't fire the store; delivery mechanics
  remain to be diagnosed.

**Campaign outcome: from 12 consecutive KPs to a deterministic surviving
walk in 4 rolls.** The base is now: every waiter word controlled at
shift=0, tree root-case harmless, full post-flow (canary/cfi ladder)
executing on a live boot. Misses are CLEAN (no reboot cost) — iteration
on delivery no longer burns boots.

NEXT (no-roll work): diagnose why dequeue_pi(ghost) didn't run the
stamped pi erase — candidates: the walk skips pi processing for our
task=init_task choice (init_task pi_waiters empty path), or the erase
fires but change_child/store-1 go somewhere unobserved (add the boot_id
oracle as delivery detector — readback-based, no KP risk on the safe
base).

## TIGHTEN CAMPAIGN (rolls 11-15, disasm-driven) — FINAL

- Roll 11: KP inside the self-leak (perf on corrupted waiter thread) →
  leak moved to waiter entry (jc2l).
- Roll 12: SURVIVED with all disasm gates green (owner=fake_task|1,
  ghost.task = leaked waiter task 256/256 votes) — no store (chain exits
  deeper).
- Roll 13: swap geometry moved to the ghost's MAIN tree (the 0x1edddc
  erase slot with positive execution proof) → KP (env missed
  W0TASK_FAKE — the W0 wake on raw-KIMAGE init_task).
- **Roll 14: THE DEEPEST RUN EVER — full surviving cycle:**
  `consumer punch sched_ret=0 → pselect ret=5 calls=1 success=1 →
  cfi probe → PROOF cfi_before_open` — the erase delivered (the cfi
  stage only proceeds on detected redirect); **KP at the OPEN** of the
  swapped node (the historical N11-N14 class).
- Roll 15: fire-6 table attempt (SLIDE_SWAP stage1) — KP early (bootid
  W0 override + high-alias page; walk variance persists on this
  geometry).

**Position after 15 rolls:** the walk is ~deterministic with the
jc2m config (roll 14), the swap DELIVERS, and the remaining wall is
the OPEN of the swapped fd — plus residual walk variance on some
pages/targets. The open-KP needs the fire-6 table replicated CLEANLY
(not via the SLIDE_SWAP target-override path that cost roll 15) — a
small next build: clone the swap_stage1 table shape into the CLONE_CFG
path (llseek=0/read=0/read_iter=ashmem/write=cfg_w) + keep WRITE_PROOF
fops targeting. That is a one-branch change, and the next session
starts one step from the canary.

## STRUCTURAL REVIEW (post-roll-15, no-fire session) — THE INTEGRATED DESIGN

User directive: stop patch-and-fire; understand the structure. Findings:

### The open-KP root cause (roll 14), decoded from misc_open + table analysis
- misc_open (0xc2428c): file->f_op=our table (+0x28), private_data (+0xd8),
  then ->open (+0x70) — all fine with our JTs (fire-6 precedent).
- THE KILL = the LIVE WINDOW: ~1.5s between swap-landing (punch) and our
  post-select open, the swapped table serves ALL system ashmem traffic.
  Roll-14's CLONE_CFG table had configfs_read JT at .read(+0x10) AND
  configfs at read_iter(+0x20) → any system read() on an ashmem fd →
  configfs function with a REAL ashmem_area as configfs_buffer →
  garbage mutex/page → KP. Plus the change_child clobber lands at
  fake_fops+8 (llseek) = data-as-code if a JT is there.
- fire-6's stage1 table survived BY DESIGN: read=0 (EINVAL, harmless),
  read_iter=ashmem (real handler), llseek=0 (absorbs the clobber),
  write=cfg_w (system writes to ashmem fds ≈ never).

### The fork already implements the full solution
g_swap_staged + swap_stage1 (put_fake_fops_table): the staged table
keeps .read NULL; configfs_read_once ARMS .read around each pread for
microseconds via the configfs write primitive, then disarms. System
traffic never sees the configfs read JT. This whole mechanism gates on
MODE4_SLIDE_SWAP — whose ONLY problematic side effect is the main.c
target force-override to bootid ("target unused by stamp" — a rationale
invalidated by the JC2 stamp: the W0 DOES use the target).

### ROLL-16 DESIGN (2-line structural fix, everything else existing)
1. main.c write_proof: skip the SLIDE_SWAP→bootid force when MODE4_JC2
   is set (the stamp no longer carries the write).
2. Fire env: MODE4_SLIDE_SWAP=1 WRITE_PROOF_TARGET=fops
   WRITE_PROOF_SHAPE=left MODE4_JC2=1 MODE4_JC2_MAIN=1 MODE4_GHOST_PRIO=1
   MODE4_OWNER_TASK=1 MODE4_W0TASK_FAKE=1 PSELECT_SHIFT=0
   (NO CLONE_CFG — it selects the hazard table!)
   → stamp: roll-14's proven full carrier + main-tree swap;
   → W0.pi: only-left@misc (roll-14 proven);
   → table: staged stage1 (window-safe, read-arm on demand);
   → owner=fake_task|1, W0.task=fake_task(P0), prio=1, alias gate on.
Expected: walk cycle (roll-14 proven) → open survives (stage1 table) →
canary via transient-arm read/write → g_swap_staged flow → physrw →
1-byte selinux → ROOTGUARD probe-redirect → cred FIELD patch → root
script. Every element cited: roll 14, fire 6, our disasm, JoinChang
inherited code, NebuSec recipe.

## ★ ROLL 21 (jc2p, 13:43) — THE BREAKTHROUGH RUN ★

Config: quiet entry + MIDSTAMP UNLOCK + punch in-select + main-tree swap +
stage1 table. DEVICE ALIVE THROUGHOUT (first boot in project history to
survive a landed swap + open + configfs dispatch).

FULL SEQUENCE ACHIEVED:
- select returned clean (walk deterministic)
- consumer punch sched_ret=0
- ★ cfi_open_ok fd=767 — THE SWAPPED FD OPENED (2nd time ever, 1st with
  full control) — misc_open → our table → ashmem_open JT ✓
- ASHMEM_SET_NAME ioctl THROUGH the fake table: ret=0 ✓
- pwrite → dispatched into configfs_write_bin_file → its OWN EINVAL (22)
  = dispatch PROVEN (fork's QEMU doc: errno22 = configfs EINVAL, not kCFI)

REMAINING: the -22 at disasm 0x6b1034 (tbnz on forged buffer/pos sign) →
0x6b1128 (mov -22). One blob field encoding (pos / bin_buffer_size /
cb_max_size at asma+0x60/0x64) needs the exact real-configfs shape.
Iterate on LIVE boots — no reboot cost (HOLD keeps state, misses are
clean errnos).

THE SOLVED STACK (for the next session):
MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 WRITE_PROOF_TARGET=fops
WRITE_PROOF_SHAPE=left MODE4_JC2=1 MODE4_JC2_MAIN=1
MODE4_JC2_QUIET_ENTRY=1 MODE4_JC2_MIDSTAMP_UNLOCK=1
MODE4_GHOST_PRIO=1 MODE4_OWNER_TASK=1 MODE4_W0TASK_FAKE=1
PSELECT_SHIFT=0 SPRAY_ALIAS_MAX=0 FOPS_MAX_ATTEMPTS=24 KPHYS=0xa8000000
UID0_NO_SYNCLOG=1 → gl_jc2p

## CAMPAIGNS 44-46 (09-19/20): child-owned cred pivot + forensics

Campaign 44 (30 attempts): 11 survived / 19 KP / 0 caps. Every survivor:
swap landed (cfi_open_ok through fake table), child died (Z) regardless.
Root NOT achieved — but the failure point moved UPSTREAM of everything:
the CAPSONLY write now targets child+0x780 with a correctly-built cred.

CAPSONLY v2 (jc3b/jc3c): child sprays ITS OWN caps-cred page
(MODE4_CAPS_CHILD), reports {task,cred} to parent, pause-polls own CapEff
forever (never exits → page pinned). Parent walk: child_task+0x780 =
child's cred. Verified live: "CAPS_CHILD spray: base=... cred=... task=..."
+ "JC2 CAPSONLY v2: pc=<child cred> left=<child+0x780>" + punch + select
return + cfi_open_ok. The child STILL dies (Z) — signal unknown; the
parent's waitpid forensics line was lost twice (log truncation when
timeout kills the wedged parent before the verdict line flushes).

FORENSICS FIX FOR NEXT SESSION (tiny):
1. Move the waitpid check to RIGHT AFTER run_main_route_threads returns
   (before try_cfi/HOLD), with explicit fflush+fsync.
2. Campaign script: pull each attempt's log IMMEDIATELY after the
   outcome check (before the next reboot loses it).
3. Child-side heartbeat: child writes its poll count to
   /data/local/tmp/caps_heartbeat every loop → after death, the file
   shows whether it polled at all post-landing.

DECISIVE QUESTION the forensics answers:
- SIGKILL → oplus guard kills on something other than uid (re-read
  diyiqiuye's tables: addr_limit gate? second guard module?)
- SIGSEGV/SIGBUS → the cred write landed DIRTY (recolor bit? partial
  store?) — fix the geometry, not the cred
- alive → write never fired (chain exits earlier than believed)

State: jc3c on device + all commits. The walk+swap+open chain is
PROVEN; the remaining unknowns are (a) walk survival ~37% and (b) the
child-death signal — both answerable with the fixes above.

## STRUCTURAL ANALYSIS (09-20): why 0/75 — the value-as-parent trap

0/75 is not luck. Re-analysis of the only-left erase found the flaw:

**The write VALUE doubles as the ghost's __rb_parent_color.** The kernel
ERASE code dereferences it: __rb_change_child(node, child, parent) reads
parent->rb_left (+8) / rb_right (+0x10), and its else-branch writes the
child pointer into parent+0x10 UNCONDITIONALLY when the left slot doesn't
match.

- PROVEN landings (bootid, misc.fops, roll 21): VALUE = fake_fops = OUR
  quiet zeroed page → parent derefs/writes hit our controlled zeros →
  harmless → write lands clean.
- CAPSONLY: VALUE = child_cred = the CHILD'S LIVE cred page → the erase
  writes the target-node pointer into *(child_cred+0x10) = the cred's
  sgid field → the child's cred is CORRUPTED BY THE KERNEL'S OWN
  ERASE — before any caps can be used. Child death on every landing is
  EXPLAINED: the value we need (a live cred page) poisons the very cred
  it points to.

**DECISIVE ISOLATION TEST (next session, one fire):** WRITE_PROOF_TARGET
= bootid (readback-verifiable) with MODE4_JC2_MAIN but value =
child_cred instead of fake_fops. Two outcomes:
- boot_id changes → the child-cred value survives the erase chain →
  the problem is the child+0x780 target specifically (revert? guard on
  cred fields?) → different fix
- boot_id UNCHANGED → the child-cred VALUE breaks the erase chain
  itself → the value-as-parent trap confirmed → the write form needs a
  quiet-page value → the caps-cred approach via THIS primitive is
  structurally dead → pivot to W0.pi delivery with pc=init_cred
  (quiet immortal page whose +8/+0x10 = NULL gid/sgid = safe parent!)
  writing *(child+0x780) = init_cred... but uid=0 = guard kill → THEN
  the guard unhook MUST land first → two-walk chain (unhook walk, then
  init_cred walk) — both targets proven (funcs leaf-NULL "Lives",
  0x778/0x780 landed in Z-era).

## ★ ISOLATION TEST DECIDED (09-20 attempt 8): VALUE SURVIVES ★

bootid target + child_cred VALUE → walk survived → boot_id CHANGED:
  before: 407e5a02-0d5a-4f5c-b080-3beaa4092b3c
  after:  00823c48-80ff-ffff-b080-3beaa4092b3c ← child_cred page bytes!

**THE VALUE-AS-PARENT TRAP IS DISPROVEN.** child_cred passes through the
erase chain cleanly and lands at any target. The problem is SPECIFICALLY
the child+0x780 target — writing to the cred slot kills the child.

Remaining suspects (narrowed):
1. Guard reads task+0x780 directly (pointer change detection, not uid)
2. Cred write lands but a bad field deref kills the child
3. Rebalance side-effect corrupts +0x788 (adjacent field)
Next: forensics (waitpid signal) on a surviving CAPSONLY run.

## ISOLATION NARROWING (09-20): the +0x780 vs +0x790 gap

The isolation proved the value survives. The child dies ONLY at +0x780.
Between the proven-safe comm canary (+0x790) and the lethal cred (+0x780)
is one qword at +0x788. Three testable causes:

A) Cred content deref: the new caps_cred has a field the kernel faults on
   during the child's next /proc/self/status read. Test: write the
   ORIGINAL cred address back (no content change) → child lives = content
   is the killer; child dies = the write mechanism is the killer.

B) Adjacent corruption at +0x788: the erase's __rb_change_child writes
   into parent+0x08 or parent+0x10. Parent = child_cred (the VALUE) —
   not at +0x788. But the REBALANCE after the erase may touch the erased
   node's neighborhood on the stack/heap. Test: write to +0x788 with a
   safe dummy, check child survival.

C) Guard pointer detection: the guard reads task+0x780 directly and
   reacts to ANY cred pointer change (even same-uid). Test: write the
   SAME cred pointer back (no change) — if child still dies, it's not
   the value, it's the WRITE EVENT at +0x780.

Test A = test C (same fire). ONE surviving walk answers both.
Priority: fire test A/C first — it distinguishes content-kill from
event-kill, which picks between fixing the cred vs fixing the write form.

Walk survival note: child_cred as the ghost's parent makes external
walks MORE dangerous than fake_fops (which points to quiet zeros) —
this may explain why the bootid isolation run took 8 attempts (vs the
~3 expected at 37%). The walk crash is the same value-as-parent issue
but during the pre-punch window when an EXTERNAL walk hits the ghost.
A quiet-page VALUE would make the walk near-deterministic but then the
write value can't be a live cred — structural tension.

## QUIET_CRED RESULT (09-20 attempt 6): +0x780 write mechanism SAFE

Walk survived; QUIET_CRED fired (pc=quiet_page, left=child+0x780);
child died — EXPECTED for zero-page cred (user_ns=NULL → deref crash).
Combined with all prior evidence:

- +0x780 write MECHANISM is safe (lands, walk survives, no KP)
- ANY value at +0x780 becomes the child's cred pointer (dereferenced
  on next syscall)
- Zero page → kills (NULL user_ns) — confirmed
- Valid caps cred → kills (mystery — construction suspected)
- +0x790 comm → survives (safe target)

REMAINING QUESTION: is our caps cred actually valid when placed on the
child's spray page? The pointers (user/user_ns/group_info/security)
come from fill_init_cred_copy with kaslr_slide=0 (raw image values).
Next step: child dumps its cred bytes to a file BEFORE the walk fires
— verify pointers are sane kernel addresses.

## 2026-09-20 (pm): 13-KP loop forensics — root cause of walk-death found (freelist window)

**Evidence (all logs pr_info-flushed per-line, so last line = exact death point):**
- jc3j loop: 13 fires, 0 survivors. 10/13 last line = `pselect pre-select +4..40ms`
  (walk window); 3/13 died in SPRAY phase (PRE_DRAIN retype/PCP rings, no UAF
  involved) — separate class, likely early-boot alloc churn (all were loop boots 1,2,5).
- Walk KP rate identical jc3i (~12/15) vs jc3j (~10/13) → cred content (KIMI fixes)
  irrelevant: death precedes any cred use. Walk survival was ALWAYS the bottleneck.
- Consumer never printed (no SKIP, no punch line) in any walk-death → death between
  stamp and punch-fire, not at punch.

**Root cause:** In the JC2 flow the ghost page is on the kmalloc freelist from the
mid-stamp 0-timeout select's kfree until the blocking select's kmalloc re-takes it.
The early mid-stamp (main.c waiter path) left that window spanning the ENTIRE route
setup — prints, fsyncs, stage.txt writes, fd opens (+4..40ms). Any competing same-size
allocation steals the page (per-CPU freelist vs cross-CPU partial); the unlock deboost
walk / consumer punch then reads thief garbage → panic. Fresh quiet boots hold the
LIFO swap (~37%); busy consecutive-reboot boots get robbed (~0%). Matches every stat.

**Fix (jc4, ghostlock-cph2521-jc4):** MODE4_JC2_LATE_MIDSTAMP=1 —
- main.c: early mid-stamp skipped (would re-expose freelist).
- fops.c do_pselect_fake_lock_route: ALL slow setup first (prints/fsyncs/fds/arm),
  then on attempt 1 only: 0-timeout select (STAMP+kfree) → FUTEX_UNLOCK_PI (walks
  STAMPED ghost, µs window) → clock_gettime (vDSO) → blocking select immediately
  (same-CPU LIFO re-takes page, re-stamps, KEEPS it allocated through the punch).
  Ghost is never walked while free. Freelist window: tens of ms → microseconds.
- Fire env adds PSELECT_ROUTE_DELAY_USEC=8000 (punch paced by wchan guard anyway).

**Residual risks:** spray-phase KP class (~3/13, early-boot churn — fire ≥180s after
cold boot); punch-walk algebra unchanged (proven by jc3i survivors).

## 2026-09-20 (evening): jc4→jc10 fire chain — walk SURVIVES, writes never land, guard-NULL is the crash

**Fix trail (each fire = one boot):**
- jc4 (LATE_MIDSTAMP): WALK SURVIVED first time — punch fired, post-select
  returned, cfi opened through swapped table, route returned. Died at SIGCONT.
- jc5 (+tail-unlock removed): same death point.
- jc6 (+selinux blob osid=sid=1 at cred+0xB0, security=0x78 fixed): same point.
- jc7 (MODE4_CAPS_NOCONT, child left frozen): **BOOT SURVIVED** → killer is the
  child-resume, not teardown. /proc render of frozen child: **CapEff=0 → the
  cred write NEVER LANDED** (cred = untouched original). Shell-sent
  `kill -CONT <child>` on the live jc7 boot KP'd instantly → resume is lethal
  independent of cred → something ELSE was corrupted.
- jc8 (delay back to 50ms): survived, CapEff still 0 → not the delay alone.
- jc9 (+35ms sched_yield settle for owner re-link): died in window — freelist
  exposure of ANY length ≈ theft on these boots.
- jc10 (no unlock at all): died right after pre-select — stamp intact → punch
  walk RAN for real → crashed. Conclusion: **the walk's 3rd write — the
  CAPSONLY+GUARD OVERRIDE leaf-NULL *(0x2950700-8-derived addr)=0 — zeroes
  random kernel memory** (hardcoded image offset + KPHYS mapping; module/
  data address not per-boot verified). jc4-8 survived because the owner's
  post-unlock re-link defused the stamp (walk exited early, zero writes).

**Code-level bug found (util.c ~1719):** the GUARD OVERRIDE also silently
replaced the KIMI DUAL pi-write — child+0x778 was NEVER written in jc4-10
("JC2 DUAL" print predates the override assignment = stale). AND the DUAL
branch itself was slide-gated (MODE4_SLIDE_*), never reached by the CAPSONLY
fire env.

**jc11 (built, NOT fired — user hold):**
- MODE4_GUARD_NULL=1 now REQUIRED for the guard leaf-NULL write (default off).
- CAPSONLY+CAPS778+child_cred enters the DUAL W0.pi branch directly:
  W0.pi → *(child+0x778)=cred, main tree → *(child+0x780)=cred. No third write.
- Fire env for next test: same as jc10 + keep NOCONT to verify CapEff render
  with zero KP risk before ever SIGCONTing.
- NOTE: if child-resume lethality persists even with only-cred writes, the
  0x780 store path itself needs the GhostLockAdapt dead-task re-check.

**Flow-flag reference (current):** MODE4_JC2_LATE_MIDSTAMP=1 (µs freelist
windows), PSELECT_LATE_UNLOCK=0 (skip unlock; owner stays blocked), delay
60000µs, PSELECT_SETTLE_MS=0 (no settle).

## 2026-09-20 (night): QEMU session — rb_erase delivery mapped, spin-stamp added, QEMU harness bug found

**rb_erase disassembly (this Image, exact):**
- rb_erase+0x7c (`str x9,[x8]` @ 0xab760c) = `child->__rb_parent_color = pc`
  on the NO-RIGHT path = the write `*(left)=pc` — the DUAL shape
  {pc=cred, right=0, left=child+0x778} delivers real_cred HERE, with the
  only side effect being parent-slot stores INTO the cred value itself
  (cred treated as rb parent: writes cred+0x10/+0x18 = sgid/euid area).
- rb_erase+0x90 (`str x10,[x9]` @ 0xab7620) = same store on the ONLY-RIGHT
  path (left=0, right≠0).

**QEMU crashes today were a harness artifact:** the QEMU bootid proof target
computed garbage `addr=ffffffffc2d89b6d` (correct alias ffffff802a6aa868 is
printed by the p0 profile in the same boot) — the stamp was seeded with a
garbage pointer, so rb_erase stored through it. Device targets were always
correct (jc11: child+0x780). QEMU must not be trusted for punch validation
until this target computation is fixed (suspect: kaslr_slide re-detection
with perf absent).

**Still-real device failure mode:** jc10/jc11 died at the punch with correct
operands — remaining suspects: (a) pi-stamp freshness — one frozen blocking
select leaves the fdset overlay exposed to nested IRQ frames for 60ms+
(historically proven clobber class); (b) erase side effects downstream.

**Implemented (in tree, validated to build):**
- MODE4_JC2_SPINSTAMP=1: replaces the single blocking select with a loop of
  0-timeout selects (every 8th blocks 3ms so the wchan guard can sample
  do_select) for a ~150ms window — the stamp is re-copied ~700x across the
  punch instead of frozen once.
- PSELECT_WCHAN_CONFIRM=N (1..3): guard confirmation count knob.
- MODE4_QEMU_DUAL=1: DUAL shape twin with bootid as left + cred_copy as pc
  (QEMU has no PMU → no child spawn).
- MODE4_GUARD_NULL opt-in + CAPSONLY DUAL branch reachable (from jc11).

**Next session plan:** fix the QEMU bootid target computation → validate the
DUAL-shape punch end-to-end in the emulator (watchpoint on bootid; expect
str x9,[x8] with x8=bootid, x9=cred) → only then a device fire with
SPINSTAMP+DUAL+NOCONT CapEff verification.

## 2026-09-20 (late night): jc12 — SURVIVAL SOLVED on device; delivery is the last gap

**SPINSTAMP works on device.** jc12 (SPINSTAMP + late-midstamp + no-unlock +
DUAL + NOCONT): 253 re-stamps over the punch window, punch sched_ret=0, full
route + cfi + teardown survived — the FIRST device fire ever to survive the
punch without the unlock-defusing. The frozen-stamp clobber class is dead.

**But the write still doesn't land (CapEff=0 on the frozen child).**

**Key QEMU finding that carries over:** with breakpoints at
rt_mutex_adjust_pi entry (+0x0) and its rb_erase call (+0x174), NEITHER fired
during the punch in the QEMU spin runs — **adjust_pi is never called** (or
bails before the erase call). The erase delivery therefore never executes;
jc10/11's device KPs were the clobbered-stamp walk (now fixed), not proof the
erase ran.

**adjust_pi call site mapped:** __sched_setscheduler+0xEE4
(bl 0xffffffc0081ef24c), gated by two flag locals (frame fp-0x2c and fp-0x1c).
rt_mutex_adjust_pi reads pi_lock at task+0x86c.
The bail inside adjust_pi: rt_mutex_waiter_equal(waiter->prio, task prio).

**Next-session discriminators (in order):**
1. QEMU: bp at __sched_setscheduler+0xEE4 → read the two gate flags + the
   punched task's pi_blocked_on (+0x86c region) at punch time. If the gate
   flag is "pi_blocked != NULL" and pi_blocked_on reads NULL, find who
   cleared it between the EDEADLK priming and the punch (suspects: the
   mid-stamp FUTEX_UNLOCK_PI wake path clearing waiter->pi_blocked_on via
   remove_waiter-on-current (the BUG itself!), or futex exit cleanup on
   the spinning waiter thread).
2. Device: vary MODE4_GHOST_PRIO (130 → 139/120) so the waiter prio can
   never equal the post-setattr task prio (139) — rules the bail in/out.
3. Device: PUNCH_ALL_TIDS=1 — sched_setattr every thread; whichever task
   still carries pi_blocked_on gets walked.

**Current fire env (working survival recipe):**
MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 WRITE_PROOF_TARGET=bootid MODE4_JC2=1
MODE4_JC2_MAIN=1 MODE4_JC2_QUIET_ENTRY=1 MODE4_JC2_LATE_MIDSTAMP=1
PSELECT_LATE_UNLOCK=0 MODE4_JC2_SPINSTAMP=1 MODE4_GHOST_PRIO=130
MODE4_OWNER_TASK=1 MODE4_W0TASK_FAKE=1 MODE4_CAPSONLY=1 MODE4_CAPS_CHILD=1
MODE4_CAPS778=1 MODE4_CAPS_NOCONT=1 PSELECT_SHIFT=0 SPRAY_ALIAS_MAX=0
FOPS_MAX_ATTEMPTS=24 KPHYS=0xa8000000 UID0_NO_SYNCLOG=1
PSELECT_ROUTE_DELAY_USEC=60000  →  gl_jc12

## 2026-09-20 (final): jc13 — the delivery blocker is the GHOST TASK WORD

jc13 (nice stairs added — untested, KP'd before any punch): self-leak WORKED
this boot → ghost task word = the REAL waiter task (ffffff8887ccdc80) → walk
proceeded past the task check into the dequeue → KP pre-punch (+16ms).

jc12 (survived, no write): self-leak FAILED → task = init_task fallback →
walk exits at the task check BEFORE the dequeue → survives BECAUSE it never
delivers. ("stamp falls back to init_task (walk will exit at task check)" —
the log line was the answer all along.)

**The fork:** ghost task word = init_task → early exit, no delivery.
Ghost task word = real waiter task → delivery path, but the chain then
continues into the real task's PI state → KP (on this boot's luck).

**Next fix (no fire yet):** ghost task word = the BSS_TAIL dead-end
(kernelsnitch dead-zone: reads as a task with pi_blocked_on=0 → walks
TERMINATE there — the GhostLockAdapt design, MODE4_CRED_INITTASK=0 selects
it for the W0 path). The ghost's task field must point at the dead-end so
the chain: top_waiter check → DEQUEUE (delivers *(child+0x780)=cred) →
task = dead-end → chain terminates cleanly. The bss_tail image offset is in
the offsets table (off_bss_tail_lock 0x02BB9D00 region, mapped via
data_addr → P0 alias).

Also note: jc12/jc13 same pre-punch recipe on the SAME boot — jc12 survived,
jc13 KP'd pre-punch — the late-midstamp window still has residual
boot-luck-dependent KP risk (~the 3/13 spray-class or the unlock deboost
reaching the ghost on leak-success boots).

Fires spent of the 5-fire budget: 2 (jc12 NOCONT, jc13 KP).

## 2026-09-20 (correction): task-word theory RETRACTED; delivery may already work

jc12/jc13 place-line comparison: BOTH runs placed the REAL leaked task word
(ffffff8027d69280 / ffffff8887ccdc80, 256 votes). The "carrier ... task=
init_task P0" line prints the fallback VARIABLE, not the placed fdset word.
jc13's pre-punch KP = residual boot luck, not geometry. The bss_tail
dead-end fix is NOT indicated.

Re-read of the QEMU runs: the punch burst's FIRST setattr is a genuine
change (BATCH/19 on a fresh SCHED_OTHER/nice-0 thread) → __sched_setscheduler
runs the tail → adjust_pi → the in-adjust_pi rb_erase delivers. In the QEMU
spin runs the write likely LANDED — at the wrong alias (my QEMU bootid
address used KPHYS base 0x401f0000; the correct _text base may be
0x40200000 → ffffff80428aa868) — the watchpoint watched the wrong address
while delivery succeeded. Survival + delivery may already coexist.

Device jc12 (survived, CapEff=0): the burst's first setattr is equally a
change on device → adjust_pi should fire → the DUAL erase should deliver
*(child+0x778/+0x780)=cred. CapEff=0 contradicts that — UNLESS the burst's
first call was consumed by an EARLIER setattr in the same boot (threads
persist per process; jc12 was the first fire on its boot, so no) — or the
erase delivered into child+0x778 while /proc renders cred (+0x780): BOTH
are written by DUAL, so a render of either shows the caps.

**Next session (1 fire):** refire jc13's binary (nice stairs already in) on
a FRESH boot, NOCONT. If it survives → read the frozen child's CapEff AND
also dump /proc/<child>/task/<tid>/... plus try a setuid probe. If CapEff
still 0 on a survived stairs-run, the delivery gap is real and the next
probe is PUNCH_ALL_TIDS=1 (the dangling pi_blocked_on may sit on a
different thread of the process than waiter_tid).

Also fix the QEMU alias question (0x401f0000 vs 0x40200000) with one
watchpoint run at ffffff80428aa868 to confirm delivery-in-QEMU.

Fires spent of the 5: 2. jc13 binary (with stairs) is on the device.

## 2026-09-20 (night, run 2): fires #3 — the walk sits ON the survival boundary

jc13 refire (fresh boot, stairs): KP inside the punch's FIRST setattr —
no punch print (the print is after setattr returns). Both jc13 runs died in
the exact call jc12 survived; jc12 survived it without delivering.

Reading rb_erase's no-right path precisely for the DUAL main stamp
{pc=cred, left=child+0x780, right=0}:
- change_child picks the LEFT slot (parent->rb_left value ≠ ghost) and
  writes child into *(cred+8) — the usage|uid qword (usage stays
  0x40000000 in the low half, uid becomes address bits — expected)
- then *(child+0x780) = pc → THE WRITE. /proc status renders real_cred
  (+0x778, also written by the DUAL pi erase). CapEff should show
  0x182082 either way. It shows 0 on survived runs.

So: identical call — KP (jc13 ×2) vs survive-without-write (jc12). The
chain's behavior at burst-1 setattr is nondeterministic at the µs level
(IRQ timing / stamp tear during the re-stamp copy / CPU migration).
Survival and delivery are the SAME coin flip, not two separate problems.

Fires spent: 3/5. Remaining levers:
1. PUNCH_ALL_TIDS=1 NOCONT — the pi_blocked_on holder may be a thread
   other than waiter_tid (QEMU lldb-proven historically).
2. Direct root fire (no NOCONT): payload fires the moment caps land;
   KP risk and root chance are the same coin.

Recommendation: stop here tonight; the next session should spend fire #4
on PUNCH_ALL_TIDS NOCONT and decide fire #5 by its result.

## 2026-09-21: fire #4 (PUNCH_ALL_TIDS) KP'd pre-punch; LOCK_ROOT_W0 = dead code; fire #5 NOT spent

- Fire #4 (jc13 + PUNCH_ALL_TIDS, NOCONT): KP pre-punch — same signature
  (0 punch lines, last line pre-select). 4/5 spent.
- Attempted fix (lock.waiters root = fake_w0 instead of fake_fops) turned
  out to be DEAD CODE: mode4_main_tree is never set to 1 anywhere; the
  JC2 env reaches the FINAL else branch which ALREADY places
  root=leftmost=fake_w0, owner=fake_task|1. jc15 binary = jc13 byte-for-
  byte (md5 verified) → NOT fired. The requeue-descends-the-fops-table
  KP theory is also wrong (root was already safe).
- Current facts: identical recipe → jc12 SURVIVED (no delivery),
  jc13r1/r2/jc14 KP'd pre-print. The variance is NOT in any env we
  control yet. The KP is inside the punch's first setattr (before its
  print) or in the pre-select window.

**Fire #5 is reserved.** It must only be spent on a REAL change. Next
session (all free work first):
1. QEMU: fix the alias question by DIRECT READ — at the punch breakpoint
   dump candidate addresses (426aa868 / 4289a868 / 428aa868) and find
   which holds the cred pointer after the walk → proves delivery live.
2. QEMU: breakpoint inside the burst-1 setattr walk on the KP path;
   single-step from adjust_pi entry to find the exact faulting deref.
3. Only then design the fire-#5 change.

## 2026-09-21 (session 2): QEMU failures FULLY root-caused — P0_PHYS wrap; delivery unblocked

**The QEMU crash formula-level root cause:** data_addr/p0_data_alias computes
(phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET with compiled P0_PHYS_OFFSET=0x80000000.
QEMU virt loads the Image at phys 0x401f0000 (< 0x80000000) → the subtraction
wraps → EVERY image alias becomes unmapped 0xffffffffc2xxxxxx. Verified
against both crash signatures (WRITE_PROOF addr=ffffffffc2d89b6d; tree_left
garbage ffffffffc2b0a8e8 stored through by rb_erase+0x90).

**Fix (in tree):** p0_phys_offset runtime global + P0_PHYS env override.
QEMU launcher: KPHYS=0x401f0000 P0_PHYS=0x40000000. WRITE_PROOF addr now
prints valid 0xffffff80-prefixed aliases.

**Result: the dequeue now DELIVERS in QEMU** — the walk passed rb_erase
(previous fatal site) and moved on to rb_insert_color (the post-dequeue
requeue), which faults at 0x8: the insert walks a parent chain into a NULL
grandparent because fake_w0 carries the old WRITE-shape fields instead of
clean tree fields. gdb breakpoints/watchpoints (Z0/Z1) confirmed broken in
this QEMU build even with correct protocol (validated: hot-function bp
never fires; Z1 same) — console panic forensics is the only QEMU visibility.

**Next free work:** make the W0 payload node a clean {pc=1, left=0, right=0}
black root in the DUAL config (its fields currently encode the old write
shape and poison the requeue walk). Then QEMU should run punch → deliver →
requeue → terminate cleanly → boot_wrote=1, no panic. That validates the
FULL chain in the emulator before fire #5.

**Fire budget: 4/5 spent.** The device-side DUAL geometry needs NO change —
the device addresses were always valid; the QEMU failures were harness-only.

## 2026-09-21 (session 2, cont): MAIN-TREE DELIVERY NOW HAPPENS IN QEMU

Latest QEMU run (P0_PHYS fixed): the punch's PI walk delivered the MAIN-tree
write — *(ashmem_misc.fops) = fake_fops (THE REAL SWAP) — and crashed one
stage LATER, in rb_insert_color (the requeue), walking a semi-real parent
chain (x9 = a real kernel waiter, grandparent NULL → [0x8] deref).

So the delivery chain is now: punch → adjust_pi/chain → dequeue →
*(target)=value LANDS → requeue-insert crashes. One contained fix left:
make the post-dequeue requeue safe (the insert descends a tree whose nodes
mix our payload fields with real kernel linkage — likely fixable by giving
the ghost a prio that makes it the tree MINIMUM, or by ensuring the fake
nodes it links under are self-consistent black roots).

Remaining unknown: whether the PI-tree (DUAL +0x778) delivery also fired
before the crash (watchpoint ambiguity — the run's stop packet was the
panic-exit, so the bootid watch did NOT fire; the DUAL pi shape's left =
QEMU_TARGET may not have been reached because adjust_pi's OWN bail is
still possible; the MAIN write came from the chain's dequeue, not adjust_pi).

**Fire #5 remains reserved.** Next free iteration: QEMU console forensics
on the rb_insert_color crash → fix the requeue termination → expect a run
with punch + delivery + NO panic + boot_wrote=1 → then the root fire.

## 2026-09-21 (final): fire #5 spent — KP in the pre-punch window; budget 5/5 done

Fire #5 (prio=1 direct root, child live with payload): KP pre-punch — same
signature as jc13/jc14. QEMU at prio=1 survives the FULL route cleanly (the
rb_insert_color crash is prio-dependent — prio=1 makes the ghost the tree
minimum; the 130 mid-tree insert was the QEMU requeue-KP), but the DEVICE
KP happens BEFORE the punch and is device-only.

Durable stage.txt (survives KPs) confirms the death window: last marker =
pselect_pre_select — i.e., inside late-midstamp select → FUTEX_UNLOCK_PI →
SPIN loop, before the first punch setattr. QEMU now survives this window
every time; the device does not (~1/5). Prime suspects: oplus_secure_harden
syscall kprobes × the SPIN select-storm (each iteration is a traced
syscall), or hardware SMP/IRQ timing QEMU cannot model.

**Campaign totals (5 fires today): jc12 survive-no-delivery; jc13r1, jc13r2,
jc14, jc16 KP pre-punch.** Root: not achieved. Structural gains: pre-select
KP class eliminated (late-midstamp), frozen-stamp clobber eliminated
(SPINSTAMP), write-delivery instruction mapped (rb_erase+0x7c / +0x90),
QEMU harness garbage root-caused (P0_PHYS) and delivery demonstrated
in-emulator, prio=1 identified as the clean-insert value.

**Next session (needs user approval for any fire):** add fine-grained
durable markers INSIDE the late-midstamp window (after the 0-timeout
select, after the unlock, every 16 spin iterations) so the next fire
pinpoints the KP instruction window on hardware. No fire before that
instrumentation exists.

## 2026-09-21 (session 3): requeue KP fully decoded; QEMU full-route survival restored

**Instrumentation added (all in tree):** durable stage.txt markers
(midstamp_select_done / late_unlock_done / spin_enter / sNN every 16 /
spin_exit iters=N succ=N), env-tunable spin cadence
(SPIN_BLOCK_EVERY=4 SPIN_BLOCK_MS=1 default; QEMU-validated 8/3), and
STOP-ON-CALLS — the spin exits the moment the consumer issues its first
setattr, so the fdsets (and the ghost) go QUIESCENT before the walk owns
the words. Re-stamping DURING the walk was clobbering kernel-written
rb linkage (the pc=1-poison decode below proved the mechanism).

**rb_insert_color+0x48 KP — final decode:** the insert entry reads the
inserted node's pc. pc==0 → treated as ROOT → color black → clean
return. pc==1 (my first fix attempt) → parsed as RED parent=NULL →
grandparent deref [0x8] → the exact KP. pc=0 is the only terminator.
The earlier "pc=0 KP" was SPINSTAMP-over-the-walk (now fixed), not the
pc value.

**QEMU: FULL ROUTE SURVIVAL RESTORED** (punch fires, route completes,
no panic) with: pc=0 pi root + stop-on-calls + cadence 8/3 + prio=1.

**Device binary rebuilt with all of the above (jc17). Next fire
(user-gated): diagnostic NOCONT — if it survives, frozen-child CapEff
tells us if delivery landed on hardware; markers pinpoint any KP stage.

## 2026-09-21 (session 3, jc17 diagnostic fire): KP PINPOINTED — inside the spin loop at ~iteration 96

Fire (jc17 NOCONT, prio=1, cadence 8/3): KP. Durable markers (first-ever
hardware stage attribution): last = s96 — the device dies INSIDE the
SPINSTAMP loop after ~96 iterations (~96ms into the 150ms window), BEFORE
the first punch (0 punch lines). QEMU runs the same loop to completion
every time.

Interpretation: the spin loop itself is the device-only killer —
consistent with the oplus syscall-hook × select-storm theory. The KP
moves with the loop (jc12's 253-iteration run at 8/3 SURVIVED once;
jc13r1/r2/jc14/jc16/jc17 all died in-window) → probabilistic exposure
growing with iteration count, NOT a fixed instruction fault.

Mitigation designed (not yet built): SPIN_MAX_ITERS cap + stop-on-calls
already in tree; next candidate recipe = cap the loop at ~32 iterations
(32 re-stamps in 150ms is still 20x the frozen-stamp freshness) — but
each additional fire costs budget. Recommend: STOP fires tonight; next
session design the cap + user approves.

## 2026-09-21 (session 3, final): jc18 built — handoff + cap + black roots

QEMU iteration results:
- pc=1 → 0 across ALL W0 sites (pc=1 is a RED root = invalid; rb_insert_color
  entry treats pc=0 as black root = clean terminate).
- LOCK_EMPTY (waiters root/leftmost=0, owner=0) now reachable together with
  MODE4_OWNER_TASK. One run with it: punch fired, FULL route completed, no
  panic. Two later stability runs KP'd again at rb_insert_color with
  x9=REAL slab node — traced to the QEMU_DUAL target (bootid) sitting
  inside the sysctl rb backing array: delivering *(bootid)=cred corrupts
  the real sysctl tree → subsequent rb ops walk corrupted nodes. The
  DEVICE DUAL target is child+0x780 (task_struct field, not an rb tree) —
  this collateral does not exist on hardware.
- Handoff race fixed: punch_consume_go is now set by the WAITER thread
  after its FINAL stamp (previously armed before select → punch raced the
  last re-copy). SPIN_MAX_ITERS cap (32) verified working in QEMU.

jc18 = device binary with: spin cap 32, handoff, LOCK_EMPTY shape, black
roots, durable markers, cadence 8/3, prio=1, stop-on-calls. Pushed
(hash 52d2c0da...). Next fire (user-gated): NOCONT diagnostic.

## 2026-09-21 (jc19 fire): spin stable 2/2; walk survival = the last coin flip

jc19 (single-shot, all jc18 fixes): markers show spin_exit iters=32 again —
the storm window is SOLVED (2/2 since the cap). KP hit before the punch
print → inside setattr#1's walk (jc18's walk #1 survived, jc19's didn't;
no second setattr was ever reached, so the single-shot fix wasn't the
variable). Walk survival history: jc12 ✓ (prio=130), jc18 ✓ (prio=1),
jc19 ✗ (prio=1) → ~2/3 and the depth of the chain walk differs by prio:
prio=1 (highest) walks the FULL real PI dag including half-linked owner
waiters; prio=130 exits earlier. jc12's proven-walk prio was 130.

Next candidate recipe: jc19 + MODE4_GHOST_PRIO=130 (jc12's walk depth,
with all new fixes). Also candidate: drop prio to 120 (never equals the
post-setattr nice-19-derived prio 139/19 boundaries).

## 2026-09-21 (jc20 fire): walk depth not the variable; LOCK_EMPTY is

jc20 (prio=130 + all fixes): spin 32 ✓ (3/3 storm solved), punch#1
returned 0 ✓, KP after — same post-punch window as jc18. With single-shot
active there was no setattr#2, so the remaining delta vs jc12 (the ONE
fully-surviving fire) is now isolated to LOCK_EMPTY:
- jc12: waiters=W0, owner=fake_task|1 → walk exits via owner-task path,
  ghost left consistent → survived punch + select + route + park.
- jc18/20 (LOCK_EMPTY: waiters=0, owner=0): walk exits via owner-NULL
  early-exit → ghost NOT dequeued → pi_blocked_on stays = ghost → the
  post-punch window (select timeout, thread exits, attempt-2 re-arm)
  re-walks the never-cleaned dangling → KP.
Next recipe: jc20 minus LOCK_EMPTY (waiters=W0 owner=fake_task|1 = the
jc12 shape) + keep cap/handoff/single-shot/pc=0/prio=130/markers.
