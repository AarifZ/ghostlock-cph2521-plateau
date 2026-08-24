# Checkpoint — CPH2521 kevent hook / g_boot_state / GBOOT (Z43–Z49)

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` only.  
**Pickup:** `docs/NEXT_SESSION_2026-08-24.md` (this cycle supersedes the Z29 “next fire is cred” text).  
**Device:** OPPO Reno 10 Pro+ CPH2521 / OP56D3L1 / `5.10.236-android12-9-o-g74d132f4467a` locked BL  
**Binary:** `ghostlock-cph2521` (~209768 bytes after kprobe/ptwalk). Rebuild `.\build_cph2521.ps1` (NDK r27d).

Logs live on disk under `logs/aarif_pull/` (gitignored):  
`Z43_holdpark_*`, `Z44_kptr_console.txt`, `Z45_gboot_console.txt`, `Z45_modip.txt`, `Z46_gboot_console.txt`, `Z47_gboot_console.txt`, `Z48_gboot_p0_console.txt`, `Z49_gboot_ptwalk_console.txt`.

---

## What this cycle proved

Park (Z15 PLAIN-STORE `*selinux_state = P0(0x02BB0000)`) is still the product. Same-process self-cred dies on **pselect return** because `oplus_root_check_post_handler` SIGKILLs uid drops. That hook is **not** in GKI `cred.c`. It is vendor module `oplus_security_guard.ko` (companion tree `android_kernel_modules_and_devicetree_oppo_sm8475`, `vendor/oplus/kernel/secureguard/gki2.0/rootguard/`).

Pulled kos: `logs/aarif_pull/Z43_oplus_security_guard.ko` (31872). ELF:

| symbol | section | file offset in core layout (5.10 STRICT_MODULE_RWX) |
|--------|---------|------------------------------------------------------|
| `.text` | EXEC page | `0x0000` (size `0xfe0`) |
| `oplus_root_check_pre_handler` | `.text+0x3ac` | |
| `oplus_root_check_post_handler` | `.text+0x3e8` | |
| `is_unlocked` | `.text+0x4b4` | `LDRB + RET` — **any nonzero byte is orange** |
| `g_boot_state` | `.data..ro_after_init` | **1 byte at core `+0x3000`** (own page; 8-byte store only hits pad) |

`is_unlocked()` is `g_boot_state == ORANGE` in source; the live `.ko` compiles to `LDRB w0,[g_boot_state]; RET`. Locked BL → GREEN (0). Setting the byte nonzero disables the SIGKILL.

**No userspace kevent disable flag.** `WHITE_LIST_SUPPORT` is userdebug-only. Killing `oplus_kevent` userspace does not stop the probe. `sys_exit` ftrace enable is already 0; OPPO uses `tracepoint_probe_register`.

Config on device (`/proc/config.gz` after park):

- `# CONFIG_RANDOMIZE_MODULE_REGION_FULL is not set` (128MB window next to kernel, still per-boot)
- `CONFIG_STRICT_MODULE_RWX=y` → `ro_after_init` **RO** after init
- `CONFIG_IKCONFIG_PROC=y`

---

## Fires

| id | what | result |
|----|------|--------|
| **Z43** | `MODE4_UID0_HOLDPARK` | Park live. kallsyms **hashed**. Names present (`g_boot_state`, `is_unlocked`, …). `/proc/modules` addresses 0. |
| **Z44** | Walk2 `kptr_restrict=0` VALUE `0xffffff8100000000` | Park OK, then KP at `pselect pre-select +2ms`. VALUE is **live DRAM**, not a zero rb_node. **Banned.** kptr unhash is also a dead end for later boots (module VA moves; walk budget already spent). |
| **Z45** | GBOOT harvest, wrong IP window `0xffffffc0` | Park + HOLD. Side `modip_probe`: live PCs are **`0xffffffe4…`**, hook `+0x3e8`. |
| **Z46** | Still too-narrow `0xffffffe0` window | This boot was `0xffffffd5…`. Side probe: `.text ffffffd549808000`. |
| **Z47** | In-process harvest + punch **module VA** | `HOOKIP …3e8`, `g_boot=ffffffd482374000`, `*VA = BSS\|1`. KP. RO vmalloc PTE. |
| **Z48** | Harvest + kernel read-watchpoint for phys | VA `ffffffedf8041000`. `perf_event_open(BREAKPOINT)` **EINVAL** on any kernel addr (user wp works). HOLD, no punch. |
| **Z49** | Harvest + kprobe `@ADDR` PGD walk | VA `ffffffe163a31000`, `swapper_pg_dir` P0 `ffffff802a491000`, idx `389/285/49`. `kprobe_events` **EACCES** (DAC; `readtracefs` is read-only). HOLD, no punch. Process later died on ADB SIGHUP; **Permissive persisted**. **Do not second GhostLock (Z5).** Phone later rebooted to `2687342b`. |

Runners (Unix LF only): `gl_run_holdpark.sh`, `gl_run_kptr.sh`, `gl_run_gboot.sh` → `/data/local/tmp/gl_uid0`.

---

## PLAIN-STORE constraints (do not violate)

- VALUE is also an rb_node: must be a **mapped zero page** (park: `P0(0x02BB0000)`).
- `change_child` stores at `VALUE+8` (`parent&~3`).
- **Z44:** `0xffffff8100000000` is live DRAM → KP. Do not reuse. Do not try `0xffffff8000000000` as “safer” without evidence it is zeros.
- **GBOOT VALUE:** `P0(0x02BB0000)|1` so stored byte0=1 (black); rb_parent masks `~3` → BSS+8 still safe.
- **Z47:** module VA of `.data..ro_after_init` is RO. Punch **physmap** (`0xffffff80…`) only.
- 5.10 `perf_virt_to_phys()` **returns 0 for vmalloc**. Instruction samples cannot PFN modules.
- Kernel hw breakpoints from uid 2000: **EINVAL** even with `perf_event_paranoid=-1`.
- `/sys/kernel/tracing/kprobe_events`: **EACCES** after park.

Walk budget: walk 1 = park, walk 2 = **one** data punch. Third walk = Z26 KP. No spray after park. No wrap `ffffff87/88/89`. No 8-byte NULL into `selinux_state`. No second GhostLock process on a park boot.

---

## Perf leak that works (no extra walk)

After park, PMU type=8 `inst_retired`, `exclude_user=1`:

- Live instruction VAs are **not** file kallsyms `0xffffffc008000000`. They sit in a per-boot window (`0xffffffd4` / `0xffffffe1` / `0xffffffe4` / `0xffffffed` observed).
- Hottest pages = getpid / el0_svc.
- **Hook page:** not hottest, many IPs with page-off in `0x3ac–0x4c8` (pre `0x3ac`, post `0x3e8`, `is_unlocked` `0x4b4`). Smoking gun: **`off=0x3e8`**.
- `g_boot_state` VA = `(hook_ip & ~0xfff) + 0x3000`.

Code: `uid0_harvest_modip()` in `src/core/main.c`. Standalone: `tools/modip_probe.c` (not a second GhostLock).

`swapper_pg_dir` file `ffffffc00a491000` → P0 **`ffffff802a491000`** (linear, known, no leak needed). ARM64 39-bit 4K: `PGDIR_SHIFT=30`, `PMD_SHIFT=21`. Z49 indexes for that boot’s VA were `389/285/49`.

---

## Blocker for living uid0

Need **hook off + cred** in two walks.

Winning shape once P0(`g_boot_state`) is known **before walk 2** (or as walk 1 if park is skipped):

1. `*P0(g_boot_state) = BSS|1` (byte 0 = 1, page is RW via physmap).
2. `*(task+0x780)` and/or `real_cred+0x778` = `init_cred` (self, not child-only).

Missing primitive: **8-byte kernel read** of `swapper_pg_dir[i]` (and then PMD/PTE) to turn the leaked module VA into a RAM phys → `P0 = 0xffffff8000000000 + (phys - 0x80000000)`.

Tried and failed for that read: kptr unhash (Z44 KP + walk waste), sysfs module sections (DAC), kprobe `@ADDR` (EACCES), kernel watchpoint (EINVAL), `perf` PHYS_ADDR (vmalloc → 0).

Likely remaining AAR: CFI-safe **fops swap + `pipe_physrw`** (offsets.h already has `*.cfi_jt` stubs). That is a data punch (walk 2) then pipe R/W without a third UAF walk. Do **not** spray after park. Or skip park: walk1 AAR-setup / g_boot, walk2 cred, stay Enforcing (ColorOS 15s may still reboot after uid0).

Self-cred without hook-off still SIGKILLs on pselect return. Child `real_cred` can look root in `/proc/status` while `getuid()` stays 2000.

---

## ADB (updated)

| | |
|--|--|
| WiFi | `192.168.1.108:5555` Shizuku 13.6 |
| USB | `596666e9` |
| After **kernel panic / softboot** | **WiFi first.** USB often dead. Do not USB-PnP. |
| After clean `adb reboot` / ColorOS 15s | USB usually comes back; 5555 dead until Shizuku. |
| After park process SIGHUP | `enforce=0` can **persist**. No second GhostLock (**Z5**). |

Do not fire on boots ≲ 2 min. Unix LF runners only (`gl_run_*.sh`). No `fire_mode.ps1`.

Last classify before this write: boot `2687342b`, Enforcing, young, USB up, **5555 refused** (Shizuku not listening). Ping `192.168.1.108` still worked.

---

## Do not reopen / do not repeat

ION / PAD3 / dual-PI / swapped ashmem / `MODE4_ROOT` this cycle / JoinChang 6.12 `.write_iter` / 8-byte NULL `selinux_state` / wrap to P0 / kptr VALUE `0xffffff8100000000` / GBOOT punch to **module VA** / second GhostLock on a Permissive park boot / `logcat -c` if capturing popups.
