Thanks for the 5.10 compact-waiter support and the CPH2521 offset table ([4f23d44](https://github.com/JoinChang/ghostlock-oneplus/commit/4f23d44)). Updating with what we have actually proven on device, and asking for a concrete recipe — living `getuid()==0` is still not achieved.

## You were right on the earlier points

- `cfi write ret=-1 errno=22` is configfs `EINVAL`, not a kCFI crash. Opening the swapped ashmem node is what dies; skipping that open, the swap can survive.
- `kernel_phys_load = 0xa8000000` is correct (Nothing Phone 2 `/proc/iomem` + our `boot_id` write proof). P0 data alias is not the bug.
- C ashmem is present (`ashmem_misc.fops` @ image `0x0291A8E8`).

KASLR is also no longer a mystery: `CONFIG_RANDOMIZE_BASE=y` and slide is **not** 0. We leak it with an Aristotle-style `boot_id` → `nfulnl_logger` oracle (`MODE4_SLIDE`). Decoded slides have included `0x1ecc400000`, `0x24aee00000`, etc. Earlier fake-fops text pointers were wrong when we assumed slide=0.

## Progress on CPH2521 (ColorOS 16.0.5.1002, `5.10.236-android12-9-o-g74d132f4467a`, locked BL)

| Piece | Status |
|---|---|
| Compact waiter (words 2–9, shift=0) | Works |
| P0 data AAW (`*sysctl_bootid`) | Works |
| KASLR slide leak | Works |
| Durable SELinux Permissive | **Works** — PLAIN-STORE `*selinux_state = P0(mapped zero page)` so `enforcing=0` and `initialized` stays set |
| Path B Write-1 as 8-byte kernel ptr (low byte 0) into `selinux_state` | **Panics this build** (`initialized=0` / delayed death). Do not use. |
| Staged fops swap, only `.write` = configfs JT, never open | **Survives** (N3/N5 ALIVE). `rb_erase` clobbers `fake_fops+0x08` (llseek) → ~2 min death clock unless repaired |
| Living `getuid()==0` | **Not achieved** |

### Why Path B cred dies here (not GKI)

ColorOS loads vendor modules (not baked into vmlinux; MTK Find X5 `=y` header is the same source, different Kconfig):

```
oplus_security_guard     (O)
oplus_secure_harden      (O)
oplus_security_keventupload (O)
```

`oplus_root_check_post_handler` on `sys_exit` SIGKILLs if uid at `sys_enter` was nonzero and uid/euid/gid/egid dropped, unless `is_unlocked()`. Live `is_unlocked` is `LDRB`+`RET` — **any nonzero** `g_boot_state` is ORANGE. `g_boot_state` is 1 byte at module `.text+0x3000` (`.data..ro_after_init`, own page).

- Store to the **module VA** → KP (`CONFIG_STRICT_MODULE_RWX=y`).
- Store must go to the **physmap** alias (`0xffffff80…`).
- Perf can leak the hook page (page-off `0x3e8`) after park with no extra UAF walk. 5.10 `perf_virt_to_phys()` returns 0 for vmalloc, so samples do not give a PFN.
- kprobe_events is `EACCES` from shell; kernel hw breakpoints are `EINVAL` from uid 2000.

So Path B (`task->cred = init_cred`) without disarming `g_boot_state` is a SIGKILL on pselect return. Child `/proc/status` can look uid 0 (`real_cred`) while `getuid()` stays 2000.

### Why README Path A (UMH) looks dead on this build

Live `/proc/config.gz`:

```
CONFIG_CFI_CLANG=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
```

Empty `STATIC_USERMODEHELPER_PATH` is documented as *execute no helper*. If that reading is right, `call_usermodehelper` cannot run `/data/local/tmp/a/e --umh`, and `modprobe_path` overwrite cannot exec either. C ashmem being present is then not enough for Path A.

Checkpoints (research fork, not a PR):

- https://github.com/AarifZ/ghostlock-cph2521-plateau/blob/research-master/docs/Z49_GBOOT_CHECKPOINT_2026-08-24.md
- https://github.com/AarifZ/ghostlock-cph2521-plateau/blob/research-master/docs/HANDOFF_2026-08-23.md

## What we think the remaining path is

One surviving mode=4 swap (already proven ALIVE if we skip the CFI open) → configfs R/W / `pipe_physrw` in the llseek-repair window → 8-byte kernel **read** of `swapper_pg_dir` (P0 `ffffff802a491000`) → `P0(g_boot_state)=1` via physmap → `*(task+0x778/0x780)=init_cred`.

That is data-only after the swap. No third UAF walk. We have `swap_probe` written for the configfs side; we have **not** completed it on a live N3/N5 window (host timing / ADB, not a new theory).

## Guidance we actually need

1. **`STATIC_USERMODEHELPER_PATH=""`** — On working C-ashmem devices (OnePlus 13), is this unset? If a device has an empty path, do you still treat Path A as available, or is the real fallback Path B cred?

2. **`oplus_security_guard` ROOTGUARD** — Do your working OnePlus units load this? After Path B `task->cred = init_cred`, does the rooted child survive `sys_exit`? Any disable besides writing `g_boot_state` (userspace kevent kill does nothing; `sys_exit` ftrace enable is already 0; OPPO uses `tracepoint_probe_register`)?

3. **SWAP_NOCFI → first configfs pwrite** — After a surviving swap we deliberately never `open()` the swapped node (that open is the death). How do you get the first configfs `pwrite`? Reuse an ashmem fd opened *before* the swap? That is the step we have not landed on device.

4. **5.10 `pipe_physrw`** — Any known difference vs 6.6/6.12 (vmemmap, `pipe_buffer`, slab coloring) we should not copy blindly?

5. **Intended CPH2521 recipe** given (1)+(2): please confirm whether it is compact waiter → mode=4 swap → `pipe_physrw` → 1-byte `enforcing` → **cred** (UMH skipped), with ROOTGUARD disarmed first if the module is present — or something else.

Happy to test a short recipe on this unit. Device is up, Enforcing, shell uid 2000. We will not fire a second GhostLock on a park boot.
