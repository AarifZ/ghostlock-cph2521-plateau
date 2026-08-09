# Kernel source evaluation + softboot ADB policy (2026-08-09)

## Softboot / ADB policy (locked) — DO NOT SKIP

After **any** softboot, ADB death, or `error: closed` / listed-but-shell-dead:

1. **Do not idle-wait** hoping ADB comes back while “thinking”  
2. **USB recover first** (emulate unplug/replug):  
   `.\adb_usb_recover.ps1 -ForceCycle`  
   → `adb kill-server` + disable/enable Android/OPPO USB PnP nodes + `adb start-server`  
3. **Hard reboot** (mandatory after softboot):  
   `.\post_softboot_hardboot.ps1`  
   → USB recover if needed → `adb reboot` → wait `boot_completed=1` with USB re-cycle if shell drops → **uptime ≲ 45s** + new/fresh `boot_id`  
4. Only then fire the next experiment  

Stale signals: `error: closed`, device in `adb devices` but shell fails, mid-run “no devices”, stage ends at `pselect_pre_select` + ADB drop.

Do **not** keep testing on high uptime after a crash.

---

## GitHub trees you found

### 1) `oppo-source/android_kernel_oppo_sm8475`  
Branch: `oppo/sm8475_b_16.0.0_reno10_pro_plus`

| Check | Result |
|--------|--------|
| Device match | **Yes** — Reno 10 Pro+ / SM8475 (waipio/taro family) |
| Useful for GhostLock? | **Yes (high ROI)** |
| Full clone? | Large (~GKI tree). Prefer **sparse/raw file** pull |

**Pulled locally (partial):**

`Oppo/kernel-src-sm8475-partial/`

- `kernel/locking/rtmutex.c`  
- `kernel/locking/rtmutex_common.h`  
- `include/linux/rtmutex.h`  
- `kernel/futex/core.c`  
- `kernel/sched/core.c`  

### 2) `oppo-source/android_kernel_modules_and_devicetree_oppo_mt6889`

| Check | Result |
|--------|--------|
| Device match | **No** — MT6889 / Reno **5** Pro (MediaTek), kernel 4.14/5.10 DT modules |
| Useful for CPH2521? | **No** for this exploit |

---

## Will kernel source help?

**Yes — for understanding paths and fields. No — as a substitute for on-device stamp timing.**

| Source gives you | Does **not** give you |
|------------------|------------------------|
| Exact C logic of `remove_waiter` / `adjust_prio_chain` / `start_proxy_lock` | Live KASLR / P0 alias |
| Early-out conditions (why write never fires) | Proof write landed |
| `pi_blocked_on` / top_waiter rules | Softboot-free stamp that works on CPH |
| Confirm bug still uses `current` not `waiter->task` | |

### Smoking-gun lines from **this** tree’s `remove_waiter`

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;   /* GhostLock: wrong task */
```

Still vulnerable-style cleanup (not fixed to `waiter->task`).

### `rt_mutex_adjust_pi` (consumer / sched path)

```c
waiter = task->pi_blocked_on;
if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task)))
    return;   /* no chain → no rb_erase */
next_lock = waiter->lock;
rt_mutex_adjust_prio_chain(task, ..., next_lock, ...);
```

And in chain walk:

```c
if (next_lock != waiter->lock)
    goto out;   /* lock identity must match */
```

**Implication for cfi22:** punch can “succeed” (`sched_setattr` OK) while **adjust never requeues/erases** if:

- `pi_blocked_on` is NULL on that task, or  
- overlay prio/deadline **equals** task’s (waiter_equal), or  
- `waiter->lock` ≠ chain’s expected lock (fake_lock vs real PI mutex).

That is the high-ROI design target — better than more stamp thrash.

Dequeue uses `rb_erase_cached` on `waiter->tree_entry` (main) / `pi_tree_entry` — same only-right write class as Image `rb_erase`.

---

## How this compares to “Samsung whole firmware”

| Material | Role |
|----------|------|
| **Kernel source (sm8475 branch)** | Logic of UAF + adjust (this) |
| **boot.img + kallsyms + Ghidra** | Offsets + proof on binary (you have) |
| **vendor_boot / DTB** | Secondary |
| **XBL** | Irrelevant to GhostLock |
| **Full OFP 9GB** | Not needed for write land |

---

## Next on phone (when ready)

Fresh boot is ready (~22s). Recommended **one** experiment after this RE:

- Design stamp so `waiter->lock` matches the lock used in chain, **and** `pi_blocked_on` still points at overlay when punch runs — without putting MISC on main at select.

Do **not** re-fire A / E2.
