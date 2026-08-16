# boot_id write-proof side effect (CPH2521)

## What happens

Write-proof targets `sysctl_bootid` (P0) and stores `fake_fops` into uuid[0..7].

`/proc/sys/kernel/random/boot_id` string changes (e.g. `0001a37e-89ff-ffff-...`).

## Why apps fail to launch

Android ashmem device node is often:

```text
/dev/ashmem{boot_id}
```

`init_ashmem_path()` in our exploit also opens `/dev/ashmem` + boot_id.

After the kernel uuid is corrupted:

- New opens of ashmem via the **old** path fail
- Apps that were **not already open** cannot create ashmem regions → launch / surfaceflinger-adjacent failures
- Already-running apps may keep working until they need a new ashmem mapping

## Policy

1. Use boot_id write-proof only as a **diagnostic gate**, not a long-lived state.
2. **`adb reboot` immediately after a successful bootid proof** to restore a real uuid and app launches.
3. Prefer future write-proof targets that are **not** boot_id (quiet BSS unused by userspace) once identified.

## Closer?

Yes for **research** (AAW real). No for **uid0** until `*MISC=fake_fops` lands ALIVE.
