# EXP Y — classic write + zeroed fake_fops — still SOFTBOOT (plateau not crossed)

## Hypothesis
skb payload memset `0x41` left unset `file_operations` slots as `0x4141…`. After `*MISC=fake_fops`, system ashmem calls those hooks → softboot.

## Fix applied
`put_fake_fops_table`: `memset(..., 0, 0x100)` before filling known slots.

## Result
`MODE4_CLASSIC_MAPPED+SAFE+LOCK_OWNER0+CFI_ON_PUNCH` still **softboot** after place (EDEADLK=35). No cfi log.

## Related EXP X (CLASSIC_NOP)
`right=real ashmem_fops` also softboot — Ghidra only-right does `*right=parent_color`, which **writes into the fops table object**. Real table is RO or critical → panic. So NOP is not a pure “no-op MISC write” probe.

## Plateau status (honest)
Still **not crossed**: no cfi≠22, no uid0.

| Fact | Implication |
|------|-------------|
| Zeroed fops not enough | Softboot ≠ only 0x41 garbage (or table still incomplete / erase walks MISC-8) |
| Classic erase still dies | Main write path blocked until erase/MISC survival solved |
| Research still valid | We know re-enqueue+fops-as-root is fatal; classic is only MISC write that keeps waiters root |

## Recovery
CLEAN `fabe043c-…` after hardboot.
