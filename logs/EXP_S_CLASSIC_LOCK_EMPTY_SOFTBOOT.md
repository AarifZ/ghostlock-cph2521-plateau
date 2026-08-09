# EXP S — classic erase + LOCK_EMPTY — SOFTBOOT

**Boot pre:** `b6c54187-…` uptime ~20s (clean adb reboot)  
**Env:** `MODE4_CLASSIC_MAPPED=1 MODE4_LOCK_EMPTY=1` consumer on (prio mismatch / erase)

## Result

| Check | Result |
|-------|--------|
| LOCK_EMPTY | waiters=0 owner=0 logged |
| EDEADLK | 35 |
| place | parent=MISC-8 right=fake_fops |
| Survive | **SOFTBOOT** |

## Interpretation

Softboot is **not** from walking fake_lock.waiters→W0 (empty lock still dies).  
Still points at **rb_erase with parent=MISC-8** (write and/or post-write), not spray tree hygiene.

## Recovery

`post_softboot_hardboot.ps1` → **CLEAN** `13103b34-…` uptime ~22s (boot_id changed).
