# Option 2 — avoid classic MISC-8 parent erase

## Step A: MODE4_ZERO_NAME — **ALIVE (big step)**

**Geometry:** parent = `ashmem_misc` base (MISC−16), right=0, left=0, prio=200, LOCK_OWNER0  
**Write:** leaf only-right → `*(name)=0` (wait_lock for ION at MISC−8)

### Stage (full return, same boot)

```text
pre_setattr
post_setattr ret=0 errno=0
cfi_on_punch_enter
cfi_open_ok
cfi_write_ret=-1 errno=22   ← expected (fops not redirected)
route_threads_returned
```

**PROOF1 contrast:** classic MISC−8 parent died at `pre_setattr` only.  
**ZERO_NAME:** erase near miscdevice **survives setprio**.

So the softboot is **specific to parent=MISC−8 / fops-slot geometry**, not “any erase near ashmem_misc.”

## Step B: MODE4_ION_SAFE same boot — **SOFTBOOT**

After ZERO_NAME (name hopefully 0), same boot:

```text
ION_SAFE lock=MISC-8 parent=1 right=fake_fops (rb-leaf fops head)
```

Stage last: **`pre_setattr` only** → death again inside setprio (like classic).

Hardboot recovered CLEAN.

### Interpretation

| Path | Survive setprio? |
|------|------------------|
| parent=MISC−8 classic | no |
| parent=MISC−16 zero name | **yes** |
| ION root lock=MISC−8 after zero | no (this fire) |

ION may still fail because: name zero didn’t stick / isn’t wait_lock; or root erase + re-enqueue still lethal even with rb-leaf fops; or second spray/race.

## Plateau

Still **not** cfi≠22 / uid0. But we have a **surviving erase write** next to miscdevice (name slot) — first non-softboot AAW near the target.

## Next

1. Confirm name zero (or fold zero+ION into one stamp if possible)  
2. Debug ION_SAFE death with PROOF (already pre_setattr-only)  
3. Try ION immediately in **same process** after ZERO without full re-spray (harder)
