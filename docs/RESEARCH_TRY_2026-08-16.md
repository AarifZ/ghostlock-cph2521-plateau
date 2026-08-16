# Research tries after AAW proof (2026-08-16)

## Safe AAW class (proven)

only-left: `parent_color=fake_fops`, `left=target`, `owner=1`, shift=-2  
→ `*target = fake_fops`, ALIVE if target’s **+8/+16 are not live kernel ptrs**.

| Target | Result |
|--------|--------|
| `sysctl_bootid` (BSS uuid) | **landed×2** |
| `ashmem_misc.fops` | softboot pre_setattr |
| `ashmem_misc.name` (ZION NAME0, parent_color=0) | softboot pre_setattr |
| `ashmem_fops.write` (FOPS_SLOT) | softboot pre_setattr |

## Why

only-left **links `left` into the tree** under `fake_fops`. Later walks treat `left` as `rb_node` and follow **+8/+16**:

- bootid: mostly uuid/quiet BSS → OK  
- miscdevice / fops table: **pointers / CFI JTs** → softboot  

## Other paths

| Path | Result |
|------|--------|
| ION_SAFE alone (lock=MISC-8, no zero) | **ALIVE**, cfi22 (no erase — wait_lock≠0) |
| CHAIN ZERO_NAME (parent=MISC-16) | softboot phase1 |
| Classic parent=MISC-8 | softboot |

## Live logging

`/sdcard/ghostlock/aarif/live_sync.log` (O_SYNC) — last line always `pre_setattr` on softboot-class MISC stamps.

## Plateau status (unchanged product)

- Still **cfi22** for fops path; no uid0.  
- Research plateau **passed**: reliable AAW to quiet BSS.  
- Blocker: **cannot zero wait_lock / patch misc or fops-table without linking a toxic node**.

## Next theories (not yet tried)

1. Find **quiet BSS** that is useful (or copy-shape leak).  
2. **pstore/last_kmsg** fault PC on softboot.  
3. Root-erase without name zero (different lock geometry).  
4. aristotle continuous-pselect / policy-alt for MISC (fidelity port) — may still hit +8/+16 walk.  
