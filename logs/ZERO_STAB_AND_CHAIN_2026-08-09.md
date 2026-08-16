# ZERO_NAME stability + CHAIN (2026-08-09)

## Detection bug
Earlier “3/3 softboot” used **ADB drop = softboot**. Wrong: shell can die while **same boot_id** continues; stage file is truth.

## Clean ZERO_NAME (re-fire, boot_id tracked)

| Check | Result |
|-------|--------|
| EDEADLK | 35 |
| same boot | **yes** |
| `post_setattr ret=0` | **yes** |
| cfi write | **errno 22** (no fops redirect — expected) |
| full route return | **yes** |

So **ZERO_NAME is real and repeatable** when ADB is not confused with softboot.

## CHAIN after that success (same boot, name already 0)

| Phase | Result |
|-------|--------|
| 1 ZERO_NAME again | stage ends `pre_setattr` only; **new boot_id** (true softboot) |
| 2 ION | never reached |

CHAIN re-enters erase with ZERO geometry (redundant) then would ION; this run died on phase1. Flaky or CHAIN packing (rb-leaf fops) interaction.

## Scoreboard

| Path | Survive setprio | cfi≠22 |
|------|-----------------|--------|
| Plateau default | yes | no |
| ZERO_NAME | **yes (confirmed)** | no |
| Classic MISC−8 erase | no | — |
| ION / CHAIN phase2 | not proven alive | no |

## Not plateau cross
Still no fops redirect. Best lever remains: **name zero holds** → get **ION root write alive**.
