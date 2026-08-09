# GLM 5.2 main-gadget experiment — REJECTED (2026-08-02)

## What GLM patched
- **Stack MAIN tree classic gadget**: `tree_pc=MISC-8`, `tree_right=fake_fops`, `tree_left=0`
- **PI tree clean** on stack: `0,0,0`
- **Heap W0**: both trees clean black root `(1,0,0)`, **prio=100** (stack prio=1 so W0 is leftmost)
- Theory: main erase does `*MISC=fake_fops` without PI cascade softboot

## On-device result (clean reboot, KS attempt=4, late spray)
```
stack mode4 MAIN-GADGET tree_pc=…(MISC-8) tree_right=…(fake_fops)
pselect place tree=ffffff802a91a8e0  (MISC-8 on overlay)
pselect pre-select +2ms
→ SOFTBOOT (ADB gone)
```
Log: `logs/glm_main_gadget.txt`

## Verdict
**No progress vs plateau.** Softboots at select with MISC-8 on main tree overlay.
Matches earlier finding: stack MAIN+MISC shapes are toxic on CPH2521.

## Policy
- Do **NOT** merge to `main` / plateau / upstream
- Keep plateau: success=1 + cfi errno=22 + ALIVE (`logs/plateau_saved.txt`)
- Branch `exp/glm-main-gadget` may remain for reference only

## Plateau remains closest
| Metric | Plateau | GLM main-gadget |
|--------|---------|-----------------|
| Survive select | YES | NO |
| success=1 | YES | n/a |
| cfi errno=22 | YES | n/a |
| fops redirect | NO | NO |
