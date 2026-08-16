# GhostLock CPH2521 — agent / lab context (pointer)

**Current checkpoint (progress + open blocker):**  
[`CPH2521_CHECKPOINT_2026-08-16.md`](CPH2521_CHECKPOINT_2026-08-16.md)

**Plateau-only freeze (2026-08-02):**  
[`CPH2521_CLOSEST_CHECKPOINT.md`](CPH2521_CLOSEST_CHECKPOINT.md)

**Boot image (zip):** `assets/CPH2521_boot.img.zip`

**Branch:** `research/cph2521-zero-name-standalone`

### Hard rules (unchanged)

- Default binary path = **plateau** (no research env) → success=1, cfi errno=22, ALIVE.
- Research is **opt-in** `MODE4_*` only.
- ADB: no USB thrash; truth = `boot_id` + live_sync/stage.
- After boot_id write-proof → **reboot** (ashmem path breaks new app launches).
- Do not thrash MISC only-left without a new theory.

### Quick fire

```powershell
.\build_cph2521.ps1
.\fire_mode.ps1 -ModeEnv "MODE4_ROOT_SPRAY=1"   # control
.\fire_mode.ps1 -ModeEnv "MODE4_WRITE_PROOF=1"  # AAW gate; reboot after
```
