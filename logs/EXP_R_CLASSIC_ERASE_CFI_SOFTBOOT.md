# EXP R - classic erase + CFI_ON_PUNCH - SOFTBOOT

**Env:** MODE4_CLASSIC_MAPPED=1 MODE4_CFI_ON_PUNCH=1 (prio mismatch, erase path)
**Boot pre:** 142693a7...
**Result:** SOFTBOOT after place (same as O2/I4). No consumer/CFI log before death.
**Recovery:** post_softboot_hardboot.ps1 -> CLEAN boot_id=0fe334fe... uptime~20s
