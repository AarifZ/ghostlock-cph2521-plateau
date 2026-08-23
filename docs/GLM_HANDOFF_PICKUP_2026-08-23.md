# GLM 5.3 handoff pickup — 2026-08-23

**Branch:** `research-master` (local tip includes SWAP_NOCFI commits; `ahead 7` of `plateau/research-master` at last check)  
**Picked up by:** Grok after GLM usage exhausted mid-cycle  

**Upstream issue:** [JoinChang/ghostlock-oneplus#31](https://github.com/JoinChang/ghostlock-oneplus/issues/31) — owner says errno=22 is configfs EINVAL not kCFI; KPHYS default 0xa8000000. Lab agrees on 22≠CFI (QEMU kwrite=35) and KPHYS (Nothing Phone 2 iomem). **Do not** treat CFI as the remaining blocker. KASLR is leaked (`MODE4_SLIDE`). See `grok_context.md` §3b.

**Superseded as the pickup file.** Next agent: read `docs/NEXT_SESSION_2026-08-23.md` first (N7 delayed death, O21/O22, N8/N9, SWAP_HOLD binary, first-fire recipe). This file is GLM-era only.  

---

## What GLM achieved (do not re-open)

### 1. SLIDE oracle works (`MODE4_SLIDE=1`)
Aristotle-style: stack erase redirects `boot_id` ctl_table.data → `nfulnl_logger`.  
Reading `/proc/sys/kernel/random/boot_id` yields a **synthetic UUID** whose bytes encode a slid kernel pointer.

Host decode: `python tools/slide_decode.py <boot_id>`  
(or `slide_decode_from_bootid()` in `util.c`)

**Important:** `fire_mode.ps1` classifies boot_id *change* as `SOFTBOOT`. For oracle fires that is often a **false positive** — the UUID rewrite is the leak, not a kernel reboot. Trust live_sync `write_proof_LANDED` + device still answering with same *real* uptime class.

Example **O18** (oracle land):
```
post=661f47d6-deff-ffff-e0a8-8d2a80ffffff
live_sync: write_proof_LANDED
```
Decoded: `SLIDE=0x1ecc400000`

### 2. SLIDE_SWAP works (`MODE4_SLIDE_SWAP=1 KASLR_SLIDE=...`)
Stack stamp (proven SLIDE mechanism):
```
tree_pc = fake_fops
tree_l  = P0(MISC.fops)   // ashmem_misc+0x10
→ *MISC.fops = fake_fops
```
Bypasses heap W0.pi placement / old toxic geometries.

### 3. Bisect: `MODE4_SWAP_NOCFI=1` — **N5 = ALIVE**
| Tag | Result |
|-----|--------|
| N5 | **ALIVE** same boot `661f47d6…`, stamp printed `SLIDE_SWAP: *MISC.fops=fake_fops` |

**Interpretation (Outcome A):**  
With CFI/open probe **skipped**, the swap **survives**. Earlier deaths after swap were largely from **opening ashmem through the swapped table** (system/`try_cfi_stage`), not from the erase itself.

Related commits (newest first):
- `9a20ebb` SWAP_NOCFI gates post-walk cfi probe in fops.c  
- `e00d50a` MODE4_SWAP_NOCFI bisect switch  
- `80734cf` staged table: bit-exact ashmem clone; only `.write` armed; `.read` armed briefly per-read  
- `1843320` SLIDE_SWAP sprays ATTACK table owner=0 (shell owner=1 killed misc_open)  
- `87467ff` MODE4_ROOT two-phase (oracle → swap)  
- `d40bcd2` SESSION BREAKTHROUGH: SLIDE oracle  

### 4. Staging / kill lessons already fixed in tree
- FRESH-FUTEX: per-run mmap’d futex words (poisoned hb reuse)  
- CLONE_FOPS + owner=0 for swap table  
- Don’t leave configfs `.read` JT live for system `read()` traffic  

---

## Device state when Grok picked up (2026-08-16 session clock / user now)

After user’s hard reboot + later idle:
```
boot_id = ba0cd675-f662-4657-adf9-cbb01dbdea96   # NEW (N5 swap GONE)
uptime  ~ large (hours) — NOT fresh-boot window
```

So: **cannot** continue N5’s live table; need **fresh oracle → decode → SWAP_NOCFI** again (or `MODE4_ROOT=1` one-shot).

---

## Recommended next loop (single-pass, no reboot thrash)

1. **Optional one reboot** only when user OK’s (phone was hot earlier). Prefer fresh boot ≤ ~90s uptime.  
2. Fire oracle:
   ```powershell
   .\fire_mode.ps1 -ModeEnv "MODE4_SLIDE=1" -TagPrefix "O_next"
   ```
3. Decode (ignore false SOFTBOOT if live_sync says LANDED and shell still up):
   ```powershell
   python tools\slide_decode.py <boot_id_after>
   ```
4. Fire swap bisect (confirmed green path):
   ```powershell
   .\fire_mode.ps1 -ModeEnv "MODE4_SLIDE_SWAP=1 KASLR_SLIDE=0x.... MODE4_SWAP_NOCFI=1" -TagPrefix "N_next"
   ```
5. If ALIVE again → **root chain**:
   - Prefer in-tree `MODE4_ROOT=1` (oracle+swap same process), **or**
   - Push/build `tools/swap_probe` against live `fake_fops` + slide: write test → llseek repair → arm read → modprobe_path  
   - Then SELinux / cred / UMH as existing pipe path

**Do not** re-enable post-swap `try_cfi_stage` until write/modprobe path is proven — N5 says open-path kills.

---

## Artifacts to read

| Path | Why |
|------|-----|
| `logs/aarif_pull/N5_*` | ALIVE SWAP_NOCFI proof |
| `logs/aarif_pull/O18_*` | oracle land that fed N5 slide |
| `tools/slide_decode.py` | host slide decode |
| `tools/swap_probe.c` | post-swap kR/W + modprobe (untracked build?) |
| `src/core/fops.c` | SLIDE / SLIDE_SWAP / SWAP_NOCFI |
| `src/core/main.c` | MODE4_ROOT two-phase |
| `src/core/util.c` | CLONE_FOPS / slide_decode_from_bootid |

---

## Uncommitted when Grok looked

```
?? tools/swap_probe.c
?? swap_probe
?? mp_script
M  ghostlock-cph2521
```

Consider committing `swap_probe.c` + this handoff on breakthrough or next push.

---

## Safety reminders (from earlier Grok session)

- No auto-reboot loops (`fire_zio_seq.ps1` was fixed once; don’t reintroduce).  
- Network ADB: WinGet platform-tools only.  
- Truth: live_sync + shell liveness; boot_id change ≠ softboot for **oracle**.  
- Cool phone before multi-fire.

---

*Pickup complete. Next human/agent action: fresh-boot oracle → N-class SWAP_NOCFI confirm → swap_probe / MODE4_ROOT.*
