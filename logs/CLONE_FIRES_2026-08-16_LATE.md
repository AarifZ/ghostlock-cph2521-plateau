# Clone-swap fire session — 2026-08-16 late evening (collaborator agent, network ADB)

Device driven via `192.168.1.108:5555` (Shizuku auto-reconnect works after every
softboot, ~60-90 s). Binary: clone-table build 147520 B (changes in
`clone_table.patch`; identical logic to HEAD when MODE4_CLONE_* unset).

## Fire log

| # | Tag | Env (short) | Result |
|---|-----|-------------|--------|
| 1 | T0_plateau | default + PROOF + CFI + delay150 | **ALIVE**, cfi errno=22, same boot — new binary plateau-clean |
| 2 | T1_wproof | WRITE_PROOF bootid (new bin) | SOFTBOOT @ pre_setattr |
| 3 | T1b_wproof | same, fresh boot | SOFTBOOT @ pre_setattr |
| 4 | T1c_wproof_OLDBIN | WRITE_PROOF bootid (HEAD build 146416) | **post_setattr ret=0, STORE LANDED** (readback shows corrupted uuid `0001884e-88ff-…`), EXIT=0; later side-effect reboot (known boot_id corruption class) |
| 5 | T2_clone_misc | +TARGET=fops SHAPE=left CLONE_FOPS | SOFTBOOT @ pre_setattr |
| 6 | T2b | same (stale 209 s uptime) | SOFTBOOT @ pre_setattr |
| 7 | T1d_NEWBIN | WRITE_PROOF bootid (new bin) | SOFTBOOT @ pre_setattr |
| 8 | T1e_OLDBIN2 | WRITE_PROOF bootid (old bin) | SOFTBOOT @ pre_setattr → **build exonerated: both binaries crash; it's the session race** |
| 9 | T2c | CLONE_FOPS, FOPS_MAX_ATTEMPTS=1 | ALIVE EXIT=255 — KS leak starved (MAX_ATTEMPTS is also the KS retry budget; keep ≥4) |
| 10 | T2d | CLONE_FOPS, MAX=4 | SOFTBOOT @ pre_setattr |
| 11 | T2e | CLONE_FOPS | SOFTBOOT @ pre_setattr |
| 12 | **T2f** | CLONE_FOPS | **pre_setattr → `post_setattr ret=0 errno=0` → cfi_on_punch_enter → cfi_before_open → KERNEL DEATH inside open() 4 ms after the walk** |
| 13 | T3_clone_cfg | CLONE_CFG (fired on stale 550 s boot by mistake) | SOFTBOOT @ pre_setattr |
| 14 | T3b_clone_cfg | CLONE_CFG, verified fresh 50 s boot | SOFTBOOT @ pre_setattr |

Tonight's walk-survival rate (all targets): **1 land / 10 crashes** — a bad-race
session (afternoon of same day was 2/2). The race is boot-lottery, not target- or
build-dependent.

## Findings (order by importance)

1. **HISTORIC FIRST: the only-left `left=MISC` walk SURVIVES (T2f).**
   `post_setattr ret=0` with parent=fake_fops, right=0, left=&ashmem_misc.fops,
   W0.main=(1,0,0), owner=1. The long-held blocker model "re-enqueue walks
   W0.left=MISC → softboot" is **dead**: the historical softboots were the
   reclaim race (proven by bootid-target crashing identically tonight).
2. **Death moved to the first post-swap open().** With the clone table
   (bit-exact real ashmem_fops), the box died inside `open_ashmem_device()`
   4–7 ms after post_setattr (`cfi_before_open` logged, `cfi_open_ok` never —
   O_SYNC). A valid clone + pinned page cannot fault there, so the prime
   suspect is **fake_fops → sprayed-page validity**: the VALUE stored into
   *MISC has never been verified to point at the actual table
   (SKB_DATA_DELTA −0xe80 / FOPS_TABLE_OFF placement), or the page is
   freed/reused in that window. T1c proves the STORE lands; nothing yet proves
   the value points at our bytes.
3. **Build A/B:** old-vs-new binary crash identically; the single land was
   old-bin bootid but bootid lands are per-boot lottery (1/5 tonight across
   bins). No build regression. (Also: my earlier 0/3-vs-1/1 split was noise.)
4. **FOPS_MAX_ATTEMPTS is the KS-leak retry budget** — setting it to 1 starves
   KernelSnitch (T2c EXIT=255). Keep 4+.
5. **Always verify reboot took** (boot_id actually changed + uptime < ~120 s)
   before firing — T3 fired on a stale 550 s boot because `adb reboot` hit an
   offline device.

## Next-session fire plan (for a GOOD session — walk lands ~100 %, like the afternoon)

1. `MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops WRITE_PROOF_SHAPE=left MODE4_CLONE_FOPS=1 FOPS_MAX_ATTEMPTS=4`
   **without MODE4_PROOF** (probe-less): if the walk lands and the box stays
   ALIVE under full system traffic with the swap live → fake_fops/page is
   VALID → T2f's death was probe-path-specific → go straight to (3).
   If it still dies (system opens hitting the table) → placement/lifetime bug → (2).
2. **Placement oracle (code to add):** WRITE_PROOF target = scratch qword inside
   the sprayed page (payload_base+SCRATCH), value = magic; after the walk, recv
   one sprayed skb from reclaim_sv and check the qword — verifies
   SKB_DATA_DELTA/FOPS_TABLE_OFF directly (aristotle's decisive diagnostic,
   still missing here). If misplaced: sweep SKB_DATA_DELTA ±0x40 around −0xe80.
3. `MODE4_CLONE_CFG=1` (attack table) + PROOF: cfi open → ioctl SET_NAME plants
   fake configfs buffer → pwrite → **expect errno≠22 / cfi_write_ret>0** =
   plateau broken.
4. Then pipe physrw → cred → uid0 (existing code).

## Ops notes

- 16 reboots tonight; stopped at heat budget. Device left on a fresh healthy
  boot, idle.
- Harness misclassification to remember: a LANDED boot_id write reads back as a
  *changed* boot_id → CLASS=SOFTBOOT false positive (T1c). The corrupted-uuid
  pattern (`…-88ff-ffff-…`) is the land signature.
- Env used for all fires via `fire_mode.ps1` (adds MODE4_ONLY + stage paths).

---

## ADDENDUM — 3-run oracle session (23:46-00:05)

Implemented (built into ghostlock-cph2521 149696 B, diff in clone_table.patch):
the **MODE4_WPROOF_SPRAY placement oracle** — stamps the walk as
`*(fake_fops+0x90) = fake_fops+0x80` (marker write into our own sprayed table,
both rb-safe readable page addrs), then after the route PEEKs (MSG_PEEK,
non-destructive) the reclaim socket stream, locates the table by slot
signature (llseek@+8 / read_iter@+0x20 / ioctl@+0x50), and:
- marker at +0x90 → VERIFIED (fake_fops really points at our bytes);
- marker elsewhere → logs every marker occurrence relative to the table
  (measures the SKB_DATA_DELTA error Y; payload stamp copies are visible too);
- no table in stream → ret -1.

Runs (all fresh verified boots, KS ok, EDEADLK 35, FOPS_MAX_ATTEMPTS=4):
| Run | Result |
|-----|--------|
| R1 | race death between pselect entry and setprio |
| R2 | race death, same |
| R3 | race death, same |

Bad-race phase persisted (tonight totals: 1 land / 13 walk-crashes).
**The oracle is compiled, stamped, and armed but has not yet seen a landed
walk** — it is the FIRST fire for the next good session:

```
MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=spray MODE4_WPROOF_SPRAY=1 \
MODE4_CLONE_FOPS=1 FOPS_MAX_ATTEMPTS=4      # NO MODE4_PROOF (no open probe)
```

Interpretation:
- `spray_placement_VERIFIED` + ALIVE → placement good → fire CLONE_CFG next
  (same boot OK: swap semantics identical) for the cfi≠22 attempt.
- `spray_placement_MISMATCH` + ALIVE → read `marker_occ[n] rel_table=±Y` →
  correct SKB_DATA_DELTA by the measured Y, refire oracle once, then CLONE_CFG.
- `spray_placement_NOTABLE` → payload never landed in the assumed stream at
  all → revisit SKB_FRAG_BIAS/stream assumptions.
