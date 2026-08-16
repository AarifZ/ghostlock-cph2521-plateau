# CPH2521 GhostLock research checkpoint — 2026-08-16

**Device:** OPPO Reno 10 Pro+ (CPH2521)  
**Build:** CPH2521_16.0.5.1002(EX01) (lab image)  
**Kernel:** `5.10.236-android12-9-o-g74d132f4467a`  
**CVE:** GhostLock / CVE-2026-43499 (futex PI UAF + pselect reclaim → `rb_erase` AAW)  
**Branch:** `research/cph2521-zero-name-standalone`  
**Binary:** `ghostlock-cph2521` via `build_cph2521.ps1`  
**Boot image (for RE):** `assets/CPH2521_boot.img.zip` (~20 MB zip of device `boot.img`)

Older freezes: `CPH2521_CHECKPOINT.md` (2026-08-01), `CPH2521_CLOSEST_CHECKPOINT.md` (2026-08-02 plateau).  
This file is the **current** progress snapshot for review / GitHub discussion.

---

## 1. One-paragraph status

On CPH2521 we have a **reliable UAF prime** (EDEADLK 35), a **surviving mode-4 plateau** (success=1, cfi errno=22, ALIVE), and a **proven arbitrary write** via only-left `rb_erase` into quiet BSS (`sysctl_bootid` / boot_id string corrupted — write-proof). The product gap remains: **`ashmem_misc.fops` is not replaced while the device stays ALIVE**, so CFI write stays EINVAL (22) and there is **no uid0**. The failure mode is **geometry of the write target** (toxic `left`/`parent` near miscdevice, or ION wait_lock on name), **not** “wrong primitive class” (`rb_node` is correct for 5.10; **not** `plist_node`).

---

## 2. Device / binary freeze

| Item | Value |
|------|--------|
| KIMAGE `_text` | `0xffffffc008000000` |
| KPHYS (P0) | `0xa8000000` (delta `0x28000000`) |
| `mm_struct` | **0x3c0**, SLUB **order-2** |
| Waiter (5.10 plain) | `tree`@0, `pi_tree`@**0x18**, `task`@**0x30**, `lock`@**0x38**, `prio`@**0x40**, `deadline`@**0x48** |
| `PSELECT_SHIFT` | **−2** (0 softboots) |
| SKB_DATA_DELTA | **−0xe80** |
| CFI | fops methods = **`.cfi_jt`** |
| fops open slot | **0x70** (Android 5.10 + `mmap_supported_flags`) |
| `ashmem_misc.fops` (P0) | **`0x0291A8E8`** → `ffffff802a91a8e8` (kallsyms-aligned) |
| `sysctl_bootid` / slide boot_id | **`0x02B99B6D`** → `ffffff802a6aa868` |
| Struct family | **`rb_node` waiters** (v5.10 `rt_mutex_waiter`); plist is pre-rb-tree era — **not applicable** |

### Boot image

| Artifact | Path |
|----------|------|
| Zip (repo) | `assets/CPH2521_boot.img.zip` |
| Unzipped source used for RE | OTA extract `boot.img` (~192 MB raw; zip ~20.5 MB) |

Unzip and analyze offline (kallsyms, `ashmem_misc`, fops tables). Prefer GitHub **Release** asset if the host repo rejects large blobs; zip is under typical 100 MB GitHub file limit.

---

## 3. Proven on-device (do not re-litigate without new evidence)

| Milestone | Status | Notes |
|-----------|--------|--------|
| Offsets match uname | yes | `src/devices/cph2521/offsets.h` |
| KS spray @ low uptime | yes | often attempt 1–3; worse when uptime high |
| EDEADLK UAF prime | **yes** | errno **35** reliable |
| Plateau inert mode-4 | **yes** | success=1, **cfi errno=22**, ALIVE |
| only-left AAW (quiet BSS) | **yes** | **boot_id write-proof landed ×3+** |
| MISC offset correct | **yes** | kallsyms `ashmem_misc+0x10` |
| `left=MISC` overlay idle | **yes** | `MODE4_NO_CONSUMER` ALIVE |
| `left=MISC` + consumer erase | **softboot** | death in setprio / erase path, not select |
| only-left `left=MISC+16` (PAD3 p1) | **softboot** | pad region also toxic as rb left |
| ZERO_NAME leaf + consumer | **softboot** (2026-08-16) | earlier “ALIVE” may be flaky/misclass; NC ALIVE |
| ZERO_NAME + NO_CONSUMER | **ALIVE** | stamp OK; erase/name zero is the kill |
| ROOT_SPRAY root erase into spray | **ALIVE** (2026-08-16) | parent=1, right=fake_fops **rb-leaf**, left=0, owner=1 |
| ION alone (name ≠ 0) | ALIVE cfi22 | wait_lock busy → no erase |
| ION after name zero | not proven | name zero softboots under consumer |
| `*MISC = fake_fops` ALIVE | **no** | product gap |
| cfi write ≠ 22 | **no** | |
| uid 0 | **no** | |

### Write-proof (canonical positive)

```text
MODE4_WRITE_PROOF=1 / MODE4_ARISTOTLE=1
only-left: parent=fake_fops, right=0, left=sysctl_bootid
owner=1, shift=-2
→ /proc/sys/kernel/random/boot_id changes (e.g. 0001a37e-89ff-…)
→ EXIT=0, ALIVE, same boot_id string now corrupted (not a reboot)
```

**Side effect:** Android ashmem path is often `/dev/ashmem{boot_id}`. After proof, **apps not already open** fail to launch. **Reboot restores** real uuid. Policy: boot_id proof = diagnostic gate only; reboot after. See `docs/BOOT_ID_SIDE_EFFECT.md`.

### ROOT_SPRAY (canonical “root erase lives”)

```text
MODE4_ROOT_SPRAY=1 MODE4_ONLY=1
parent=1, right=fake_fops (rb-leaf shell + write JT @ +0x18), left=0
lock=fake_lock, owner=1
→ success=1, full route, cfi errno=22 (expected: did not retarget MISC), ALIVE
```

Shows re-enqueue into an **rb-leaf** at `fake_fops` is viable; earlier softboots were packing, not “root erase impossible.”

---

## 4. What is ruled out / low ROI

| Idea | Verdict |
|------|---------|
| “Must use `plist_node` on 5.10” | **False** — v5.10 uses `rb_node`; AAW proves rb path |
| MISC offset wrong | **False** — kallsyms + boot_id alias separate issues |
| UAF never primes | **False** — EDEADLK 35 |
| only-left `*MISC` like boot_id | Softboots — re-enqueue walks `W0.left=MISC` (toxic kids) |
| PAD3 zero MISC+8/+16 then fops | Softboot phase1 (MISC neighbors not quiet BSS) |
| ION_FOPS into `ashmem_fops` body | Softboot — table likely **.rodata** |
| Classic parent=MISC−8 only-right | Softboot class (historical matrix) |
| Multi-hour stamp matrix without write oracle | Deprioritized |

---

## 5. Working model of the blocker

```text
rb_erase only-left:
  *left = parent_color          ← AAW (works on boot_id)
  re-enqueue walks lock.waiters
  if W0.left still points at MISC → walk MISC+8/+16 → softboot

rb_erase root (parent=1, right=leaf, left=0):
  *waiters = right              ← ALIVE on spray (ROOT_SPRAY)
  for *MISC need waiters @ MISC i.e. lock = MISC-8
  wait_lock @ name (non-zero) → trylock fails → no erase (cfi22)
  zeroing name (ZERO_NAME)     → softboot under consumer on live ashmem
```

**Open product path:** write MISC with a lock that trylocks **without** permanent `name=NULL`, or erase **without** re-enqueue walk of toxic left (`remove_waiter` / unlock-shaped path), or another quiet intermediate — not “switch to plist.”

---

## 6. Research tooling (env, keep opt-in)

| Env | Role |
|-----|------|
| (default / no MODE4_*) | Plateau inert → cfi22 ALIVE |
| `MODE4_ONLY=1` | Stop after fops; no Write1 |
| `MODE4_WRITE_PROOF=1` / `MODE4_ARISTOTLE=1` | only-left AAW oracle (bootid/enforce/fops target) |
| `MODE4_ROOT_SPRAY=1` | Root erase survival control |
| `MODE4_ION_SAFE=1` | Root erase with lock=MISC−8 (needs wait_lock 0) |
| `MODE4_ZI=1` | ZERO_NAME then ION same process (phase1 softboots under consumer today) |
| `MODE4_NO_CONSUMER=1` | Isolate select vs erase |
| `MODE4_PAD3=1` | Rejected softboot class (documented) |
| live_sync | O_SYNC under `/sdcard/ghostlock/aarif/live_sync.log` |

Fire helper (lab): `fire_mode.ps1 -ModeEnv "MODE4_ROOT_SPRAY=1"` (network ADB `192.168.1.108:5555` via Shizuku).

ADB policy: **no USB thrash**; truth = **`boot_id` + stage/live_sync**; softboot recovery = `adb reboot` / `post_softboot_hardboot.ps1`.

---

## 7. Scoreboard (honest)

| Layer | Closer? |
|-------|---------|
| Research (UAF + AAW real, MISC offset, crash class isolated) | **Yes** |
| Product (`*MISC=fake_fops` ALIVE → cfi≠22 → uid0) | **Not yet** |

Suggested GitHub discussion ask:

> Given proven only-left AAW on boot_id and proven ROOT_SPRAY root erase ALIVE on 5.10.236 CPH2521, what is the cleanest way to get `*ashmem_misc.fops = fake_fops` without (a) only-left left=MISC re-enqueue walk or (b) zeroing miscdevice.name for ION wait_lock?

---

## 8. Repo hygiene (this freeze)

- Research code: `src/core/{fops,main,util}.c` (PAD3/ZI/ROOT packing, live_sync, write-proof).  
- Docs: this checkpoint + `docs/BOOT_ID_SIDE_EFFECT.md`, `docs/RESEARCH_PAD3_2026-08-16.md`, MISC/port study notes.  
- **Not** committed: `github-bundle/`, bulk `logs/aarif_pull/`, alt binaries (`*-a53exp`, `*-glm`), raw exp scrapes (see `.gitignore`).  
- Plateau default path remains inert unless research env is set.

---

## 9. Reproduce plateau (sanity)

```powershell
# build
.\build_cph2521.ps1
# push + run with NO research env → expect success=1 cfi errno=22 ALIVE
adb push ghostlock-cph2521 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/ghostlock-cph2521; /data/local/tmp/ghostlock-cph2521"
```

Write-proof (then **reboot**):

```text
MODE4_WRITE_PROOF=1 MODE4_ONLY=1
```

Root-erase control:

```text
MODE4_ROOT_SPRAY=1 MODE4_ONLY=1
```
