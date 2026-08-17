# Grok session handoff — GhostLock CPH2521 lab

**Purpose:** Full context for a collaborating agent (stronger coding/RE focus) working **with** Grok Build on this repo.  
**Author of this file:** Grok 4.5 (xAI Build TUI session)  
**Date:** 2026-08-16 (evening IST)  
**Repo workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Active branch:** `research-master` @ `66a930c` (tracks `plateau/research-master`)

> **Read first:** `CPH2521_CHECKPOINT_2026-08-16.md` (scoreboard) + this file.  
> **Do not** thrash MISC-only-left or dual-PI without a new theory.  
> **Do not** auto-reboot loops — phone overheated from a bad retry script.

---

## 1. Mission

| Goal | Status |
|------|--------|
| GhostLock (CVE-2026-43499) on **OPPO Reno 10 Pro+ CPH2521** | In progress |
| Kernel `5.10.236-android12-9-o-g74d132f4467a`, locked BL | Confirmed |
| Product win: `*ashmem_misc.fops = fake_fops` ALIVE → cfi≠22 → pipe/cred → **uid0** | **Not yet** |
| Research win: UAF + AAW proven | **Yes** |

**Branch policy (user):**
- Work only on **`research-master`** until plateau is broken or a merge-worthy jump.
- **Do not** merge to `main` until fops land / uid0 / similarly significant result.
- Git push target: `plateau` → https://github.com/AarifZ/ghostlock-cph2521-plateau  
- `origin` (JoinChang/ghostlock-oneplus) → no write as AarifZ (403).

---

## 2. Device & ADB (lab)

| Item | Value |
|------|--------|
| Device | CPH2521 / OP56D3L1 |
| Network ADB | `192.168.1.108:5555` via **Shizuku** |
| Host adb | WinGet: `%LOCALAPPDATA%\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe` |
| **Do not use** | Desktop `platform-tools` adb (broken/silent) |
| USB thrash | **Banned** — kill/start-server + manual replug only |
| Truth signals | `boot_id` change = real softboot; ADB drop ≠ softboot |
| Live breadcrumbs | O_SYNC `/sdcard/ghostlock/aarif/live_sync.log` |
| pstore/dmesg | **Denied** as shell uid 2000 |

**Fire helpers:**
```powershell
.\build_cph2521.ps1
.\fire_mode.ps1 -ModeEnv "MODE4_ZERO_NAME=1"   # single env fire
.\fire_zio_seq.ps1                              # SAFE: one pass, no reboot loop
.\fire_zio_seq.ps1 -RebootFirst                 # optional single reboot then fire
```

**Rest-state log dump (no fire):**  
`logs/aarif_pull/rest_20260816_193618/` (+ `INDEX.md`)

---

## 3. Proven vs blocked (memory — do not re-litigate)

### Proven on-device

| Fact | Evidence |
|------|----------|
| Offsets / CFI JT / open@0x70 | kallsyms + live match |
| KPHYS `0xa8000000`, KIMAGE `0xffffffc008000000` | P0 |
| `mm_struct` 0x3c0 order-2 | boot.img |
| Waiter 5.10 flat **rb_node** (not plist) | offsets + AAW |
| PSELECT_SHIFT **−2** | shift 0 softboots |
| EDEADLK **35** UAF prime | reliable |
| Plateau inert: success=1, **cfi errno=22**, ALIVE | default binary |
| **only-left AAW** lands on quiet BSS | **boot_id write-proof ×3+** |
| MISC offset correct | `ashmem_misc+0x10` = `0x0291A8E8` |
| NO_CONSUMER + left=MISC | ALIVE (overlay OK) |
| left=MISC + consumer erase | **SOFTBOOT** |
| PAD3 left=MISC+16 | **SOFTBOOT** |
| ROOT_SPRAY root erase into spray | **ALIVE** (parent=1,right=fake_fops leaf,left=0,owner=1) |
| ZERO_NAME leaf consumer | **ALIVE flaky** (often ALIVE, sometimes SOFTBOOT) |
| ION alone / ION after ZERO | ALIVE **cfi22** (no fops land) |
| Dual main+pi only-left | **SOFTBOOT even on boot_id** — reject |
| aristotle dual port | not free win; their 5.10 repo **not HW-validated** |

### Product gap

```
*MISC = fake_fops while ALIVE  →  still NO
cfi write ≠ 22                 →  still NO
uid 0                          →  still NO
```

### Working model of the blocker

```text
only-left AAW:
  *left = parent_color     // works on boot_id
  parent=fake_fops also does change_child → may poison fake_fops+8/+16
  re-enqueue / concurrent ashmem after *MISC swap can softboot

ROOT erase (ION shape):
  parent=1, right=fake_fops leaf, left=0
  *waiters = fake_fops
  lock must be MISC-8 so waiters slot == MISC
  wait_lock overlays name (need 0)
  owner overlays MISC+16 (need 0 or safe value)
  ROOT_SPRAY proves geometry on spray lock ALIVE

ZERO_NAME leaf parent=MISC-16 → *name=0 can ALIVE
ZERO_OWNER leaf parent=MISC+8 → *MISC+16=0  SOFTBOOTS (toxic)
ION after ZERO still cfi22 (wait_lock not cleared for real, or store miss)
```

### Side effects remembered

- **boot_id write-proof** corrupts uuid → `/dev/ashmem{boot_id}` breaks **new app launches**. Reboot restores. Diagnostic only.
- Phone **overheated** from auto-reboot loop in old `fire_zio_seq.ps1` (fixed: no loop). Cool before more stress.

---

## 4. Key files

| Path | Role |
|------|------|
| `CPH2521_CHECKPOINT_2026-08-16.md` | Current scoreboard |
| `docs/ARISTOTLE_VS_CPH_2026-08-16.md` | Aristotle restudy + dual reject |
| `docs/BOOT_ID_SIDE_EFFECT.md` | ashmem path side effect |
| `docs/PORT_STUDY_AND_REDIRECT_2026-08-16.md` | Port study |
| `docs/KERNEL_5_10_RTMUTEX_WRITE_PATH.md` | rb_erase / setprio |
| `docs/MISC_OFFSET_RECHECK_2026-08-16.md` | MISC offset proof |
| `src/core/fops.c` | MODE4 stamps, phases (ZIO/WION/PAD3/…) |
| `src/core/util.c` | packing owner=0/1, rb_leaf fops, spray |
| `src/core/main.c` | WRITE_PROOF path, MODE4_ONLY stop |
| `src/devices/cph2521/offsets.h` | device offsets |
| `build_cph2521.ps1` | NDK aarch64 build → `ghostlock-cph2521` |
| `fire_mode.ps1` | single-env network fire + classify |
| `fire_zio_seq.ps1` | SAFE single-pass ZERO→OWNER→ION |
| `assets/CPH2521_boot.img.zip` | ~20.5 MB boot.img for RE |
| `../CVE-2026-43499-aristotle/` | cloned soralis 5.10 port (reference) |

### Important env flags

| Env | Meaning |
|-----|---------|
| (none) | Plateau inert |
| `MODE4_ONLY=1` | Stop after fops (implied by fire scripts) |
| `MODE4_WRITE_PROOF=1` | only-left AAW oracle (bootid default) |
| `MODE4_ARISTOTLE_DUAL=1` | dual main+pi — **SOFTBOOT on CPH** |
| `MODE4_ARISTOTLE_MAIN_ONLY` | N/A default is main-only now |
| `MODE4_ROOT_SPRAY=1` | root erase control ALIVE |
| `MODE4_ZERO_NAME=1` | leaf *name=0 |
| `MODE4_ZERO_OWNER=1` | leaf *MISC+16=0 — softboots |
| `MODE4_ION_SAFE=1` | lock=MISC-8 parent=1 right=fake_fops |
| `MODE4_ZIO=1` | same-process ZERO→OWNER→ION (flaky phase1) |
| `MODE4_NO_CONSUMER=1` | no setprio erase |
| `MODE4_PAD3=1` | rejected |

---

## 5. Next research targets (ordered)

1. **Prove name stayed 0** after ZERO_NAME (oracle) before ION.  
2. **ION with wait_lock=0 and owner quiet** without softboot (ROOT_SPRAY is the control packing).  
3. **Avoid only-left left=MISC** (toxic / poisons parent table). Prefer root erase.  
4. Optional: Ghidra decompile `rb_erase` / `adjust_prio_chain` / `remove_waiter` on loaded Image.  
5. After `*MISC` lands: cfi≠22 → pipe physrw → cred (existing code paths).

**Aristotle (soralis):** same CVE family, dual stack stamps; **not** proven root on HW for 5.10 fork. JoinChang: “different chain / not GhostLock port” — partially product-tree politics; primitives are still UAF+pselect+rb_erase.

---

## 6. Grok Build — tools & abilities (this agent)

Grok runs as an **interactive CLI/TUI coding agent** (Grok Build). Capabilities used in this lab:

### 6.1 Core workspace tools

| Tool | Use |
|------|-----|
| `run_terminal_command` | PowerShell, adb, build, git (note: no `&&`; use `;`) |
| `read_file` / `write` / `search_replace` | Edit code/docs |
| `grep` / `list_dir` | Search (no shell grep/find) |
| `todo_write` | Multi-step progress |
| `web_search` / `web_fetch` / `open_page*` | External docs, GitHub |
| `x_*` | X/Twitter (not used for this lab) |
| `spawn_subagent` | general-purpose / explore / plan subagents |
| `workflow` | Rhai multi-agent workflows |
| `image_*` / `image_to_video` | Media (not used here) |
| `monitor` | Long-running watchers |

**Shell notes (Windows):**
- Prefer WinGet `adb.exe` path above.  
- PowerShell: avoid `&&`; quote carefully; UTF-8 special chars broke one script.  
- Do not thrash USB / PnP.

### 6.2 MCP servers connected

MCP tools are invoked via **`search_tool` then `use_tool`** with qualified name `server__tool`.

#### A) `ghidra` (~27 tools)

RE against a Ghidra-open program (user’s Oppo/kernel Image when loaded).

Useful tools include:
- `ghidra__list_functions` / `list_methods` / `list_imports` / `list_exports` / `list_segments`
- `ghidra__search_functions_by_name`
- `ghidra__decompile_function` / `decompile_function_by_address`
- `ghidra__disassemble_function`
- `ghidra__get_function_by_address` / `get_current_function` / `get_current_address`
- `ghidra__get_function_xrefs`
- `ghidra__rename_function` / `rename_function_by_address` / `rename_variable`
- `ghidra__set_function_prototype` / `set_local_variable_type`
- `ghidra__set_decompiler_comment` / `set_disassembly_comment`

**Lab use:** decompile `rb_erase`, `rt_mutex_adjust_prio_chain`, `remove_waiter`, ashmem_misc layout if Image is open in Ghidra.

#### B) `tasks` (~9 tools)

Automations (schedules / event triggers): create, list, update, pause, delete, run_now, get_results, trigger catalog/resources.

**Lab use:** optional — e.g. scheduled “when device online, pull live_sync” (not currently set).

#### C) `voice` (~1 tool)

- `voice__list_voices` — TTS voice list (not used for exploit work).

### 6.3 Skills available (bundled)

Under `~/.grok/bundled/skills/`: create-skill, create-workflow, design, execute-plan, review, pr-babysit, resume-*, docx/pdf/pptx, game-*, imagine, build-with-ai, etc.  
**Primary for this project:** none required; pure C + adb + RE.

### 6.4 Safety / policy (practical)

- Research exploit on **user’s own device** only (local security research).  
- No USB thrash; confirm before destructive git/remote ops unless user authorized.  
- User asked: **no live git spam** — commit only meaningful breakthroughs (or explicit request).  
- Default binary path = **plateau** (survive cfi22); research is **opt-in env**.

---

## 7. Memory / decisions log (session compact)

1. **rb_node is correct on 5.10** — not plist.  
2. **AAW real** — boot_id only-left main-only + owner=1.  
3. **Dual PI only-left** softboots boot_id → main-only default.  
4. **ROOT_SPRAY ALIVE** → root erase packing works; ION is the right shape for *MISC.  
5. **ION needs quiet wait_lock (name) and likely quiet owner (MISC+16).**  
6. **ZERO_NAME ALIVE flaky**; **ZERO_OWNER SOFTBOOT** in sequence.  
7. **ION after ZERO → ALIVE cfi22** (no confirmed fops land).  
8. **WION parent=PAGE_OFFSET** softboots (change_child into physmap).  
9. **Aristotle** = popsicle lineage 5.10 port, not JoinChang OPPO tree; not HW-validated root.  
10. **Reboot-loop bug** in old fire_zio_seq — fixed; phone got hot; cool before stress.  
11. **Rest collect** saved under `logs/aarif_pull/rest_20260816_193618/`.  
12. Remotes: push **`plateau`**, not origin.

---

## 8. Suggested division of labor

| Grok Build (this agent) | Collaborator agent (you) |
|-------------------------|---------------------------|
| Device fire, adb, classify softboot/ALIVE | Deep C packing / geometry correctness |
| Checkpoint docs, branch hygiene | rb_erase / rt_mutex path formal analysis |
| MCP Ghidra if Image open | Propose exact stamp + lock layout for ION |
| Build/push binary | Code review of fops.c/util.c multi-phase |

**Success criteria for “breakthrough” commit:**
- Same boot_id, `*MISC=fake_fops` evidence (cfi≠22 or clear open/write success), or hard proof of new write primitive.

---

## 9. Quick commands for the new agent

```powershell
cd "C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus"
$ADB = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
& $ADB connect 192.168.1.108:5555
& $ADB -s 192.168.1.108:5555 shell "getprop sys.boot_completed; cat /proc/uptime; cat /proc/sys/kernel/random/boot_id"

git checkout research-master
git pull plateau research-master

# Read
# CPH2521_CHECKPOINT_2026-08-16.md
# docs/ARISTOTLE_VS_CPH_2026-08-16.md
# grok_context.md (this file)
```

**Aristotle reference clone:**  
`C:\Users\LENOVO\Desktop\HILY installer\Oppo\CVE-2026-43499-aristotle\`

**Boot image zip:** `assets/CPH2521_boot.img.zip`

---

## 10. Contact / user preferences

- User: lab operator on Windows (`LENOVO`), network ADB + Shizuku.  
- Prefers: progress + theory over thrash; careful with heat/reboots.  
- Wants: collaborative agent with strong coding/RE to partner with Grok.  
- Git: `research-master` only until real breakthrough.

---

*End of handoff. Update this file when scoreboard changes materially.*
