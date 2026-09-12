# GLM handoff pickup — 2026-09-12

You are picking up GhostLock on **CPH2521** from Grok. The 2026-08-23 / 2026-08-29 GLM pickups and the 09-01 “chain complete” commit (`743669e`) are **stale for next-fire**.

**Read this file first**, then `docs/NEXT_SESSION_2026-09-12.md`, then `docs/HANDOFF_2026-09-12.md`. ColorOS popup question: `docs/COLOROS_POPUP_VS_ROOT_2026-08-29.md`.

**Do not fire** until you classify: `boot_id`, `uptime`, `getenforce`, `id`. Last recorded boot after the KP was `c2773f39`, Enforcing, uid 2000. That was hours ago in wall-clock if you are later; re-read the device.

**Do not retry Exact Z33 as-is.** Park landed, then W2 `*(child_x28+0x780)=init_cred` on `ffffff88bb2cac80` kernel-panicked at `pselect pre-select +2ms`.

**Do not retry `MODE4_ZI`.** **Do not run `gl_run_chain.sh` P2** after a living P1 walk (Z5).

---

## Operator last words (2026-09-12)

1. Asked JoinChang Path B / ROOTGUARD port / chaining. Answer given: do not run Path B as written; keep our park; steal `pipe_physrw` only after a living swap.
2. Picked **“1”** = Z33 + child payload, then **Exact Z33** (punch child `+0x780` even if x28 is `ffffff88/89`).
3. That fire KPd. Asked **“what next plan”**. Offered A=hookcred self-only (recommended), B=retry Z33, C=park-only. **Did not pick.**
4. Then: hand off for GLM / when quota is back; **push to research-master**.

Do not fire A/B/C unless the operator (or this pickup’s recommended A after the gate is coded) says so. If they say “continue”, recommended is **A**.

---

## Last fire in one block

```
boot c5ad8ad0  runner gl_run_parkchild.sh  binary 226752  md5 46c058e3269e9d1a9fd8384f84cb0aea
W1 PLAIN park *selinux_state=P0(0x02BB0000)  LANDED  ENF=0
self_x28=ffffff89c23e0000/252
child_x28=ffffff88bb2ca500/114  who=child_x28  (no wrap)
W2 *ffffff88bb2cac80 = init_cred ffffff802a7e0be0  PLAIN only-left
pselect lock=bss_tail ffffff802abb9d00  task=init_task  prio=3
pselect pre-select +2ms  → KP
new boot c2773f39  Enforcing  uid 2000  sys.boot.reason=reboot
ROOTED = 25 NUL bytes root:root     NOT ASCII payload
uid0_id.txt = 0 bytes uid=0 gid=0xBB2CA500 (child x28 low32)
no UID0 WIN line
```

Log in-tree: `logs/Z33_parkchild.txt`.

Original Z33 (08-24) used the same `who=child_x28` geometry and **lived** ~2 min (`UID0 WIN child is root`, `/proc` Uid 0, parent 2000). This retry died in the walk. High-alias child is **not** “always fatal”, but it is **not** a free punch either.

---

## Lab rules (operator — do not violate)

| Rule | Why |
|------|-----|
| Branch `research-master` only | user |
| Push only to `plateau` (`AarifZ/ghostlock-cph2521-plateau`) unless asked | origin is JoinChang; do not spam #31 |
| Unix LF `gl_run_*.sh` | `fire_mode.ps1` CRLF / Permission denied |
| USB `596666e9` bootstrap only (`tcpip 5555`) | dual USB+WiFi → `error: closed` |
| Exploit/push/shell on `192.168.1.2:5555` | user |
| No second GhostLock after **any** successful walk | Z5 |
| No 8-byte NULL `selinux_state` / no Path B W1 | Z14 |
| No wrap `ffffff87/88/89`→P0 | Z23, Z28 |
| One data punch after park; child retry default 1 | Z26; 12 retries KPd |
| No fire ≲ 2 min | Z21 |
| No GBOOT module VA / no kptr `0xffffff8100000000` / no T1 `tree_pc=0` / no ZI | Z47, Z44, KP, KP×2 |
| Quote remote `$(...)` in PowerShell | host ate unquoted `$(cat /proc/...)` |
| Never grep `/data/local/tmp/a/e` | JoinChang stock binary |
| Research only; user’s device | |

Workspace: `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
Host adb: `.\adb_local.exe` or WinGet platform-tools.  
Push binary: `/data/local/tmp/gl_uid0`. NDK r27d `.\build_cph2521.ps1`.  
KPHYS=`0xa8000000`. CORE_SEL=7.

---

## First actions (in order)

1. **Classify, do not fire.** If uptime < 120s or both USB and WiFi are `device`, wait / disconnect USB from the fire path.
2. If the operator wants kernel progress: **code the self-only cred gate**, rebuild, then `gl_run_hookcred.sh` (same process: W1 leaf-NULL, W2 **self**). StdSP is already `disable-user`. Mute is already called on this path. Flush `getuid_after_store` is already in `fops.c` — still confirm the file on disk before claiming uid0.
3. If they insist on Exact Z33 again: tell them it KPd this session; only fire if they accept another reboot.
4. Stop after two pre-select SOFTBOOTs in a row or if the phone is hot.

### Self-only gate (required before hookcred)

Current fallback in `uid0_cred_punch` (`src/core/main.c`):

1. if `UID0_PREFER_CHILD` and child x28 ok → **child** (Z33 path)
2. else if self x28 is **P0** → self
3. else if child x28 ok → **child**  ← hookcred lands here on this phone
4. else self raw

`gl_run_hookcred.sh` does not set `UID0_PREFER_CHILD`, but step 3 still punches the child. Self this fire was `ffffff89` (not P0). That is today’s KP with a leaf-NULL W1 instead of park.

Fix: punch self when `MODE4_NULL_STORE` / hookcred / `UID0_PREFER_SELF`; do not fall through to child. High-alias self historically **missed** without KP. A miss after a living W1 still burns the only remaining walk — say so.

Do **not** implement wrap-to-P0 as the fix.

---

## What is already in the binary (do not “rediscover”)

- Cred stamp default = park-class **PLAIN only-left** (`tree_pc=init_cred`, `tree_l=slot`, `tree_r=0`). GLM 08-31 only-right is `MODE4_CRED_RIGHT=1` (KPd 4/4).
- `UID0_PREFER_CHILD=1` punches raw child x28, including `ffffff88/89`, slot `+0x780` unless `UID0_SLOT=`.
- Child payload: `child_seen_root()` is `getuid/euid/status Uid==0`; writes `/data/local/tmp/ROOTED`; parent writes `uid0_go` on child-only WIN. **Did not run a living payload this fire.**
- `LANDING_RETRY` child default 1, self 2.
- `uid0_mute_coloros()` **is** called on the NULL_STORE path (08-29 bug is fixed).
- `MODE4_ROOT` no longer forces `MODE4_SLIDE_SPRAY`. Still do not fire sprayed swap on a whim.

---

## Proven vs not

| Claim | Evidence |
|-------|----------|
| Park lives | Z15; this session W1 |
| Leaf-NULL lives | 24c41c5a ret=5 |
| Child `/proc` Uid 0 ~2 min | Z33 08-24 only |
| Exact Z33 09-12 | **KP** |
| Parent getuid=0 | **not** on disk |
| JoinChang Path A on CPH | miss, success=0 |
| Product root / KSU | **no** |

Do not write “we were one step away” or “ROOTED means uid0”.

---

## Issue #31

https://github.com/JoinChang/ghostlock-oneplus/issues/31  
Our update: `docs/ISSUE31_UPDATE_2026-08-28.md` (comment 5456301814). **Do not post again** unless the operator asks or the owner replies.

Remaining kR/W ask: first pwrite without post-swap `open()`.
