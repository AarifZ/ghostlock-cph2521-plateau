# Aristotle (soralis) vs CPH2521 GhostLock — restudy (2026-08-16)

Sources:
- JoinChang [issue #9 comment](https://github.com/JoinChang/ghostlock-oneplus/issues/9#issuecomment-5092588416)
- [soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle) (local clone under `../CVE-2026-43499-aristotle`)

---

## 1. What JoinChang actually said

> *"The aristotle repo targets kernel 5.10 with a completely different exploit chain — it's not a GhostLock port and uses different primitives."*

| Claim | Accuracy |
|-------|----------|
| Different **product tree** (not JoinChang OPPO port) | **True** — popsicle → aristotle Xiaomi XIG04 |
| Different **CVE / UAF** | **False** — same CVE-2026-43499 / Futex-PI UAF |
| Different **core primitive** | **Mostly false** — still KS spray + pselect reclaim + **`rb_erase` AAW** |
| “They already rooted aristotle 5.10” | **Not claimed in-repo** — README: *code-complete, **not yet validated on hardware*** |

So: aristotle is a **sibling 5.10 line** of the same bug family, not proof that OPPO “just needs their tree.” Popsicle (6.12 Xiaomi) is the line that advertises full root; aristotle 5.10 is a static port.

---

## 2. Same chain (stages)

| Stage | Aristotle | Our CPH research |
|-------|-----------|------------------|
| 1 KASLR | slide via only-left loggers→boot_id | P0 assume + boot_id write-proof |
| 2 UAF | EDEADLK requeue + pselect | same |
| 3 AAW | `rb_erase` only-left (shape0) or classic (shape1) | same (WRITE_PROOF / ARISTOTLE) |
| 4 fops | only-left `*MISC=fake_fops` (intended) | **softboot** when left=MISC |
| 5 R/W | multi-shot direct AAW + pipe path | pipe present; blocked on fops |
| 6 root | direct-root: cred→init_cred, SELinux flip | UMH after fops (not reached) |

**Waiter:** both **5.10 flat `rb_node`** (not plist). Offsets 0x00/0x18/0x30/0x38/0x40/0x48 match.

---

## 3. Geometry differences that matter

### Aristotle stack (`fops.c` `prepare_pselect_fdsets`)

Default **shape 0 (only-left)**:

```text
parent = value (fake_fops)
right  = 0
left   = target
→ stamps BOTH main tree AND pi_tree the same way
task   = fake_task
lock   = fake_lock
prio   = FAKE_WAITER_PRIO
```

Shape 1 (classic): `parent=target-8`, `right=value`, `left=0`.

### Aristotle heap (`util.c` `put_direct_waiter`)

```text
W0.main  = 1, 0, 0          # empty black leaf
W0.pi    = parent, right, left   # write shape lives on PI
lock.waiters = W0
lock.owner   = fake_task | 1     # NOT bare owner=1
pi_waiters   = 0 for FOPS payload
```

### Our CPH (proven vs gap)

| Piece | CPH now | Aristotle source |
|-------|---------|------------------|
| only-left boot_id | **PROVEN land** | slide stage |
| stack dual main+pi | opt-in `MODE4_ARISTOTLE_DUAL` | **always dual** |
| heap main leaf + PI shape | yes for ARISTOTLE | yes |
| owner | **1** (clean exit; our proof) | **fake_task\|1** |
| stack task | init_task-ish path | **fake_task** |
| only-left MISC | **SOFTBOOT** | intended (unvalidated) |
| ROOT_SPRAY root erase | **ALIVE** | n/a (they use only-left) |

---

## 4. What is portable to CPH (high ROI)

1. **Dual stack stamp by default** for only-left (aristotle always dual) — cheap; may change which tree re-enqueue walks.
2. **Write-proof gate before any MISC fire** — already policy; keep.
3. **Multi-shot `direct_pselect_write_once` loop** (re-spray per write) — useful after fops lands; optional later.
4. **Shape1 classic** only as secondary after dual only-left still dies — we already softbooted classic historically.
5. **Do not** chase plist (JoinChang #9 iQOO note) for CPH 5.10 — wrong generation.
6. **Do not** assume aristotle “solved MISC” until someone shows on-device fops land; their README admits no HW validation.

### What is *not* a free win

- Porting owner=`fake_task|1` wholesale (we softbooted that class before; owner=1 is our clean-exit proof).
- Copying MTK phys/slide constants.
- Expecting popsicle 6.12 waiter layout on 5.10.

---

## 5. Lab result: dual PI on CPH (2026-08-16 evening)

| Fire | Config | Result |
|------|--------|--------|
| `ari_dual_bootid_*` | WRITE_PROOF only-left bootid, **dual_pi=1** | **SOFTBOOT** after place (new boot_id) |

So aristotle’s “always dual main+pi” is **not portable** to CPH as-is: it kills even the quiet boot_id target that **main-only** previously landed.  
**Default stays main-only.** `MODE4_ARISTOTLE_DUAL=1` is research-only.

---

## 6. Where we are → next target

```text
WHERE WE ARE
  UAF prime .............. yes
  AAW (quiet BSS) ........ yes (boot_id, main-only)
  Dual PI only-left ...... SOFTBOOT even on boot_id (reject as default)
  Root erase packing ..... yes (ROOT_SPRAY ALIVE)
  *MISC=fake_fops ALIVE .. NO  ← product plateau
  uid0 ................... NO

WHERE WE WANT
  *MISC=fake_fops ALIVE → cfi≠22 → pipe/cred → uid0

NEXT (ordered)
  N1  Stop dual/MISC only-left thrash
  N2  ION / wait_lock without permanent name=NULL (ROOT_SPRAY proves left=0 lives)
  N3  remove_waiter / unlock-shaped dequeue (no re-enqueue walk of left)
  N4  Optional: aristotle multi-shot write loop AFTER a safe MISC land
```

---

## 6. Suggested GitHub question (when asking for help)

> CPH2521 5.10.236: only-left AAW proven on sysctl_bootid; only-left left=MISC softboots (re-enqueue walks toxic left); ROOT_SPRAY root erase ALIVE. Aristotle 5.10 source uses dual main+pi only-left for fops but is not HW-validated. Is the working 5.10 root path on real devices still only-left MISC, or did anyone land fops via root-erase (ION) / unlock-shaped dequeue?
