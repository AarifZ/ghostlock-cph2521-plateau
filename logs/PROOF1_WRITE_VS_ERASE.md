# PROOF1 — write-lands-then-dies vs dies-in-erase (2026-08-09)

## Method
pstore denied for shell. Used **durable `stage.txt` on /storage** (survives softboot) with fsync markers:

- `pre_setattr` — immediately before `sched_setattr`
- `post_setattr` — after setprio returns  
- `cfi_*` — open/write probe after punch  

Fire: classic SAFE + LOCK_OWNER0 + CFI_ON_PUNCH + zeroed fake_fops. EDEADLK=35.

## Stage after softboot + hardboot (survived)

```text
... after_cmp_requeue_pi
waiter_after_requeue_enter_pselect
pselect_setup / pselect_pre_select
PROOF pre_setattr          ← last line
```

**Missing:** `post_setattr`, `cfi_on_punch_enter`, `cfi_open_*`, `cfi_write_*`.

## Verdict

| Question | Answer |
|----------|--------|
| Die after userspace CFI open/write? | **No** — never reached |
| Die after setprio returns? | **No** — no `post_setattr` |
| Die **during** setprio (erase/adjust)? | **Yes** — last marker is `pre_setattr` |

So this is **not** “write lands, fake_fops used, then CFI fails.”  
It is **synchronous death inside the punch syscall** (`sched_setattr` → adjust → dequeue/`rb_erase` / immediate fallout), before return to userspace.

Write may still land in the same ms as the panic (we cannot prove/disprove store without pstore/fault PC). We **can** rule out: “erase succeeds, process continues, bad fops on later open.”

## pstore
`/sys/fs/pstore` → Permission denied (shell). Need root or eng build for console-ramoops.

## Implication for plateau cross
Fix must make **rb_erase with parent=MISC-8 (or that chain step) non-fatal**, or avoid that geometry. Hardening fake_fops alone cannot help if we never return from setprio.

## Recovery
CLEAN `0d2bf8a1-…` after hardboot.
