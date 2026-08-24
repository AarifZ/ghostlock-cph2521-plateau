# Next session pickup — 2026-08-24 (GBOOT / kevent)

**Read first:** this file, then `docs/Z49_GBOOT_CHECKPOINT_2026-08-24.md`, then `docs/Z29_UID0_CHECKPOINT_2026-08-24.md` (x28/cred offsets still valid), then `docs/Z15_SELINUX_PLAIN_PARK_2026-08-23.md`.  
**Supersedes** the earlier “next fire is self-cred” text in this filename. Self-cred still SIGKILLs until the OPPO sys_exit hook is off.

**Workspace:** `C:\Users\LENOVO\Desktop\HILY installer\Oppo\ghostlock-oneplus`  
**Branch:** `research-master` only.  
**Binary:** `ghostlock-cph2521` — rebuild `.\build_cph2521.ps1` if the tree moved.

---

## One-sentence status

Park is durable. Perf can leak `oplus_security_guard` `.text` (page-off `0x3e8`). `g_boot_state` is 1 byte at `.text+0x3000`. Writing that **module VA** KPs (`STRICT_MODULE_RWX`). Physmap punch needs an 8-byte kernel read of `swapper_pg_dir` (P0 `ffffff802a491000`). kprobe/watchpoint/kptr all failed for that read.

---

## Policy (do not violate)

- No second GhostLock on a park boot (**Z5**). Permissive can persist after the process dies.
- No 8-byte NULL into `selinux_state` (**Z14**).
- No spray after park. No wrap `ffffff87/88/89` → P0 (**Z23, Z28**).
- One data punch after park (**Z26** third walk KP).
- Unix LF runners only. No `fire_mode.ps1`.
- No kptr VALUE `0xffffff8100000000` (**Z44** live DRAM).
- No GBOOT punch to the **module VA** (**Z47** RO page).
- Do not fire on boots ≲ 2 min.
- After **kernel panic / softboot: WiFi ADB `192.168.1.108:5555` first** (USB often dead). Do not USB-PnP.
- After clean `adb reboot` / ColorOS 15s: USB `596666e9` usually returns; 5555 dead until Shizuku.
- No JoinChang #31 post. Push only if asked.

---

## Next fire (fresh boot, uptime ≳ 2 min, **one** process)

Need **P0(`g_boot_state`)** then:

```
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 DATAONLY_TARGET=0x2a793c8
MODE4_SWAP_NOCFI=1 MODE4_UID0=1 MODE4_UID0_GBOOT=1
CORE_SEL=7
```

Push `ghostlock-cph2521` → `/data/local/tmp/gl_uid0` + Unix LF `gl_run_gboot.sh`.

Harvest already finds VA = hook_page + `0x3000`. **Do not store to that VA.** Store BSS|1 (`P0(0x02BB0000)|1`) to the **physmap alias**. If P0 is unknown, HOLD (Z48/Z49) — do not guess DRAM VALUEs.

**AAR to try next (not done):** CFI-safe ashmem fops swap (`offsets.h` `*.cfi_jt`) + `pipe_physrw`, then walk `swapper_pg_dir` and write g_boot + cred through P0. Spray-free overlay only. Alternatively skip park: walk1 hook-off, walk2 cred, accept ColorOS 15s after uid0.

Success: hook off (self-cred pselect returns) then `getuid()==0`. ColorOS 15s dialog after that is still a kernel win.

---

## ADB

| | |
|--|--|
| WiFi | `192.168.1.108:5555` Shizuku 13.6 — **use after softboot/KP** |
| USB | `596666e9` — classify/fire after clean reboot if 5555 is down |
| Host | WinGet `platform-tools\adb.exe` |
| Last seen | boot `2687342b` Enforcing, USB up, **5555 refused** (Shizuku not bound). Ping `192.168.1.108` ok. |

---

## Do not reopen

ION / PAD3 / dual-PI / swapped ashmem / `MODE4_ROOT` this cycle / JoinChang 6.12 `.write_iter` on 5.10 / kptr DRAM VALUE / module-VA GBOOT punch.

---

## Logs / tools

`logs/aarif_pull/Z43_*` … `Z49_gboot_ptwalk_console.txt` (gitignored).  
`tools/modip_probe.c` — perf IP histogram, not a second GhostLock.  
`tools/bp_probe.c` — kernel watchpoints EINVAL; user watchpoints work.
