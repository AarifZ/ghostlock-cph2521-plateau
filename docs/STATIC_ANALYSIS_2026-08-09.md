# CPH2521 static analysis notes (WSL, 2026-08-09)

## Root / tools

- WSL Ubuntu: **root works** (`wsl -u root`)
- Installed: `cpio`, `dtc`, `binwalk` (+ deps)
- Lab: `~/cph-lab/` (aarifz) — tools + links to boot.img / kernel / kallsyms
- Pre-existing: `~/toolchain` (aarch64-linux-gnu-objdump, llvm-*)

## Unpacked boot

| Item | Value |
|------|--------|
| boot.img | HEADER_VER 4, OS 12, patch 2026-06 |
| KERNEL | raw ARM64 Image, **48114492** bytes |
| RAMDISK | lz4_legacy ~1.7 MB → `ramdisk.cpio` |
| KIMAGE base | `0xffffffc008000000` |

## Confirmed kallsyms (from device dump)

| Symbol | Address |
|--------|---------|
| `task_blocks_on_rt_mutex` | `0xffffffc0081ecaf0` |
| `remove_waiter` | `0xffffffc0081ed254` |
| `rb_erase` | `0xffffffc008ab7590` |
| `rt_mutex_setprio` | `0xffffffc0081a5d60` |
| `ashmem_fops` | `0xffffffc00a2bfdc8` |
| `ashmem_misc` | `0xffffffc00a91a8d8` |

## remove_waiter (disasm summary)

Matches our earlier dig:

1. **Main tree erase:** `rb_erase(waiter, lock+8)` — waiters at lock+0x08  
2. **pi_lock** at task+**0x86c** (`add x21, x20, #0x86c`)  
3. **pi_waiters** at task+**0x880** (`add x1, x21, #0x880` then `bl rb_erase`)  
4. Only if removed waiter was top / matching owner path  

So: **heap W0 alone is not erased** unless it is the node passed to `remove_waiter` (the stack UAF waiter), or is linked in a tree that gets walked incorrectly.

## rb_erase only-right path (classic write)

At `rb_erase` ~`0x…ab7618`:

- Load `__rb_parent_color`  
- Mask parent `~3`  
- **`str parent_color → [rb_right]`** when only-right child path  
- Then `__rb_change_child` style parent slot update  

Primitive: **`*rb_right = __rb_parent_color`** (then parent rewiring).  
Classic stamp: parent_color=MISC-8, right=fake_fops → `*MISC = fake_fops` via change_child on parent’s rb_right slot.

## ashmem_fops layout (from Image dump)

| Off | Content |
|-----|---------|
| +0x00 | owner = 0 |
| +0x08 | llseek JT `…981fef8` |
| +0x10 | **read = 0** |
| +0x18 | **write = 0** |
| +0x20 | read_iter JT |
| +0x50 | ioctl JT |
| +0x70 | open JT |
| +0x80 | release JT |
| +0xe0 | show_fdinfo JT |

**ashmem_misc+0x10 = ashmem_fops** — matches CPH offsets.  
**errno=22** is expected until `ashmem_misc.fops` is redirected (no `.write` on real ashmem_fops).

## Implications for plateau

| Fact | Impact |
|------|--------|
| Write fires only if **erased node** carries classic/inverted gadget | Heap W0 inert ⇒ no redirect (current plateau) |
| Stack MAIN classic (MISC-8) softboots on CPH | Still true on-device; static doesn’t contradict |
| pi_waiters under fake_task softboots | Confirmed path exists in remove_waiter |
| Consumer delay ≥50ms | Orthogonal; keeps route alive |

**Still open:** get a **surviving** stamp that is actually **erased** (stack after link, or lock.waiters node that remove_waiter targets) without softboot.

## remove_waiter (llvm/aarch64-objdump, re-check 2026-08-09)

Confirmed from `~/cph-lab/work/disasm/remove_waiter.dis`:

1. Args: `x0=lock`, `x1=waiter` → `x19=lock`, `x23=waiter`
2. **`mrs sp_el0` → `current`** used for `pi_lock` @ +0x86c (GhostLock “wrong task” path)
3. Main erase: `rb_erase(waiter, lock+8)` @ `…1ed30c` → **erased node is the stack UAF waiter itself**, not heap W0
4. If top waiter path: `rb_erase(waiter.pi_tree, owner+0x880)` after owner `pi_lock` @ +0x86c
5. Later may re-link next waiter into owner’s pi tree and call `rt_mutex_setprio`

### Write implication (stronger)

| Node | Erased by remove_waiter? | Can carry classic gadget? |
|------|--------------------------|---------------------------|
| Stack pselect overlay waiter (main rb @ +0) | **YES** (always main erase) | Yes — only path that matches erase |
| Heap W0 | **No** (unless it *is* the pointer passed in) | Useless alone for fops write |
| fake_task.pi_waiters → W0 | Softboot on CPH when walked | Rejected |

Classic only-right (`rb_erase` @ `…ab7618`):

- `*right = parent_color`
- then parent left/right slot ← right child  
- For fops: `parent_color = MISC-8`, `right = fake_fops`, node was parent’s **left** child → `*(MISC) = fake_fops`

A53 `write_set[1/2]=MISC-8,fake_fops` lands on **task/lock** under CPH `shift=-2` → softboot (rejected).  
`MODE4_CLASSIC_MAPPED` maps tree words correctly but historically softboots (MISC walk / link race) — do not re-fire without new timing theory.

## Ghidra / GhidraMCP status (2026-08-09)

| Item | Status |
|------|--------|
| Ghidra install | `C:\Users\LENOVO\Desktop\ghidra_12.1.2_PUBLIC` |
| Plugin zip | `Downloads\GhidraMCP-release-1-4\...\GhidraMCP-1-4.zip` |
| `javaw` process | often running |
| HTTP `127.0.0.1:8080` | **DOWN** — plugin server not listening |
| This client MCP tools | **empty** (bridge not registered) |

To enable agent decompile:

1. Ghidra → Install Extensions → `GhidraMCP-1-4.zip` → restart  
2. File → Configure → Developer → enable **GhidraMCPPlugin**  
3. Edit → Tool Options → GhidraMCP HTTP Server → port **8080**, start/enable  
4. Open project with kernel Image analyzed  
5. Optional: register `bridge_mcp_ghidra.py` in client MCP config  

Until then: WSL objdump remains the RE path.

## Next static (optional)

- Map `task_blocks_on_rt_mutex` link order vs when stack is free for stamp  
- When stack classic can exist *only after* link (if reclaim timing allows)  
- Do **not** re-open A53_STAMP / pi_waiters / DIG without new evidence  

## Space note

C: still ~**33 GB free**. Avoid large Ghidra projects unless you free more space. Current lab is lean (symlinks + small tools).
