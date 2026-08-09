# Session 2026-08-09 — research + on-device tests

## GhidraMCP

| Item | Status |
|------|--------|
| Ghidra | `Desktop\ghidra_12.1.2_PUBLIC` |
| Plugin release | `Downloads\GhidraMCP-release-1-4\...\GhidraMCP-1-4.zip` |
| `javaw` | often running |
| HTTP `127.0.0.1:8080` | **not listening** |
| Agent MCP tools | **not exposed** |

Enable: Extensions → GhidraMCP → Developer configure → Tool Options → GhidraMCP HTTP Server port 8080 + open analyzed kernel Image.

## Static (WSL objdump, no Ghidra needed)

- `remove_waiter` erases **stack waiter** via `rb_erase(waiter, lock+8)`; uses **current** for pi_lock (GhostLock path).
- Heap W0 is **not** the erased node → inert W0 cannot produce fops write alone.
- Classic write needs stamp on **stack main rb_node** (parent=MISC-8, right=fake_fops, left=0).
- A53 `write_set[1/2]` collides with CPH `shift=-2` task/lock → still rejected.
- Disasm artifacts: WSL `~/cph-lab/work/disasm/*.dis`

## On-device results (CPH2521)

| Run | Env | Result |
|-----|-----|--------|
| R1 baseline delay=50ms | `MODE4_ONLY=1 KPHYS=0xa8000000` | **softboot** at pre-select |
| R2 baseline delay=50ms | same | **softboot** at pre-select |
| NO_CONSUMER | `MODE4_NO_CONSUMER=1` | **ALIVE** post-select ret=0 success=0 |
| delay=150ms | `PSELECT_ROUTE_DELAY_USEC=150000` | **success=1, cfi errno=22, ALIVE** |

### Plateau reconfirm (proven this session)

```text
mode4 BASELINE t0 W0 main=1,0,0 pi=1,0,0 pi_waiters=0
stack BASELINE main=0,0,0 pi=0,0,0 task=init_task lock=fake_lock
pselect place tree=0 pi=0 task=init_task lock=fake_lock
post-select ret=5 success=1 delay=150000
cfi write ret=-1 errno=22
ALIVE
```

Log: `logs/plateau_delay150_r2.txt`

### Interpretation

1. Overlay packing is **not** the softboot source (NO_CONSUMER survives).
2. Default 50ms consumer is **flaky** on this device; **150ms** recovered plateau this session.
3. Write still not landing (expected until stack classic stamp survives erase path).

## Policy unchanged

- Do not merge A53_STAMP / CLASSIC_MAPPED / DIG / pi_waiters without new theory.
- Prefer `PSELECT_ROUTE_DELAY_USEC=150000` for retests until 50ms is re-characterized.
- Next write progress = stack main classic that survives link→erase, not heap W0 gadgets.
