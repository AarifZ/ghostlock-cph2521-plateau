# Experiment B — MODE4_PI_CLASSIC — RESULT (revised)

**Date:** 2026-08-09  
**Device:** CPH2521, delay=150ms  
**Binary:** ghostlock-cph2521 (123080)

## Stamp (RE-backed erase target B)

Stack **pi_tree @ +0x18** classic only-right:

- main tree = 0
- `pi parent = MISC-8`, `pi right = fake_fops`, `pi left = 0`
- task/lock preserved
- stack prio=1, W0 prio=200 (prefer top for PI erase)

## Results

### r1 (clean boot ~29s)

```text
PI_CLASSIC(B) … place tree=0 pi=MISC-8 task=init lock=fake prio=1
post-select ret=3 success=1 delay=150000
cfi write ret=-1 errno=22
```

Post-check: `uptime` continuous 29→46s, `ALIVE` printed. **Looks like true survive** for that run.

### r2 (uptime ~72s, same session)

Userspace log eventually showed the same `success=1` / `cfi22` / `EXIT`, but **ADB dropped mid-run** (“no devices”) until manual reconnect — **same symptom class as softboot** from the operator’s perspective.

Classification:

| Signal | r1 | r2 |
|--------|----|----|
| Full log + cfi22 | yes | yes (on device file) |
| ADB stayed up through end | **yes** | **no** (dropout) |
| Confirmed no reboot (`uptime` monotonic / same `boot_id`) | **yes** (29→46) | **unproven** at drop time |

**Do not treat ADB dropout as “just a blip.”** Until we log `boot_id` + `uptime` immediately before/after every fire, post-route ADB loss counts as **softboot-class / unstable**.

## Verdict (revised)

| Metric | Outcome |
|--------|---------|
| Softboot / ADB death | **A hard-rejects; B flaky** (r1 ok, r2 ADB loss) |
| Route | often `success=1` when process finishes |
| Write landed | **No** (errno=22) |
| Plateau upgrade? | **No** — not safer than inert baseline overall |

**Not a merge candidate.** B is not a reliable “survive” stamp; one clean cfi22 does not outweigh softboot-like ADB death on retest.

Env: `MODE4_PI_CLASSIC=1` remains **opt-in only, not default**.

## Classification rule (for future runs)

After every fire, immediately:

```text
adb shell 'cat /proc/uptime; cat /proc/sys/kernel/random/boot_id'
```

- **Softboot / reboot:** `boot_id` changed OR `uptime` reset near 0  
- **ADB-only drop:** same `boot_id`, `uptime` still climbing (USB/stack issue)  
- **Ambiguous:** device gone and no pre-stored boot_id → treat as softboot-class
