# ADB drop vs softboot (CPH2521 test hygiene)

Route `success=1` can still be followed by:

1. **True softboot / panic reboot** — kernel dies, phone restarts  
2. **ADB/USB disconnect** — userspace exploit finished, but host loses device  
3. **Delayed crash** — log completes, death seconds later  

Operator view of (1) and (2) is often identical: “device not detected until reconnect.”

## Never call it “just a blip” without proof

Before fire (print + save):

```sh
cat /proc/uptime
cat /proc/sys/kernel/random/boot_id
```

After fire / when ADB returns:

```sh
cat /proc/uptime
cat /proc/sys/kernel/random/boot_id
```

| Observation | Classification |
|-------------|----------------|
| `boot_id` changed | **reboot / softboot** |
| `uptime` near 0 after was high | **reboot / softboot** |
| same `boot_id`, uptime still increasing | **ADB/USB drop only** |
| cannot compare | **softboot-class** (fail-safe) |

## Related note

Post-route ADB instability after GhostLock mode4 is a known pain (consumer punch / heavy spray). Still: for stamp experiments, unstable ADB after success does **not** count as “beats plateau” unless write lands **and** device stays stable across retests.