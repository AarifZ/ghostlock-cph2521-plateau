#!/bin/bash
set -x
ADB=./adb_local.exe
WIFI=192.168.1.2:5555
cd "$(dirname "$0")"
B="q$(date +%s | tail -c 5)"; L="r$(date +%s | tail -c 6)"
for try in 1 2 3; do
  P=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push ghostlock-cph2521 /data/local/tmp/$B 2>&1 | grep -c "1 file pushed")
  echo "TRY$try P=$P"
  [ "$P" = "1" ] || break
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "chmod 755 /data/local/tmp/$B; cd /data/local/tmp; nohup sh -c 'echo probe' > /sdcard/Download/$L.txt 2>&1 &" >/dev/null 2>&1
  sleep 5
  V=$(MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "ls /sdcard/Download/$L.txt 2>/dev/null" 2>/dev/null | tr -d "\r")
  echo "TRY$try V=[$V]"
  [ -n "$V" ] && break
done
