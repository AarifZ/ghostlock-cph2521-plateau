#!/bin/bash
ADB="/c/Users/LENOVO/AppData/LOCAL/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
MAX=${1:-10}
gettemp() { "$ADB" -s 192.168.1.108:5555 shell "dumpsys battery | grep -i temperature" 2>/dev/null | grep -oE "[0-9]+" | head -1; }
for attempt in $(seq 1 "$MAX"); do
  sleep 30; "$ADB" connect 192.168.1.108:5555 >/dev/null 2>&1
  t=$(gettemp); [ -z "$t" ] && t=0
  echo "A$attempt start temp=$((${t:-0}/10)).$((${t:-0}%10))C"
  if [ "$t" -ge 750 ]; then echo "HOT — cooling"; while :; do sleep 120; t=$(gettemp); [ -z "$t" ] && t=0; [ "$t" -le 500 ] && break; echo "  $((${t:-0}/10)).$((${t:-0}%10))C"; done; fi
  pre=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
  [ -z "$pre" ] && { echo "A$attempt: no shell"; continue; }
  "$ADB" -s 192.168.1.108:5555 reboot; sleep 5; ok=0
  for i in $(seq 1 90); do sleep 10; out=$("$ADB" connect 192.168.1.108:5555 2>&1)
    if echo "$out" | grep -q "connected to"; then
      bid=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
      bc=$("$ADB" -s 192.168.1.108:5555 shell "getprop sys.boot_completed" 2>/dev/null | tr -d '\r')
      if [ "$bc" = "1" ] && [ -n "$bid" ] && [ "$bid" != "$pre" ]; then ok=1; break; fi
    fi; done
  [ "$ok" = "1" ] || { echo "A$attempt: reboot cycle failed"; continue; }
  up=$("$ADB" -s 192.168.1.108:5555 shell 'cat /proc/uptime' | tr -d '\r'); up_s=${up%%.*}
  [ "$up_s" -lt 30 ] && sleep $((30-up_s))
  cls=$(powershell -ExecutionPolicy Bypass -File fire_mode.ps1 -ModeEnv "MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops MODE4_STATIC_CHAIN=1 MODE4_SC_UMASK=1 MODE4_SELFSTAMP=1 SELFSTAMP_SINGLE=3 MODE4_PROOF=1" -TagPrefix "B3_${attempt}" 2>&1 | grep -aoE "CLASS=[A-Z]+" | head -1)
  ls_log=$(ls -t logs/aarif_pull/B3_${attempt}*_live_sync.log 2>/dev/null | head -1)
  ba=$(grep -a "WP_BOOTAFTER" "$ls_log" 2>/dev/null | head -1 | sed 's/.*WP_BOOTAFTER=//' | tr -d '')
  hn=$(grep -a "SS_HOSTNAME" "$ls_log" 2>/dev/null | head -1 | sed 's/.*SS_HOSTNAME=//')
  t2=$(gettemp); echo "A$attempt: $cls $ba endtemp=$((${t2:-0}/10)).$((${t2:-0}%10))C"
  if echo "$ba" | grep -q "80ff-ffff\|9dbb"; then echo "*** BOOTID LANDING: $ba ***"; exit 0; fi
done
echo "P3 exhausted"; exit 1
