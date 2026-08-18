#!/bin/bash
ADB="/c/Users/LENOVO/AppData/LOCAL/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
N=$1; MAX=${2:-8}
gettemp() { "$ADB" -s 192.168.1.108:5555 shell "dumpsys battery | grep -i temperature" 2>/dev/null | grep -oE "[0-9]+" | head -1; }
for attempt in $(seq 1 "$MAX"); do
  sleep 30; "$ADB" connect 192.168.1.108:5555 >/dev/null 2>&1
  t=$(gettemp); [ -z "$t" ] && t=0
  if [ "$t" -ge 750 ]; then echo "HOT — cooling"; while :; do sleep 120; t=$(gettemp); [ -z "$t" ] && t=0; [ "$t" -le 500 ] && break; done; fi
  pre=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
  [ -z "$pre" ] && { echo "A$attempt: no shell"; continue; }
  "$ADB" -s 192.168.1.108:5555 reboot; sleep 5; ok=0
  for i in $(seq 1 60); do sleep 10; out=$("$ADB" connect 192.168.1.108:5555 2>&1)
    if echo "$out" | grep -q "connected to"; then
      bid=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
      bc=$("$ADB" -s 192.168.1.108:5555 shell "getprop sys.boot_completed" 2>/dev/null | tr -d '\r')
      if [ "$bc" = "1" ] && [ -n "$bid" ] && [ "$bid" != "$pre" ]; then ok=1; break; fi
    fi; done
  [ "$ok" = "1" ] || { echo "A$attempt: reboot failed"; continue; }
  up=$("$ADB" -s 192.168.1.108:5555 shell 'cat /proc/uptime' | tr -d '\r'); up_s=${up%%.*}
  [ "$up_s" -lt 30 ] && sleep $((30-up_s))
  tag=$(powershell -ExecutionPolicy Bypass -File fire_mode.ps1 -ModeEnv "MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops MODE4_STATIC_CHAIN=1 MODE4_SC_UMASK=1 MODE4_SELFSTAMP=1 SELFSTAMP_SINGLE=$N MODE4_PROOF=1" -TagPrefix "S${N}_${attempt}" 2>&1 | grep -aoE "CLASS=[A-Z]+" | head -1)
  ls_log=$(ls -t logs/aarif_pull/S${N}_${attempt}*_live_sync.log 2>/dev/null | head -1)
  echo "P$N A$attempt: $tag | $(tail -2 "$ls_log" 2>/dev/null | grep -aoE 'STAGE [a-z_]+|PROOF [a-z_=0-9-]+' | tail -2 | tr '\n' ' ')"
  if [ "$N" = "1" ]; then
    enf=$("$ADB" -s 192.168.1.108:5555 shell "getenforce" 2>/dev/null | tr -d '\r')
    echo "  getenforce=$enf"
    [ "$enf" = "Permissive" ] && { echo "P1 LANDED"; exit 0; }
  elif [ "$N" = "2" ]; then
    ks=$("$ADB" -s 192.168.1.108:5555 shell "head -1 /proc/kallsyms" 2>/dev/null | tr -d '\r')
    echo "  kallsyms: $ks"
    echo "$ks" | grep -qE "^[0-9a-f]{12,16} " && { echo "P2 LANDED — SLIDE OPEN"; exit 0; }
  else
    post=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
    echo "$post" | grep -q "80ff-ffff" && { echo "P3 LANDED"; exit 0; }
  fi
done
echo "P$N: exhausted"; exit 1
