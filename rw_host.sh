#!/bin/bash
# rw_host.sh — host launcher for the device-side root chain.
# Pushes binaries + rw_chain.sh (LF-normalized), launches it detached,
# polls for ROOTED / CHAIN_DONE with full transport recovery.
# Usage: ./rw_host.sh [attempts]
ADB="/c/Users/LENOVO/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft_Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
WIFI=192.168.1.108:5555
USB=596666e9
ROOT="$(cd "$(dirname "$0")" && pwd)"
MAX=${1:-10}

push_any() { # local remote
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push "$1" "$2" >/dev/null 2>&1 && return 0
  MSYS_NO_PATHCONV=1 "$ADB" -s $USB push "$1" "$2" >/dev/null 2>&1 && return 0
  return 1
}
shell_any() { # cmd
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "$1" 2>/dev/null && return 0
  MSYS_NO_PATHCONV=1 "$ADB" -s $USB shell "$1" 2>/dev/null && return 0
  return 1
}
conn() {
  MSYS_NO_PATHCONV=1 "$ADB" connect $WIFI >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -qE "$WIFI.*device$|$USB.*device$"
}

cd "$ROOT"
echo "== setup =="
conn || { echo "no device — open Shizuku/replug USB"; exit 1; }
for f in ghostlock-cph2521:gl_rw swap_probe:swap_probe slide_dec:slide_dec rw_chain.sh:tmp_c_raw.sh; do
  src=${f%%:*}; dst=${f##*:}
  push_any "$src" "/data/local/tmp/$dst" || echo "PUSH FAILED: $src"
done
shell_any 'tr -d "\r" < /data/local/tmp/tmp_c_raw.sh > /data/local/tmp/rw_chain_lf.sh && chmod 755 /data/local/tmp/gl_rw /data/local/tmp/swap_probe /data/local/tmp/slide_dec /data/local/tmp/rw_chain_lf.sh && echo READY'

for att in $(seq 1 $MAX); do
  echo "== attempt $att $(date +%H:%M:%S) =="
  shell_any 'rm -f /data/local/tmp/rw_chain.log /data/local/tmp/CHAIN_DONE /data/local/tmp/ROOTED /data/local/tmp/probe_out.txt; nohup sh /data/local/tmp/rw_chain_lf.sh >/dev/null 2>&1 & echo CHAIN_LAUNCHED' || { echo "launch failed"; sleep 30; continue; }

  for i in $(seq 1 250); do
    OUT=$(shell_any 'test -f /data/local/tmp/ROOTED && echo HAVE_ROOT; test -f /data/local/tmp/CHAIN_DONE && echo CHAIN_DONE; tail -1 /data/local/tmp/rw_chain.log 2>/dev/null' 2>/dev/null)
    if echo "$OUT" | grep -q HAVE_ROOT; then
      echo "*** ROOTED at $(date +%H:%M:%S) ***"
      shell_any 'cat /data/local/tmp/ROOTED; echo ===PROBE===; cat /data/local/tmp/probe_out.txt 2>/dev/null | tail -30; echo ===CHAIN===; cat /data/local/tmp/rw_chain.log'
      exit 0
    fi
    if echo "$OUT" | grep -q CHAIN_DONE; then
      echo "chain finished at $(date +%H:%M:%S):"
      shell_any 'cat /data/local/tmp/rw_chain.log; echo ===PROBE===; tail -30 /data/local/tmp/probe_out.txt 2>/dev/null'
      break
    fi
    sleep 6
  done

  shell_any 'test -f /data/local/tmp/ROOTED' >/dev/null 2>&1 && {
    shell_any 'cat /data/local/tmp/ROOTED'; exit 0; }
  echo "attempt $att done — settling 120s"
  sleep 120
  conn || { echo "waiting for device..."; for w in $(seq 1 40); do sleep 20; conn && break; done; }
done
echo "no root after $MAX attempts"
exit 1
