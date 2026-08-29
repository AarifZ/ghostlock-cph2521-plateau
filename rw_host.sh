#!/bin/bash
# rw_host.sh — host launcher: pushes everything, starts the device-side chain
# detached, then polls the chain log / ROOTED with full transport recovery.
# Usage: ./rw_host.sh [attempts]
ADB="/c/Users/LENOVO/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe"
WIFI=192.168.1.108:5555
USB=596666e9
ROOT="$(cd "$(dirname "$0")" && pwd)"
MAX=${1:-10}

dev() { # run on whichever transport is alive
  if MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI shell "$@" 2>/dev/null; then return 0; fi
  MSYS_NO_PATHCONV=1 "$ADB" -s $USB shell "$@" 2>/dev/null
}
conn() {
  MSYS_NO_PATHCONV=1 "$ADB" connect $WIFI >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 "$ADB" devices 2>/dev/null | grep -qE "$WIFI.*device$|$USB"
}

echo "== setup =="
MSYS_NO_PATHCONV=1 "$ADB" kill-server >/dev/null 2>&1; sleep 2
conn || { echo "no device — open Shizuku/replug USB"; exit 1; }
for f in ghostlock-cph2521:gl_rw swap_probe:swap_probe slide_dec:slide_dec; do
  src=${f%%:*}; dst=${f##*:}
  MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push "$src" /data/local/tmp/$dst >/dev/null 2>&1 || \
  MSYS_NO_PATHCONV=1 "$ADB" -s $USB push "$src" /data/local/tmp/$dst >/dev/null 2>&1
done
MSYS_NO_PATHCONV=1 "$ADB" -s $WIFI push rw_chain.sh /data/local/tmp/rw_chain.sh >/dev/null 2>&1 || \
MSYS_NO_PATHCONV=1 "$ADB" -s $USB push rw_chain.sh /data/local/tmp/rw_chain.sh >/dev/null 2>&1
dev "tr -d '
' < /data/local/tmp/rw_chain.sh > /data/local/tmp/rw_chain_lf.sh && chmod 755 /data/local/tmp/gl_rw /data/local/tmp/swap_probe /data/local/tmp/slide_dec /data/local/tmp/rw_chain_lf.sh; rm -f /data/local/tmp/rw_chain.log /data/local/tmp/ROOTED; echo READY"

for att in $(seq 1 $MAX); do
  echo "== attempt $att =="
  dev "rm -f /data/local/tmp/rw_chain.log /data/local/tmp/CHAIN_DONE /data/local/tmp/probe_out.txt; nohup sh /data/local/tmp/rw_chain_lf.sh >/dev/null 2>&1 & echo CHAIN_LAUNCHED"

  # poll chain log until chain ends or ROOTED appears (with transport recovery)
  for i in $(seq 1 200); do
    OUT=$(dev "test -f /data/local/tmp/CHAIN_DONE && echo CHAIN_DONE; test -f /data/local/tmp/ROOTED && echo HAVE_ROOT; tail -1 /data/local/tmp/rw_chain.log 2>/dev/null")
    if echo "$OUT" | grep -q HAVE_ROOT; then
      echo "*** ROOTED ***"
      dev "cat /data/local/tmp/ROOTED; cat /data/local/tmp/probe_out.txt | tail -20"
      exit 0
    fi
    if echo "$OUT" | grep -q CHAIN_DONE; then
      echo "chain finished:"
      dev "cat /data/local/tmp/rw_chain.log; echo ----; tail -25 /data/local/tmp/probe_out.txt 2>/dev/null"
      break
    fi
    sleep 6
  done

  # retry only if the walk missed (chain ended without ROOTED)
  if dev "test -f /data/local/tmp/ROOTED"; then
    dev "cat /data/local/tmp/ROOTED"; exit 0
  fi
  # let the boot settle if it crashed
  echo "attempt $att done — settling 120s"
  sleep 120
  conn || { echo "waiting for device..."; for w in $(seq 1 30); do sleep 20; conn && break; done; }
done
echo "no root after $MAX attempts"
exit 1
