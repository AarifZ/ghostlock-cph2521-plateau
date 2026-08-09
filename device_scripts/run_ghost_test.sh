#!/system/bin/sh
# Run GhostLock with on-device durable logging.
#
# Soft reboot kills this process — only flushed /sdcard lines survive.
# Exploit stdout/stderr are tee'd to ghost_log.txt with periodic sync.
#
# Env (optional):
#   KPHYS=0xa8000000
#   PSELECT_SHIFT=0|-2|2|...
#   PSELECT_SIMPLE_LAYOUT=0|1
#   GHOST_BIN=/data/local/tmp/a/e
#   CLEAN=1          # wipe logs before run (default 1)
#   SKIP_COLLECTOR=0 # set 1 to only tee exploit, no logcat
#
# Usage:
#   /data/local/tmp/run_ghost_test.sh
#   KPHYS=0xa8000000 PSELECT_SHIFT=2 /data/local/tmp/run_ghost_test.sh

if [ -d /storage/emulated/0 ]; then
  LOG_DIR="/storage/emulated/0/ghostlock_logs"
else
  LOG_DIR="/sdcard/ghostlock_logs"
fi
RUN_DIR="/data/local/tmp/ghostlock_run"
COLLECT="/data/local/tmp/collect_log.sh"
MAIN_LOG="$LOG_DIR/ghost_log.txt"
EXPLOIT_LOG="$LOG_DIR/exploit.txt"
META_LOG="$LOG_DIR/meta.txt"
BIN="${GHOST_BIN:-/data/local/tmp/a/e}"
CLEAN="${CLEAN:-1}"
SKIP_COLLECTOR="${SKIP_COLLECTOR:-0}"

# After hard reboot, emulated storage can lag a few seconds.
i=0
while [ $i -lt 40 ]; do
  mkdir -p "$LOG_DIR" "$RUN_DIR" 2>/dev/null
  if touch "$LOG_DIR/.writetest" 2>/dev/null; then
    rm -f "$LOG_DIR/.writetest"
    break
  fi
  i=$((i + 1))
  sleep 0.5
done
mkdir -p "$LOG_DIR" "$RUN_DIR" 2>/dev/null

ts() {
  U=$(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)
  D=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo nodate)
  echo "[$D up=${U}s]"
}

say() {
  line="$(ts) $*"
  echo "$line"
  echo "$line" >> "$MAIN_LOG"
  echo "$line" >> "$META_LOG"
  sync 2>/dev/null
}

if [ ! -x "$BIN" ] && [ -f "$BIN" ]; then
  chmod 755 "$BIN" 2>/dev/null
fi
if [ ! -f "$BIN" ]; then
  echo "ERROR: missing binary $BIN"
  exit 2
fi

if [ "$CLEAN" = "1" ]; then
  if [ -x "$COLLECT" ]; then
    sh "$COLLECT" clean
  else
    rm -rf "$LOG_DIR"
    mkdir -p "$LOG_DIR"
  fi
fi

mkdir -p "$LOG_DIR"
say "=== run_ghost_test BEGIN ==="
say "bin=$BIN"
say "KPHYS=${KPHYS:-unset} PSELECT_SHIFT=${PSELECT_SHIFT:-unset} PSELECT_SIMPLE_LAYOUT=${PSELECT_SIMPLE_LAYOUT:-unset}"
say "uname=$(uname -r 2>/dev/null) uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
say "uptime=$(cat /proc/uptime 2>/dev/null)"

# export defaults
export KPHYS="${KPHYS:-0xa8000000}"

if [ "$SKIP_COLLECTOR" != "1" ] && [ -f "$COLLECT" ]; then
  chmod 755 "$COLLECT" 2>/dev/null
  sh "$COLLECT" start
  # Android kill -0 status can be flaky; report pid file instead
  if [ -f /data/local/tmp/ghostlock_run/collect_log.pid ]; then
    say "collector pid=$(cat /data/local/tmp/ghostlock_run/collect_log.pid 2>/dev/null)"
  else
    say "collector: start attempted (no pid file)"
  fi
else
  say "collector skipped"
fi

# Background fsync watchdog while exploit runs (keeps last lines on disk)
(
  trap '' HUP
  while true; do
    sync 2>/dev/null
    sleep 0.5
  done
) &
SYNC_PID=$!

say "launching exploit..."
# Record start marker for post-mortem
echo "$(ts) EXPLOIT_START" >> "$EXPLOIT_LOG"
echo "$(ts) EXPLOIT_START" >> "$MAIN_LOG"
sync 2>/dev/null

# Avoid pipe+while (Android toybox often loses child output / early exit).
# Write raw stream, then copy into durable logs with sync.
RAW="$LOG_DIR/exploit_raw.txt"
rm -f "$RAW" 2>/dev/null
# line-buffered-ish: run under script if available; else plain redirect
if command -v script >/dev/null 2>&1; then
  script -q -c "$BIN" "$RAW" >/dev/null 2>&1
  RC=$?
else
  "$BIN" >"$RAW" 2>&1
  RC=$?
fi
echo "$RC" > "$RUN_DIR/last_exit_code"

# Append raw output to durable logs (even partial if soft-rebooted mid-write
# we still have exploit_raw on sdcard if the FS flushed pages).
if [ -f "$RAW" ]; then
  echo "$(ts) --- exploit stdout/stderr (raw copy) ---" >> "$EXPLOIT_LOG"
  echo "$(ts) --- exploit stdout/stderr (raw copy) ---" >> "$MAIN_LOG"
  cat "$RAW" >> "$EXPLOIT_LOG" 2>/dev/null
  cat "$RAW" >> "$MAIN_LOG" 2>/dev/null
  # also print for adb-attached runs
  cat "$RAW" 2>/dev/null
fi
echo "$(ts) --- exploit exit rc=$RC ---" >> "$EXPLOIT_LOG"
echo "$(ts) --- exploit exit rc=$RC ---" >> "$MAIN_LOG"
sync 2>/dev/null

say "exploit finished rc=$RC (if you see this, no soft-reboot)"

# Final dumps
if [ -f "$COLLECT" ]; then
  sh "$COLLECT" dump-hints
fi
{
  echo "$(ts) --- final dmesg tail ---"
  dmesg 2>/dev/null | tail -n 120
} >> "$MAIN_LOG" 2>/dev/null

kill "$SYNC_PID" 2>/dev/null
sync 2>/dev/null
say "=== run_ghost_test END rc=$RC ==="
exit "$RC"
