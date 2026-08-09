#!/system/bin/sh
# On-device log collector for GhostLock soft-reboot survivability.
#
# Survives ADB drop while the process is alive. On *kernel soft reboot*
# this process dies too — only data already flushed to /sdcard remains.
# We fsync aggressively for that reason.
#
# Usage:
#   /data/local/tmp/collect_log.sh start   # background
#   /data/local/tmp/collect_log.sh stop
#   /data/local/tmp/collect_log.sh status
#   /data/local/tmp/collect_log.sh clean   # wipe old session logs

# Prefer emulated path early after boot when /sdcard symlink is late.
if [ -d /storage/emulated/0 ]; then
  LOG_DIR="/storage/emulated/0/ghostlock_logs"
else
  LOG_DIR="/sdcard/ghostlock_logs"
fi
RUN_DIR="/data/local/tmp/ghostlock_run"
PID_FILE="$RUN_DIR/collect_log.pid"
MARKER_FILE="$RUN_DIR/session_id"
MAIN_LOG="$LOG_DIR/ghost_log.txt"
LOGCAT_LOG="$LOG_DIR/logcat.txt"
DMESG_LOG="$LOG_DIR/dmesg_poll.txt"
META_LOG="$LOG_DIR/meta.txt"
KERNEL_HINT="$LOG_DIR/kernel_hints.txt"

ensure_dirs() {
  mkdir -p "$RUN_DIR" 2>/dev/null
  # wait up to ~15s for userdata/sdcard after hard reboot
  i=0
  while [ $i -lt 30 ]; do
    if mkdir -p "$LOG_DIR" 2>/dev/null; then
      if touch "$LOG_DIR/.writetest" 2>/dev/null; then
        rm -f "$LOG_DIR/.writetest" 2>/dev/null
        return 0
      fi
    fi
    i=$((i + 1))
    sleep 0.5
  done
  # last try
  mkdir -p "$LOG_DIR" 2>/dev/null
  return 1
}

ensure_dirs

ts() {
  # boottime-ish stamp + wall clock if date works
  U=$(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)
  D=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo nodate)
  echo "[$D up=${U}s]"
}

log_meta() {
  echo "$(ts) $*" >> "$META_LOG"
  # best-effort fsync of meta
  if command -v sync >/dev/null 2>&1; then
    sync
  fi
}

append_flush() {
  # $1=file, rest=message
  f="$1"
  shift
  echo "$*" >> "$f"
}

stop_collector() {
  if [ -f "$PID_FILE" ]; then
    OPID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OPID" ]; then
      kill "$OPID" 2>/dev/null
      # children often in same process group if we started with setsid-like
      kill -9 "$OPID" 2>/dev/null
    fi
    rm -f "$PID_FILE"
  fi
  # also kill by pattern (stale)
  for p in $(ps -A 2>/dev/null | grep '[c]ollect_log.sh' | awk '{print $2}'); do
    [ "$p" = "$$" ] && continue
    kill "$p" 2>/dev/null
  done
  for p in $(ps -A 2>/dev/null | grep '[l]ogcat.*ghostlock_logs' | awk '{print $2}'); do
    kill "$p" 2>/dev/null
  done
  log_meta "collector stop requested"
  echo "stopped"
}

status_collector() {
  if [ -f "$PID_FILE" ]; then
    OPID=$(cat "$PID_FILE")
    if [ -n "$OPID" ] && kill -0 "$OPID" 2>/dev/null; then
      echo "running pid=$OPID"
      echo "main_log=$MAIN_LOG"
      ls -la "$LOG_DIR" 2>/dev/null
      return 0
    fi
  fi
  echo "not running"
  ls -la "$LOG_DIR" 2>/dev/null
  return 1
}

clean_logs() {
  stop_collector
  # Wipe only our session artifacts. NEVER delete user system traces
  # (trace-*, *.pftrace, *.perfetto*, bugreport*, systrace*).
  ensure_dirs
  if [ -d "$LOG_DIR" ]; then
    for f in "$LOG_DIR"/*; do
      [ -e "$f" ] || continue
      base=$(basename "$f")
      case "$base" in
        ghost_log.txt|logcat.txt|dmesg_poll.txt|meta.txt|kernel_hints.txt|exploit.txt|exploit_raw.txt|run_console.txt|post_reboot_*)
          rm -f "$f" 2>/dev/null
          ;;
        trace-*|*.pftrace|*.perfetto*|bugreport*|systrace*|system_trace*)
          # preserve user-captured system traces
          ;;
        *)
          # leave other unknown files alone
          ;;
      esac
    done
  fi
  echo "cleaned session logs $(ts) (user traces preserved)" > "$META_LOG"
  sync 2>/dev/null
  echo "cleaned session logs in $LOG_DIR (traces preserved)"
  ls -la "$LOG_DIR" 2>/dev/null
}

dump_kernel_hints() {
  {
    echo "===== kernel hints $(ts) ====="
    echo "--- uname ---"
    uname -a 2>/dev/null
    echo "--- uptime ---"
    cat /proc/uptime 2>/dev/null
    echo "--- boot_completed ---"
    getprop sys.boot_completed 2>/dev/null
    echo "--- last_kmsg / pstore (may be empty) ---"
    for f in /proc/last_kmsg /sys/fs/pstore/console-ramoops-0 \
             /sys/fs/pstore/console-ramoops /sys/fs/pstore/dmesg-ramoops-0 \
             /proc/sys/kernel/printk; do
      if [ -e "$f" ]; then
        echo "### $f ###"
        # cap size
        dd if="$f" bs=4096 count=64 2>/dev/null || cat "$f" 2>/dev/null | head -c 262144
        echo
      fi
    done
    echo "--- dmesg tail ---"
    dmesg 2>/dev/null | tail -n 200
  } >> "$KERNEL_HINT" 2>/dev/null
  sync 2>/dev/null
}

collector_loop() {
  SID=$(cat "$MARKER_FILE" 2>/dev/null)
  log_meta "collector start session=$SID pid=$$"
  append_flush "$MAIN_LOG" "$(ts) === collect_log session=$SID pid=$$ ==="
  dump_kernel_hints

  # logcat all buffers; restart if it dies
  (
    while true; do
      logcat -v threadtime -b all 2>/dev/null | while IFS= read -r line; do
        echo "$line" >> "$LOGCAT_LOG"
      done
      echo "$(ts) logcat exited; restart in 1s" >> "$META_LOG"
      sleep 1
    done
  ) &
  LC_PID=$!

  # periodic dmesg snapshot + fsync (critical for soft-reboot)
  n=0
  while true; do
    n=$((n + 1))
    {
      echo "===== dmesg poll #$n $(ts) ====="
      dmesg -T 2>/dev/null | tail -n 80 || dmesg 2>/dev/null | tail -n 80
    } >> "$DMESG_LOG" 2>/dev/null

    # heartbeat into main log every ~2s so we know last alive time
    if [ $((n % 2)) -eq 0 ]; then
      append_flush "$MAIN_LOG" "$(ts) heartbeat collector n=$n"
    fi

    # force disk flush
    sync 2>/dev/null

    # if parent asked to stop via missing pid file ownership, exit
    if [ -f "$PID_FILE" ]; then
      CUR=$(cat "$PID_FILE" 2>/dev/null)
      if [ "$CUR" != "$$" ] && [ -n "$CUR" ]; then
        # replaced by newer collector
        kill "$LC_PID" 2>/dev/null
        exit 0
      fi
    fi
    sleep 1
  done
}

start_collector() {
  stop_collector
  mkdir -p "$LOG_DIR" "$RUN_DIR"
  SID="s_$(date +%Y%m%d_%H%M%S 2>/dev/null || cat /proc/uptime | cut -d. -f1)"
  echo "$SID" > "$MARKER_FILE"
  append_flush "$MAIN_LOG" ""
  append_flush "$MAIN_LOG" "$(ts) NEW SESSION $SID"

  # run in background, disown from adb shell
  # toybox/android: use & and ignore HUP
  (
    trap '' HUP
    collector_loop
  ) >/dev/null 2>&1 &
  echo $! > "$PID_FILE"
  sleep 0.3
  log_meta "collector bg pid=$(cat "$PID_FILE")"
  echo "started pid=$(cat "$PID_FILE") log=$MAIN_LOG session=$SID"
}

cmd="$1"
case "$cmd" in
  start) start_collector ;;
  stop) stop_collector ;;
  status) status_collector ;;
  clean) clean_logs ;;
  dump-hints) dump_kernel_hints; echo "hints -> $KERNEL_HINT" ;;
  *)
    echo "Usage: $0 {start|stop|status|clean|dump-hints}"
    exit 1
    ;;
esac
