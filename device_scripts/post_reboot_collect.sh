#!/system/bin/sh
# Run once after soft reboot to capture leftover kernel crash crumbs
# into /sdcard/ghostlock_logs (does not wipe existing logs).

LOG_DIR="/sdcard/ghostlock_logs"
COLLECT="/data/local/tmp/collect_log.sh"
mkdir -p "$LOG_DIR"

ts() {
  U=$(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)
  D=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo nodate)
  echo "[$D up=${U}s]"
}

{
  echo ""
  echo "$(ts) ===== POST_REBOOT_COLLECT ====="
  echo "uname=$(uname -a)"
  echo "boot_completed=$(getprop sys.boot_completed)"
  echo "uptime=$(cat /proc/uptime)"
} >> "$LOG_DIR/ghost_log.txt"

if [ -f "$COLLECT" ]; then
  sh "$COLLECT" dump-hints
fi

# Append any pstore crumbs into a dedicated post file
POST="$LOG_DIR/post_reboot_$(cat /proc/uptime | cut -d. -f1).txt"
{
  echo "$(ts) post reboot dump"
  for f in /proc/last_kmsg /sys/fs/pstore/console-ramoops-0 \
           /sys/fs/pstore/console-ramoops /sys/fs/pstore/dmesg-ramoops-0; do
    if [ -e "$f" ]; then
      echo "### $f ###"
      dd if="$f" bs=4096 count=128 2>/dev/null
      echo
    fi
  done
  dmesg 2>/dev/null | tail -n 300
} > "$POST" 2>/dev/null

sync 2>/dev/null
echo "wrote $POST and updated ghost_log.txt"
ls -la "$LOG_DIR"
