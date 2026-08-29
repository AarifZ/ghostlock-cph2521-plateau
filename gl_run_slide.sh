#!/system/bin/sh
export MODE4_ONLY=1
export MODE4_SLIDE=1
export MODE4_SWAP_NOCFI=1
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
exec /data/local/tmp/gl_uid0
