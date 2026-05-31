#!/usr/bin/env bash
# Probe ONE daemon's real-Tor bootstrap + hidden-service publish.
# Goal: find out exactly how far Tor gets and how long the onion takes,
# so the two-daemon dial test can use a correct timeout (or so we learn
# the publish is genuinely broken). Self-verifying via $OUT.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OND="$ROOT/target/release/onyxd"
ONX="$ROOT/target/release/onyx"
D=/tmp/torprobe
OUT=/tmp/torprobe_result.txt
: > "$OUT"
note() { echo "$*" >> "$OUT"; }

cleanup() { pkill -9 -f "torprobe/s.sock" 2>/dev/null; }
trap cleanup EXIT
cleanup
rm -rf "$D"; mkdir -p "$D/tor"

note "onyxd_exists=$([ -x "$OND" ] && echo yes || echo NO)"
START=$(date +%s)
HOME="$D" ONYX_PASSPHRASE=probepass123 ONYX_TOR_STATE_DIR="$D/tor" \
  "$OND" --api-socket "$D/s.sock" > "$D/d.log" 2>&1 &
PID=$!
note "pid=$PID"

# Poll up to ~10 minutes (real first-publish can be slow on a cold arti).
ONION=""; TOR=""
for i in $(seq 1 60); do
  sleep 10
  ELAPSED=$(( $(date +%s) - START ))
  if [ -S "$D/s.sock" ]; then
    HOME="$D" "$ONX" --socket "$D/s.sock" status > "$D/st.json" 2>/dev/null
    ONION=$(python3 -c 'import json;print(json.load(open("'"$D"'/st.json")).get("onion") or "")' 2>/dev/null)
    TOR=$(python3 -c 'import json;print(json.load(open("'"$D"'/st.json")).get("tor_state"))' 2>/dev/null)
  fi
  # newest interesting log line
  LASTLOG=$(grep -iE "bootstrap|tor|onion|hidden service|publish|descriptor|ready|error|warn" "$D/d.log" 2>/dev/null | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-110)
  note "[t=${ELAPSED}s] alive=$(kill -0 $PID 2>/dev/null && echo y || echo N) tor=${TOR:-?} onion=${ONION:0:14} | ${LASTLOG}"
  [ -n "$ONION" ] && { note "ONION_PUBLISHED_AT=${ELAPSED}s"; break; }
done

note "final_onion=${ONION}"
note "final_tor_state=${TOR}"
note "--- last 25 log lines (ansi-stripped) ---"
tail -25 "$D/d.log" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUT"

[ -n "$ONION" ] && exit 0 || exit 1
