#!/usr/bin/env bash
# Full real-Tor two-daemon connect-code test.
# Uses a 0700 dir under $HOME (arti's fs-mistrust rejects world-writable
# /tmp). A publishes a hidden service; B dials it with the connect-code
# coordinates (--dial-onion + --dial-pubkey). PASS iff B's dial reaches A
# and both register the conversation. Reuses the daemon A already started
# by the caller IF $REUSE_A_SOCK is set; otherwise starts its own.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OND="$ROOT/target/release/onyxd"
ONX="$ROOT/target/release/onyx"
BASE="$HOME/.onyx-cctest"
OUT=/tmp/tor_p2p_result.txt
: > "$OUT"
note() { echo "$*" >> "$OUT"; }
REG="conversation registered with registry"
HS="Noise XK handshake|MLS round-trip complete|$REG"

# A is assumed already running (caller started it). Wait for its onion.
A_ONION=""; A_PUB=""
for i in $(seq 1 90); do   # up to ~15 min for first HS publish
  sleep 10
  if [ -S "$BASE/A/s.sock" ]; then
    HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" status > "$BASE/A/st.json" 2>/dev/null
    A_ONION=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/st.json")).get("onion") or "")' 2>/dev/null)
  fi
  ELAPSED=$((i*10))
  note "[wait_onion ${ELAPSED}s] onion=${A_ONION:0:16}"
  [ -n "$A_ONION" ] && { note "A_ONION_AT=${ELAPSED}s"; break; }
done
if [ -z "$A_ONION" ]; then note "VERDICT=FAIL_A_NO_ONION"; exit 1; fi

HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" identity > "$BASE/A/id.json" 2>/dev/null
A_PUB=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/id.json")).get("identity_pub_b32",""))' 2>/dev/null)
note "A_onion=$A_ONION"
note "A_pub=$A_PUB"
note "connect_code=onyx://connect/v1?onion=${A_ONION}&id=${A_PUB}"

# Start B, dialing A with the connect-code coordinates.
mkdir -p "$BASE/B/tor"; chmod -R 700 "$BASE/B"
HOME="$BASE/B" ONYX_PASSPHRASE=passB12345 ONYX_TOR_STATE_DIR="$BASE/B/tor" \
  "$OND" --dial-onion "$A_ONION" --dial-pubkey "$A_PUB" \
         --api-socket "$BASE/B/s.sock" > "$BASE/B/d.log" 2>&1 &
BPID=$!
note "B_pid=$BPID"

# B must bootstrap its own Tor, then build a circuit to A and handshake.
DONE=0
for i in $(seq 1 90); do   # up to ~15 min
  sleep 10
  BH=$(grep -cE "$HS" "$BASE/B/d.log" 2>/dev/null)
  AH=$(grep -cE "$HS" "$BASE/A/d.log" 2>/dev/null)
  ELAPSED=$((i*10))
  LAST=$(grep -iE "dial|noise|handshake|circuit|onion|connect|register|error|fail" "$BASE/B/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -1 | cut -c1-100)
  note "[dial ${ELAPSED}s] Bhits=${BH:-0} Ahits=${AH:-0} | $LAST"
  if [ "${BH:-0}" -gt 0 ] && [ "${AH:-0}" -gt 0 ]; then DONE=1; note "HANDSHAKE_AT=${ELAPSED}s"; break; fi
done

note "A_registered=$(grep -cE "$REG" "$BASE/A/d.log" 2>/dev/null)"
note "B_registered=$(grep -cE "$REG" "$BASE/B/d.log" 2>/dev/null)"
note "--- A.log handshake/register lines ---"
grep -E "$HS" "$BASE/A/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' >> "$OUT"
note "--- B.log handshake/register lines ---"
grep -E "$HS" "$BASE/B/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' >> "$OUT"

if [ "$DONE" -eq 1 ]; then note "VERDICT=PASS_REAL_TOR_P2P"; else note "VERDICT=FAIL_NO_HANDSHAKE"; fi
[ "$DONE" -eq 1 ] && exit 0 || exit 1
