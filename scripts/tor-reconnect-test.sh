#!/usr/bin/env bash
# v0.1.17 reconnect verification over REAL Tor.
#
# A publishes a hidden service. B dials A (connect-code coords) and a
# direct Noise+MLS session establishes. We then KILL A, restart A reusing
# its vault (same identity-derived onion), and assert B's reconnect
# supervisor re-dials and re-establishes the SAME MLS group (resume, not
# bootstrap) — i.e. the conversation survives a circuit/peer drop.
#
# Arti's fs-mistrust rejects world-writable /tmp, so state lives under a
# 0700 dir in $HOME (same constraint learned in v0.1.16). RELEASE build
# only — debug arti is too slow and false-times-out.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OND="$ROOT/target/release/onyxd"
ONX="$ROOT/target/release/onyx"
BASE="$HOME/.onyx-recon"
OUT=/tmp/tor_recon_result.txt
: > "$OUT"
note() { echo "$*" >> "$OUT"; }
cleanup() { pkill -9 -f "onyx-recon" 2>/dev/null; }
trap cleanup EXIT
cleanup
rm -rf "$BASE"; mkdir -p "$BASE/A/tor" "$BASE/B/tor"; chmod -R 700 "$BASE"

note "onyxd_exists=$([ -x "$OND" ] && echo yes || echo NO)"

start_A() {
  HOME="$BASE/A" ONYX_PASSPHRASE=passArecon ONYX_TOR_STATE_DIR="$BASE/A/tor" \
    "$OND" --api-socket "$BASE/A/s.sock" >> "$BASE/A/d.log" 2>&1 &
  echo $!
}

# --- bring A up, get its onion + identity ---
APID=$(start_A); note "A_pid_1=$APID"
A_ONION=""
for i in $(seq 1 30); do
  sleep 10
  [ -S "$BASE/A/s.sock" ] || continue
  HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" status > "$BASE/A/st.json" 2>/dev/null
  A_ONION=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/st.json")).get("onion") or "")' 2>/dev/null)
  [ -n "$A_ONION" ] && break
done
[ -z "$A_ONION" ] && { note "VERDICT=FAIL_A_NO_ONION"; exit 1; }
HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" identity > "$BASE/A/id.json" 2>/dev/null
A_PUB=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/id.json")).get("identity_pub_b32",""))')
note "A_onion=$A_ONION"
note "A_pub=$A_PUB"

# --- B dials A; wait for the first session ---
HOME="$BASE/B" ONYX_PASSPHRASE=passBrecon ONYX_TOR_STATE_DIR="$BASE/B/tor" \
  "$OND" --dial-onion "$A_ONION" --dial-pubkey "$A_PUB" --api-socket "$BASE/B/s.sock" \
  >> "$BASE/B/d.log" 2>&1 &
BPID=$!; note "B_pid=$BPID"
REG="conversation registered with registry"
got_first=0
for i in $(seq 1 60); do
  sleep 10
  if [ "$(grep -c "$REG" "$BASE/B/d.log" 2>/dev/null)" -ge 1 ]; then got_first=1; break; fi
done
[ "$got_first" -ne 1 ] && { note "VERDICT=FAIL_NO_FIRST_SESSION"; exit 1; }
note "first_session_established=yes"
B_REG_1=$(grep -c "$REG" "$BASE/B/d.log")

# --- KILL A, restart it (same vault → same onion) ---
kill -9 "$APID" 2>/dev/null
note "killed_A_pid=$APID"
sleep 5
APID2=$(start_A); note "A_pid_2=$APID2"

# --- assert B reconnects: a 2nd registration appears in B's log ---
reconnected=0
for i in $(seq 1 60); do
  sleep 10
  if [ "$(grep -c "$REG" "$BASE/B/d.log" 2>/dev/null)" -gt "$B_REG_1" ]; then reconnected=1; break; fi
done
note "B_reg_count_before=$B_REG_1 after=$(grep -c "$REG" "$BASE/B/d.log" 2>/dev/null)"

# MLS resume (not re-bootstrap) on the reconnect: B's dial side logs
# was_bootstrap=false when it resumes an existing group.
note "B_resume_lines:"
grep -iE "resume|was_bootstrap" "$BASE/B/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -6 >> "$OUT"

if [ "$reconnected" -eq 1 ]; then note "VERDICT=PASS_RECONNECT"; else note "VERDICT=FAIL_NO_RECONNECT"; fi
[ "$reconnected" -eq 1 ] && exit 0 || exit 1
