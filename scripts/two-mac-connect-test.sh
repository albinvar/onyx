#!/usr/bin/env bash
# Two local onyx instances over REAL Tor — the Mac↔Mac stand-in for the
# Mac↔phone test. A publishes a hidden service; B dials A using A's
# connect-code coordinates (onion + identity pubkey). PASS = both sides
# register the conversation (Noise XK + MLS handshake completed) — i.e.
# "the peer connected", the exact thing that's failing for the user.
#
# arti's fs-mistrust rejects world-writable /tmp, so state lives under a
# 0700 dir in $HOME. RELEASE build only (debug arti times out).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OND="$ROOT/target/release/onyxd"
ONX="$ROOT/target/release/onyx"
BASE="$HOME/.onyx-2mac"
OUT=/tmp/two_mac_result.txt
: > "$OUT"
note() { echo "$*" >> "$OUT"; }
cleanup() { pkill -9 -f "onyx-2mac" 2>/dev/null; }
trap cleanup EXIT
cleanup
rm -rf "$BASE"; mkdir -p "$BASE/A/tor" "$BASE/B/tor"; chmod -R 700 "$BASE"

note "onyxd=$([ -x "$OND" ] && echo ok || echo MISSING)  onyx=$([ -x "$ONX" ] && echo ok || echo MISSING)"

# --- A: default mode (publishes a hidden service) ---
HOME="$BASE/A" ONYX_PASSPHRASE=passA2mac ONYX_TOR_STATE_DIR="$BASE/A/tor" \
  "$OND" --api-socket "$BASE/A/s.sock" >> "$BASE/A/d.log" 2>&1 &
note "A_pid=$!"

# Wait for A's onion (HS publish can take a few minutes on a cold arti).
A_ONION=""
for i in $(seq 1 36); do
  sleep 10
  [ -S "$BASE/A/s.sock" ] || continue
  HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" status > "$BASE/A/st.json" 2>/dev/null
  A_ONION=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/st.json")).get("onion") or "")' 2>/dev/null)
  note "[A wait ${i}0s] onion=${A_ONION:0:16}"
  [ -n "$A_ONION" ] && break
done
[ -z "$A_ONION" ] && { note "VERDICT=FAIL_A_NO_ONION"; note "--- A.log tail ---"; tail -20 "$BASE/A/d.log" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUT"; exit 1; }
HOME="$BASE/A" "$ONX" --socket "$BASE/A/s.sock" identity > "$BASE/A/id.json" 2>/dev/null
A_PUB=$(python3 -c 'import json;print(json.load(open("'"$BASE"'/A/id.json")).get("identity_pub_b32",""))')
note "A_onion=$A_ONION"
note "A_pub=$A_PUB"
note "CONNECT_CODE=onyx://connect/v1?onion=${A_ONION}&id=${A_PUB}"

# --- B: default mode + dial A via DialPeer (the ^D / connect-code path) ---
HOME="$BASE/B" ONYX_PASSPHRASE=passB2mac ONYX_TOR_STATE_DIR="$BASE/B/tor" \
  "$OND" --api-socket "$BASE/B/s.sock" >> "$BASE/B/d.log" 2>&1 &
note "B_pid=$!"
# Wait for B's daemon + Tor ready, then issue the dial.
for i in $(seq 1 36); do
  sleep 10
  [ -S "$BASE/B/s.sock" ] || continue
  BREADY=$(HOME="$BASE/B" "$ONX" --socket "$BASE/B/s.sock" status 2>/dev/null \
           | python3 -c 'import sys,json;print(json.load(sys.stdin).get("tor_state"))' 2>/dev/null)
  note "[B wait ${i}0s] tor=$BREADY"
  [ "$BREADY" = "Ready" ] && break
done
HOME="$BASE/B" "$ONX" --socket "$BASE/B/s.sock" dial --onion "$A_ONION" --pubkey "$A_PUB" > "$BASE/B/dial.json" 2>&1
note "dial_resp=$(cat "$BASE/B/dial.json")"

# --- assert both sides register the conversation (= connected) ---
REG="conversation registered with registry"
done=0
for i in $(seq 1 30); do
  sleep 10
  AH=$(grep -c "$REG" "$BASE/A/d.log" 2>/dev/null)
  BH=$(grep -c "$REG" "$BASE/B/d.log" 2>/dev/null)
  LAST=$(grep -iE "dial|noise|handshake|circuit|connect|register|error" "$BASE/B/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -1 | cut -c1-90)
  note "[connect ${i}0s] A_reg=$AH B_reg=$BH | $LAST"
  if [ "${AH:-0}" -gt 0 ] && [ "${BH:-0}" -gt 0 ]; then done=1; break; fi
done

note "--- A handshake/register lines ---"
grep -iE "Noise XK|MLS round-trip|$REG" "$BASE/A/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -5 >> "$OUT"
note "--- B handshake/register lines ---"
grep -iE "Noise XK|MLS round-trip|$REG|dialing|circuit established" "$BASE/B/d.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -8 >> "$OUT"

if [ "$done" -eq 1 ]; then note "VERDICT=PASS_TWO_MAC_CONNECTED"; else note "VERDICT=FAIL_NO_CONNECT"; fi
[ "$done" -eq 1 ] && exit 0 || exit 1
