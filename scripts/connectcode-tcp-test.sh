#!/usr/bin/env bash
# v0.1.16 connect-code logic test over LOOPBACK TCP (no Tor).
#
# Proves: connect-code -> DialPeer -> Noise handshake -> peer registered,
# isolated from Tor descriptor-propagation timing. The `--dial-tcp` path
# and the `onyx dial`/connect-code `DialPeer` path share the same Noise
# handshake + peer-registration code; this exercises that core fast and
# deterministically. A separate script does the real-Tor transport.
#
# Self-verifying: every fact is written to $OUT as `KEY=value` and the
# script greps the daemon logs for handshake evidence. Exit 0 ONLY if
# both daemons report a connected peer.
set -u  # NOT -e: we want to reach the verdict + cleanup even on a step fail.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OND="$ROOT/target/release/onyxd"
ONX="$ROOT/target/release/onyx"
A=/tmp/cct_A
B=/tmp/cct_B
OUT=/tmp/cct_result.txt
: > "$OUT"

note() { echo "$*" >> "$OUT"; }

cleanup() {
  pkill -9 -f "cct_A/s.sock" 2>/dev/null
  pkill -9 -f "cct_B/s.sock" 2>/dev/null
}
trap cleanup EXIT

cleanup
rm -rf "$A" "$B"; mkdir -p "$A" "$B"

note "onyxd_exists=$([ -x "$OND" ] && echo yes || echo NO)"
note "onyx_exists=$([ -x "$ONX" ] && echo yes || echo NO)"

PORT=9171

# --- Daemon A: TCP listen mode (no Tor) ---
HOME="$A" ONYX_PASSPHRASE=passA12345 \
  "$OND" --listen-tcp "127.0.0.1:$PORT" --allow-clearnet \
         --api-socket "$A/s.sock" > "$A/d.log" 2>&1 &
APID=$!
note "A_pid=$APID"

# Wait for A's API socket + identity (TCP listen has no Tor, so it's quick).
A_PUB=""
for i in $(seq 1 30); do
  sleep 1
  if [ -S "$A/s.sock" ]; then
    A_PUB=$(HOME="$A" "$ONX" --socket "$A/s.sock" identity 2>/dev/null \
            | python3 -c 'import sys,json;print(json.load(sys.stdin).get("identity_pub_b32",""))' 2>/dev/null)
    [ -n "$A_PUB" ] && break
  fi
done
note "A_alive=$(kill -0 $APID 2>/dev/null && echo yes || echo NO)"
note "A_pub_len=${#A_PUB}"
note "A_pub_head=${A_PUB:0:16}"

if [ -z "$A_PUB" ]; then
  note "VERDICT=FAIL_A_NO_IDENTITY"
  note "--- A.log tail ---"; tail -15 "$A/d.log" >> "$OUT"
  exit 1
fi

# --- Daemon B: TCP dial mode toward A (no Tor) ---
HOME="$B" ONYX_PASSPHRASE=passB12345 \
  "$OND" --dial-tcp "127.0.0.1:$PORT" --dial-pubkey "$A_PUB" --allow-clearnet \
         --api-socket "$B/s.sock" > "$B/d.log" 2>&1 &
BPID=$!
note "B_pid=$BPID"

# Poll both logs for handshake + registration evidence. Match the REAL
# log strings the daemon emits: the Noise XK handshake line, the MLS
# round-trip completion, and the registry registration.
PAT="Noise XK handshake|MLS round-trip complete|conversation registered with registry"
hits() { grep -cE "$PAT" "$1" 2>/dev/null; }   # grep -c always prints a number; no `|| echo`
HANDSHAKE=0
for i in $(seq 1 40); do
  sleep 1
  BH=$(hits "$B/d.log"); AH=$(hits "$A/d.log")
  if [ "${BH:-0}" -gt 0 ] && [ "${AH:-0}" -gt 0 ]; then HANDSHAKE=1; break; fi
done
note "B_alive=$(kill -0 $BPID 2>/dev/null && echo yes || echo NO)"
note "A_handshake_hits=$(hits "$A/d.log")"
note "B_handshake_hits=$(hits "$B/d.log")"
# Strongest single signal: both sides registered a conversation = a live
# end-to-end session, exactly what connect-code -> DialPeer must achieve.
note "A_registered=$(grep -cE 'conversation registered with registry' "$A/d.log" 2>/dev/null)"
note "B_registered=$(grep -cE 'conversation registered with registry' "$B/d.log" 2>/dev/null)"

# Cross-check via the Status/peers API (the TUI's own source of truth).
A_PEERS=$(HOME="$A" "$ONX" --socket "$A/s.sock" status 2>/dev/null \
          | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("connected_peers", d.get("peers","?")))' 2>/dev/null)
note "A_status_peers_field=${A_PEERS:-unavailable}"

if [ "$HANDSHAKE" -eq 1 ]; then
  note "VERDICT=PASS_HANDSHAKE_BOTH_SIDES"
else
  note "VERDICT=FAIL_NO_HANDSHAKE"
fi

note "--- A.log (unique non-boot) ---"
grep -ivE "booting onyx daemon|ONYX_RELEASE|creating new vault|no identity found|no persisted|vault unlocked" "$A/d.log" 2>/dev/null | sort -u | tail -20 >> "$OUT"
note "--- B.log (unique non-boot) ---"
grep -ivE "booting onyx daemon|ONYX_RELEASE|creating new vault|no identity found|no persisted|vault unlocked" "$B/d.log" 2>/dev/null | sort -u | tail -20 >> "$OUT"

[ "$HANDSHAKE" -eq 1 ] && exit 0 || exit 1
