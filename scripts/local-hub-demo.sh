#!/usr/bin/env bash
# Onyx — local two-party demo over a plain-TCP hub (NO TOR, NO ANONYMITY).
#
# Spins up a local `onyx-hub` in TCP test mode and prints the exact
# `onyx` commands to run two clients (alice + bob) against it, so you
# can exercise the full rooms + files flow on one machine without
# standing up onion services.
#
#   ⚠  TEST/DEV ONLY. --listen-tcp / --hub-tcp disable Tor entirely.
#      Never use this for anything you need to stay private.
#
# Usage:
#   ./scripts/local-hub-demo.sh            # uses ./target/debug binaries
#   ONYX_BIN=/path/to/dir ./scripts/local-hub-demo.sh
#
# The hub runs in THIS terminal (Ctrl-C to stop it). Open two more
# terminals for alice and bob using the commands this script prints.

set -euo pipefail

ONYX_BIN="${ONYX_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
HUB_ADDR="${HUB_ADDR:-127.0.0.1:7100}"
WORK="${WORK:-/tmp/onyx-demo}"

HUB="$ONYX_BIN/onyx-hub"
ONYX="$ONYX_BIN/onyx"
for b in "$HUB" "$ONYX"; do
  [ -x "$b" ] || { echo "missing binary: $b (run: cargo build)"; exit 1; }
done

strip() { sed $'s/\x1b\\[[0-9;]*m//g'; }

rm -rf "$WORK"
mkdir -p "$WORK/hub" "$WORK/alice" "$WORK/bob"

echo "Starting local hub on $HUB_ADDR (TCP, ephemeral, NO TOR)…"
ONYX_HUB_PASSPHRASE=demo-hub "$HUB" \
  --listen-tcp "$HUB_ADDR" \
  --vault "$WORK/hub/hub.db" \
  --state-db "" >"$WORK/hub/log" 2>&1 &
HUB_PID=$!
trap 'kill "$HUB_PID" 2>/dev/null || true' EXIT

# Wait for the hub to print its identity pubkey.
HUB_PUB=""
for _ in $(seq 1 30); do
  HUB_PUB="$(strip <"$WORK/hub/log" | grep -o 'hub_pub_b32=[a-z2-7]*' | head -1 | cut -d= -f2)"
  [ -n "$HUB_PUB" ] && break
  sleep 0.3
done
[ -n "$HUB_PUB" ] || { echo "hub didn't come up; see $WORK/hub/log"; cat "$WORK/hub/log"; exit 1; }

cat <<EOF

────────────────────────────────────────────────────────────────────
 Local hub is UP.  pubkey: $HUB_PUB
 (this terminal runs the hub — Ctrl-C here stops everything)
────────────────────────────────────────────────────────────────────

Open TWO more terminals and run:

  # Terminal A — alice
  HOME=$WORK/alice ONYX_PASSPHRASE=alice \\
    $ONYX --hub-tcp $HUB_ADDR,$HUB_PUB

  # Terminal B — bob
  HOME=$WORK/bob ONYX_PASSPHRASE=bob \\
    $ONYX --hub-tcp $HUB_ADDR,$HUB_PUB

Then, in the TUI:
  Ctrl-N  create a room        Ctrl-I  invite a peer (paste their
  Ctrl-F  send a file          fingerprint + KEM pub + KeyPackage)
  ↑/↓ switch · Enter send · Esc quit

To get bob's invite material (run in a 4th shell):
  HOME=$WORK/bob   $ONYX identity            # fingerprint + KEM pub
  HOME=$WORK/alice $ONYX fetch-keypackage \\
      --peer-fingerprint "<bob-fingerprint>" # bob's KeyPackage (kp_b64)

File note: images (jpg/png/…) are metadata-stripped automatically.
Arbitrary files (.txt, .pdf, …) need --keep-metadata, e.g.:
  HOME=$WORK/alice $ONYX room send-file --group-id <id> \\
      --path notes.txt --keep-metadata

Hub log:    tail -f $WORK/hub/log
Client logs: $WORK/alice/.onyx/onyx.log , $WORK/bob/.onyx/onyx.log
────────────────────────────────────────────────────────────────────

EOF

echo "Hub running. Press Ctrl-C to stop."
wait "$HUB_PID"
