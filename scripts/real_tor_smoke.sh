#!/usr/bin/env bash
# Operator-driven golden-standard room smoke against real Tor.
#
# NOT part of `cargo test`. Real Tor bootstrap takes 30-60s per
# process, requires actual network, and flakes in CI environments.
# This script exists for the operator who wants to verify the room
# flow end-to-end against actual onion-service circuits after code
# changes that touch the transport / hub / daemon plumbing.
#
# ── How to use ────────────────────────────────────────────────────────
#
# This script drives ALICE + BOB daemons. You're expected to run the
# HUB separately (long-running server pattern). Two-step workflow:
#
# 1. In a SEPARATE terminal, start the hub:
#
#      cargo build --release
#      ONYX_HUB_PASSPHRASE='hub-pass' \
#        ./target/release/onyx-hub \
#          --vault ./hub-vault.db \
#          --state-db ./hub-state.db
#
#    Wait ~60s for Tor bootstrap, then copy two values from its log:
#      * the `onion = <addr>` line ("hub hidden service published")
#      * the `hub_pub_b32 = <b32>` line ("hub vault unlocked")
#
# 2. Export them and run this script:
#
#      export ONYX_HUB_ONION='abc...xyz.onion:1'
#      export ONYX_HUB_PUBKEY='b32pubkeyhere'
#      ./scripts/real_tor_smoke.sh
#
# The script spawns alice + bob daemons (each gets its own vault +
# Tor state dir + API socket under ./onyx-real-smoke-state/), waits
# for them to publish their KPs to the hub directory, then drives:
#
#   alice creates a room
#   alice fetches bob's KP
#   alice invites bob
#   alice sends a room message
#   bob's `tail` subscription receives the message
#
# All assertions print PASS / FAIL. Exit 0 on full pass; non-zero on
# any failure (and the offending daemon + hub state is left under
# ./onyx-real-smoke-state/ for you to inspect).
#
# ── What this catches that the TCP smoke doesn't ────────────────────
#
#   * Real Tor circuit latency + variance (cover-traffic timing
#     assumptions break if latency dwarfs the Poisson mean).
#   * NAT + MTU edge cases (Tor stream reassembly hides most, but
#     fragmentation can still surface in arti).
#   * Cold-start hidden-service hsdesc publication race (recipient
#     subscribing to a freshly-spawned service before its hsdesc is
#     on the directory hash ring).
#
# ── Requirements ────────────────────────────────────────────────────
#
#   * Built binaries: `cargo build --release`.
#   * `jq` for JSON parsing.
#   * `nc` (netcat) with `nc -U` Unix-domain support (macOS BSD nc OK).
#   * Internet for Tor bootstrap.

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────
BIN_DIR="${ONYX_BIN_DIR:-./target/release}"
STATE_DIR="${ONYX_REAL_SMOKE_STATE:-./onyx-real-smoke-state}"
DAEMON_BIN="$BIN_DIR/onyxd"
CLI_BIN="$BIN_DIR/onyx"
PASSPHRASE="real-smoke-pass-do-not-use-in-production"
SETUP_TIMEOUT=180  # seconds; cold-cache Tor bootstrap + first-hsdesc-publish

# ── Preflight ─────────────────────────────────────────────────────────
log()  { printf '\033[1;36m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ -x "$DAEMON_BIN" ]] || die "daemon binary not found at $DAEMON_BIN — run \`cargo build --release\` first"
[[ -x "$CLI_BIN"   ]] || die "CLI binary not found at $CLI_BIN"
command -v jq >/dev/null || die "jq is required"
command -v nc >/dev/null || die "nc (netcat with -U Unix-socket support) is required"

[[ -n "${ONYX_HUB_ONION:-}"  ]] || die "ONYX_HUB_ONION env var unset — run the hub separately first, see top-of-file usage"
[[ -n "${ONYX_HUB_PUBKEY:-}" ]] || die "ONYX_HUB_PUBKEY env var unset"

rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR/alice-tor" "$STATE_DIR/bob-tor"

# ── Spawn ─────────────────────────────────────────────────────────────
spawn_daemon() {
    local label="$1"
    local vault="$STATE_DIR/$label-vault.db"
    local sock="$STATE_DIR/$label.sock"
    local tor_state="$STATE_DIR/$label-tor"
    local log_file="$STATE_DIR/$label.log"
    log "spawning $label (vault=$vault sock=$sock)"
    ONYX_PASSPHRASE="$PASSPHRASE" \
    ONYX_VAULT="$vault" \
        "$DAEMON_BIN" \
            --api-socket "$sock" \
            --tor-state-dir "$tor_state" \
            --hub "$ONYX_HUB_ONION,$ONYX_HUB_PUBKEY" \
            >"$log_file" 2>&1 &
    echo $! > "$STATE_DIR/$label.pid"
    log "$label PID $!"
}

cleanup() {
    log "cleaning up alice/bob daemons"
    for pidfile in "$STATE_DIR"/{alice,bob}.pid; do
        [[ -f "$pidfile" ]] || continue
        local pid; pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null || true
    done
    log "state left under $STATE_DIR for inspection"
}
trap cleanup EXIT INT TERM

api_call() {
    printf '%s\n' "$2" | nc -U -w 30 "$1"
}

api_call_until_ok() {
    local socket="$1" request="$2" label="$3"
    local deadline=$(( $(date +%s) + SETUP_TIMEOUT ))
    while [[ $(date +%s) -lt $deadline ]]; do
        local resp; resp=$(api_call "$socket" "$request" 2>/dev/null || true)
        if [[ -n "$resp" ]]; then
            local kind; kind=$(echo "$resp" | jq -r '.kind // "empty"' 2>/dev/null || echo "parse_error")
            if [[ "$kind" != "Error" && "$kind" != "empty" && "$kind" != "parse_error" ]]; then
                echo "$resp"
                return 0
            fi
        fi
        sleep 2
    done
    fail "$label: timed out after ${SETUP_TIMEOUT}s waiting for non-Error response"
}

# ── 1. Spawn daemons ──────────────────────────────────────────────────
spawn_daemon alice
spawn_daemon bob

ALICE_SOCK="$STATE_DIR/alice.sock"
BOB_SOCK="$STATE_DIR/bob.sock"

log "waiting for alice/bob to bootstrap Tor + publish KPs to hub (may take 1-2 min)"
alice_id=$(api_call_until_ok "$ALICE_SOCK" '{"kind":"Identity"}' "alice ready")
bob_id=$(api_call_until_ok "$BOB_SOCK"   '{"kind":"Identity"}' "bob ready")
ALICE_FP=$(echo "$alice_id" | jq -r '.fingerprint')
BOB_FP=$(echo "$bob_id"   | jq -r '.fingerprint')
BOB_KEM=$(echo "$bob_id"  | jq -r '.identity_kem_pub_b32')
pass "alice ready (fp=${ALICE_FP:0:16}…), bob ready (fp=${BOB_FP:0:16}…)"

# ── 2. alice creates a room ───────────────────────────────────────────
resp=$(api_call "$ALICE_SOCK" '{"kind":"CreateRoom","name":"real-tor-smoke"}')
GROUP_ID=$(echo "$resp" | jq -r '.group_id_b32 // empty')
[[ -n "$GROUP_ID" ]] || fail "CreateRoom failed: $resp"
pass "room created: group_id=${GROUP_ID:0:16}…"

# ── 3. alice fetches bob's KP from the hub directory ─────────────────
fetch_req=$(jq -nc --arg fp "$BOB_FP" '{kind:"FetchPeerKeyPackage", peer_fingerprint:$fp}')
resp=$(api_call_until_ok "$ALICE_SOCK" "$fetch_req" "fetch bob KP")
BOB_KP=$(echo "$resp" | jq -r '.kp_b64 // empty')
[[ -n "$BOB_KP" ]] || fail "FetchPeerKeyPackage returned no kp_b64: $resp"
pass "fetched bob's KP from hub directory"

# ── 4. Subscribe to bob's tail BEFORE the invite ─────────────────────
TAIL_OUT="$STATE_DIR/bob-tail.jsonl"
( printf '{"kind":"Tail"}\n'; sleep 60 ) | nc -U -q 60 "$BOB_SOCK" > "$TAIL_OUT" &
TAIL_PID=$!
sleep 1  # let tail subscription register before the invite

# ── 5. alice invites bob ─────────────────────────────────────────────
invite_req=$(jq -nc \
    --arg gid "$GROUP_ID" --arg fp "$BOB_FP" \
    --arg kem "$BOB_KEM"  --arg kp "$BOB_KP" \
    '{kind:"InviteToRoom", group_id_b32:$gid, peer_fingerprint:$fp,
      peer_kem_pub_b32:$kem, peer_kp_b64:$kp}')
resp=$(api_call "$ALICE_SOCK" "$invite_req")
kind=$(echo "$resp" | jq -r '.kind')
[[ "$kind" == "InviteToRoomOk" ]] || fail "InviteToRoom failed: $resp"
pass "alice invited bob (kind=InviteToRoomOk)"

# ── 6. bob's daemon should persist the room ──────────────────────────
log "polling bob's ListRooms until the new room appears"
for _ in $(seq 1 30); do
    rooms=$(api_call "$BOB_SOCK" '{"kind":"ListRooms"}' 2>/dev/null || true)
    if [[ -n "$rooms" ]] && echo "$rooms" | jq -e --arg gid "$GROUP_ID" '.rooms[]? | select(.group_id_b32 == $gid)' >/dev/null; then
        pass "bob received the Welcome and persisted the room"
        break
    fi
    sleep 2
done

# ── 7. alice sends a room message ────────────────────────────────────
send_req=$(jq -nc --arg gid "$GROUP_ID" '{kind:"SendRoom", group_id_b32:$gid, text:"hello over real Tor"}')
resp=$(api_call "$ALICE_SOCK" "$send_req")
kind=$(echo "$resp" | jq -r '.kind')
[[ "$kind" == "SendRoomOk" ]] || fail "SendRoom failed: $resp"
delivered_hub=$(echo "$resp" | jq -r '.delivered_to_hub // 0')
[[ "$delivered_hub" == "1" ]] || fail "expected delivered_to_hub=1, got $delivered_hub"
pass "alice sent room message (delivered_to_hub=1)"

# ── 8. bob's tail should receive the EventMessage ────────────────────
log "waiting for bob's tail to surface the message"
expected_prefix="room/${GROUP_ID:0:8}"
for _ in $(seq 1 30); do
    if grep -q '"hello over real Tor"' "$TAIL_OUT" && grep -q "$expected_prefix" "$TAIL_OUT"; then
        pass "bob's tail received the room message"
        kill "$TAIL_PID" 2>/dev/null || true
        log "ALL CHECKS PASSED — real-Tor room flow works end-to-end"
        exit 0
    fi
    sleep 2
done
kill "$TAIL_PID" 2>/dev/null || true
fail "bob's tail never received the message; tail output captured in $TAIL_OUT"
