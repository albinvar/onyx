#!/usr/bin/env python3
# cover-traffic-measure.py — F1.2 of the fortification plan.
#
# Measures what a PASSIVE NETWORK OBSERVER of the daemon<->hub link
# actually sees, to test the §3.1 claim that with constant-rate shaping
# the traffic is invariant whether the user is active or idle.
#
# How it works: a transparent TCP tap is interposed between the daemon
# and an `onyx-hub --listen-tcp`. The tap parses the 2-byte big-endian
# length prefix that frames every Noise ciphertext on the wire
# (transport.rs §"Outer length-prefix framing"), so it records the
# EXACT timestamp + byte-size of every frame in each direction — the
# same view a wiretap on that TCP link would have. It never sees
# plaintext (the bytes are Noise ciphertext), only sizes and timing —
# which is precisely the metadata the timing defense is about.
#
# What this measures vs. real Tor:
#   * It measures the real wire observer's view of frame SIZE and
#     TIMING over a real OS socket with real scheduling — no mocked
#     clock (unlike the unit tests).
#   * It runs over loopback TCP, NOT Tor, so it does NOT include Tor's
#     transport jitter. That omission is SAFE for the timing claim:
#     Tor adds latency/jitter that is a function of the circuit, not of
#     the frame contents — every frame is equal-size ciphertext and Tor
#     cannot tell a PAD from a DELIVER — so Tor jitter perturbs the
#     active and idle streams identically and cannot reintroduce a
#     distinguisher that constant-rate removed. The real-Tor end-to-end
#     drill (two peers, live circuits) remains the operator confirmation
#     documented in ANONYMITY.md §3.1.
#
# Metric: coefficient of variation (CV = stdev/mean) of inter-frame
# intervals. Constant-rate => CV near 0 (a metronome). Poisson cover or
# unshaped traffic => CV ~1 or bursty. Low CV that is INDEPENDENT of
# whether real traffic is present is the property we want.
#
# Usage:
#   scripts/cover-traffic-measure.py --mode constant --slot-ms 500 \
#       --direction downstream --duration 30 --out /tmp/measure.txt
#
#   --mode      constant | poisson | off   (shaping applied)
#   --direction downstream (hub->client) | upstream (client->hub)
#   --slot-ms   constant-rate slot, or poisson mean*1000
#   --duration  measurement window, seconds
#
# Requires release binaries: `cargo build --release`.

import argparse
import asyncio
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REL = os.path.join(ROOT, "target", "release")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def require_binaries():
    for b in ("onyx-hub", "onyxd", "onyx"):
        if not os.path.isfile(os.path.join(REL, b)):
            sys.exit(f"missing {REL}/{b} — run `cargo build --release` first")


# ── Transparent framing tap ─────────────────────────────────────────────────
class Tap:
    """Pumps bytes between a downstream client and the hub, parsing the
    2-byte length prefix to record one (t, size) per complete frame in
    each direction."""

    def __init__(self, hub_host, hub_port):
        self.hub_host = hub_host
        self.hub_port = hub_port
        self.up = []    # client -> hub  (t, size)
        self.down = []  # hub -> client  (t, size)

    async def handle(self, creader, cwriter):
        hreader, hwriter = await asyncio.open_connection(self.hub_host, self.hub_port)
        await asyncio.gather(
            self._pump(creader, hwriter, self.up),
            self._pump(hreader, cwriter, self.down),
            return_exceptions=True,
        )

    async def _pump(self, reader, writer, sink):
        try:
            while True:
                prefix = await reader.readexactly(2)
                length = int.from_bytes(prefix, "big")
                body = await reader.readexactly(length)
                sink.append((time.monotonic(), length))
                writer.write(prefix + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def run(args):
    require_binaries()
    workdir = tempfile.mkdtemp(prefix="onyx-measure-")
    os.chmod(workdir, 0o700)  # arti fs-mistrust
    procs = []

    hub_port = free_port()
    tap_port = free_port()
    hub_vault = os.path.join(workdir, "hub-vault.db")

    hub_const = args.slot_ms if args.mode == "constant" and args.direction == "downstream" else None
    hub_cover = (args.slot_ms // 1000 or 1) if args.mode == "poisson" and args.direction == "downstream" else None

    hub_cmd = [
        os.path.join(REL, "onyx-hub"),
        "--vault", hub_vault,
        "--state-db", "",
        "--listen-tcp", f"127.0.0.1:{hub_port}",
    ]
    if hub_const:
        hub_cmd += ["--constant-rate-ms", str(hub_const)]
    if hub_cover:
        hub_cmd += ["--cover-traffic-mean-secs", str(hub_cover)]

    hub_env = dict(os.environ, ONYX_HUB_PASSPHRASE="measure-hub-pass")
    hub_log = open(os.path.join(workdir, "hub.log"), "w+")
    hub = subprocess.Popen(hub_cmd, env=hub_env, stdout=hub_log, stderr=subprocess.STDOUT)
    procs.append(hub)

    # Parse the hub's b32 pubkey from its log. The tracing fmt layer
    # wraps field names/values in ANSI color codes, so strip those first.
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    hub_pub = None
    deadline = time.time() + 30
    while time.time() < deadline and hub_pub is None:
        time.sleep(0.3)
        hub_log.seek(0)
        for line in hub_log.read().splitlines():
            m = re.search(r"hub_pub_b32\s*=\s*([a-z2-7]+)", ansi.sub("", line))
            if m:
                hub_pub = m.group(1)
                break
    if not hub_pub:
        cleanup(procs, workdir, hub_log)
        sys.exit("could not read hub pubkey from hub log (hub failed to start?)")

    # Start the tap.
    tap = Tap("127.0.0.1", hub_port)
    server = await asyncio.start_server(tap.handle, "127.0.0.1", tap_port)

    # Start the daemon pointed at the tap (clearnet TCP hub).
    home = os.path.join(workdir, "daemon-home")
    os.makedirs(home, mode=0o700, exist_ok=True)
    sock = os.path.join(workdir, "d.sock")
    d_cmd = [
        os.path.join(REL, "onyxd"),
        "--hub-tcp", f"127.0.0.1:{tap_port},{hub_pub}",
        "--allow-clearnet",
        "--no-tor",
        "--api-socket", sock,
    ]
    if args.mode == "constant" and args.direction == "upstream":
        d_cmd += ["--constant-rate-ms", str(args.slot_ms)]
    if args.mode == "poisson" and args.direction == "upstream":
        d_cmd += ["--cover-traffic-mean-secs", str(args.slot_ms // 1000 or 1)]
    d_env = dict(os.environ, ONYX_PASSPHRASE="measure-daemon-pass", HOME=home)
    d_log = open(os.path.join(workdir, "daemon.log"), "w+")
    daemon = subprocess.Popen(d_cmd, env=d_env, stdout=d_log, stderr=subprocess.STDOUT)
    procs.append(daemon)

    print(f"measuring: mode={args.mode} direction={args.direction} "
          f"slot/mean-ms={args.slot_ms} window={args.duration}s ...", flush=True)
    # Let the session establish, then measure a clean window.
    await asyncio.sleep(3.0)
    series = tap.up if args.direction == "upstream" else tap.down
    series.clear()
    t0 = time.monotonic()
    await asyncio.sleep(args.duration)
    window = [(t, sz) for (t, sz) in series if t >= t0]

    server.close()
    cleanup(procs, workdir, hub_log, d_log, keep=False)
    return report(args, window)


def report(args, window):
    n = len(window)
    if n < 2:
        return (f"mode={args.mode} dir={args.direction}: only {n} frames in "
                f"{args.duration}s — nothing to analyze (shaping off + idle "
                f"correctly produces little/no traffic).", 0.0, n)
    times = [t for (t, _) in window]
    sizes = [sz for (_, sz) in window]
    intervals = [b - a for a, b in zip(times, times[1:])]
    mean = statistics.mean(intervals)
    stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else 0.0
    size_set = sorted(set(sizes))
    lines = [
        f"mode={args.mode}  direction={args.direction}  slot/mean-ms={args.slot_ms}",
        f"frames observed : {n} in {args.duration}s  ({n/args.duration:.2f}/s)",
        f"inter-frame ms  : mean={mean*1000:.1f}  stdev={stdev*1000:.1f}  "
        f"min={min(intervals)*1000:.1f}  max={max(intervals)*1000:.1f}",
        f"CV (stdev/mean) : {cv:.3f}   "
        f"({'INVARIANT — metronomic' if cv < 0.05 else 'VARIABLE — bursty/sporadic'})",
        f"frame sizes     : {size_set} bytes  "
        f"({'uniform' if len(size_set) == 1 else 'mixed'})",
    ]
    return ("\n".join(lines), cv, n)


def cleanup(procs, workdir, *logs, keep=False):
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    for lg in logs:
        try:
            lg.close()
        except Exception:
            pass
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Onyx cover-traffic wire-observer measurement (F1.2)")
    ap.add_argument("--mode", choices=["constant", "poisson", "off"], default="constant")
    ap.add_argument("--direction", choices=["downstream", "upstream"], default="downstream")
    ap.add_argument("--slot-ms", type=int, default=500)
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    text, cv, n = asyncio.run(run(args))
    print("\n" + text + "\n", flush=True)
    if args.out:
        with open(args.out, "a") as f:
            f.write(text + "\n\n")
        print(f"appended transcript to {args.out}", flush=True)


if __name__ == "__main__":
    main()
