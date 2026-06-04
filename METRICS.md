# Hub telemetry (opt-in liveness)

This document is the threat model and field justification for Onyx's
**optional** hub telemetry: how an operator can watch their hubs' health on a
central collector *without* weakening the anonymity properties the project
exists to provide.

> **One-line summary:** hubs may opt in to sending a **signed, liveness-only
> heartbeat** to a collector **over Tor**. The heartbeat contains nothing that
> tracks user activity, so a stream of them cannot be reversed to a user,
> time-series-correlated, or used to deanonymize anyone. Off by default.

See also: [`ANONYMITY.md`](./ANONYMITY.md) (adversary model A1–A4) and
`onyx_core::metrics` (the wire type, where the field set is enforced in code).

---

## 0. The design constraint

A hub is a **blind relay**: it sees only sealed envelopes on unlinkable
per-epoch routing tokens (see `ANONYMITY.md` §A2). Telemetry must not turn it
into an observer. The dangerous failure mode is **time-series correlation**:

> Any value that changes with *what users do* — connection count, frames
> delivered, subscriptions, queue depth, keypackage-directory size, bandwidth
> — becomes, when sampled repeatedly, a time series of the hub's activity.
> An adversary who obtains that series can line it up against a target's known
> online windows and link them to a hub. **Bucketing the values does not fix
> this**: a *sequence* of buckets still reveals the activity *shape*.

So the rule is not "coarsen usage metrics" — it is **do not emit usage metrics
at all**. We emit only signals that are constant, or monotonic and independent
of user activity, and ideally **already publicly observable** for a listed hub
(so the telemetry adds no new observable).

---

## 1. What is emitted — the complete field set

A `HubHeartbeat` (in `onyx_core::metrics`) carries exactly:

| Field | Why it is safe |
|-------|----------------|
| `software_version` | Static; it is the released binary the operator installed. |
| `up` | Always true when sent — the *absence* of beats is what signals "down". Anyone can connect to a listed hub to learn this. |
| `tor_reachable` | Whether the hub's onion was published/reachable. Hub self-health, externally checkable; not user activity. |
| `uptime` | A **coarse bucket** only: `<1h` / `<1d` / `<1w` / `>1w`. Reveals at most that the hub recently restarted — a restart is not user data. |
| `coarse_ts` | Unix seconds **snapped to a 5-minute boundary**. Lets the collector dedupe/replay-reject without carrying fine timing. |
| `hub_id_b32` | The hub's public X25519 id — the **same value already in `hubs.json`**. A label, not a secret. |

**Explicitly excluded — and structurally absent from the wire type:**
connections, frames delivered, subscriptions, queue depth/bytes, keypackage
count, bandwidth, per-routing-id anything, per-connection anything, or any
finely-timestamped value. Adding any of these would break the guarantee; the
module docs forbid it.

---

## 2. How it travels

| Property | Mechanism |
|----------|-----------|
| **Tor-only** | The hub dials the collector's `.onion` via the shared `TorRuntime` on a **fresh isolated circuit** per beat. The hub's IP is never exposed, and beats aren't linkable to the hub's other circuits. There is no clearnet code path (the reporter is spawned only on the real-Tor startup path). |
| **Fixed cadence** | A constant tick (default 300 s). A metronome that fires regardless of users carries no signal beyond up/down — so, unusually, *not* jittering is the more private choice here. |
| **Signed** | Each report is signed by the hub's Ed25519 key; the collector verifies it (`SignedHeartbeat::verify`). |
| **Authorised** | The collector stores a report only if its signing key is in the operator's `--allowlist`. Unknown keys are logged (for enrollment) and dropped, so learning the collector onion doesn't let anyone inject fake hubs. |
| **Fail-open** | A send error is logged and dropped — never queued, never retried, never blocks the hub. A missed beat just shows as a brief gap. |
| **Opt-in** | Off unless the operator sets `--metrics-report <collector-onion>`. |

---

## 3. The collector (`onyx-metrics`)

- An **onion service** that receives heartbeats; hubs dial *it*, so hub IPs
  stay hidden from the collector.
- Stores **only the latest state per hub** (SQLite upsert) — **no history, no
  time series** — so the collector database itself can't be turned into a
  correlation oracle even if seized.
- Serves a plain status page on **`127.0.0.1` by default** (`/` HTML + `/json`).
  View it locally or over an SSH tunnel; a non-loopback bind is loudly warned.

### Enrollment
A hub's **reporting key** is the Ed25519 verifying key embedded in its
heartbeats (`hub_sig_pub_b32`). The collector logs the key of any un-enrolled
heartbeat it receives; copy it into the `--allowlist` JSON
(`allowlist.example.json` is a template) and restart the collector.

---

## 4. Honest residual risk

Even with all of the above, enabling telemetry is a conscious choice to learn
**coarse, per-hub, liveness-only** state centrally, and it makes the collector
a target. The mitigations shrink the surface to: no IPs, no per-user data, no
history, no activity-correlated values, signed, Tor-only, allowlisted. That is
deliberately the *minimum* that still answers "are my hubs alive, current, and
reachable?" — and nothing more. If a future change wants richer metrics,
re-read §0 first: the time-series argument does not go away.
