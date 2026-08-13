# ADR-0009: Two listening ports, one request lifecycle, no application-level auth

**Status:** Implemented and verified. Real Tailscale ACL enforcement confirmed against a live
tailnet on 2026-08-01 — see Consequences.
**Date:** 2026-08-01
**Deciders:** Ross

## Context

ADR-0008 decided the shape — a relay on a separate device, Tailscale ACLs rather than new
application-level crypto deciding who can approve. It didn't nail the actual protocol. Two more
concrete choices needed making before code could exist:

**How to split privilege at the network layer, since Tailscale ACLs work at IP:port granularity,
not HTTP paths.** A single port serving both "register a request" and "submit a decision" can't be
split by ACL alone — the network layer can't tell those two POST bodies apart, only which peer and
which port. Options: two separate ports, one for each operation (broker reaches one, the approving
device reaches the other); or one port plus an application-level identity check (parsing a header
Tailscale's proxy could inject, or embedding a per-peer token) — which reopens exactly the
"write new auth code" door ADR-0008 closed.

**How the broker actually waits.** Long-polling (relay holds the connection open until a decision
lands or a server-side timeout) versus plain polling (broker asks repeatedly, sleeps between).
Long-polling is lower-latency and lower-load at real scale; this relay serves one user with
approval latency inherently bounded by human response time, not machine speed — the gap between
"instant" and "checked every couple seconds" is invisible next to that.

## Decision

**Two ports, not one.** The relay (`internal/relay`, run via `cmd/secrets-broker-relay`) exposes:
- A **control port** (`NewControlHandler`) — `POST /requests/{id}` to register, `GET /requests/{id}`
  to poll. Meant to be reachable by the broker host's tailnet identity only.
- A **decision port** (`NewDecisionHandler`) — `POST /requests/{id}/decide` with
  `{"decision": "approve"|"deny"}`. Meant to be reachable by the approving device's tailnet
  identity only. Its bookmarkable `GET /` dashboard refreshes every two seconds and shows all live
  pending requests, so the operator does not need an out-of-band request ID.

Neither handler checks *who* is calling — that's deliberate. The split exists purely so a Tailscale
ACL policy can restrict each port to a different peer, with zero application code involved in the
authorization decision. Example policy (illustrative — apply via the Tailscale admin console, not
committed anywhere real device/tailnet names would appear):

```json
{
  "acls": [
    {"action": "accept", "src": ["tag:secrets-broker-host"], "dst": ["tag:secrets-broker-relay:7620"]},
    {"action": "accept", "src": ["tag:secrets-broker-approver"], "dst": ["tag:secrets-broker-relay:7621"]}
  ]
}
```

**Plain polling, not long-polling.** `TailscaleApprover` (`internal/approval/tailscale.go`) ticks
on a configurable interval (default 2s) against the control port until it sees `approved`,
`denied`, `expired`, or its own timeout (default 300s) elapses — whichever first. A transient poll
failure doesn't end the wait early; only the timeout does, keeping the failure mode "slower to
notice the relay is unreachable" rather than "prematurely denies on one dropped packet."

**Request lifecycle:** `internal/relay.Store` is an in-memory, mutex-guarded map, not a database —
appropriate for one relay serving one user's low-volume approval traffic. `Create` fails on an ID
collision (a caller bug, not a race to paper over). `Get` computes `expired` on read, from the
stored deadline, rather than mutating state proactively — a `Decide` racing in right at the
boundary is judged against the same deadline `Get` already saw, so there's no window where a
"just expired" request can still be approved. `Decide` only accepts the first decision to arrive
before the deadline; a second call, a call after expiry, or a call for an unknown ID all fail
rather than silently overwriting or reviving a closed request. A `Sweep` method removes old closed
entries so a long-running relay doesn't leak memory — scheduled by `cmd/secrets-broker-relay`'s own
ticker, kept out of the store's own concerns.

## Consequences

**Positive**
- Zero application-level authentication code — the entire "who can approve" question is answered
  by which port a connection reaches, decided by Tailscale ACLs before the relay's own code ever
  runs. Exactly what ADR-0008 asked for.
- Full hermetic test coverage: `internal/relay` (store + both handlers, via `httptest`),
  `internal/approval` (`HTTPRelayClient` against a real handler via `httptest`, `TailscaleApprover`
  against a `FakeRelayClient`) — none of it needs a real network or a real Tailscale setup to run in
  CI.
- The decision dashboard makes the approval flow discoverable without relay log access or a push
  notification service. It lists only live pending requests and reuses the existing same-origin
  decision forms. Approval pages use a `same-origin` referrer policy so standards-compliant
  browsers retain a verifiable `Origin` on form POSTs without sending a referrer cross-origin.
- A real (non-fake) smoke test proved the actual wire protocol end to end on localhost: register,
  poll pending, decide, poll reflects the decision, a second decide correctly rejected with 409.
- **Real Tailscale ACL enforcement confirmed.** Verified end to end on a live tailnet: a personal
  device (phone, untagged / `autogroup:member`) reached the decision port and tapped Approve on a
  pending request; the broker's `TailscaleApprover`, polling the control port, observed the
  approval and executed the wrapped command. The relay itself ran on the same host as the broker
  for this pass (development stand-in, not the production topology — see ADR-0008), so this proves
  the *protocol's* ACL-shaped design holds against a real ACL policy, not yet the same-host-vs-
  separate-device property in isolation. The blocking issue hit along the way was mundane and
  worth naming: the tailnet's own default-deny ACL policy had no rule permitting personal devices
  to reach port 7621 at all — nothing to do with this project's code, but a reminder that "the
  protocol is correct" and "the network actually lets the right traffic through" are separate
  things to check.

**Negative — what's still unverified**
- No TLS between broker/approver and relay — traffic is plaintext HTTP. Acceptable because the
  tailnet itself is already an encrypted WireGuard tunnel; adding HTTPS on top would be defense in
  depth, not a closed gap, and isn't built for v1.
- The relay is a single point of failure with no persistence — a crash or restart loses every
  in-flight request, which then simply times out on the broker side. Correct fail-closed behavior,
  not a design gap, but worth naming: this relay has no high-availability story and isn't meant to.
