# ADR-0008: A separate relay device for the headless `Approver`, not a same-host listener

**Status:** Accepted (design) — not yet implemented.
**Date:** 2026-08-02
**Deciders:** Ross

## Context

ADR-0007 split headless deployment into two problems: `Resolver` (solved — env/file backends) and
`Approver` (deferred — needs a real remote channel with its own authentication). This ADR scopes
that second half.

Three transport options were considered for how a remote decision reaches the broker:

1. **Tailscale/VPN-bound endpoint.** No new credential — Tailscale's own device identity is the
   auth. No public attack surface. Reuses infrastructure already trusted for other things, rather
   than inventing a new one.
2. **Self-hosted relay with its own auth** (signed links, bearer tokens), public-facing. Doesn't
   need a VPN client active on the approving device, but means owning a public-facing
   authentication implementation — link expiry, replay protection, rate limiting — exactly the
   class of hand-rolled auth this project has consistently avoided elsewhere.
3. **Third-party push** (ntfy, Pushover, a Discord/Slack bot). Best tap-to-approve UX, but the
   relay service becomes part of the trust boundary — its own security posture, delivery
   guarantees, and (for a bot) a new credential (bot token) to manage.

Tailscale was chosen as the transport. Both remaining options impose *some* dependency on anyone
using this Approver — "zero dependencies" was never actually the bar, since the project is already
hard-coupled to Bitwarden by choice. The real bar has consistently been "don't roll your own auth"
and "don't expose new public attack surface," which only option 1 clears outright. Because
`Approver` is already an interface, this isn't a permanent commitment — a future clone of this
project without Tailscale writes a different `Approver` against the same interface, the same story
that already played out three times for `Resolver`.

**The catch, found before any code was written:** the obvious implementation — the broker's own
process binds an HTTP listener to its host's tailscale IP, done — has a same-host bypass. Binding
to the tailscale interface stops traffic from hosts outside the tailnet. It does nothing to stop a
co-located process on the *same* host from reaching that address directly; that's local routing,
not a WireGuard-tunneled packet, and it isn't necessarily subject to the same ACL enforcement path
remote peer traffic gets (this wasn't verified either way — see Consequences). Since the broker is
invoked by an agent that has unrestricted shell access to the exact machine that would be running
the listener, that agent could answer its own approval request. This is the same class of failure
already ruled out for `KDialogApprover` (a scripted `xdotool` click defeats the point of routing
approval through a human-facing dialog at all) — just cheaper to pull off here, since it needs no
GUI automation, only a `curl` call the agent already has the means to make.

## Decision

The decision-granting endpoint lives on a **separate, always-on device** — not the broker's own
host. Concretely:

1. When approval is needed, the broker POSTs a pending-request record (a generated ID, the prompt)
   to a small relay service running elsewhere on the tailnet (a homelab device, not the machine
   running the agent).
2. The broker then blocks — polling or holding an open request against the relay — until a
   decision arrives or a timeout expires.
3. The approving device (phone, on the tailnet) hits the relay directly to submit a decision for
   that request ID.
4. The relay enforces, via Tailscale's own ACLs, that only the approving device's specific tailnet
   identity may reach the decision-submission path. The broker's host can register requests; it
   cannot resolve them.
5. No decision within the timeout is a denial, matching every other ambiguous case in this
   project's deny-by-default table.

`internal/approval.Approver`'s signature (`Approve(ctx, prompt) (Decision, error)`) does not
change. This is a new implementation — call it `TailscaleApprover` or similar — behind the existing
interface, the same shape as every prior adapter swap.

Deliberately not chosen: a same-host listener secured by an application-level signature scheme
(a key living only on the approving phone, verifying each request). This would avoid needing a
third device, but means writing and trusting new signature/replay-protection code — the project's
standing preference is to borrow a hardened primitive (Tailscale ACLs) over writing new auth logic,
even at the cost of one more small service to run.

## Consequences

**Positive**
- Closes a real bypass before it shipped, not after — caught during design, the same value ADR-0003
  already demonstrated once for the KWallet-as-architecture smell.
- No new cryptography written by this project. The relay's access control is entirely Tailscale
  ACL configuration, not application code.
- Consistent with the existing interface boundary — `broker.go` needs no changes at all for this to
  land.

**Negative**
- Requires a third, always-on device beyond the agent's host and the approver's phone — real
  infrastructure to stand up and keep running, not just a config change. Appropriate given this
  project's homelab context, but a genuine cost, not a free lunch.
- Whether same-host traffic to a tailscale-bound address is actually subject to the same ACL
  enforcement as remote-peer traffic was never verified — the relay-device design was chosen
  specifically to make that question moot rather than to answer it. If it's ever revisited, verify
  before trusting, per the project's own established pattern (ADR-0004, ADR-0006).
- Not yet implemented. This ADR records the design and the reasoning that shaped it; the relay
  service, the broker-side client, and `TailscaleApprover` itself remain to be built.

## A note on scope, recorded rather than acted on

Ross flagged, explicitly as a non-commitment, that this project might someday extend beyond
Bitwarden specifically. Noted here so the possibility isn't lost, not as a design constraint on
anything above — nothing in this ADR or the current codebase assumes Bitwarden-agnosticism, and
building toward it now would be exactly the kind of scope creep this project has consistently
avoided elsewhere.
