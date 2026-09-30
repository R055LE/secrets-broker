# ADR-0022: Serve project administration through a protected Unix socket

**Status:** Proposed; live Tailscale Serve identity check required before implementation
**Date:** 2026-09-27
**Revised:** 2026-09-30
**Deciders:** Ross

## Context

The root-only administrator CLI can edit local broker policy safely, but routine use still requires
a terminal on the broker host. A browser UI will hold the same authority. The agent account must
never gain that authority, and the approval relay must remain a separate, narrower boundary.
The worker isolation and administrator audit rules in ADR-0010, ADR-0015, and ADR-0017 still apply.

This design covers the current single-worker host. It does not create Bitwarden projects, change
grants, write secrets, or give the worker or agent a new route to the root-owned policy.

## Decision

### Host and operator boundary

- Install the web role only when explicitly requested. Keep the existing CLI-only deployment valid.
- Run one root-owned service through systemd socket activation. Listen only on a fixed Unix socket
  at `/run/secrets-broker-admin.sock`; neither the service nor its unit may bind TCP. The socket is
  `root:root` mode `0600` in the root-owned `/run` directory. The service uses
  the existing fixed policy, recovery, credential, and administrator audit paths, with no overrides.
- Expose that socket through [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve)
  on Barnabas as a private HTTPS site on port 443. Never enable Funnel for this site. The tailnet
  policy grants personal devices access to `tag:jumpbox:443`; no LAN or public listener is added.
  Keep the approval relay's control and decision ports, and the agent-facing CLI and sudoers rule,
  separate. The existing root-only administrator CLI remains independently usable.
- Host administration must leave Tailscale's local `operator` setting empty. The agent's Unix
  account must not be able to change Serve configuration or reach the Tailscale LocalAPI with
  management authority. The installer refuses an unexpected operator, a conflicting Serve or
  Funnel configuration, or an unsafe socket owner or mode. Tailscale configuration and revocation
  remain root-owned host operations.
- On every connection, read Linux `SO_PEERCRED` and require the root-owned `tailscaled` peer.
  On every request, require exactly one `Tailscale-User-Login` header matching the configured
  personal login. Reject missing, duplicated, or different identities before routing. Tailscale
  Serve strips client-supplied identity headers before adding its own; tagged-device traffic has no
  user header. Never treat an arbitrary local connection or a forwarded username as identity.
  The socket mode and peer check protect this header boundary from the agent account.

The host administrator revokes web access by removing the tailnet grant or disabling Serve, then
restarting the web service and socket to close existing connections. Root and host Tailscale
administration remain trusted. The separately provisioned SSH operator account is not needed for
this route and receives no socket access.

### Browser and operation contract

- Serve server-rendered HTML with escaping. Accept only bounded, named administrator operations
  against fixed paths; never accept policy text, shell commands, executable paths, or path overrides.
  Reuse the root-only editor and its complete validation, concurrent-change check, atomic replacement,
  and start-before-write audit behavior. The CLI remains independently usable.
- GET requests only read local state. Access diagnostics and all changes require POST. Before any
  POST action, require an exact `Origin` matching the configured HTTPS tailnet hostname and a
  single-use, action-bound form token. Tokens expire after ten minutes, are bound to the Tailscale login,
  and are kept in bounded server memory. Reject missing or stale tokens. Forms that depend on policy
  carry an opaque revision reference; reject them if the policy changed since rendering, before
  starting an administrator operation. The editor still checks for a race during replacement.
- Cap headers at 16 KiB, request bodies at 64 KiB, concurrent connections at eight, and form-token
  state at 128 entries. Set finite read, write, idle, and operation timeouts. Reject unsupported
  methods and content types. A service crash or timeout must not perform an unaudited policy write.
  Service failure leaves the administrator CLI and worker available.
- Send `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, and a restrictive Content Security Policy with no inline script and
  `frame-ancestors 'none'`. Never put tokens or policy details in URLs. Show sanitized outcomes;
  the first release omits credentials, secret names and values, raw BWS output, and recovery artifact
  contents. A later human-only secret-entry surface needs its own reviewed boundary.
- For each audited web operation, add the authenticated Tailscale login as actor attribution to the
  existing start and finish record without replacing the effective UID. Keep the existing correlation ID and fail-closed
  start. If the finish record fails after a policy change, report that the change may have committed
  and require reconciliation. Finish the audit even if the browser disconnects. Do not claim rollback.
  Read-only page loads remain unaudited.

The first release exposes project setup, diagnostics, exact argv, approval mode, and metadata
through their separately reviewed issue contracts. Removal, exact recovery, and activity views can
follow later. Secret writes, Bitwarden grants, relay decisions, and generic policy editing stay
outside this release.

### Threats and limits

| Threat | Control |
| --- | --- |
| Agent or another local user reaches a root policy operation | Root-only socket, exact peer UID and Tailscale user checks before routing, no agent sudoers change |
| Agent changes Serve routing or impersonates the phone | No agent Tailscale operator authority; live same-host denial check before implementation |
| A web page on another origin sends a request through Serve | Exact HTTPS Host and Origin checks, single-use form token, POST-only mutations |
| Policy text or diagnostic output injects browser markup or leaks secrets | Escaped templates, restrictive headers, no raw BWS output or secret data |
| A stale form overwrites a newer decision | Opaque policy revision check before operation, editor's concurrent-change protection |
| A crash, timeout, or audit failure hides a partial change | Synced audit start before editing, attempted finish independent of browser connection, explicit uncertain outcome |
| A revoked user keeps an active browser connection | Remove tailnet access or disable Serve, then restart service and socket |
| A client exhausts the service | Body, header, connection, token-state, and time limits |

The personal device and its Tailscale login remain trusted. A compromised root account or Tailscale
administrator can change the host directly. The socket and application checks protect against
less-privileged local accounts and cross-origin browser requests, not those host authorities.

## Verification before implementation

The installed Tailscale 1.102.4 CLI accepts `unix:` Serve targets. Tailscale documents that Serve
adds user identity headers, strips client-supplied copies, and omits them for tagged-device traffic.
Barnabas currently reports no local Tailscale operator, while the host documentation still describes
an older `--operator=ross` setup. The live boundary has not been proven. Do not implement the
editable service until these checks pass with a temporary root-only Unix listener:

The reviewed `scripts/admin-identity-probe.py` is the one-time listener for this check. Run a pinned
git object as root, then remove the temporary Serve route and stop the listener. Do not install it.

1. Confirm the agent account cannot change Serve configuration or reach the Unix listener. Confirm
   the intended personal phone reaches the listener through private HTTPS Serve, and record the
   listener's peer UID and exact Tailscale login header.
2. Send a forged identity header from the phone and confirm Serve replaces it. Test same-host
   access from the agent account and a tagged device; neither may acquire the personal identity.
3. Confirm Funnel is disabled, the tailnet ACL grants only the intended private port, and the
   listener has no TCP endpoint. If any check fails, revise this ADR before implementation.

## Acceptance contract

- Installer checks prove opt-in installation, empty Tailscale operator setting, exact configured
  user login, socket owner and mode, service ownership, fixed paths, no new agent sudoers command,
  private Serve only, and no application-owned TCP listener or LAN/public route.
- Handler tests prove peer and header authorization before both reads and writes, agent and missing
  or forged-identity denial. A live phone test repeats those checks through Serve.
- Browser tests cover cross-origin and missing-Origin POSTs, forged and replayed tokens, stale
  forms, oversized requests, HTML escaping, safe headers, and no side effects on GET.
- Editor and audit tests prove Tailscale login attribution, start-before-change ordering, no write after
  audit-start failure, explicit uncertainty after audit-finish failure, and continued CLI and worker
  behavior. Tests and pages must not emit secret values.

The independent issue contracts for the service, pages, forms, and release remain the source of
their detailed feature acceptance. Production installation still requires explicit approval.
