# ADR-0022: Keep project administration behind an operator-only Unix socket

**Status:** Proposed; live SSH peer-identity check required before implementation
**Date:** 2026-09-27
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
  `root:secrets-broker-operators` mode `0660` in the root-owned `/run` directory. The service uses
  the existing fixed policy, recovery, credential, and administrator audit paths, with no overrides.
- Require an existing dedicated operator account in `secrets-broker-operators`. It must be distinct
  from the agent, worker, and runner accounts, absent from their groups and the broker client group,
  and without host administrator privileges. Installation must not create a login, grant sudo, or
  enroll the agent. Host administration provisions the account and SSH authentication separately.
  The installer records the exact operator UID and refuses a missing or ambiguous account,
  unexpected group membership, unsafe socket owner or mode, or a conflicting listener.
- On every accepted connection, read Linux `SO_PEERCRED` and require the configured operator UID.
  Check that the account still exists and remains in the operator group before each request. Reject
  every other peer before routing, including root and the agent. The socket mode is the first gate;
  the peer check is the service gate. Never trust a header, cookie, or forwarded username as identity.
- The operator opens `http://127.0.0.1:PORT` on a separate trusted device with
  `ssh -N -T -L 127.0.0.1:PORT:/run/secrets-broker-admin.sock operator@broker-host`. Require SSH
  local StreamLocal forwarding on that login. Do not expose a broker-host TCP listener. Keep the
  approval relay's control and decision ports, and the agent-facing CLI and sudoers rule, separate.

The host administrator enrolls an operator by creating that account and its SSH credential through
normal host management, then adding only that account to the operator group. Revocation removes its
SSH credential and group membership, terminates its active SSH sessions, and restarts the web service
and socket to close existing connections. A removed operator must not retain access through an open
tunnel. Root and host SSH administration remain trusted; this design does not resist either.

### Browser and operation contract

- Serve server-rendered HTML with escaping. Accept only bounded, named administrator operations
  against fixed paths; never accept policy text, shell commands, executable paths, or path overrides.
  Reuse the root-only editor and its complete validation, concurrent-change check, atomic replacement,
  and start-before-write audit behavior. The CLI remains independently usable.
- GET requests only read local state. Access diagnostics and all changes require POST. Before any
  POST action, require an exact `Origin` matching a `127.0.0.1` Host with an explicit port and a
  single-use, action-bound form token. Tokens expire after ten minutes, are bound to the peer UID,
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
  omit credentials, secret names and values, raw BWS output, and recovery artifact contents.
- For each audited web operation, add the peer UID as actor attribution to the existing start and
  finish record without replacing the effective UID. Keep the existing correlation ID and fail-closed
  start. If the finish record fails after a policy change, report that the change may have committed
  and require reconciliation. Finish the audit even if the browser disconnects. Do not claim rollback.
  Read-only page loads remain unaudited.

The first release may expose project setup, diagnostics, exact argv, approval mode, metadata,
removal, and exact recovery only through their separately reviewed issue contracts. Secret writes,
Bitwarden grants, relay decisions, and generic policy editing stay outside this service.

### Threats and limits

| Threat | Control |
| --- | --- |
| Agent or another local user reaches a root policy operation | Socket group and mode, exact peer UID check before routing, no agent sudoers change |
| A web page on another origin sends a request through the local tunnel | Loopback Host and exact Origin checks, single-use form token, POST-only mutations |
| Policy text or diagnostic output injects browser markup or leaks secrets | Escaped templates, restrictive headers, no raw BWS output or secret data |
| A stale form overwrites a newer decision | Opaque policy revision check before operation, editor's concurrent-change protection |
| A crash, timeout, or audit failure hides a partial change | Synced audit start before editing, attempted finish independent of browser connection, explicit uncertain outcome |
| A former operator keeps an active tunnel | Per-request account and group check, terminate sessions and restart service during revocation |
| A client exhausts the service | Body, header, connection, token-state, and time limits |

The separate trusted device, including local processes able to use its forwarded loopback port,
remains trusted. A compromised root account or SSH administrator can change the host directly.
The socket and application checks protect against less-privileged local accounts and cross-origin
browser requests, not those host authorities.

## Verification before implementation

OpenSSH 10.2p1's [StreamLocal protocol](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/PROTOCOL)
has the client ask the server to connect to the Unix socket. Its
[server loop](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/serverloop.c) makes that
connection after the session [drops to the authenticated user's UID](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/sshd-session.c).
This supports the design but does not prove this host's installed SSH configuration and credentials.
A localhost batch SSH attempt on 2026-09-27 was denied for lack of an authorized public key, so
the live check has not passed. Do not implement the editable service until it does:

1. With the actual provisioned operator login, forward a loopback port to a temporary protected
   Unix listener that reports Linux `SO_PEERCRED` UID. Record that the UID equals the operator UID,
   not root or the agent UID. Reject a connection from the agent account and from an unrelated UID.
2. Confirm the same result using the installed SSH daemon and intended SSH account restrictions.
   If forwarding connects as another UID or bypasses socket permissions, revise this ADR before
   implementing the web service.

## Acceptance contract

- Installer checks prove opt-in installation, exact operator identity and group, socket owner and
  mode, service ownership, fixed paths, no new agent sudoers command, and no broker-host TCP listener.
- Handler tests prove per-connection peer authorization before both reads and writes, agent and
  unrelated-UID denial, and denial after operator revocation. A live test repeats those checks over
  SSH forwarding from the separate device.
- Browser tests cover cross-origin and missing-Origin POSTs, forged and replayed tokens, stale
  forms, oversized requests, HTML escaping, safe headers, and no side effects on GET.
- Editor and audit tests prove actor UID attribution, start-before-change ordering, no write after
  audit-start failure, explicit uncertainty after audit-finish failure, and continued CLI and worker
  behavior. Tests and pages must not emit secret values.

The independent issue contracts for the service, pages, forms, and release remain the source of
their detailed feature acceptance. Production installation still requires explicit approval.
