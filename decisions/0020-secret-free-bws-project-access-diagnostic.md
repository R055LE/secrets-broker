# ADR-0020: Secret-free BWS project access diagnostic

**Status:** Accepted
**Date:** 2026-08-26
**Deciders:** Ross

## Context

The first live `github-ops` request passed local worker validation and then failed inside `bws run`
with `404 Resource not found`. The configured project ID was valid, but the project was assigned to
a different Bitwarden machine account from the worker's bootstrap token. Assigning the project to
the correct account fixed the request.

The existing worker check is deliberately offline. It validates policy, runtime paths, working
directories, and token-file metadata without reading the token, contacting Bitwarden, requesting
approval, or writing an audit record. Adding network access to that check would make installation
and routine health checks depend on an external service and silently spend a credential.

[Bitwarden documents](https://bitwarden.com/help/secrets-manager-cli/) that a machine-account token
can interact only with projects in its assigned scope. `bws 2.1.0` provides
`project get PROJECT_ID --output none`: its
[project command](https://github.com/bitwarden/sdk-sm/blob/0520690b9710af7a8b1e47aad776f002f369688f/crates/bws/src/command/project.rs#L55-L66)
requests one project while its
[renderer](https://github.com/bitwarden/sdk-sm/blob/0520690b9710af7a8b1e47aad776f002f369688f/crates/bws/src/render.rs#L84-L86)
does not serialize a successful response. It still writes human-oriented errors to stderr and
exposes no stable machine-readable error format. The diagnostic therefore needs a strict privacy
boundary and conservative, version-aware error classification.

This is a read-only credential operation, not a policy mutation and not an approved project
execution. It belongs behind the root administrator surface while the token read and BWS process
remain under the credential-owning worker UID.

## Decision

### Operator surface

Add these root-only commands against the fixed worker deployment:

```text
secrets-broker-admin projects access check
secrets-broker-admin projects access check ALIAS
```

The no-argument form checks every configured project in policy order. The alias form checks exactly
one configured project. There is no token, policy, worker, executable, server, output, concurrency,
or timeout override. Unknown aliases fail before token resolution or BWS execution.

Successful diagnostic output contains exactly these columns:

```text
ALIAS  BWS_PROJECT_ID  STATUS
```

Project IDs are already root-readable deployment identifiers and are deliberately shown so the
operator can compare the local policy with Bitwarden. Project names, token entries, working
directories, allowlists, secret names, secret values, and raw BWS output are never shown.

Exit status is `0` only when every selected project is accessible. Status `1` means the diagnostic
completed and at least one project was inaccessible or hit a remote error. Status `2` means usage,
local validation, audit, token resolution, worker invocation, or output handling failed before a
complete diagnostic result could be trusted.

### Privilege and execution path

The root administrator command writes its audit start record, then invokes this exact fixed path:

```text
/usr/sbin/runuser -u secrets-broker -- /usr/local/libexec/secrets-broker-worker access-check [ALIAS]
```

The existing client sudoers rule remains unchanged. It permits only the worker with no arguments,
so an agent cannot select the reserved `access-check` subcommand. Direct execution as the client
cannot read the worker-owned policy or token. Root, the installed administrator and worker
binaries, policy, token file, host privilege boundary, and Bitwarden remain trusted.

The worker subcommand loads and validates the fixed policy and runtime, resolves the selected alias,
and reads the fixed token file with the existing no-follow ownership, mode, type, and size checks.
It reads the token once, then checks selected projects serially. It never starts the relay,
requests approval, calls `bws run`, crosses to the runner UID, or invokes an allowlisted command.

For each project the worker runs the administrator-owned BWS path with these fixed arguments:

```text
bws project get BWS_PROJECT_ID --output none --color no
```

The environment contains only the fixed runtime `PATH`, worker `HOME`, `LANG=C.UTF-8`, and
`BWS_ACCESS_TOKEN`. The token exists only in the child environment, never argv. Each probe has a
fixed 30-second timeout and probes are not parallelized. This is an explicit low-volume diagnostic;
large fleet discovery and persistent BWS sessions are separate problems.

The worker returns one versioned JSON document containing only the aggregate outcome and selected
alias, project ID, and status rows. The administrator captures worker stdout and stderr separately
with a 2 MiB limit, rejects unknown fields, malformed or trailing data, invalid status values, and
oversized output, then renders the table. It never passes `runuser` output directly to the terminal
or audit log. Worker stderr is limited to fixed local error classes and is reduced to a generic
administrator error.

### Output and error classification

BWS stdout is discarded even though `--output none` should leave it empty. Stderr is captured only
inside the worker, capped at 64 KiB, used for classification, and discarded. Neither stream is
forwarded to the administrator, client, or an audit logger.

The worker emits one of these sanitized statuses:

| Status | Meaning |
| --- | --- |
| `accessible` | BWS exited successfully. |
| `inaccessible` | BWS reported `404 Not Found`; this can mean a missing ID or a project outside the machine account's scope. |
| `authentication_error` | BWS explicitly reported an authentication or credential rejection, including HTTP 401 or 403. |
| `network_error` | The fixed timeout expired or BWS reported a recognized DNS, connection, TLS, or transport failure without an HTTP response. |
| `api_error` | BWS reported an explicit service response such as rate limiting or a 5xx response. |
| `unknown_error` | BWS failed but its bounded error did not match a reviewed classifier. |

Classification is diagnostic information only. It never changes policy, approval, or execution
authorization. The classifier is pinned by tests to reviewed BWS 2.1.0 error forms. A future BWS
message change degrades to `unknown_error` instead of exposing raw text or guessing that access is
valid.

A process-start failure, malformed worker result, oversized worker output, unsafe local file, or
other local failure is not converted into a project status. The administrator returns a sanitized
error and exit status `2` because it cannot trust a complete result.

### Audit

Audit the diagnostic in the existing root-owned administrator log. Its start record is synced
before the worker is invoked and contains effective UID, operation `check_project_access`, and the
project alias only for a single-project request. An all-project request omits the project field.

The finish record contains one aggregate outcome: `all_accessible`, `inaccessible`,
`authentication_error`, `network_error`, `api_error`, `unknown_error`, or `failed`. Mixed results
use this precedence: authentication, network, API, unknown, inaccessible, then all accessible.
Per-project results remain terminal output rather than duplicated audit data.

Records omit BWS project IDs, token entries, token values, BWS stdout and stderr, project names,
secret data, policy contents, and raw failure text. The existing `mutation_id` JSON field remains
the correlation key for compatibility even though this operation is read-only. The operation name
distinguishes the new record from policy mutations.

An administrator audit start failure prevents policy or token access and worker execution. A finish
failure is returned after the read-only probes; there is nothing to roll back. The worker execution
audit is not used because no agent-requested command or approval decision occurred.

## Pre-implementation test contract

Implementation starts with failing tests for the following behavior.

### Command and privilege boundary

- Non-root use fails before audit, policy, token, worker, or BWS access.
- The administrator accepts no arguments or one exact alias and exposes no path, token, server,
  output, timeout, concurrency, or error-detail flags.
- The administrator invokes only the fixed `runuser`, worker path, UID, and reserved subcommand.
- Installer acceptance proves the client sudoers rule still rejects every worker argument while
  root can invoke the diagnostic through the administrator command.
- An unknown alias is an audited failure and calls neither the token resolver nor BWS.
- The existing deployment `check` remains offline, reads only token metadata, and creates no audit
  or network activity.

### BWS boundary

- All-project and single-project selection preserve policy order and use each configured project ID
  exactly once.
- The token is read once and appears only as `BWS_ACCESS_TOKEN` in the fixed child environment.
- Every invocation uses the configured absolute BWS binary and exact `project get`, project ID,
  `--output none`, and `--color no` arguments.
- BWS calls are serial, have the fixed timeout, discard stdout, cap stderr, and never invoke a
  shell, relay, runner-side sudo, allowlisted command, or approval adapter.
- The worker emits one bounded, versioned result containing only aggregate outcome and approved row
  fields. The administrator rejects malformed, trailing, unknown, invalid, or oversized worker
  output and never forwards child stdout or stderr directly.
- Token resolution, process start, cancellation, and local output failures stop with a sanitized
  local error and no partial success exit.

### Classification and privacy

- Exit zero maps to `accessible`; the observed 404 form maps to `inaccessible`; reviewed 401/403,
  transport, timeout, rate-limit, 5xx, and unknown forms map only to their documented statuses.
- An unknown bounded BWS error maps to `unknown_error`. BWS or worker output above its limit is a
  local failure with exit status two. Neither case forwards captured bytes.
- Output contains only alias, configured project ID, and status in a fixed table.
- Sentinel token values, project names, token entries, working directories, allowlist argv, secret
  names, secret values, raw stdout, raw stderr, URLs, and server response bodies appear in neither
  administrator output nor either audit log.
- A changed BWS error form produces `unknown_error`; it cannot become `accessible` or raw output.
- Exit status is zero only for an all-accessible selection, one for complete non-success results,
  and two for incomplete or untrusted local results.

### Audit and failure ordering

- Audit start is durable before `runuser`, token resolution, or BWS execution; start failure calls
  none of them.
- Single-project starts record the alias, all-project starts omit it, and both use
  `check_project_access`.
- Complete results record the documented aggregate outcome. Local failures record `failed`.
- Audit records contain no project IDs, project names, token data, raw BWS data, policy fields,
  secret data, or detailed error text.
- Audit finish failure is visible to the operator after probing and never causes a second probe or
  policy change.

### Packaged and live acceptance

- Release contents include the diagnostic-capable administrator and worker without widening the
  sudoers rule or changing relay deployment.
- Packaged worker installation and check pass in the isolated installer environment without network
  access or a real token.
- Live acceptance checks all configured projects, reports only the approved columns, and produces a
  correlated root-owned audit pair without adding a worker execution record or approval request.
- A disposable inaccessible project proves the nonzero, secret-free `inaccessible` path without
  changing a real BWS project or grant.

## Consequences

- Operators can distinguish a locally valid project ID from one the deployed machine account cannot
  retrieve before attempting an approved command.
- The offline worker and installer checks keep their current availability and privacy properties.
- The diagnostic spends the real worker credential and creates remote sessions only when root asks
  for it explicitly.
- BWS error classification depends on reviewed human-readable output. Version drift fails closed as
  `unknown_error`; supporting a new BWS release requires new fixtures and review.
- One BWS process per selected project favors metadata privacy and direct ID checks over fleet-scale
  efficiency. Bitwarden rate limits and large centralized deployments need a different design.
- Project access does not prove that secret keys are safe environment names, that a wrapped command
  is correctly hardened, or that the machine account has write permission. Those remain separate
  checks and trust decisions.
- The agent CLI, no-argument worker protocol, runner UID, approval relay, project policy, external
  grants, and secrets remain unchanged.
- Implementation, release, live acceptance, and any future fleet diagnostic remain separate work.
