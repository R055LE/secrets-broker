# ADR-0023: Keep human secret entry separate from runtime custody

**Status:** Proposed; implement after the first operator web release and explicit acceptance of the write grant
**Date:** 2026-09-30
**Deciders:** Ross

## Context

The runtime worker has a read-only Bitwarden machine-account token so an agent can run an approved
command without receiving the token or secret values. Entering or rotating a value is a different
operation. The operator wants to do it from a phone or terminal without passing a password through
an agent chat, command argument, or policy file. Bitwarden remains the store of record. The human
still creates the Bitwarden project and grants machine accounts in Bitwarden's web app.

Bitwarden's [BWS CLI](https://bitwarden.com/help/secrets-manager-cli/) accepts the value as a
command argument for secret creation and editing, which exposes it through process arguments. The
official [Go SDK](https://github.com/bitwarden/sdk-go) accepts the value in process memory, but uses
cgo and a Rust library. The existing release bundles build their Go binaries with `CGO_ENABLED=0`
for two architectures. Adding the SDK to the worker or main admin binary would change that release
boundary.

Bitwarden [documents](https://bitwarden.com/help/machine-accounts/) that a machine account's
read/write project permission can also create new projects. A write token therefore carries more
Bitwarden authority than the two UI operations below need. Project scoping and a separate account
reduce exposure, but do not remove that permission. This tradeoff requires explicit acceptance
before the credential is created.

## Decision

- Keep the existing worker token read-only. Create a separate Bitwarden machine account with
  read/write access only to the existing projects selected for human entry. Store its token in a
  separate root-owned `0600` file on Barnabas; neither the worker, runner, nor agent may read it.
  The installer must not create, replace, or grant this credential automatically.
- Add an optional, fixed-path administrator-only writer helper using a pinned official Go SDK
  release. Build it with cgo for Barnabas's Linux amd64 target and package it separately from the
  current cgo-free worker, relay, and administrator binaries. The helper accepts only bounded
  create and rotate requests over stdin and returns sanitized metadata. It has no path, token,
  server, or executable override. Install it as root-owned mode `0700` with no agent sudoers entry.
  The root-owned web service and root-only admin CLI invoke it without a shell; secret values never
  appear in argv or environment variables.
- In the browser, accept a value only through a protected POST on the admin service described in
  ADR-0022. List secret IDs and names for selection, but never render an existing value. In the
  CLI, require a real terminal and read the new value with echo disabled. Provide no `--value` flag
  or piping mode. Both surfaces use the same local alias and fixed BWS project ID from policy.
- Create a secret only within an existing locally configured, writer-accessible BWS project. Rotate
  by an explicit secret ID after the helper confirms that the secret still belongs to that project.
  Preserve the existing key, note, and project assignment during rotation. Do not delete secrets,
  create projects or grants, reveal values, or change broker allowlists as a side effect.
- The authenticated phone submission or root terminal operation is the human authorization for the
  write. Require confirmation of the target project and secret identity before a rotation. Audit a
  synced start before credential resolution or any SDK call, then a finish with success, failure, or
  uncertain remote outcome. Record the actor, local project alias, operation, timestamp, and
  correlation ID. Omit secret IDs, names, values, request bodies, SDK responses, and raw errors.
  A timeout or lost response must not trigger an automatic retry; direct the operator to inspect
  Bitwarden before trying again.
- Rotate the writer token by installing a new root-only file, verifying it against the selected
  projects, switching the fixed token path atomically, and revoking the old token in Bitwarden.
  Revocation or writer failure leaves runtime command execution and local policy administration
  available.

## Threats and limits

| Threat | Control |
| --- | --- |
| Agent obtains write credential or value | Separate root-owned token, no agent route, no argv/environment value, protected Unix socket |
| Browser form is forged or replayed | ADR-0022 identity, Origin, one-use action token, bounded POST, stale target check |
| Wrong project or secret is overwritten | Select from existing local alias and writer-visible project; confirm current secret ID and project before rotate |
| Error leaks plaintext through logs or response | Fixed sanitized errors, metadata-only response and audit, no raw SDK output |
| Remote write succeeds but response or audit finish fails | Report uncertainty, no automatic retry, reconcile in Bitwarden |
| Write token is stolen from the trusted root boundary | Bitwarden grant can include project creation; revoke the token and review Bitwarden events |

Root, the trusted phone, the Tailscale identity boundary, the SDK, and Bitwarden remain trusted.
The browser and helper necessarily hold the newly entered value briefly in memory. This design
does not claim memory erasure or protection from a compromised host administrator.

## Implementation and acceptance

1. Prove the pinned SDK can create and update a disposable secret through the separately scoped
   token without logging or returning its value. Verify native build and release provenance for
   the optional Linux amd64 helper. Keep this proof out of the agent's context.
2. Add the fixed writer helper and metadata-only protocol. Test rejected overrides, project
   mismatch, token-file permissions, bounded input, and uncertain responses with fakes.
3. Add browser create/rotate forms and terminal prompts. Test authorization, CSRF, replay, no
   value echo, audit ordering, and that the agent account cannot invoke either route.
4. Package the optional writer role and document credential creation, rotation, revocation, and
   a disposable-project acceptance run. Deployment and credential changes need explicit approval.
