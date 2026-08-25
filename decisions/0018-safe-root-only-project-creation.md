# ADR-0018: Safe root-only project creation

**Status:** Implemented
**Date:** 2026-08-24
**Deciders:** Ross

## Context

Adding a project previously required editing `/etc/secrets-broker/policy.toml` as root. That made a
routine operation depend on remembering the schema and its safest starting state. A malformed edit
could also damage an otherwise valid worker policy.

Project creation crosses the same policy boundary as approval and allowlist changes. It must remain
outside the agent-facing CLI and must not turn into a way to create secrets, replace the worker's
bootstrap credential, or change BWS grants.

## Decision

Add `secrets-broker-admin projects create ALIAS` to the root-only administrator binary. It uses the
fixed `/etc/secrets-broker/policy.toml` path and requires explicit `--bws-project-id`,
`--token-entry`, and `--working-dir` values. The working directory must be absolute.

The command fixes the initial policy state rather than accepting caller-selected security options:

- approval is `allowlisted-prompt`, presented to operators as `confirm`;
- the exact argv allowlist is empty;
- duplicate aliases and missing fields are errors.

The editor appends one canonical project block, parses and validates the complete worker policy,
and compares the parsed result with the intended semantic change. It then uses the existing
concurrent-change check and metadata-preserving atomic replacement. Updates larger than the
administrator's existing 1 MiB secure read limit are rejected. A rejected or invalid update leaves
the original policy unchanged.

Project creation uses the administrator mutation audit from ADR-0017. Its start record contains the
effective UID, project alias, `create_project` operation, and fixed `confirm` mode. It omits the BWS
project ID, token entry, working directory, policy contents, and secret material. Audit start failure
blocks creation.

## Consequences

- Operators can add a project without hand-editing TOML or choosing an unsafe initial mode.
- A new project cannot execute anything until a separate allowlist mutation succeeds, and each
  allowlisted command still requires live approval.
- Creation does not contact BWS or validate that the existing machine account can access the
  project. That remains an operational grant and acceptance concern.
- The agent CLI, worker protocol, worker sudoers rule, and credential scope remain unchanged.
- Removal and recovery are separate operations and are not implied by creation.
