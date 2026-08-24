# ADR-0017: Root-owned administrator mutation audit

**Status:** Implemented
**Date:** 2026-08-24
**Deciders:** Ross

## Context

The root-only administrator can change approval modes and exact argv allowlists. Those changes are
validated and atomic, but they previously left no application-level operational record. The host's
sudo and journal records show that the binary ran without preserving the selected project or the
semantic change.

Root remains trusted and can edit the policy directly. This audit is an operational history, not a
tamper-proof boundary against root. It still needs protection from the worker, runner, and client
accounts.

The worker execution log cannot safely hold administrator records. Its directory is owned by the
worker account so that command execution can fail closed when the worker cannot append. A root-owned
file inside that directory could still be renamed or removed by the worker because directory write
permission controls those operations.

## Decision

Audit every requested administrator mutation in a separate fixed log at
`/var/log/secrets-broker-admin/audit.jsonl`. The deployment owns the directory and file as
`root:root`, modes `0700` and `0600`. Read-only project and allowlist listing remains unaudited.

Use append-only JSONL start and finish records with a random correlation ID:

- Start records contain the timestamp, effective UID, project alias, operation, and the requested
  operator-facing approval mode or a SHA-256 digest and argument count of the canonical JSON argv.
- Finish records contain the timestamp and one of `changed`, `no_change`, or `failed`.
- Records omit raw argv, policy contents, BWS project ID, token, secret names, secret values, and
  raw failure text.

The start record must be written and synced before the policy editor runs. A start failure blocks
the operation. After a successful start, the administrator always attempts a finish record. If the
policy changes and the finish write fails, rolling the policy back would create another unaudited
mutation and can race another administrator. The command instead returns an explicit error that the
policy changed. The unmatched start record marks the incomplete audit sequence for reconciliation.

Rotate the administrator log independently under the existing deployment-owned logrotate policy.
It uses the worker audit's daily schedule, 10 MiB early threshold, 30 retained rotations, delayed
compression, rename-and-create behavior, and correlation across adjacent rotations. Installation
creates or repairs the root-owned directory without creating, truncating, or replacing an existing
audit file.

## Consequences

- Approval and allowlist mutation attempts now have a semantic record, including no-ops and failed
  policy updates.
- An unavailable administrator audit path prevents new policy mutations.
- Worker, runner, and client accounts cannot read or replace administrator audit records.
- The separate log keeps worker availability and ownership rules unchanged.
- Effective UID is currently always root. Human attribution still comes from the host's sudo or
  journal records and can be correlated by timestamp.
- Root can still alter both policy and administrator audit state. Stronger non-repudiation would
  require forwarding records across a separate trust boundary.
