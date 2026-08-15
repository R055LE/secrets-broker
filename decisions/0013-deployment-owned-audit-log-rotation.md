# ADR-0013: Rotate worker audit logs outside request execution

**Status:** Accepted
**Date:** 2026-08-15
**Deciders:** Ross

## Context

The worker synchronously appends a start record before policy, approval, token resolution, or
execution and appends a finish record after the outcome. That ordering makes missing audit writes
fail closed, but the fixed JSONL file had no retention policy and could grow for the lifetime of a
host.

Rotation inside the short-lived worker would add retention state to the credential-bearing path.
Copying and truncating the active file outside the worker would introduce a window where appended
records could be lost.

## Decision

Ship a root-owned logrotate policy with the worker deployment. Check the log daily, rotate early
when it exceeds 10 MiB, retain 30 rotations, and compress files after one uncompressed rotation.
Use rename-and-create with a new `secrets-broker:secrets-broker` mode `0600` active file. Never use
`copytruncate`.

The worker already opens and closes the fixed audit path for each start and finish record, so it
does not need a signal or reload after rotation. A rotation between those appends may put a run's
two records in adjacent files. Their shared run ID remains the correlation key.

The worker installer owns `/etc/logrotate.d/secrets-broker`, validates it with logrotate in both
install and check modes, and requires the installed file to match the bundled policy. Installer CI
forces a rotation with isolated state and verifies record retention, ownership, permissions, and
denied read access from both the client and runner identities.

## Consequences

- Audit retention stays outside the credential-bearing request path and does not change the
  audit-before-execution or fail-closed behavior.
- Rename-and-create avoids `copytruncate`'s record-loss window and works because every append
  reopens the fixed path.
- Rotated records remain inside the worker-owned mode `0700` audit directory.
- The 10 MiB threshold is evaluated when the host invokes logrotate. A burst can exceed it before
  the next scheduled run, so this is bounded retention rather than a real-time disk quota.
- Deployments now require logrotate and its normal host scheduler.
