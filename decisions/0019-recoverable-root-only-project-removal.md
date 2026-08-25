# ADR-0019: Recoverable root-only project removal

**Status:** Accepted
**Date:** 2026-08-25
**Deciders:** Ross

## Context

ADR-0018 made project creation safe by fixing the initial approval mode and allowlist. Removal has
a different failure shape. A mistaken creation can be removed later, while a mistaken removal can
discard deployment identifiers, exact argv policy, and comments needed to reconstruct the project.
Direct TOML editing also makes it easy to remove the wrong array-of-tables span.

Root remains trusted and can edit or replace the policy manually. The administrator command should
still protect an operator from selecting the wrong project, preserve an exact recovery path, and
refuse to guess when policy changed after removal.

Removal only changes the local worker policy. It does not delete a BWS project or secret, revoke a
machine-account grant, stop a command that already passed policy, or uninstall the worker.

## Decision

### Deliberate selection

Add these root-only commands against the existing fixed policy path:

```text
secrets-broker-admin projects remove ALIAS --confirm ALIAS
secrets-broker-admin projects recovery list
secrets-broker-admin projects recovery restore RECOVERY_ID --confirm ALIAS
```

The two alias values must match exactly. Confirmation is a required value rather than a boolean,
and there is no `--yes`, `--force`, path override, or interactive fallback. A syntactically complete
request with a missing project or mismatched confirmation is an audited failure.

The command refuses to remove the last configured project. Worker policy requires at least one
project, and full deployment decommissioning is a separate administrative operation.

### Editable layout

Removal accepts only the canonical array-of-tables layout with exactly one literal `[[projects]]`
header for each parsed project. The selected byte span begins at that header and ends at the next
`[[projects]]` header or end of file. Comments and whitespace inside that span belong to the selected
project. Comments intended for the following project belong after its header.

The editor removes the complete span without interpreting nested allowlist formatting. It reparses
and validates the complete worker policy, then proves that the semantic result equals the original
configuration with exactly the selected project removed. Every byte outside the selected span must
remain unchanged. Valid alternate TOML layouts stay readable but are not editable by this command.

The existing metadata-preserving atomic writer performs the policy replacement and keeps its size,
owner, group, mode, and concurrent-change checks.

### Recovery artifact

Before replacing policy, publish one recovery artifact under the fixed directory
`/var/lib/secrets-broker-admin/recovery`. The installer owns the directory as `root:root` mode
`0700`; artifacts are regular, non-symlink files owned by `root:root` mode `0600`.

The filename is a 128-bit random lowercase hexadecimal recovery ID and contains no alias or caller
input. The versioned JSON artifact is limited to 2 MiB and contains:

- recovery ID and creation timestamp;
- selected project alias;
- SHA-256 digests of the exact pre-removal and post-removal policy bytes; and
- the exact pre-removal policy bytes encoded as base64 by the JSON representation.

The artifact has the same confidentiality as the worker policy. It contains deployment identifiers,
working directories, allowlist entries, and policy comments, but no new credential or secret value.
It is created exclusively, synced, atomically published, and never overwrites an existing ID.

Artifacts are retained after restoration and are not automatically rotated or pruned in the first
implementation. Silent expiry would weaken the recovery promise. Removal is expected to be rare;
explicit artifact cleanup and bounded retention can be designed separately.

### Ordering and audit

Removal follows this order:

1. Sync an administrator audit start record.
2. Securely read and validate policy, selection, confirmation, layout, and the non-final-project
   rule.
3. Construct and validate the exact post-removal policy.
4. Create and sync the recovery artifact.
5. Atomically replace policy with the existing metadata and concurrency checks.
6. Sync the administrator audit finish record.

The start record contains effective UID, project alias, `remove_project`, and the opaque recovery
ID. The finish outcome remains `changed` or `failed`. Audit records omit policy bytes, policy
digests, artifact paths, BWS project IDs, token entries, working directories, allowlist argv, and
secret material.

The recovery ID is reported whenever an artifact was published, including an error after that
point. This leaves a usable reconciliation handle if policy replacement or audit completion fails.

| Failure point | Policy result | Recovery result |
| --- | --- | --- |
| Audit start | Unchanged | No artifact |
| Selection, validation, or layout | Unchanged | No artifact |
| Artifact creation or sync | Unchanged | No published artifact |
| Concurrent policy replacement | Concurrent writer wins | Prepared artifact may remain |
| Policy replacement | Unchanged | Prepared artifact remains |
| Audit finish after replacement | Removal stays committed; command errors | Artifact remains usable |

Prepared artifacts left by a failed removal are safe. Their post-removal digest will only authorize
restoration if current policy exactly matches the state that artifact describes.

### Restoration

`projects recovery list` is read-only and displays only recovery ID, project alias, and creation
time. It does not print the stored policy, digests, deployment identifiers, or paths. Malformed or
unsafe artifacts are reported rather than silently ignored.

Restore requires the recovery ID and an exact alias confirmation. It securely reads the current
policy and artifact, verifies the artifact's ID, ownership, mode, size, JSON version, pre-removal
digest, and confirmed alias, then requires the current policy bytes to match the stored post-removal
digest exactly.

The stored policy must parse and pass complete worker validation. Its semantic difference from the
current policy must be exactly one project with the confirmed alias, and applying the canonical
removal to the snapshot must reproduce the current policy bytes. Restore then atomically writes the
exact stored bytes while preserving current policy metadata and checking for a concurrent change.

Any intervening policy mutation, prior restoration, artifact corruption, or semantic mismatch
causes restore to fail without writing. The artifact remains available for deliberate manual repair
by root. Restore uses the same audit ordering with operation `restore_project`, project alias, and
recovery ID. A successful restore records `changed`; rejected restoration records `failed`.

## Pre-implementation test contract

Implementation starts with failing tests for the following behavior.

### Selection and policy mutation

- Non-root use fails before policy or recovery access, and no policy-path override exists.
- Missing or mismatched confirmation, unknown aliases, and removal of the last project fail without
  creating an artifact or changing policy.
- Removing the first, middle, and last project from multi-project policies changes only the selected
  canonical span and the corresponding semantic project.
- Nested allowlist tables, comments, quoted values, LF, CRLF, and a missing final newline remain
  correct without broad TOML serialization.
- Alternate valid TOML project layouts, malformed policy, oversized policy, symlinks, unexpected
  ownership, or open permissions fail without a write.
- Successful removal preserves policy owner, group, and mode and leaves the remaining policy valid
  to the worker.

### Recovery artifact and restoration

- The recovery directory and artifact use exact ownership and modes; client, worker, and runner
  identities cannot read them in installer CI.
- The artifact contains exact original bytes and matching before/after digests, uses a valid random
  ID, stays within its size bound, and is durable before policy replacement begins.
- Unsafe recovery directories, artifact symlinks, ID collisions, short writes, and sync failures
  cannot change policy or overwrite an artifact.
- Restoring an unchanged post-removal policy reproduces the original file byte for byte, preserves
  current metadata, validates the worker policy, and retains the artifact.
- Wrong IDs, path traversal, wrong alias confirmation, unsafe or malformed artifacts, digest
  mismatch, invalid stored policy, and a semantic difference other than one confirmed project fail
  without writing.
- Any policy mutation after removal blocks automatic restore, including recreation of the same
  alias. Recovery listing exposes only the three approved fields.

### Audit and failure ordering

- Audit start failure calls neither the recovery writer nor policy editor.
- Successful remove and restore operations record correlated `changed` pairs with recovery IDs.
- Confirmation, final-project, validation, artifact, and restore failures record `failed` pairs.
- Persisted audit records contain none of the stored policy, digests, deployment fields, exact argv,
  or secret material.
- Audit finish failure after a policy change reports the committed change and recovery ID without
  attempting rollback.

### Concurrency

- Replacing policy after removal reads it but before atomic replacement makes removal fail while the
  concurrent file wins; a prepared artifact may remain and no data is overwritten.
- Editing policy after restore's digest check but before atomic replacement makes restore fail while
  the concurrent file wins.
- Two concurrent removals can publish distinct artifacts, but at most one policy replacement from
  the shared original inode succeeds.
- Two concurrent restores of one artifact allow at most one replacement; neither can overwrite an
  intervening change.
- A forced recovery-ID collision fails closed and never replaces the existing artifact.

## Consequences

- A mistaken removal has an exact, protected rollback while policy remains otherwise unchanged.
- Recovery after later edits requires manual reconciliation, which avoids silently discarding newer
  privileged changes.
- Recovery artifacts increase root-owned persistent state and retain policy-sensitive metadata
  until explicitly removed.
- Removing a project reduces future broker authority but does not revoke external credentials or
  stop already-approved work.
- The agent CLI, worker protocol, sudoers policy, relay, and credential scope remain unchanged.
- Implementation, artifact cleanup, and deployment decommissioning remain separate follow-up work.
