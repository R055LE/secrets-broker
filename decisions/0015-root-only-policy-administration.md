# ADR-0015: Root-only policy administration with safe approval modes

**Status:** Accepted
**Date:** 2026-08-16
**Deciders:** Ross

## Context

The fixed, root-owned policy is part of the worker's trust boundary, but routine project changes
still required opening TOML as root. The four stored approval names also describe implementation
behavior poorly from an operator's point of view. In particular, `never` means an allowlisted
command runs automatically, while `allowlisted-prompt` is the normal confirm-before-running mode.

The agent-facing CLI cannot gain policy mutation flags. The caller is the untrusted party, and a
path or approval override there would bypass the boundary the worker exists to enforce. Persistent
policy changes also do not belong on the approval relay: approving one request is a narrower act
than changing what future requests may do.

The broader usability direction includes project and allowlist management, trusted secret entry,
and a simpler mobile approval surface. This change is the smallest useful administrator slice and
does not pre-commit those later trust designs or a repository split.

## Decision

Install a separate `/usr/local/sbin/secrets-broker-admin` binary that:

- requires effective uid 0;
- always reads `/etc/secrets-broker/policy.toml`, with no path override;
- lists projects using operator-facing approval names;
- permits only `confirm` and `automatic` mutations;
- maps `confirm` to `allowlisted-prompt` and `automatic` to `never`;
- preserves the policy's existing text outside the selected approval value; and
- validates the complete worker policy before an atomic, metadata-preserving replacement.

The administrator binary is root-owned and is not added to the client group's sudoers policy.
Existing `prompt` and `always` policies remain readable and are displayed as `prompt-unlisted` and
`prompt-any`, but selecting those broader modes still requires deliberate manual administration.

## Consequences

- Routine prompt-to-automatic changes no longer require direct TOML editing.
- The agent-facing protocol and worker remain unchanged.
- A malformed policy, unsupported TOML layout, symlink, writable parent directory, ownership
  mismatch, concurrent replacement, or failed validation prevents the write.
- Project creation, allowlist changes, and secret writes remain manual. Secret entry will require a
  separate write-capability design rather than broadening the worker's runtime credential.
- The relay and its web dashboard stay in this repository. A native mobile client warrants a
  separate repository only when it has an independent toolchain, signing, and release lifecycle.
