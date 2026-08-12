# ADR-0002: A custody broker holds the bootstrap token, not the agent

**Status:** Amended by [ADR-0010](0010-isolated-worker-and-runner-uids.md). A separate process
under the caller's UID was not a custody boundary.
**Date:** 2026-07-31
**Deciders:** Ross

## Context

Bitwarden Secrets Manager's `bws run --project-id <id> --no-inherit-env -- <command>` injects
secrets straight into a child process's environment without the *calling* process ever seeing the
values. That solves exposure of secret *values*. It does not solve exposure of the bootstrap
`BWS_ACCESS_TOKEN` itself — something has to hold that credential to call `bws` at all, and it's
irreducible: no amount of clever injection removes the need for one process, somewhere, to
authenticate to Bitwarden first.

The first plan (superseded by this ADR) was to give the agent's own shell that token directly —
resolved from KWallet at shell-init time, landing in the agent's own `BWS_ACCESS_TOKEN` environment
variable. That's an improvement over a plaintext dotfile export, but it still hands the bootstrap
credential to the same unrestricted-Bash process the agent already has. At that point an allowlist,
an audit log, or an approval step are just policy documents — nothing structurally stops the agent
from calling `bws` directly with whatever project/command it wants, since it holds the same
credential the policy is supposed to gate.

## Decision

A separate broker binary holds custody of the bootstrap token. The agent never receives
`BWS_ACCESS_TOKEN` in its own environment at any point. Every secret-using command the agent wants
to run is phrased as `secrets-broker run --project <alias> -- <command>` instead of a direct `bws`
call — the broker resolves the token itself (from KWallet, see ADR-0003), decides whether the
command is allowed (allowlist, or a human approval prompt), and only then invokes `bws` on the
agent's behalf, with the token confined to that one subprocess call.

## Consequences

**Positive**
- The allowlist, audit log, and approval gate are now structurally enforced, not just documented
  policy — the agent has no path to Bitwarden that bypasses the broker, because it never holds a
  credential that would let it call `bws` directly.
- The broker's own process only ever holds the token transiently, for the duration of one `bws`
  invocation (see `internal/runner/bws.go`) — never in a long-lived environment variable.

**Negative**
- Every secret-using command the agent runs must be phrased through the broker explicitly; there's
  no ambient "just works" access the way an exported env var would give. This is the point, not a
  bug, but it's a real ergonomic cost worth naming.
- The broker itself is now a thing that must be trusted and kept correct — a bug in `broker.go`'s
  deny-by-default logic is a real security bug, not just an inconvenience. This is why that file
  has full unit coverage of the decision matrix (`internal/broker/broker_test.go`) against fakes,
  independent of any real KWallet/kdialog/bws being present.
