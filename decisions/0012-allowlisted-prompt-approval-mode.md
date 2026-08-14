# ADR-0012: Add an allowlisted-and-approved mode

**Status:** Accepted
**Date:** 2026-08-14
**Deciders:** Ross

## Context

Live v0.1.0 acceptance used `approval = "prompt"` with an exact `/usr/bin/true` allowlist entry.
The command exited successfully without creating a relay request. That behavior matched the
original policy design: an allowlist match ran directly, while an unlisted command fell through
to human approval.

The acceptance test exposed a missing policy. A security-sensitive operation may need both an
exact argv match and a live human decision. `approval = "always"` supplies the human decision but
also lets the operator approve argv that are absent from the allowlist. Redefining `prompt` would
silently change the behavior of policies already deployed with v0.1.0.

## Decision

Add `approval = "allowlisted-prompt"`. It prompts only after exact argv and working-directory
policy checks succeed. An unlisted command is denied before approval, token resolution, or
execution.

The complete command decision table is:

| `approval` | Exact allowlist match | No allowlist match |
|---|---|---|
| `never` | Run | Deny |
| `prompt` | Run | Prompt |
| `allowlisted-prompt` | Prompt | Deny |
| `always` | Prompt | Prompt |

The existing modes retain their v0.1.0 behavior. An omitted mode still defaults to `never`.

## Consequences

**Positive**

- Deployments can require exact argv, exact cwd, and an independent human decision for every
  secret-bearing invocation.
- Commands outside the allowlist cannot reach the approval relay in this mode, which avoids
  presenting a broad human override as part of the strict path.
- Existing policies keep their behavior.

**Negative**

- There are now four modes whose names alone do not fully describe the decision matrix. The README
  and example policy carry the table operators need when choosing one.
- Existing deployments must opt in explicitly. Upgrading the binary does not rewrite preserved
  policy files.
