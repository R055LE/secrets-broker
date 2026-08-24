# ADR-0016: Root-only exact allowlist administration

**Status:** Accepted
**Date:** 2026-08-23
**Deciders:** Ross

## Context

ADR-0015 established a fixed-path, root-only administrator for routine approval changes and left
allowlist editing as direct TOML work. That still makes a common operator task depend on carefully
editing nested array-of-tables syntax as root.

Moving allowlist mutation into the agent-facing CLI would let the untrusted caller change what the
worker permits. Shell-string input would also add quoting and tokenization ambiguity to the exact
argv policy chosen in ADR-0005.

## Decision

Extend `secrets-broker-admin projects allowlist` with `list`, `add`, and `remove` for existing
projects. The commands:

- require root and use the fixed worker policy path;
- accept argv as already-tokenized command arguments after `--`;
- keep exact element-for-element matching with no shell parsing, prefixes, or globs;
- treat duplicate adds and missing removals as no-ops;
- remove every identical duplicate so the requested argv is no longer effective;
- validate the complete worker policy and the expected semantic change before writing; and
- use the existing metadata-preserving atomic replacement path.

The editor accepts the canonical `[[projects]]` and `[[projects.allow]]` layout. Removal requires a
single-line `argv` field. Other valid TOML layouts remain readable, but a mutation fails closed
instead of rewriting the whole document and dropping comments.

## Consequences

- Operators can inspect and change exact argv entries without opening the policy in an editor.
- The agent protocol, worker, relay, credential path, and sudoers rules do not change.
- Project creation and secret writes remain separate design problems.
- Commands with dynamic arguments still require explicit exact entries. ADR-0005's deferred
  wildcard tradeoff is unchanged.
