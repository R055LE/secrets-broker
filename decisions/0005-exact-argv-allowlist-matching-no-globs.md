# ADR-0005: Exact argv allowlist matching, no globs or prefixes

**Status:** Amended by [ADR-0012](0012-allowlisted-prompt-approval-mode.md). Exact matching remains;
the approval mode now determines whether a match runs immediately or prompts.
**Date:** 2026-07-31
**Deciders:** Ross

## Context

Each project in `policy.toml` has an allowlist of commands. Its approval mode determines whether an
exact match runs immediately or requires human approval. Two ways to express and match an entry:

1. **Shell strings** (`"git push"`), parsed and compared against the requested command line.
   Requires a parser and a set of quoting rules before any comparison can happen at all — an
   entire class of ambiguity (quoting, escaping, word-splitting) that a credential-adjacent tool
   shouldn't need to own.
2. **Argv arrays** (`["git", "push"]`), matched element-for-element against the requested argv.
   There's nothing to parse — a TOML array already *is* the token list.

And within (2), two matching strategies:

- **Prefix/glob matching** — `["terraform", "apply"]` would also satisfy `terraform apply
  -destroy`, or a dynamic branch name in `["git", "push", "origin", "*"]`. More usable for
  routine dynamic commands, but a naive prefix match also silently permits *appended* dangerous
  flags — the exact footgun a tool meant to bound blast radius shouldn't introduce.
- **Exact matching** — the requested argv must match an allowlist entry element-for-element, same
  length, no wildcards.

## Decision

Argv arrays, matched exactly, element-for-element, in v1. No globs, no prefixes, no shell-string
parsing anywhere in `internal/policy`.

## Consequences

**Positive**
- `internal/policy/policy.go` is a single pure function with no parsing, no ambiguity, and full
  unit coverage including the specific case this decision exists to prevent
  (`TestMatch_ExtraTrailingArgsAreNotAPrefixMatch`).
- The allowlist is trivially auditable by reading the TOML file — what's allowed is exactly what's
  written, no mental parsing of glob semantics required.

**Negative**
- Under `approval = "prompt"`, routine dynamic commands (a commit against a branch name, a version
  string that changes per release) fall through to the approval prompt every time. Under
  `approval = "allowlisted-prompt"`, they are denied. This is accepted friction in exchange for
  avoiding a prefix-match footgun. If prompt fatigue turns out to matter in practice, a narrowly
  scoped trailing wildcard (`argv = ["git", "push", "origin", "..."]`, wildcard only as the last
  token, never replacing the risky or flag-bearing part of a command) is the deliberate Phase 2
  answer. It remains deferred until there is a demonstrated need.
