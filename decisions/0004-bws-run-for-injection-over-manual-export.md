# ADR-0004: `bws run` for secret injection, with explicit argv quoting and env construction

**Status:** Accepted
**Date:** 2026-07-31
**Deciders:** Ross

## Context

Two ways to get a secret from Bitwarden Secrets Manager into a wrapped command:

1. **Manual fetch + re-injection:** `bws secret get <id>`, parse the value, `export`/pass it to the
   wrapped command ourselves. This means the broker's own process handles the secret value
   directly — it passes through Go variables, could end up in a debug log, and the broker has to
   get env-construction right on every call site.
2. **`bws run --project-id <id> -- <command>`:** `bws` fetches the project's secrets and injects
   them directly into the *child* process it spawns — the broker's own process never sees the
   values at all.

(1) is rejected — it reintroduces exactly the "broker holds secret values" exposure this project
exists to avoid, for no benefit.

Before writing `internal/runner/bws.go` against option (2), we verified `bws`'s actual behavior
against its source (`crates/bws/src/command/run.rs`, `bws` 2.1.0) rather than assuming from the
`--help` text alone — two things didn't match the initial assumption:

- **`bws run` is not a raw `exec(argv)`.** It joins the trailing command tokens with spaces
  (`command.join(" ")`) and runs the result via `sh -c "<joined>"` (or `--shell` if given). Any
  wrapped-command argument containing a space or shell metacharacter would be re-split or
  reinterpreted by that inner shell unless each token is quoted before being handed to `bws`.
- **`--no-inherit-env` is stricter than expected, not looser.** It does `env_clear()` then
  repopulates *only* `PATH` (from `bws`'s own process env) plus the injected secrets — `HOME`,
  `PWD`, `SHLVL` do not survive, and there's no flag to add other vars back. This breaks any
  wrapped command that needs `HOME` (e.g. `git` reading `~/.gitconfig`), and there's no way around
  it via `bws`'s own flags.

## Decision

Use `bws run`, but don't rely on it naively:

- **Shell-quote every wrapped-command argv token** before handing it to `bws run` (POSIX
  single-quote style, in `internal/runner/bws.go`'s `shellQuote`). This restores the argv-element
  boundaries that `bws`'s internal join-then-`sh -c` step would otherwise flatten, so the exact
  argv match already verified in `internal/policy` survives intact into what actually executes.
- **Don't pass `--no-inherit-env`.** Instead, the broker builds `bws`'s own process environment
  explicitly (`PATH`, `HOME`, `LANG` if set, plus `BWS_ACCESS_TOKEN`) via `buildEnv` in
  `bws.go`, and lets `bws`'s *default* (non-`--no-inherit-env`) behavior inherit from that
  already-minimal environment into the wrapped command. This achieves the actual goal —the wrapped
  command sees a small, deliberate set of vars plus the injected secrets, nothing else — without
  losing `HOME`, and without the wrapped command inheriting whatever happened to be in the
  *agent's* ambient shell when it invoked the broker (which naive inheritance would otherwise
  leak, since `bws` would inherit from whatever env the broker process itself received).

## Consequences

**Positive**
- Secret values never pass through the broker's own memory/logs at all — only `bws` and the
  wrapped command ever see them.
- Wrapped commands that need `HOME` work correctly, which `--no-inherit-env` alone would have
  broken.
- The broker controls exactly what the wrapped command inherits, rather than trusting `bws`'s
  blunter flag — closes a leak path (the agent's ambient environment) that `--no-inherit-env`
  alone doesn't address.

**Negative**
- This depends on undocumented (source-verified, not `--help`-documented) behavior of `bws`
  2.1.0's `run` command. A future `bws` release could change the join/shell behavior or the
  default-env-inheritance behavior without warning — `internal/runner/bws_test.go` pins the exact
  argv and env construction expected today, so a `bws` upgrade that silently changes this shows up
  as a test failure to investigate, not silent breakage in production.
- `passthroughEnvVars` in `bws.go` is a fixed, short list (`PATH`, `HOME`, `LANG`). A wrapped
  command needing some other ambient var (e.g. `XDG_CONFIG_HOME` for a specific tool) won't get it
  in v1 — expanding that list is a one-line change when a real case shows up, not built speculatively
  now.
