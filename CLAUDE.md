# secrets-broker

## Project Overview

A custody broker between AI coding agents and Bitwarden Secrets Manager. The agent asks the
broker to run a command; the broker — never the agent — holds the bootstrap access token,
checks the command against a per-project allowlist, prompts a human via `kdialog` for anything
not pre-approved, and writes an append-only audit record before and after every attempt. See
`decisions/` for why this shape and not the official Bitwarden MCP server, and not handing the
agent the token directly.

## Git Conventions

- Do NOT add Co-Authored-By trailers to commits.
- Use conventional commit format: `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, etc.
- Keep commits atomic and descriptive.

## Architecture

- `cmd/secrets-broker/` — Composition root. The only place real adapters (Secret Service, kdialog,
  bws, JSONL audit log) are constructed and wired together.
- `internal/cli/` — cobra plumbing only. No policy/security logic — that all lives in
  `internal/broker`.
- `internal/broker/` — The orchestrator. `broker.go` contains the entire deny-by-default decision
  matrix and depends only on the four domain interfaces below, never on a concrete adapter.
- `internal/token/` — `Resolver` interface + three implementations: `SecretServiceResolver`
  (desktop, shells out to `secret-tool` — not `kwallet-query`, whose write path is broken; see
  ADR-0006), `EnvResolver` and `FileResolver` (headless; see ADR-0007). The composition root
  (`internal/cli/run.go`'s `newResolver`) picks one based on `config.TokenSource.Backend`.
- `internal/approval/` — `Approver` interface + `KDialogApprover` (v1's only implementation).
- `internal/runner/` — `Runner` interface + `BWSRunner`, which shells out to `bws run`.
- `internal/audit/` — `Logger` interface + `JSONLLogger`, append-only, write-before-exec/
  finalize-after.
- `internal/policy/` — Pure function, exact-argv allowlist matching. No I/O.
- `internal/config/` — Loads and validates `policy.toml`.
- `internal/execx/` — The one shared `os/exec` seam every adapter depends on instead of calling
  `os/exec` directly, so adapters are unit-testable against a `FakeRunner`.
- `decisions/` — ADRs. Read these before changing anything security-relevant; several encode
  non-obvious findings (e.g. `bws run`'s actual shell-join behavior) that aren't visible from the
  code alone.

## Build Order

```bash
task test              # Hermetic unit tests (no Secret Service/kdialog/bws required)
task test:integration  # Real Secret Service/bws, local-only. Needs SECRETS_BROKER_TEST_TOKEN_ENTRY,
                        # SECRETS_BROKER_TEST_PROJECT_ID, SECRETS_BROKER_TEST_SECRET_NAME env vars
                        # (skips cleanly if unset); kdialog approval is verified manually, not by this suite
task lint               # golangci-lint
task build              # Build binary to bin/secrets-broker
```

## Key Constraints

- Go 1.26.2, cobra for the CLI, `github.com/pelletier/go-toml/v2` for config — deliberately
  minimal dependencies otherwise.
- `internal/broker/broker.go` depends only on `token.Resolver` / `approval.Approver` /
  `runner.Runner` / `audit.Logger` — never import `secretservice.go`, `kdialog.go`, or `bws.go`
  directly from `broker.go`. This is what keeps a future container-native `Resolver`/`Approver`
  pair a pure addition instead of a rewrite (see ADR-0003), and is what made swapping the
  `Resolver`'s backing CLI tool (ADR-0006) a same-day change instead of a rewrite.
- **`BWS_ACCESS_TOKEN` must never touch the broker's own long-lived environment or any log line.**
  It's resolved on demand per invocation (`internal/token`) and handed to `bws` only for the
  duration of that one subprocess call (`internal/runner/bws.go`). `token.Token`'s
  `String()`/`LogValue()` are deliberately redacted — don't "fix" that.
- **No `--yes`/`--force`/approval-bypass flag on `secrets-broker run`, ever.** The agent invoking
  this binary is exactly the untrusted party the approval gate exists for. A self-service bypass
  would make that gate theater. If this seems like a missing feature, it isn't — see ADR-0002.
- Deny-by-default: config missing/unparseable, unknown project, not allowlisted with
  `approval="never"`, an approval prompt that errors or is missing its desktop session, token
  resolution failing, or `bws` failing to start are all hard denials — never treated as implicit
  approval and never falling back to an alternate credential source. Full matrix in
  `internal/broker/broker.go` and README.
- `KDialogApprover` requires an active desktop session — a real, documented limitation, not an
  assumption baked into the architecture (ADR-0003). `EnvResolver`/`FileResolver` (ADR-0007) remove
  that requirement for token resolution specifically, but **there is no headless `Approver` yet** —
  a deployment with `approval` set to anything but `"never"` on a box with no desktop session will
  hang or fail. Don't treat the Resolver split as having solved headless deployment in general;
  it solved half of it.
- Exact argv matching only in `internal/policy` — no globs, no shell-string parsing (ADR-0005).
