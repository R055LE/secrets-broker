# secrets-broker

## Project overview

A custody broker between AI coding agents and Bitwarden Secrets Manager. The agent-facing CLI
sends a bounded request to a fixed worker running under a dedicated Linux UID. The worker owns the
bootstrap token, policy, and audit log. `bws` passes project secrets to the approved command under
a second runner UID. Read `decisions/`, especially ADR-0010, before changing a security boundary.

## Git conventions

- Do not add Co-Authored-By trailers.
- Use conventional commit subjects: `feat:`, `fix:`, `docs:`, `ci:`, `chore:`, and so on.
- Keep commits atomic and descriptive.

## Architecture

- `cmd/secrets-broker/`: untrusted, agent-facing CLI. It has no adapter or path override flags.
- `cmd/secrets-broker-worker/`: fixed no-argument worker launched as `secrets-broker`.
- `cmd/secrets-broker-relay/`: two-port approval relay for a separate Tailscale device.
- `internal/worker/`: bounded JSON protocol, fixed client invocation, and worker composition.
- `internal/broker/`: deny-by-default policy, approval, token, audit, and execution flow. It depends
  only on domain interfaces and is tested against fakes.
- `internal/token/`: token resolver interface and adapters. `ValidateWorker` accepts file only.
- `internal/approval/`: approval interface and adapters. `ValidateWorker` accepts relay only.
- `internal/runner/`: `bws run --no-inherit-env` plus the isolated runner-UID sudo hop.
- `internal/audit/`: synced JSONL start and finish records.
- `internal/securefile/`: no-follow opens plus type, owner, mode, and size checks.
- `internal/policy/`: pure exact-argv matching.
- `internal/config/`: TOML parsing plus stricter worker deployment validation.
- `internal/execx/`: shared process-execution seam for unit tests.
- `internal/relay/`: bounded in-memory request store and two HTTP handlers.
- `deploy/`: idempotent role installers and root-installed deployment policy.
- `decisions/`: ADRs containing verified behavior and trust-boundary decisions.

## Build order

```bash
task test
task test:integration  # Real Bitwarden tests; skips unless the documented env vars are set
task vet
task lint
task check:installers
task build
task build:worker
task build:relay
```

The integration runner path also requires the isolated worker and runner sudoers deployment.

## Key constraints

- Go 1.26.5, cobra, and `github.com/pelletier/go-toml/v2`. Avoid new dependencies unless the
  requested change needs one.
- The caller controls only project alias, resolved cwd, exact argv, and dry-run. Do not add config,
  audit, token, worker path, executable path, or approval override flags.
- `/usr/local/libexec/secrets-broker-worker`, `/etc/secrets-broker/policy.toml`, and
  `/var/log/secrets-broker/audit.jsonl` are fixed deployment paths.
- The worker UID and runner UID must remain distinct. The runner receives project secrets but must
  not be able to read the bootstrap token, policy, or audit directory.
- `BWS_ACCESS_TOKEN` belongs only in the worker-to-`bws` environment. `bws` removes it before
  spawning its child. Keep `--no-inherit-env` as well so the rest of the worker's runtime
  environment does not cross into the runner-side sudo hop.
- The runner-side sudo preserves the already-cleared `bws --no-inherit-env` environment through a
  worker-scoped `env_keep` rule. Its command is `NOSETENV` and may target only the dedicated
  `secrets-broker-runner` account. Do not widen that account or environment scope.
- BWS secret names are trusted deployment data. Reject or rename control-variable keys such as
  `LD_PRELOAD`, `BASH_ENV`, and `PATH` before using a project with this broker.
- Policy and executable paths are administrator-owned. Sensitive file reads must keep the
  no-symlink, regular-file, owner, permission, and size checks.
- Audit start must succeed and sync before policy, approval, token resolution, or execution. A
  failed finish record must be visible to the caller.
- No `--yes`, `--force`, or approval bypass. The caller is the untrusted party.
- Exact argv and exact cwd do not make agent-controlled hooks, plugins, scripts, providers, or
  config safe. Allowlist a root-owned operation wrapper that validates or disables those inputs.
- The relay runs on a separate device. Control and decision ports are authorized by different
  Tailscale ACLs. Do not add same-host deployment guidance or merge the ports.
- Relay handlers deliberately do not authenticate callers. Preserve body and state limits, ID
  validation, listener validation, timeouts, browser headers, and same-origin form checks.
