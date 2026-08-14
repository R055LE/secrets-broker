# secrets-broker

`secrets-broker` lets an AI coding agent request a secret-bearing command without giving the
agent Bitwarden's bootstrap token or direct access to the resulting secret environment.

The security boundary is a fixed, no-argument worker launched as a dedicated Linux user. The
agent-facing CLI only sends a bounded JSON request containing the project alias, resolved working
directory, exact argv, and dry-run flag. Policy, credentials, executable paths, and audit paths
come from the worker's fixed deployment, never from caller flags or environment variables.

```text
agent UID
  secrets-broker run ...
    -> sudo fixed worker                 secrets-broker UID
       -> bws run --no-inherit-env
          -> sudo approved command       secrets-broker-runner UID
```

The three identities matter:

- The agent cannot read the worker's token file, config, audit log, or process environment.
- The runner receives project secrets but cannot read the bootstrap token or alter the audit log.
- `BWS_ACCESS_TOKEN` is cleared before `bws` starts the runner-side sudo hop.

See [ADR-0010](decisions/0010-isolated-worker-and-runner-uids.md) for the finding that forced this
shape and the alternatives considered.

## What is enforced

- Fixed `/usr/local/libexec/secrets-broker-worker` invocation with no arguments.
- Fixed `/etc/secrets-broker/policy.toml` and `/var/log/secrets-broker/audit.jsonl` paths.
- Root-owned policy and executable deployment, plus symlink, owner, mode, type, and size checks on
  sensitive files.
- File-only bootstrap token resolution and remote approval through a separate Tailscale relay.
- Exact argv matching and an exact, symlink-resolved working directory for every project.
- A trusted `bws` path, `PATH`, and `HOME`. The agent's environment is not inherited.
- Audit start records written and synced before policy, approval, token resolution, or execution.
- Bounded worker and relay request bodies, bounded relay state, server timeouts, and hardened
  approval-page response headers.

Each project selects one approval mode:

| `approval` | Exact allowlist match | No allowlist match |
|---|---|---|
| `never` | Run | Deny |
| `prompt` | Run | Prompt |
| `allowlisted-prompt` | Prompt | Deny |
| `always` | Prompt | Prompt |

Use `allowlisted-prompt` when a command must satisfy both the exact argv policy and a live human
approval. `always` lets a human approve argv that are absent from the allowlist.

There are two deliberate limits:

1. The wrapped command receives every secret in the configured BWS project. Its stdout and stderr
   are returned to the caller. Do not approve commands whose purpose is to print secrets.
2. Exact argv and cwd do not make agent-controlled files safe. Git hooks, package scripts,
   Terraform providers, plugins, config files, and similar state can change what a command does.
   Do not allowlist such commands directly from an agent-writable tree. Use a root-owned operation
   wrapper that validates or disables those extension points, then allowlist the wrapper's exact
   argv. A human approval prompt shows argv and cwd; it cannot attest to hidden filesystem state.

## Build

Requires Go 1.26.6 and [Task](https://taskfile.dev/).

```bash
task test
task vet
task lint
task check:installers
task build
task build:worker
task build:relay
```

The local lint task expects `golangci-lint` on `PATH`. CI pins its own version.

Tagged releases contain versioned Linux archives for amd64 and arm64. Each archive keeps the
repository layout needed by the installers: the three binaries under `bin/`, deployment files
under `deploy/`, and the example policy at the archive root. Verify the downloaded archive against
the adjacent `checksums.txt`, extract it, and run the installer from inside that directory.

```bash
sha256sum --check --ignore-missing checksums.txt
tar -xzf secrets-broker-VERSION-linux-ARCH.tar.gz
cd secrets-broker-VERSION-linux-ARCH
```

## Install

The deployment scripts target Linux with systemd, sudo or sudo-rs, standard account tools, and
POSIX ACL tools (`setfacl` and `getfacl`). When installing from a source checkout, build all three
binaries first. Release archives already contain them:

```bash
task build
task build:worker
task build:relay
```

Run the worker installer on the broker host. Give it the local human account that will invoke the
CLI and a trusted Bitwarden `bws` binary on the first install:

```bash
sudo deploy/install-worker.sh install --client-user "$USER" --bws /path/to/bws
```

The installer creates the worker, runner, and client identities; installs root-owned binaries and
sudoers policy; establishes private state and audit directories; and grants both service accounts
traverse-only access to the client's home directory. It never creates or replaces the token and
never replaces an existing policy.

Edit `/etc/secrets-broker/policy.toml` as root. The configured working directory must be
traversable by `secrets-broker` and usable by `secrets-broker-runner`. Grant traverse access on any
additional private parent directories with `setfacl`. Log out and back in after the first install
so the client-group membership reaches the login session.

Provision the BWS access token from a trusted terminal outside the agent session. The token must
not be typed into an agent prompt, command argument, environment file, or shell history:

```bash
sudo -u secrets-broker /bin/bash -c \
  'umask 077; read -rsp "BWS access token: " token; printf "\n" >&2; printf %s "$token" > /var/lib/secrets-broker/bws-access-token'
```

Run the read-only deployment check after policy and token provisioning:

```bash
sudo deploy/install-worker.sh check --client-user "$USER"
```

The check validates accounts, group membership, ACLs, fixed paths, ownership, modes, sudoers
syntax, template completion, and installed CLI, `bws`, and sudo versions. It inspects only the
token file's metadata and size. It does not read or print the token, invoke the worker, request an
approval, or write an audit record.

Install the relay on a separate Tailscale device. Start from the example and replace both values
with that device's literal Tailscale IPv4 address:

```bash
install -m 0600 deploy/secrets-broker-relay.env.example "$HOME/secrets-broker-relay.env"
${EDITOR:-vi} "$HOME/secrets-broker-relay.env"
sudo deploy/install-relay.sh install --environment "$HOME/secrets-broker-relay.env"
sudo deploy/install-relay.sh check
```

The relay installer accepts only the Tailscale IPv4 range, requires ports 7620 and 7621, installs
and enables the hardened systemd service, and verifies the local decision dashboard. An existing
`/etc/secrets-broker-relay/environment` is preserved on every rerun. Edit it explicitly as root
when the relay address changes, then rerun the installer.

Tailscale ACLs must restrict the control port to the broker host and the decision port to the
approving device. The relay does not authenticate callers itself. See
[ADR-0008](decisions/0008-tailscale-relay-approver-design.md),
[ADR-0009](decisions/0009-two-port-relay-protocol.md), and
[ADR-0011](decisions/0011-idempotent-role-installers-and-checks.md).

Keep the decision port's root page open on the approving device. It refreshes every two seconds,
shows live pending requests, and submits approvals or denials. The broker host cannot reach this
page when the documented ACL split is applied.

## Use

```bash
secrets-broker run --project agent-project -- /usr/local/sbin/deploy-agent-project
```

The CLI has no config, audit, token, worker, or approval override flags. `--dry-run` asks the same
worker to resolve cwd and argv policy without approval, token access, execution, or an audit
record:

```bash
secrets-broker run --project agent-project --dry-run -- /usr/local/sbin/deploy-agent-project
```

Exit code 125 means the request was denied or the worker was unavailable. Exit code 126 means the
request was approved but execution could not start. Otherwise the wrapped command's exit code is
returned.

## Repository layout

```text
cmd/secrets-broker/        Agent-facing CLI
cmd/secrets-broker-worker/ Fixed credential-owning worker
cmd/secrets-broker-relay/  Approval relay for a separate device
internal/worker/           Bounded request/response protocol and worker composition
internal/broker/           Deny-by-default policy, approval, audit, and execution flow
internal/securefile/       Sensitive-file open and validation helpers
internal/token/            Bootstrap token resolvers; the worker permits file only
internal/approval/         Approval adapters; the worker permits Tailscale relay only
internal/runner/           bws invocation and isolated runner hop
internal/audit/            Synced JSONL start/finish records
internal/relay/            Bounded in-memory store and HTTP handlers
internal/policy/           Exact argv matching
internal/config/           TOML parsing and worker-specific validation
decisions/                 Architecture decision records
deploy/                    Role installers and administrator-owned deployment policy
```

Legacy Secret Service, environment-token, and `kdialog` adapters remain for migration and focused
tests. `ValidateWorker` rejects them in the credential-bearing deployment.

## License

MIT. See [LICENSE](LICENSE).
