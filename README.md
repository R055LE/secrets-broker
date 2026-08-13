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

There are two deliberate limits:

1. The wrapped command receives every secret in the configured BWS project. Its stdout and stderr
   are returned to the caller. Do not approve commands whose purpose is to print secrets.
2. Exact argv and cwd do not make agent-controlled files safe. Git hooks, package scripts,
   Terraform providers, plugins, config files, and similar state can change what a command does.
   Do not allowlist such commands directly from an agent-writable tree. Use a root-owned operation
   wrapper that validates or disables those extension points, then allowlist the wrapper's exact
   argv. A human approval prompt shows argv and cwd; it cannot attest to hidden filesystem state.

## Build

Requires Go 1.26.5 and [Task](https://taskfile.dev/).

```bash
task test
task vet
task lint
task build
task build:worker
task build:relay
```

The local lint task expects `golangci-lint` on `PATH`. CI pins its own version.

## Install the isolated worker

These are administrator steps. Run token provisioning from a trusted terminal outside the agent
session.

1. Create the two service accounts and the client group:

   ```bash
   sudo useradd --system --create-home --home-dir /var/lib/secrets-broker \
     --shell /usr/sbin/nologin secrets-broker
   sudo useradd --system --create-home --home-dir /var/lib/secrets-broker-runner \
     --shell /usr/sbin/nologin secrets-broker-runner
   sudo chmod 0700 /var/lib/secrets-broker /var/lib/secrets-broker-runner
   sudo groupadd --system secrets-broker-clients
   sudo usermod -aG secrets-broker-clients "$USER"
   ```

2. Install root-owned executables. Install the Bitwarden `bws` binary at the exact path named in
   policy.

   ```bash
   install -Dm0755 bin/secrets-broker "$HOME/.local/bin/secrets-broker"
   sudo install -Dm0755 bin/secrets-broker-worker /usr/local/libexec/secrets-broker-worker
   sudo install -Dm0755 /path/to/bws /usr/local/bin/bws
   ```

3. Install policy, audit storage, and sudoers rules:

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/secrets-broker
   sudo install -o root -g secrets-broker -m 0640 policy.example.toml \
     /etc/secrets-broker/policy.toml
   sudo install -d -o secrets-broker -g secrets-broker -m 0700 /var/log/secrets-broker
   sudo install -o root -g root -m 0440 deploy/secrets-broker.sudoers \
     /etc/sudoers.d/secrets-broker
   sudo visudo -cf /etc/sudoers.d/secrets-broker
   ```

   Edit `/etc/secrets-broker/policy.toml` as root. The configured working directory must be
   traversable by `secrets-broker` and usable by `secrets-broker-runner`. Log out and back in after
   changing client-group membership.

   If the working directory is below a private home directory, grant the service accounts traverse
   permission on the home directory without adding them to the user's group:

   ```bash
   sudo setfacl -m u:secrets-broker:--x,u:secrets-broker-runner:--x "$HOME"
   ```

4. Provision the BWS access token as the worker account. The token must not be typed into an agent
   prompt, command argument, environment file, or shell history.

   ```bash
   sudo -u secrets-broker /bin/bash -c \
     'umask 077; read -rsp "BWS access token: " token; printf "\n" >&2; printf %s "$token" > /var/lib/secrets-broker/bws-access-token'
   ```

5. Install the relay on a separate device, then configure its Tailscale IP in policy. The relay
   has a broker-only control port and an approver-only decision port. A hardened systemd unit and
   environment-file example are in `deploy/`:

   ```bash
   sudo install -Dm0755 bin/secrets-broker-relay /usr/local/bin/secrets-broker-relay
   sudo install -d -o root -g root -m 0755 /etc/secrets-broker-relay
   sudo install -o root -g root -m 0644 deploy/secrets-broker-relay.env.example \
     /etc/secrets-broker-relay/environment
   sudoedit /etc/secrets-broker-relay/environment
   sudo install -o root -g root -m 0644 deploy/secrets-broker-relay.service \
     /etc/systemd/system/secrets-broker-relay.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now secrets-broker-relay.service
   ```

   Tailscale ACLs must restrict the control port to the broker host and the decision port to the
   approving device. The relay rejects wildcard listen addresses, but it does not authenticate
   callers itself. See [ADR-0008](decisions/0008-tailscale-relay-approver-design.md) and
   [ADR-0009](decisions/0009-two-port-relay-protocol.md).

   Keep the decision port's root page open on the approving device. It refreshes every two seconds,
   shows live pending requests, and submits approvals or denials through the existing decision
   endpoint. The broker host cannot reach this page when the documented ACL split is applied.

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
deploy/                    Administrator-owned deployment policy
```

Legacy Secret Service, environment-token, and `kdialog` adapters remain for migration and focused
tests. `ValidateWorker` rejects them in the credential-bearing deployment.

## License

MIT. See [LICENSE](LICENSE).
