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
repository layout needed by the installers: the four binaries under `bin/`, deployment files
under `deploy/`, and the example policy at the archive root. Use a current GitHub CLI with
`gh attestation verify`; older distro packages may not include that command. Verify the archive's
checksum and GitHub build provenance before extracting it and running the installer from inside
that directory:

```bash
version=VERSION
arch=ARCH
archive="secrets-broker-$version-linux-$arch.tar.gz"
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "$archive" \
  --repo R055LE/secrets-broker \
  --signer-workflow R055LE/secrets-broker/.github/workflows/ci.yml \
  --source-ref "refs/tags/$version" \
  --deny-self-hosted-runners
tar -xzf "$archive"
cd "secrets-broker-$version-linux-$arch"
```

The checksum detects corruption or a mismatched download. The attestation binds the archive digest
to the release workflow and tag in this repository and rejects provenance from a self-hosted
runner. It does not establish that the source or workflow is safe.

## Install

The deployment scripts target Linux with systemd, sudo or sudo-rs, logrotate, standard account
tools, and POSIX ACL tools (`setfacl` and `getfacl`). When installing from a source checkout, build
all four binaries first. Release archives already contain them:

```bash
task build
task build:admin
task build:worker
task build:relay
```

Run the worker installer on the broker host. Give it the local human account that will invoke the
CLI and a trusted Bitwarden `bws` binary on the first install:

```bash
sudo deploy/install-worker.sh install --client-user "$USER" --bws /path/to/bws
```

The installer creates the worker, runner, and client identities; installs root-owned binaries and
sudoers and audit-rotation policies; establishes private state and audit directories; and grants
both service accounts traverse-only access to the client's home directory. It never creates or
replaces the token and never replaces an existing project policy.

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

### Upgrade an installed role

After the first release containing `/usr/local/bin/secrets-broker-upgrade` is installed, later
upgrades use one role-explicit command on each device:

```bash
secrets-broker-upgrade worker vMAJOR.MINOR.PATCH
secrets-broker-upgrade relay vMAJOR.MINOR.PATCH
```

Run the worker form on the worker host and the relay form on the separate relay device. The helper
requires an explicit release and detects amd64 or arm64. It downloads the matching archive and
checksums as the current user, verifies the checksum and the repository, workflow, tag, and
hosted-runner provenance policy, then binds that archive digest again after copying it into
root-owned staging. The privileged phase extracts there, invokes the bundled installer and check,
and compares the installed role binaries with the verified bundle before reporting success.

The helper does not select `latest`, perform network access as root, or replace policy, token, BWS,
or relay environment state. It is an upgrade path only. First installation still uses the manual
release verification and role setup above, and the first release carrying the helper must be
installed that way once to bootstrap later one-command upgrades. GitHub CLI must be current and
able to reach the release and attestation APIs on both devices.

### Manage project policy

The worker installer also installs `/usr/local/sbin/secrets-broker-admin`. It is a separate,
root-only interface to the fixed worker policy; it is not available through the agent sudoers rule
and has no policy-path override.

```bash
sudo secrets-broker-admin projects list
sudo secrets-broker-admin projects create github-ops \
  --bws-project-id 00000000-0000-0000-0000-000000000000 \
  --token-entry github-ops-agent \
  --working-dir /home/YOUR-USER/code/YOUR-PROJECT
sudo secrets-broker-admin projects set-approval omada-read confirm
sudo secrets-broker-admin projects set-approval omada-read automatic

sudo secrets-broker-admin projects access check
sudo secrets-broker-admin projects access check omada-read

sudo secrets-broker-admin projects allowlist list omada-read
sudo secrets-broker-admin projects allowlist add omada-read -- \
  /usr/local/libexec/secrets-broker-ops/omada-acl
sudo secrets-broker-admin projects allowlist remove omada-read -- \
  /usr/local/libexec/secrets-broker-ops/omada-acl

sudo secrets-broker-admin projects remove github-ops --confirm github-ops
sudo secrets-broker-admin projects recovery list
sudo secrets-broker-admin projects recovery restore RECOVERY_ID --confirm github-ops
```

Project creation requires every deployment identifier and an absolute working directory. It always
starts in `confirm` mode with an empty allowlist. Duplicate aliases and incomplete input are
rejected. The command only changes the local worker policy; it does not create secrets, change the
worker's BWS access token, or broaden that token's project grants. The `--token-entry` value's
meaning depends on the configured resolver backend: under `env` and `file` resolvers it is advisory
only (a memorable label, commonly the project alias) and is ignored at runtime; only Secret Service
deployments use it as a lookup key (ADR-0007).

The working directory only fixes where the approved command starts. The command still runs as
`secrets-broker-runner` (ADR-0010), and that account's own file permissions apply. A normal checkout
owned by your user is readable but not writable by the runner, so a command that writes a log or
output file relative to its cwd fails with `Permission denied`. Point output at a path the runner
can write, such as `/tmp` or a dedicated runner-owned directory, not the project checkout.

`confirm` means an exact allowlist match still requires a live approval. `automatic` means an exact
allowlist match runs without a prompt; unlisted commands remain denied. The broader legacy modes
are shown as `prompt-unlisted` and `prompt-any` by `projects list`, but this command deliberately
cannot select them.

The access diagnostic uses the deployed worker token to ask Bitwarden for either every configured
project or one exact alias. It reports only `ALIAS`, `BWS_PROJECT_ID`, and `STATUS`. Exit status `0`
means every selected project was accessible, `1` means the check completed with an inaccessible or
remote-error result, and `2` means a local or audit failure prevented a trusted complete result.
Unlike the installer check, this command reads the token and contacts Bitwarden. It does not request
approval, retrieve secrets, or run an allowlisted command.

Allowlist entries are argv arrays, not shell strings. `--` separates the administrator command from
the exact argv being stored, including any arguments that begin with `-`. Adding an existing entry
and removing a missing entry are safe no-ops. Removal clears every identical entry so a duplicate
cannot leave the command allowed. Allowlist and approval commands manage existing projects only.

An update changes only the requested project field or appends one canonical project, validates the
complete worker policy, and atomically replaces the file while preserving its owner, group, and
permissions. A failed validation leaves the original policy in place. Approval edits require the
existing array-of-tables policy layout, and allowlist removal also requires each `argv` field on one
line.

Project removal requires the alias twice and refuses to remove the last configured project. Before
changing policy, it publishes a root-only recovery artifact under
`/var/lib/secrets-broker-admin/recovery`. The artifact retains the exact pre-removal policy bytes,
so it has the same confidentiality as the policy. `projects recovery list` prints only its opaque
ID, project alias, and creation time.

Restore writes the exact saved bytes only while the current policy still matches the state created
by that removal. Any later policy edit, including recreation of the same alias, blocks automatic
restore and requires manual reconciliation by root. Recovery artifacts remain after restore and
are not automatically pruned. Removal changes only local broker policy. It does not delete a BWS
project or secret, revoke access, or stop a command that already passed policy.

For live acceptance after installing a release, use a deliberately disposable local project. This
does not contact BWS unless somebody later attempts to run the project:

```bash
set -euo pipefail
accept_alias=broker-removal-acceptance
admin=/usr/local/sbin/secrets-broker-admin

sudo "$admin" projects create "$accept_alias" \
  --bws-project-id 00000000-0000-0000-0000-000000000001 \
  --token-entry recovery-acceptance-unused \
  --working-dir "$(pwd -P)"
created_policy="$(sudo sha256sum /etc/secrets-broker/policy.toml)"

remove_output="$(sudo "$admin" projects remove "$accept_alias" --confirm "$accept_alias")"
printf '%s\n' "$remove_output"
recovery_id="${remove_output##*Recovery ID: }"
recovery_id="${recovery_id%.}"
[[ "$recovery_id" =~ ^[0-9a-f]{32}$ ]]
sudo "$admin" projects recovery list | grep -F "$recovery_id"

sudo "$admin" projects recovery restore "$recovery_id" --confirm "$accept_alias"
test "$created_policy" = "$(sudo sha256sum /etc/secrets-broker/policy.toml)"
sudo "$admin" projects remove "$accept_alias" --confirm "$accept_alias"
if sudo "$admin" projects list | grep -Fq "$accept_alias"; then
  echo "Disposable project was not removed." >&2
  exit 1
fi
```

Every requested project creation, removal, restoration, approval, allowlist mutation, or BWS access
diagnostic writes a root-owned audit start record before the policy editor or worker runs, followed
by a `changed`, `no_change`, `failed`, or diagnostic aggregate finish record. A failed start record
prevents the policy or diagnostic operation. If the policy replacement succeeds but the finish
record fails, the command reports that the policy changed and leaves the unmatched start record for
recovery. Project and recovery listings do not write this log.

Administrator audit records contain the effective UID, project alias, operation, requested
approval mode or a SHA-256 digest and count of the exact argv, outcome, timestamps, and a
correlation ID. Removal and restoration records also include the opaque recovery ID. Project
creation records identify the alias, operation, and fixed `confirm` mode,
but omit the supplied BWS project ID, token entry, and working directory. Records do not contain raw
argv, policy contents, tokens, secret names, secret values, or raw failure text. The fixed
administrator audit path is
`/var/log/secrets-broker-admin/audit.jsonl`, owned by `root:root` and separate from the worker-owned
execution audit. See
[ADR-0017](decisions/0017-root-owned-administrator-mutation-audit.md),
[ADR-0018](decisions/0018-safe-root-only-project-creation.md), and
[ADR-0019](decisions/0019-recoverable-root-only-project-removal.md). The access diagnostic's
privilege, privacy, classification, and audit boundaries are in
[ADR-0020](decisions/0020-secret-free-bws-project-access-diagnostic.md).

The check validates accounts, group membership, ACLs, fixed paths, ownership, modes, sudoers
syntax, template completion, and installed CLI, `bws`, and sudo versions. It also invokes the
worker's reserved `check` mode as the worker account. That mode parses and validates the policy,
runtime paths, project working directories, and token metadata. It does not read or print the
token, contact the relay, invoke `bws`, run a project command, request an approval, or write an
audit record.

The root-owned logrotate policy checks both audit files daily and rotates either one early when it
exceeds 10 MiB. It retains 30 rotations and compresses older files after one cycle. New worker logs
are `secrets-broker:secrets-broker` mode `0600`; new administrator logs are `root:root` mode `0600`.
Rotation renames each file instead of copying and truncating it. Each operation opens its fixed
audit path for every record, so neither process needs a reload. A rotation between start and finish
records can place them in adjacent files; the shared ID still correlates the pair. The 10 MiB
threshold is evaluated when the host's logrotate schedule runs, so it is not a real-time disk
quota.

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
cmd/secrets-broker-admin/  Root-only fixed-policy administrator CLI
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
internal/admin/            Validated atomic project policy updates
decisions/                 Architecture decision records
deploy/                    Role installers and administrator-owned deployment policy
```

Legacy Secret Service, environment-token, and `kdialog` adapters remain for migration and focused
tests. `ValidateWorker` rejects them in the credential-bearing deployment.

## License

MIT. See [LICENSE](LICENSE).
