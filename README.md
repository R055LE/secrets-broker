# secrets-broker

> A custody broker between an AI coding agent and Bitwarden Secrets Manager — the agent asks, a
> human's desktop decides, the vault never talks to the agent directly.

## Why this exists

I pay for Bitwarden and had Secrets Manager sitting there enabled and basically unused. The
official path to giving an AI coding agent access to it is Bitwarden's own MCP server — which
hands the agent direct, interactive read/write access to a whole vault. My agent already has an
unrestricted shell. Handing it full vault access on top of that felt like the wrong shape of
solution: more surface area, not less.

Bitwarden Secrets Manager's `bws run` command gets closer — it injects secrets straight into a
child process's environment without the calling process ever seeing the values. That solves
secret *value* exposure. It doesn't solve the bootstrap credential problem: something still has
to hold the `BWS_ACCESS_TOKEN` that authenticates to Bitwarden in the first place, and if that
something is the agent's own shell, an allowlist or an approval step is just policy on paper —
nothing stops the agent from calling `bws` directly.

So: a separate broker. It holds the bootstrap token. The agent never does. Every secret-using
command the agent wants to run goes through it, gated by a per-project allowlist, a human
approval prompt for anything not pre-approved, and an append-only audit log of every attempt —
approved or not.

Tools like this already exist (doppler, teller, chamber, 1Password's `op run`, Vault agent).
Building one anyway was the point — see [`decisions/`](decisions/) for the actual reasoning, not
just the result.

## What this demonstrates

- Secret *values* never pass through the broker's own process — `bws run` injects directly into
  the wrapped command's environment.
- The bootstrap access token never touches the agent's environment, and never sits in a plaintext
  dotfile — it's resolved on demand, per invocation, from the OS keyring (Secret Service), an env
  var, or a permission-checked file, depending on deployment target.
- Exact-argv allowlisting with no shell-string parsing — nothing to quote-escape, nothing
  ambiguous about what's allowed.
- A human desktop prompt (`kdialog`) gates anything not pre-approved. There is no bypass flag, on
  purpose — see [ADR-0002](decisions/0002-custody-broker-over-direct-agent-token-access.md).
- An append-only JSONL audit trail, written *before* the command runs and finalized after —
  borrowed from an earlier lab's [audit-before-forwarding pattern](#related-projects).
- Deny-by-default at every failure point: unknown project, missing config, a broken approval
  prompt, a failed token lookup — all hard denials, never an implicit approval.
- Fully interface-seamed (`Resolver`, `Approver`, `Runner`, `Logger`) so the entire decision
  matrix is unit tested against fakes — `go test ./...` needs no real Secret Service, `kdialog`,
  or `bws` present.

## Quick start

```bash
task build
cp policy.example.toml ~/.config/secrets-broker/policy.toml
# edit policy.toml: paste your BWS Secrets Manager project UUID
```

Store the bootstrap token yourself, interactively — never through the agent. This needs
`secret-tool` (`libsecret-tools` package): the native `kwallet-query -w` looks like the obvious
way to do this on KDE, but on kwallet6 6.24.0 it reports success while silently failing to
persist a new folder or entry — verified against the on-disk wallet file and KWallet's own D-Bus
API directly, not assumed (see [ADR-0006](decisions/0006-secret-service-over-kwallet-query-cli.md)).
`secret-tool` talks to the same underlying keyring via the standard Secret Service API and
round-trips correctly:

```bash
secret-tool store --label='secrets-broker: claude-code-agent' service secrets-broker entry claude-code-agent
```

It won't print a prompt — it's silently waiting on stdin. Paste or type the token, then press
Ctrl-D on its own line to signal end-of-input. (`secret-tool` reads everything up to EOF verbatim,
trailing newline included, if you leave one — `SecretServiceResolver` trims that on read, so it
doesn't actually matter either way, but Ctrl-D-terminated is the cleaner habit.)

Confirm it landed using the exact read path `secrets-broker` itself uses:

```bash
secret-tool lookup service secrets-broker entry claude-code-agent
```

Then:

```bash
./bin/secrets-broker run --project claude-code -- printenv TEST_SECRET_NAME
```

`--dry-run` resolves the policy decision (allow / would-prompt / deny) without touching Secret
Service, without invoking `bws`, and without writing an audit record:

```bash
./bin/secrets-broker run --project claude-code --dry-run -- git push
```

## Headless deployment

The desktop-only setup above uses `backend = "secret-service"`. For a systemd unit or container
with no desktop session, no D-Bus session bus, and nothing to render `kdialog` into, two other
`token_source.backend` values exist:

```toml
[token_source]
backend = "env"

[token_source.env]
var = "SECRETS_BROKER_BOOTSTRAP_TOKEN"
```

or

```toml
[token_source]
backend = "file"

[token_source.file]
path = "/run/secrets/bws-token"   # must be mode 0600 or tighter
```

Resolver-only, `KDialogApprover` still needs a live desktop session to render into —
`approval = "prompt"` or `"always"` on a headless box hangs or fails outright unless the remote
approver below is also configured. See [ADR-0007](decisions/0007-headless-env-and-file-resolvers.md).

### Remote approval (`secrets-broker-relay`)

`cmd/secrets-broker-relay` is a second binary — meant to run on a **separate, always-on device**,
never the same host as `secrets-broker` itself. Binding the broker's own machine to a tailscale IP
looks sufficient but isn't: a co-located process (the invoking agent) reaches that address directly
without ever crossing the tailnet. See [ADR-0008](decisions/0008-tailscale-relay-approver-design.md)
for that catch and why the fix is a separate device, and
[ADR-0009](decisions/0009-two-port-relay-protocol.md) for the actual protocol.

The relay exposes two ports — a **control port** (broker registers/polls) and a **decision port**
(the approving device submits approve/deny) — specifically so a Tailscale ACL policy can restrict
each to a different peer, with no application-level auth code at all. The decision port serves a
minimal tap-to-approve HTML page at `GET /requests/<id>` — no app or scripting needed on the
approving device, just open the link in any mobile browser and tap Approve or Deny. It also
accepts a plain JSON `POST /requests/<id>/decide` (`{"decision":"approve"|"deny"}`) for scripted
use, same endpoint either way.

```
secrets-broker-relay -control-addr <tailscale-ip>:7620 -decision-addr <tailscale-ip>:7621
```

Then point the broker's `policy.toml` at it:

```toml
[approval_source]
backend = "tailscale-relay"

[approval_source.tailscale_relay]
control_url = "http://<relay-tailscale-ip>:7620"
```

An example Tailscale ACL policy restricting each port to a different tailnet peer is in
[ADR-0009](decisions/0009-two-port-relay-protocol.md). **That ACL enforcement is the one piece not
verified from this environment** — the protocol and every code path have full test coverage
(including a real localhost round trip), but proving a Tailscale ACL policy actually restricts
port 7620 vs 7621 to different peers needs a real tailnet with two devices, which this environment
doesn't have. Treat that specific property as designed and implemented, not yet proven, until
checked against a real tailnet.

## Project structure

```
cmd/secrets-broker/       Composition root — wires real adapters together
cmd/secrets-broker-relay/ The approval relay — a separate binary, runs on a separate device
internal/
  cli/                 cobra plumbing only, no policy logic
  broker/               The orchestrator — the whole deny-by-default matrix lives here
  token/                Resolver interface + SecretServiceResolver, EnvResolver, FileResolver
  approval/             Approver interface + KDialogApprover, TailscaleApprover, RelayClient
  runner/               Runner interface + BWSRunner (shells out to `bws run`)
  audit/                 Logger interface + JSONLLogger
  policy/                Pure allowlist matching, no I/O
  config/                policy.toml loading and validation
  execx/                 Shared os/exec seam every adapter is built on
  relay/                 The relay's own store + HTTP handlers (used by cmd/secrets-broker-relay)
decisions/              ADRs — read before changing anything security-relevant
```

## Design decisions

| Decision | Rationale |
|---|---|
| CLI wrapper, not an MCP server | The agent already has an unrestricted shell; a structured tool-call schema adds surface area without removing it. [ADR-0001](decisions/0001-cli-wrapper-over-mcp-server.md) |
| A broker holds the token, not the agent | Otherwise the allowlist/audit/approval gate is just policy on paper — the agent could call `bws` directly. [ADR-0002](decisions/0002-custody-broker-over-direct-agent-token-access.md) |
| `Resolver`/`Approver` interfaces, KWallet-backed keyring/kdialog as v1's only implementation | This machine's KDE session is where v1 runs, not what the tool is defined by — a container/headless deployment is an additive implementation, not a rewrite. [ADR-0003](decisions/0003-pluggable-resolver-kwallet-as-v1-reference-impl.md) |
| `bws run` with explicit argv quoting and env construction | `bws` joins its command tokens and reparses them through a shell, and `--no-inherit-env` drops `HOME` with no way back — verified against `bws`'s own source before writing the adapter. [ADR-0004](decisions/0004-bws-run-for-injection-over-manual-export.md) |
| Exact-argv allowlist matching, no globs | A prefix match would let `["terraform","apply"]` also satisfy `terraform apply -destroy`. [ADR-0005](decisions/0005-exact-argv-allowlist-matching-no-globs.md) |
| Secret Service (`secret-tool`) over the native `kwallet-query` CLI | `kwallet-query -w` reports success while silently failing to persist, verified against the wallet file and D-Bus directly. [ADR-0006](decisions/0006-secret-service-over-kwallet-query-cli.md) |
| `env`/`file` Resolver backends for headless deployment | Secret Service resolution kept working all weekend without a human present — it was the desktop-only `Approver` that actually failed. The `Resolver` half of headless deployment was the tractable piece to fix first. [ADR-0007](decisions/0007-headless-env-and-file-resolvers.md) |
| Remote `Approver` design: relay on a separate device, not the broker's own host | A same-host listener bound to the tailscale interface doesn't stop the invoking agent from reaching it directly — that traffic never has to cross the tailnet at all. [ADR-0008](decisions/0008-tailscale-relay-approver-design.md) |
| Two relay ports, no application-level auth | Tailscale ACLs work at IP:port, not HTTP paths — splitting register/poll from decide onto separate ports lets ACLs alone decide who can approve, no new auth code. [ADR-0009](decisions/0009-two-port-relay-protocol.md) |
| No `--yes`/`--force` flag on `run`, ever | The agent is exactly the untrusted party the approval gate exists for. A bypass flag would make it theater. |

## Related projects

[`agentic-platform-lab`](../agentic-platform-lab) — this broker borrows its audit-before-forwarding
proxy pattern directly: write the audit record before doing anything else, finalize it once a
verdict is reached, so a crash mid-command leaves a detectable orphaned record instead of silence.

## License

MIT — see [LICENSE](LICENSE).
