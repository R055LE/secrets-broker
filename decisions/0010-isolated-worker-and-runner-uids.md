# ADR-0010: Isolate the worker and wrapped command under separate UIDs

**Status:** Implemented
**Date:** 2026-08-12
**Deciders:** Ross

## Context

The original CLI put policy and adapter logic in a separate process, but that process still ran as
the invoking agent's Linux user. That was process separation without a custody boundary. An agent
with an unrestricted shell could choose a different config or audit path, alter `PATH`, `HOME`, or
XDG variables, call `bws` directly once it found the token source, and inspect readable same-UID
process environments through `/proc`.

Moving only the broker to a service account was still incomplete. If the approved command ran as
that same account, a hook, plugin, or config file controlled by the agent could make it read the
bootstrap token file or rewrite the audit log.

The practical options were a daemon and authenticated socket, a setuid binary, a container or VM
boundary, or a short-lived worker launched through a fixed sudoers rule. The workflow is
predominantly CLI-driven and low-volume, so a resident service and protocol authentication would
add machinery without improving the local UID boundary.

## Decision

Use three Linux identities:

1. The agent-facing `secrets-broker` CLI runs as the caller. It has no credential or policy
   adapters. It resolves cwd and sends one JSON request, capped at 64 KiB.
2. `/usr/local/libexec/secrets-broker-worker` runs as `secrets-broker` through an exact sudoers
   command with no arguments. It uses fixed config and audit paths, validates sensitive file
   ownership and modes, resolves the bootstrap token, obtains remote approval, and invokes the
   root-owned `bws` binary with a trusted environment.
3. The approved command runs as `secrets-broker-runner`. `bws` removes its bootstrap token before
   spawning the runner-side sudo hop, and `--no-inherit-env` clears the rest of the worker runtime
   environment. A worker-scoped `env_keep` rule lets that already-cleared BWS environment cross
   the hop on both sudo-rs and classic sudo. The command rule is `NOSETENV`, so the worker cannot
   add command-line environment assignments. The runner cannot read the worker-owned token or
   audit directory.

The worker accepts only the file token backend and Tailscale relay approval. Caller-controlled
config, audit, executable, desktop session, keyring, and environment-token selection are rejected.
The policy fixes the `bws` path, runtime `PATH` and `HOME`, exact project cwd, and exact allowlisted
argv. Dry runs use the same worker and fixed policy.

The relay remains a separate-device boundary. It now also bounds request bodies and in-memory
state, validates IDs and listen addresses, sets server timeouts, and hardens the browser response.

## Consequences

**Positive**

- The caller cannot replace policy or audit destinations, read the bootstrap token, inspect the
  secret-bearing runner environment through same-UID `/proc`, or call the worker with hidden
  adapter overrides.
- A wrapped command cannot read the bootstrap token or alter the audit log, even if its normal
  behavior is influenced by agent-controlled files.
- The deployment stays ephemeral and CLI-driven. There is no daemon lifecycle, socket ownership,
  or application authentication protocol to operate.

**Negative**

- Installation requires two system users, one client group, two sudoers edges, root-owned
  executables and policy, and carefully provisioned file permissions.
- Commands execute as `secrets-broker-runner`, not as the invoking user. Project permissions and
  tool configuration must account for that identity.
- The nested sudo hop must preserve arbitrary BWS project secret names. Its `env_keep = "*"` scope
  is limited to the worker account, after `bws --no-inherit-env` has removed the worker runtime
  environment and bootstrap token. The command itself is tagged `NOSETENV`.
- BWS injects environment variables before starting its command shell. Secret names are trusted
  deployment data and must not be control variables such as `LD_PRELOAD`, `BASH_ENV`, or `PATH`.
- Exact argv and cwd do not authenticate agent-writable hooks, plugins, providers, scripts, or
  config files. Security-sensitive operations still need root-owned wrappers that disable or
  validate those extension points. Human approval shows argv and cwd, not the full filesystem
  state that will influence execution.
- Root, the two service accounts, the root-owned binaries and policy, Bitwarden, and the separate
  relay device remain trusted. This is a local least-privilege boundary, not isolation from a
  hostile administrator or kernel.
