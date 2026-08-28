# ADR-0021: Version-pinned verified role upgrades

**Status:** Accepted
**Date:** 2026-08-27
**Deciders:** Ross

## Context

The worker and relay installers already make upgrades idempotent, preserve local state, and check
their deployed roles. Release archives have checksums and GitHub build provenance. The operator
still has to assemble download, verification, extraction, installation, and validation into a
large shell block for every release and on both devices.

Eight alpha releases proved the security path and also made its usability cost clear. Repeating
the block does not add assurance. It makes omissions, transcription errors, lost output, and
running the right command on the wrong role more likely.

The fleet-wide shape is recorded in the runbook's `playbooks/verified-release-consumption.md`.
Secrets Broker needs the archive and privilege-specific implementation of that contract.

## Decision

Release bundles ship `deploy/upgrade-release.sh`. Both role installers place it at the fixed,
root-owned `/usr/local/bin/secrets-broker-upgrade` path and their checks require the installed bytes
to match the bundle.

The operator runs one of:

```text
secrets-broker-upgrade worker vMAJOR.MINOR.PATCH
secrets-broker-upgrade relay vMAJOR.MINOR.PATCH
```

The worker form defaults the client account to the unprivileged invoking account and accepts an
explicit `--client-user` when needed. The public operator mode refuses root; only its fixed
privileged handoff mode accepts root. It uses a fixed system `PATH`, supports only Linux amd64 and
arm64, and fixes the repository and signer workflow in its own source. There are no repository,
workflow, installer, verifier, archive, or `latest` overrides.

For the requested tag and detected architecture, the helper:

1. creates a private temporary directory;
2. downloads the matching archive and `checksums.txt` with GitHub CLI;
3. requires the archive's exact checksum entry to pass;
4. requires exactly one provenance attestation matching `R055LE/secrets-broker`, the release
   workflow, `refs/tags/VERSION`, and a GitHub-hosted runner;
5. computes the archive digest before and after provenance verification and requires it to stay
   unchanged;
6. passes the archive path and bound digest through `/usr/bin/sudo` to the already installed,
   root-owned helper;
7. copies the archive into root-owned staging, recomputes and matches the bound digest, then
   extracts it;
8. invokes the bundled role installer and its read-only role check; and
9. compares every role binary and the installed helper with the root-owned verified bundle.

The privileged phase never performs network access and never executes or installs directly from
the operator-owned temporary directory. This closes the same-UID replacement window between
verification and installation.

The helper prints the verified release and role before sudo. A worker upgrade preserves the
existing policy, bootstrap token, and installed BWS binary through ADR-0011's installer. A relay
upgrade preserves the existing listener environment. The helper requires an existing deployment;
first installation, token entry, relay addressing, and Tailscale ACLs stay separate operator work.

The first release carrying the helper still needs the existing manual verified upgrade. That
upgrade installs the command used by later releases.

## Test contract

- Argument tests reject root execution, malformed versions, unsupported roles, and extra arguments
  before network or installation. Architecture selection permits only the two packaged targets.
- ShellCheck and Bash syntax checks cover the packaged helper.
- Packaged CI places a fake `gh` at the first fixed system path. It asserts the exact release
  download and attestation policy, then supplies the locally built release assets.
- A verification failure proves the helper never calls sudo or changes an installed binary.
- Privileged acceptance proves a changed user-owned archive cannot pass the root-owned digest
  handoff.
- Worker acceptance upgrades the existing CI deployment, preserves policy and token bytes, checks
  the installed role, and compares the CLI, administrator, worker, and helper bytes.
- Relay acceptance preserves the listener environment, restarts and checks the service, and
  compares the relay and helper bytes.
- Release bundle inspection requires the helper in both architecture archives.

## Consequences

- Routine upgrades become one short, role-explicit command while retaining every existing
  verification and preservation boundary.
- GitHub CLI, the GitHub attestation API, and Sigstore trust remain online upgrade dependencies.
- The helper can reinstall any explicitly named official release, including an older tag. It does
  not silently choose or order versions. Downgrade compatibility remains an operator decision.
- The existing installers are idempotent but not transactional. A failed install can require
  rerunning the same verified release or deliberately reinstalling an older verified bundle. This
  change does not claim automatic rollback.
- The privileged handoff binds bytes but does not independently prove the unprivileged provenance
  check occurred. It relies on the operator's existing general sudo authorization and must not be
  granted a narrow passwordless sudo rule. Such a rule would require independent authenticity
  verification inside the privileged phase.
- First installation remains longer because it establishes trust and has no installed helper yet.
