# ADR-0011: Idempotent role installers and read-only checks

## Status

Accepted

## Context

The isolated deployment has more security-relevant host state than the three Go binaries. Worker
and runner accounts, group membership, ACLs, file ownership, sudoers syntax, systemd hardening,
and the two relay listeners must agree with the code's fixed paths. The original manual install
instructions made that state hard to reproduce and easy to check incompletely.

The worker host and relay device are separate trust zones. Token entry must stay in a trusted
operator terminal, and upgrades must not silently replace local policy or listener configuration.

## Decision

Ship separate root-run Bash installers for the worker host and relay device. Each installer has an
idempotent `install` mode and a read-only `check` mode.

The worker installer owns deterministic accounts, groups, fixed executable paths, private state
directories, the sudoers policy, and home-directory traverse ACLs. It installs an initial policy
only when none exists. It never creates or replaces the BWS access token. Its check validates the
deployment contract and reports token metadata without opening the token or invoking the worker.

The relay installer owns the binary, systemd unit, and initial listener environment. It preserves
an existing environment on every rerun. The first version accepts literal Tailscale IPv4 addresses
in `100.64.0.0/10` on the fixed split ports, then checks that the service is enabled, active, and
serving the decision dashboard.

CI exercises both installers on a fresh Ubuntu 24.04 runner, reruns them, and verifies that policy,
token, and relay environment contents survive unchanged.

## Consequences

Fresh deployments and upgrades now use the same checked path. A successful check gives a bounded
answer about host configuration without causing approvals, secret resolution, execution, or audit
writes.

Installation still needs root and explicit operator work for policy, token, Tailscale ACLs, and
relay addressing. IPv6 listener configuration is outside this first installer contract. Release
packaging must include the scripts and their adjacent policy files before installers can be used
from release artifacts alone.
