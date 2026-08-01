# ADR-0007: `env` and `file` Resolver backends for headless deployment

**Status:** Accepted
**Date:** 2026-08-02
**Deciders:** Ross

## Context

v1 shipped with exactly one `Resolver`: Secret Service, requiring a live desktop session (KWallet
or GNOME Keyring, a D-Bus session bus, PAM-unlocked at login). That's a real constraint on where
the broker can run, surfaced concretely rather than theoretically: an approval request got stuck
mid-weekend because the person who needed to click `kdialog` had physically left the machine.
Working through that incident separated two different problems wearing one name. Secret Service
resolution kept working the whole weekend — the desktop session was still logged in, the keyring
stayed unlocked, nothing about *token resolution* required anyone present. It was `KDialogApprover`
that failed, because it needs a human watching a screen at the moment of the prompt, not just a
live session.

That distinction mattered for scoping this decision. A true headless deployment — a server with no
display, no login manager, no D-Bus user session, no keyring daemon *to* unlock — breaks both
pieces completely, not just the interactive one. But they fail for different reasons and need
different fixes. The `Resolver` half is the tractable one: a headless process still needs to
receive its bootstrap token from *somewhere*, and servers already have established conventions for
that. The `Approver` half needs an actual remote communication channel with its own authentication
story — a bigger, separate design problem, deliberately not addressed here.

## Decision

Two new `Resolver` implementations, `EnvResolver` and `FileResolver`, both in `internal/token`,
alongside `SecretServiceResolver`. `EnvResolver` reads a single configured environment variable —
matching how `bws` itself already natively reads `BWS_ACCESS_TOKEN`, and how a systemd unit or
container typically receives exactly one injected secret. `FileResolver` reads a single configured
file path — the Docker-secrets/Kubernetes-Secret-volume convention, usually tmpfs-backed — and
refuses to read a file more permissive than `0600` (not group- or world-readable), since a plain
file has only filesystem permissions defending it, unlike Secret Service's daemon-mediated access.

Both ignore the `entry` parameter `Resolver.Resolve` takes. This is a deliberate single-tenant
assumption: a headless deployment using either backend is assumed to be one broker process, one
token — matching how a container or systemd unit is typically scoped to one purpose. Multi-entry
resolution at runtime stays Secret Service's job.

`config.TokenSource.Backend` gains two new valid values (`"env"`, `"file"`) alongside
`"secret-service"`, each with its own optional sub-table (`[token_source.env]`,
`[token_source.file]`) — additive to the schema, exactly as ADR-0003 intended. Selection happens in
`internal/cli/run.go`'s `newResolver`, a small switch at the composition root; `broker.go` is
untouched.

**Explicitly out of scope for this ADR:** any headless `Approver`. Building one requires a real
remote channel (webhook, chat bot, push notification) and, more importantly, an actual
authentication scheme for who's allowed to approve a pending request remotely — a new trust
boundary that doesn't exist yet, not a port of an existing one. That's deliberately deferred to a
dedicated design session rather than bundled in here just because it was adjacent.

## Consequences

**Positive**
- The broker can now run as a systemd service or in a container with `approval = "never"` or
  pre-populated allowlists, without any desktop session at all — the actual headless deployment
  target this project was always aimed at, not just the interactive-desktop case v1 shipped with.
- Verified end-to-end against the real Bitwarden project, not just unit tests: both backends
  successfully resolved the real token and injected it via `bws run`; the file backend's permission
  check was confirmed to actually deny resolution when the file was loosened to `0644`.
- Zero changes to `broker.go` or its test suite — the interface boundary did exactly what ADR-0003
  argued it would.

**Negative**
- Headless deployment still has no answer for the approval half. A broker configured with
  `approval = "prompt"` or `"always"` on a truly headless box will hang or fail outright, since
  `KDialogApprover` can't render anywhere — headless deployments need `approval = "never"` plus a
  tight allowlist for now, which is a real usability gap until the remote `Approver` exists.
- `EnvResolver`/`FileResolver`'s single-tenant assumption means a headless box wanting multiple
  distinct tokens for multiple projects isn't supported by either backend as built — not a
  rejected feature, just not a demonstrated need yet.
