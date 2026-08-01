# ADR-0003: Pluggable `Resolver`/`Approver` interfaces, KWallet/kdialog as v1's reference impl

**Status:** Accepted — the interface-pluggability decision below still stands and is exactly what
made [ADR-0006](0006-secret-service-over-kwallet-query-cli.md) a same-day adapter swap instead of
a rewrite. The specific claim that `KWalletResolver` wraps `kwallet-query` is superseded by
ADR-0006 — see there for why.
**Date:** 2026-07-31
**Deciders:** Ross

## Context

The bootstrap token has to live somewhere the broker can read it. Options considered for where:

1. **Plaintext dotfile export** (`export BWS_ACCESS_TOKEN=...` in `~/.bashrc`). Rejected outright —
   this is exactly the anti-pattern the project exists to avoid, and worse, dotfiles are commonly
   synced/backed up, multiplying the exposure.
2. **A second secrets manager** to hold the first one's bootstrap credential. Circular — doesn't
   actually solve the problem, just moves it.
3. **Hosting infrastructure** (Vault, a custom broker daemon holding it in memory behind a socket).
   Real added infrastructure for a single-user, single-machine v1 — disproportionate.
4. **OS keyring**, queried on demand. Encrypted at rest, no infrastructure to host, and on this
   machine specifically — KDE Plasma with `kwallet6` and PAM integration already installed — it
   auto-unlocks with the login session, so there's no extra unlock step in practice.

Separately: the first draft of this design leaned on KWallet (for token storage) and `kdialog`
(for approval prompts) as if they were the architecture, not an implementation detail — the config
schema had a top-level `[kwallet]` section, the per-project field was named `kwallet_entry`, and
`CLAUDE.md`/README language treated "Linux/KDE-only" as a permanent property of the tool. That's
wrong for the actual goal: this machine's KDE desktop is where v1 happens to run today, not a
permanent constraint. An eventual distroless container deployment has no desktop session, no
D-Bus, no KWallet daemon, and no `kdialog` — token resolution and approval need to be swappable
without a rewrite when that day comes.

## Decision

`internal/token.Resolver` and `internal/approval.Approver` are the stable interfaces
`internal/broker/broker.go` depends on. v1 ships exactly one implementation of each — a
KWallet-backed `Resolver` and `KDialogApprover` (wraps `kdialog --yesno`) — because that's what
this machine has today, not because the architecture assumes a desktop forever. (The KWallet
`Resolver`'s exact implementation changed after this ADR was written — see ADR-0006 — but which
CLI tool it shells out to is exactly the kind of detail this interface boundary was meant to make
swappable without touching `broker.go`.) The
config schema reflects this: `[token_source]` / `backend = "kwallet"` is a named, swappable
section, and the per-project field is the backend-agnostic `token_entry`, not `kwallet_entry`. A
container/headless deployment needs a new `Resolver` (env var injected by the orchestrator, or a
mounted secret file) and a new `Approver` (webhook, chat-bot prompt) — additions behind these
interfaces, not changes to `broker.go` or the config schema.

## Consequences

**Positive**
- No hosting infrastructure for v1; the token is encrypted at rest and auto-unlocks with the
  existing login session.
- `broker.go` and its full test suite (`broker_test.go`) never import `kwallet.go` or `kdialog.go`
  directly — they're proven against fakes, which is exactly what makes the container-path addition
  later a new adapter, not a broker rewrite.
- The config schema doesn't need to change shape when a second backend is added — a new
  `[token_source.<backend>]` block is additive.

**Negative**
- v1 genuinely only runs where KWallet and an active KDE desktop session exist — a real, documented
  limitation, not hand-waved. `KDialogApprover` in particular has no fallback; a broken or missing
  desktop session is a hard deny (see `internal/approval/kdialog.go`), not a degraded prompt.
- The container/headless path is real future work, not fully designed yet — Phase 2, tracked in the
  README's deferred list, not built now.
