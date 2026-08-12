# ADR-0006: Secret Service (`secret-tool`) over the native `kwallet-query` CLI

**Status:** Superseded for deployment by [ADR-0010](0010-isolated-worker-and-runner-uids.md).
Secret Service remains a legacy adapter, but the isolated worker accepts only a service-owned file.
**Date:** 2026-08-01
**Deciders:** Ross

## Context

ADR-0003 chose KWallet as v1's token store and `kwallet-query` as the CLI to talk to it — reads
via `kwallet-query -r`, with the setup docs telling operators to write the bootstrap token via
`kwallet-query -w`.

`kwallet-query -w` doesn't actually work on this machine (kwallet6 6.24.0). It reports exit 0 —
apparent success — but the write never persists: verified by checking the on-disk wallet file's
mtime (unchanged across multiple write attempts) and by reading the entry back in a fresh process
immediately after, which failed with "folder does not exist." This wasn't limited to creating a
new folder either — writing into a folder that already existed (created via direct D-Bus calls to
`org.kde.KWallet.createFolder`) also silently failed to persist via `kwallet-query -w`. Reads
(`kwallet-query -r`) and listing (`kwallet-query -l`) both work correctly — this is specifically a
broken write path in that one CLI tool, not a broken wallet or a permissions/D-Bus-session
problem (`kwalletd6` was confirmed running, the D-Bus session bus was correctly set, and the
wallet was confirmed open via `isOpen`).

This left the project's own setup instructions non-functional as written — a real bug, not a
documentation nit, since anyone following the README's Quick Start would hit exactly the failure
this ADR's author hit.

KDE's `kwalletd6` also implements the freedesktop Secret Service D-Bus API (the same standard
GNOME Keyring implements) as a compatibility layer over the same underlying wallet storage.
`secret-tool` (from `libsecret-tools`) is the standard CLI for that API. Verified empirically,
store-then-read in separate process invocations, exactly the same test that caught the
`kwallet-query -w` bug: `secret-tool store` and `secret-tool lookup` both persist and round-trip
correctly. `secret-tool clear` also works, which `kwallet-query` doesn't offer at all (no delete
capability).

One real difference: `secret-tool`'s writes did not appear in `kwallet-query -l kdewallet`'s
folder listing — Secret Service's flat, attribute-tagged model doesn't map onto KWallet's
native folder/entry concept the way `kwallet-query -f <folder>` expects, even though both are
ultimately served by the same `kwalletd6` process. This means reads and writes have to go through
the *same* API consistently — mixing `kwallet-query -r` reads with `secret-tool store` writes (or
vice versa) would silently look in the wrong place.

## Decision

Replace the KWallet-native `Resolver` (`kwallet-query`) with a Secret-Service-based one
(`secret-tool`), for both the resolver's reads and the setup instructions' writes. Concretely:
`internal/token/kwallet.go` → `internal/token/secretservice.go`, `KWalletResolver` →
`SecretServiceResolver`, config's `[token_source.kwallet]` sub-table (with `wallet`/`folder`
fields) → nothing — Secret Service has no folder concept, so `token_entry` alone plus a fixed
`service=secrets-broker` attribute (in `secretServiceAttr`) is enough to namespace and look up an
entry. `token_source.backend` changes from `"kwallet"` to `"secret-service"`.

This was a same-day, contained swap specifically because ADR-0003 already isolated the storage
backend behind the `Resolver` interface — `broker.go` didn't change, `broker_test.go` didn't
change (it only referenced the config's `Backend` string, not the concrete adapter), only
`internal/token/*`, `internal/config/config.go`, and `internal/cli/run.go`'s composition-root
wiring changed.

## Consequences

**Positive**
- The project's own setup instructions now work as written — verified end-to-end: `secret-tool
  store` a throwaway token, `secrets-broker run` resolved it via `SecretServiceResolver` and
  successfully invoked `bws` with it (which then failed on its own, on an intentionally-fake
  project ID — proving the resolver → runner handoff works, independent of having a real Bitwarden
  account yet).
- Secret Service is a freedesktop standard also implemented by GNOME Keyring, not just KWallet —
  this resolver is less desktop-environment-specific than its predecessor, incidentally moving a
  step toward the portability goal ADR-0003 already cared about, though it still needs *some* live
  desktop keyring and isn't the container/headless answer on its own.
- `secret-tool` supports deletion (`clear`), which `kwallet-query` doesn't — a minor but real
  operational improvement for anyone rotating or removing a stored token.

**Negative**
- This is now the second time this project depended on undocumented, empirically-verified CLI
  behavior rather than trusting `--help` text or assuming a tool works as named (ADR-0004 hit the
  same category of surprise with `bws run`). Worth treating as a pattern: verify the actual
  persistence/behavior of any credential-handling CLI before writing setup docs or adapter code
  against it, not just its documented interface.
- Reads and writes must go through Secret Service consistently now — an operator (or a future
  contributor) reaching for `kwallet-query -r` out of habit, because it "should" see what
  `secret-tool store` wrote, will be looking in the wrong namespace. Worth a comment at the call
  site (see `internal/token/secretservice.go`) rather than assuming this is obvious.
