# ADR-0014: Attest release bundles with GitHub build provenance

**Status:** Accepted
**Date:** 2026-08-15
**Deciders:** Ross

## Context

Tagged releases publish SHA-256 checksums beside the Linux archives. A checksum detects corruption
or a mismatched download, but an attacker who can replace both files can make them agree. It does
not identify the repository or workflow that produced an archive.

Standalone release signatures and GitHub build provenance solve related but different operational
problems. Adding both in one change would make it harder to prove which trust path worked and would
introduce long-lived signing-key custody before that operating model has been chosen.

## Decision

The tag-only release job generates SLSA build provenance for both archives with GitHub artifact
attestations. `actions/attest` is pinned to an immutable commit, consumes the existing
`dist/checksums.txt`, and publishes one attestation containing both archive names and digests.

Only the release job receives `id-token: write` and `attestations: write`. Its existing
`contents: write` permission remains necessary to publish release assets. The action uses the
workflow's short-lived GitHub OIDC identity to obtain a Sigstore signing certificate and stores the
attestation with GitHub. Operators verify a downloaded archive against `R055LE/secrets-broker`
with a current GitHub CLI before extraction.

Standalone signatures remain a separate release-hardening decision. That later work must choose
the signing identity, long-lived key custody or keyless alternative, rotation and revocation, and
an offline verification path on its own merits.

## Consequences

- Verification cryptographically binds an archive digest to this repository's release workflow;
  replacing an archive and its checksum is no longer sufficient.
- Provenance identifies where and how the artifact was built. It does not prove the source,
  workflow, dependencies, or resulting binary are safe.
- Verification depends on the GitHub attestation API, GitHub's workflow identity, and Sigstore's
  trust roots. This tranche does not provide a GitHub-independent or offline trust path.
- Pull-request CI can review the workflow and rebuild the archives but cannot prove the tag-only
  attestation path. Acceptance requires verifying an archive from the first tagged release after
  this change merges.
