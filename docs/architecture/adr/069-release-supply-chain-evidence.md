# ADR 069: Release supply-chain evidence

Status: implemented and run from a clean commit; no publisher key yet.

## Problem

GATE-10 requires SBOMs, provenance and notices. Acquirers and enterprise buyers ask for an SBOM per artifact, licence texts and a way to check that downloaded artifacts are the ones the vendor built. The Community edition must provide this without paid services.

## Decision

`scripts/release/release_evidence.py` builds the images and CLI binaries from a clean checkout and writes `dist/release-<commit12>/`:

- CycloneDX SBOMs per image from the digest-pinned Syft image (already in `tools/scanners.lock.json`), run with no network against `docker save` archives, plus an SBOM of the console's npm lock file.
- Licence identification from SBOM metadata, falling back to each Go module's licence file in the local module cache; copyleft identifiers are listed for review.
- `THIRD_PARTY_LICENSES.txt` with the licence and NOTICE texts of every shipped Go module and production npm package.
- CLI binaries for three platforms, each built twice and compared.
- A manifest binding the source commit, toolchain, pinned base images, image IDs and all digests, then `SHA256SUMS` and an optional OpenSSH signature (`ssh-keygen -Y sign`, namespace `aegis-release`).

OpenSSH signatures were chosen over Sigstore keyless signing because they work offline, need no account, and every customer already has the verifier. Frontier releases can add Sigstore/SLSA provenance in CI without changing the layout.

## Validation

`docs/evidence/release-supply-chain.json` is written by the script itself (`--evidence-out`), not by hand. Every check is run from the artefacts on disk:
- clean tree at the recorded commit;
- every component has a licence identifier or licence file;
- every shipped Go module and npm package has licence text;
- all nine CLI binaries rebuilt byte-identical with an empty Go build cache;
- `SHA256SUMS` re-hashed from disk;
- the SSH signature verifies with the run's key;
- an edited `SHA256SUMS` is refused.

The recorded run used a throwaway test key. The per-release `release-checks.json` sits beside the signed set.

## Limitations

No publisher key, provenance attestation or transparency log; images are not claimed reproducible; cross-host binary reproducibility is untested (same-host rebuilds use an empty build cache); the licence inventory is not a legal review.
