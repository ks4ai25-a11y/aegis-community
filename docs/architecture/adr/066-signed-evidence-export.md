# ADR 066: Installation-signed evidence export

Status: implemented; unit-tested and validated on a local stack with offline verification.

## Problem

Verification reports carried a self-digest, which detects accidental change but lets anyone who edits a report recompute it. The v4 proof contract (D7) allows an optional signature from a local key, and the Frontier plan (C7) needs Community-originated evidence that an external verifier can check.

## Decision

On first start the controller creates an Ed25519 key as a 32-byte seed in `AEGIS_DATA/evidence-signing.key` (exclusive create, mode 0600; a group- or world-readable key is refused). `GET /api/v1/evidence/key` publishes the scheme, a key ID (first 16 hex digits of the public key's SHA-256) and the public key. `GET /api/v1/verify/reports/{digest}/signed` returns an owned report wrapped in an envelope: scheme `aegis-evidence-ed25519-v1`, key ID, public key, document digest, signature over `aegis-evidence-v1\0` + digest, the document and a note that a signature proves origin and integrity, not truth. Exports are audited. `aegisctl report verify FILE [--key KEY_ID_OR_PUBLIC_KEY]` verifies envelopes offline (scheme, key/ID consistency, optional pinning, signature, and that the document's canonical digest equals the signed digest) and still verifies unsigned reports' self-digest. The console Report panel adds **Export signed evidence**.

## Consequences

- The key lives on the controller's data volume. Database snapshots and recovery bundles do not include it, so a restored installation signs with a new key; earlier exports remain verifiable with the earlier public key, which owners should record.
- A host administrator who can read the data volume can sign as the installation; hardware-backed keys are a Frontier capability.

## Validation

Evidence tests cover persistence, private mode, pinned and untrusted keys, tampered documents, key-ID mismatch and a world-readable key. On a local stack an exported report verified offline with and without pinning; a tampered copy and a wrong pinned key were rejected; the key ID was unchanged after a controller restart.
