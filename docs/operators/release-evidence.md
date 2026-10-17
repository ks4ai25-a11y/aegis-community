# Release supply-chain evidence

`scripts/release/release_evidence.py` produces the evidence a buyer or auditor needs to know what a release contains (release gate GATE-10). It costs nothing to run: every tool is local or a digest-pinned image, and no paid signing or transparency service is used.

```bash
python3 scripts/release/release_evidence.py [--sign-key ~/.ssh/aegis-release] [--tag TAG] [--allow-dirty]
```

Run it from a clean checkout of the release commit. It refuses a dirty tree unless `--allow-dirty` is given, and records `working_tree_clean` either way.

## Output: `dist/release-<commit12>/`

| File | Content |
|---|---|
| `gateway.cdx.json`, `controller.cdx.json`, `demo-origin.cdx.json` | CycloneDX SBOM of each built image, made by the pinned Syft image with `--network none`, read-only root and no capabilities, from a `docker save` archive (the archive's SHA-256 is recorded, the archive is deleted) |
| `console-npm.cdx.json` | SBOM of the console's npm dependencies (its JavaScript is compiled into the controller image, so the image SBOM does not list them) |
| `bin/aegisctl-*`, `bin/aegis-mcp-*`, `bin/aegis-scanner-db-*` | CLI binaries for linux/amd64, linux/arm64 and darwin/arm64, built with `-trimpath -buildvcs=false -ldflags=-buildid=` and `CGO_ENABLED=0`. Each is built twice; `rebuild_identical` records whether both builds matched |
| `THIRD_PARTY_LICENSES.txt` | Licence and NOTICE texts of every shipped Go module (from the local module cache, plus the Go licence) and every production npm package, and a note on Alpine OS packages |
| `release-manifest.json` | Source commit, toolchain versions, pinned base images, image IDs, archive and SBOM digests, binary digests, licence counts, copyleft identifiers for review, limitations |
| `SHA256SUMS` | SHA-256 of every file above |
| `SHA256SUMS.sig` | Only with `--sign-key`: an OpenSSH signature, namespace `aegis-release` |

## Verifying a release

```bash
shasum -a 256 -c SHA256SUMS
```

```bash
ssh-keygen -Y verify -f allowed_signers -I <publisher identity> -n aegis-release -s SHA256SUMS.sig < SHA256SUMS
```

`allowed_signers` holds one line, `<publisher identity> <public key>`, published by the vendor through a channel the customer trusts.

## Licences

Every component is identified either from package metadata reported by Syft or from the module's own licence file (Go modules often carry no metadata). `copyleft_identifiers_for_review` lists identifiers that need a decision before distribution. For the current images these are unmodified Alpine OS packages (GPL-2.0-only: busybox, apk-tools, alpine-baselayout, scanelf, ssl_client; musl-utils), `ca-certificates` (MPL-2.0 AND MIT) and `github.com/go-sql-driver/mysql` (MPL-2.0, linked through Caddy's ACME server storage, unmodified). This is an inventory, not legal advice.

## Limitations

- No publisher key exists yet. The recorded evidence was signed with a throwaway test key to prove the signing and verification path.
- No SLSA provenance attestation or transparency-log entry is produced.
- Image IDs are not claimed reproducible. CLI binaries rebuild identically on the same host; cross-host reproducibility is not yet tested.

Recorded run: `docs/evidence/release-supply-chain.json`.
