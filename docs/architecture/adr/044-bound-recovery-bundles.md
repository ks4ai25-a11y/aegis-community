# ADR 044: Bound private recovery bundles and authority-safe offline restore

Status: implemented for the schema-13 reference demo; broader recovery release acceptance remains open.

## Decision

Extend the database-only snapshot primitive with operator-local `backup bundle`, `backup verify` and confirmed `backup restore` commands. Bind a compacted consistent database snapshot to its exact active policy, persisted reference gateway rendering and independently trusted six-tool scanner lock. Refuse unknown schema/profile, policy apply uncertainty, invalid full SQLite integrity/audit/foreign-key state, unrecognized configuration, noncanonical manifests, altered artifacts and unexpected directory entries. No web export endpoint or engine socket is added to the controller.

Use fresh private directories, exclusive files, bounded reads/copies, owned regular single-link artifacts and a lifetime advisory lock. Publish the canonical manifest last. Restores require the exact bundle digest before destination allocation and cannot overwrite or target the bundle. A fresh destination contains a pending marker that normal controller and snapshot opening refuse. One database transaction invalidates restored authority and appends a mandatory audit event; an audit failure rolls back the operation. Preserve immutable evidence and scanner cleanup uncertainty. Sync the completed data/configuration and receipts before clearing quarantine. No command activates services, attests publisher signatures or claims application verification.

The supported profile is deliberately exact: current product, schema 13, reference HTTP demo upstream/listener/admin/event paths. This avoids silently restoring unrelated gateway settings under a digest-only claim. Historical-prefix database-only snapshots remain available; recovery bundles require current schema. A future profile or migration requires explicit compatibility tests and a separate reviewed specification.

## Validation and correction

Unit tests challenge configuration drift, pending applies, bad audit/schema/tool identities, corruption, unknown members, symlinks/FIFOs/hard links, permissive modes, concurrent locks, incomplete manifests, confirmation and destination restrictions, authority invalidation, cleanup holds, rollback on audit failure and quarantine enforcement. Native CLI proof checks unchanged source/bundle bytes, installed database digest, copied configuration and refused authority/corruption cases. The isolated application drill destroys only its disposable database volume, preserves gateway serving, restores the captured database, rejects pre-backup sessions, accepts fresh owner login and checks inventory, cancelled scans and gateway revision.

An initial draft drill reused resource names emitted by Compose's resolved configuration. That attempt stopped before database destruction but temporarily shared demo socket volumes. The original gateway continued HTTP serving; restarting its existing deployer/verifier and gateway restored readiness. The corrected harness removes resolved resource names, validates every effective name against its unique project before startup or cleanup, rejects external/shared resources and checks volume labels before destruction. Pure refusal tests cover the namespace boundary. The corrected application drill passes and the original demo's readiness is separately checked.

Observed final validation: full `make test` and controller `go vet` pass; 72 race-detector recovery test events across three repetitions, ten native CLI checks, three namespace tests and six isolated application checks pass. Eight actual contract payloads validate with timestamp checks; ten malformed or overstated variants are rejected. The updated named demo passes readiness and private bundle creation/verification using the existing operator init service; no new web-controller volume access is granted. Detailed metadata is in [recovery evidence](../../evidence/recovery-bundle-acceptance.json).

## Limits

This is a single-engine synthetic reference drill, not second-clean-machine recovery, signed archive provenance, encrypted backup, full disk-loss recovery, arbitrary deployment restore or an independent security review. Crash remnants remain quarantined for explicit inspection; automated repair is absent. GATE-11 and public-beta readiness remain incomplete. No automatic scanner dispatch release is introduced. See the operator guide and recorded evidence for exact scope and observed checks.
