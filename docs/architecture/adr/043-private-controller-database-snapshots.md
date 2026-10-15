# ADR 043: Private controller database snapshots

Status: implemented and locally validated; application recovery remains incomplete.

## Problem

The existing local backup command checks a pathname, creates a SQLite output, then changes its permissions. That leaves output creation/publication outside an exclusive private staging boundary. It lacks a machine-readable artifact receipt. Database snapshots alone also cannot establish that a matching gateway configuration, scanner manifest or safe application restore exists.

## Decision

Open an existing owned SQLite file read-only and query-only, validate a consecutive known migration-checksum prefix, and refuse missing/empty/unknown state without creating or upgrading it. Recheck the captured artifact history before publication so a concurrent unsupported upgrade cannot bypass preflight. Use the already pinned modernc SQLite driver's online backup API. Pin a read transaction on the operator connection, copy in bounded page batches, and leave the running controller's WAL writer independent. Enforce a thirty-second context, 512 MiB snapshot limit and finite step budget. The command remains an operator-local facility; no public export endpoint or new Docker/admin socket is introduced.

Allocate a mode-0700 staging directory under an existing operator-owned parent without group/other write permission. Create its database file exclusively at mode 0600 before SQLite writes. Compact the isolated destination to remove deleted freelist content, validate `quick_check`, sync the file, and publish with a same-directory hard link that refuses an existing destination. Verify inode, ownership, mode and link count, remove staging and sync the parent. Handled failures remove owned staging; interrupted processes can leave private staging for later explicit recovery. Publication/directory-sync failure is an error, never a successful receipt.

Preserve `backup ABSOLUTE_FILE` and add `backup create ABSOLUTE_FILE [--json]` plus `backup --help`. A bounded receipt records the exact artifact digest/size and explicitly leaves gateway-configuration capture, tool-manifest capture and restore verification false. JSON Schema and generated bindings cover this restricted scope. Receipts contain no host paths or database contents and do not provide authenticity or independent sign-off.

## Validation

Challenge committed WAL state, concurrent writes, private intermediate/final modes, a late competing destination, existing files, symlinks/FIFOs, URI characters, cancellation and a subprocess file-size write failure. A deleted-content canary must exist in the source's free pages and be absent from the published snapshot. The native CLI harness uses only private synthetic state and runs within `make test`.

The draft page-copy implementation initially retained that deleted canary. Destination compaction corrects this before publication; the source is preserved. The online backup API supplies consistency while compaction preserves the previous vacuumed-output privacy behavior.

Observed evidence is recorded in `docs/evidence/database-snapshot-acceptance.json`: 84 repeated store/preflight/argument checks, eleven native CLI checks, nine packaged snapshot checks and 58 existing live regression checks pass. Actual native/packaged receipts pass the declared JSON Schema, including timestamp format checks; seven malformed/overstated variants are rejected. The deployed four-service image retains its privilege restrictions. A separate offline validation copy passes the audit-chain verifier while the original private snapshot hash and gateway policy remain unchanged. This increment does not complete GATE-11. A complete recovery bundle still needs matching gateway/policy/tool identities, tested offline preflight and restore, authority/session revocation, upgrade compatibility, crash/publication recovery and a complete disk-full/application-restore drill.

## Primary references

- [SQLite online backup API](https://www.sqlite.org/backup.html)
- [SQLite VACUUM and deleted-content removal](https://www.sqlite.org/lang_vacuum.html)
- The checksum-pinned modernc driver source used by `controller/go.mod`, especially `backup.go` and `conn.go`.
