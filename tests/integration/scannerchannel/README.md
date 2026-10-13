# Private scanner channel integration

Run `go test -race ./...` here, or `make test` at the repository root. This test-only module connects the real alpha client to the real controller registry, migrated SQLite queue and private Unix HTTP handler. It introduces no production alpha/controller module dependency.

Fixtures use fresh owned temporary state, credential files and sockets. They never launch repository code, scanner containers or other host services. The five-second lease-keeper test revokes a real enrollment and verifies cancellation, task join and retained admission. This is component interoperability evidence; deployed worker execution, result ingestion and cleanup release need separate acceptance. See ADR 026.
