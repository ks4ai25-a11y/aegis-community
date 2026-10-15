# ADR 042: Journaled scanner engine lifecycle

Status: implemented as an experimental operator backend; no cleanup admission release.

## Problem

A Docker CLI process exit or an absence query cannot establish that a daemon-side create/start request has finished. An interrupted request can leave an unknown outcome. The existing worker/observer path therefore cannot authorize reusable scanner admission.

## Decision

Add an explicitly selected operator execution backend using the checksum-pinned official Moby Go SDK, with an explicit local Unix endpoint and fixed API version. Preserve the fixed scanner image/guard/argv, network-none, non-root, read-only, capability/resource/logging and private snapshot constraints. Do not read proxy/endpoint configuration from ambient SDK environment variables. Do not expose a general Docker API or mount its socket in the public controller.

Persist private bounded write-ahead intent before create/start/remove. Observe complete daemon responses independently of tool exit codes. Any mutation whose response cannot be established remains unresolved across cancellation, crashes and restart; an absence observation cannot erase it. Unrecognized/torn journals and capacity exhaustion refuse new mutation. A lifetime kernel lock excludes concurrent writers in the selected journal namespace. Persistent records contain opaque identity/config digests, not credentials, host paths or raw scanner output.

Use the normal bounded HTTP transport for the fixed attach upgrade (the SDK raw-hijack path does not preserve this custom transport). Attach stdout/stderr before start, bound each multiplexed stream and close/join receivers on cancellation. Register a next-exit wait before start, using the SDK's acknowledged wait registration, so auto-removal cannot race away the exit result. Cleanup targets only the exact randomly named resource, with independent bounded context and response tracking. A read-only removed-state wait follows a known exit before DELETE so asynchronous AutoRemove does not race it into a 409 response. A 409/incomplete mutation response stays quarantined. The existing absolute-deadline guard remains mandatory.

The SDK backend is an operator facility while service integration is completed. Its journal is not independently authenticated cleanup evidence and does not exclude callers bypassing this backend. Observer/worker role separation, controller-provisioned gate binding, dedicated deployment, registry/lease exclusion, incomplete allocations and separately authorized atomic release remain required. Existing dispatch holds remain held; no journal status or local worker claim grants release.

## Validation

Inject delayed responses that outlive caller cancellation, truncated/oversized bodies, unexpected status and malformed container IDs; prove unresolved state persists and prevents new writes. Challenge directory/symlink/FIFO/torn records, concurrent writers, limits, stream framing/size, cancellation joins and exact-resource ownership. Exercise pinned scanner images on the actual local engine and compare existing normalized evidence and sandbox metadata. Never stop/remove unrelated containers.

These challenges pass in the recorded local evidence. A SIGKILL helper proves that an unresolved intent survives process death while its kernel lock releases. Six actual pinned scanner attempts retain four completed static adapters, one stale-database classification and one unavailable-database error; controller admission remains held. Native scanner/status CLI and an already-expired guard pass. An independently read stopped SDK container matches the fixed sandbox and mounted-byte expectations. See `docs/evidence/scanner-engine-journal-acceptance.json` for exact observed classifications and source identities.

The status command reads only an existing namespace and refuses to create/repair missing metadata. Local observations always leave controller binding, exclusive mediation and cleanup-release authority false.

## Primary references

- [Docker SDK examples](https://docs.docker.com/reference/api/engine/sdk/examples/)
- [Moby Go client v0.6.2](https://github.com/moby/moby/tree/client/v0.6.2/client)
- [Container wait registration](https://github.com/moby/moby/blob/client/v0.6.2/client/container_wait.go)

Documentation and module checksums are implementation references, not independent security or publisher-signature sign-off. Arbitrary repository/patch execution still requires the v4 D6 disposable VM/isolated-host boundary.
