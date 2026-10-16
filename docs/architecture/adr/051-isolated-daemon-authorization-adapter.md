# ADR 051: Native authorization adapter for an isolated scanner daemon

Status: experimental; full broker deployment and independent cleanup authority remain unfinished.

## Decision

Use Docker's existing native authorization plugin interface as the first daemon-side enforcement layer. A dedicated `aegis-engine-authz` binary serves only Docker's activation, request and response callbacks on an owned mode-0600 Unix socket under an owned canonical mode-0700 directory. It opens no engine connection. The daemon must supply a verified TLS principal: `aegis-engine-broker` or `aegis-engine-observer`. Empty, unknown, admin and non-TLS principals are denied. The plugin is never enabled on the workstation daemon, retained demo or default Compose profile.

An exact API 1.55 allowlist supports fixed pinned image inspection, engine info, the current tracked container's inspection and exact name-filtered list. The observer cannot write. The broker may create the existing static scanner profile, attach output without stdin, wait for next exit/removal, start once and remove its exact returned full container ID. Pull/build/exec/plugin/network/prune/general list APIs and alternative versions, encoded paths, extra/duplicate queries and arbitrary IDs are denied. Unrecognized operations default to denial.

Extract the common static scanner profile into `alpha/engineprofile` and use it from SDK creation and policy evaluation. The isolated authorization profile disables daemon auto-removal and requires an explicit tracked DELETE 204; the existing unmediated SDK experiment retains its original auto-removal behavior. The policy checks complete typed Docker request semantics and the exact JSON object shape. It rejects duplicate/case/Unicode-fold aliases, invalid UTF-8, unknown or omitted fields, null safety fields, excessive nesting, trailing data and bounded body violations. Allowed creation requires the pinned tool image, non-root configured user, guard entrypoint, at most 120 seconds per tool and an original absolute deadline at most fifteen minutes ahead, fixed environment, no stdin/TTY, read-only root and mounts confined to the canonical work root, network none/private IPC, all capabilities dropped, no-new-privileges, no logs, and the existing memory/CPU/PID/tmpfs limits. Create bodies must be visible JSON; opaque/non-JSON creation is denied.

## Mutation uncertainty

The plugin owns a separate private durable `enginejournal` namespace, outside the broker work root. Initialization is explicit and empty-only; serving uses existing-only open and retains its lifetime lock. Before an allow response for create/start/remove, it fsyncs an intent. A matching response callback must carry a complete successful response and exact returned container ID. Docker can invoke response authorization before serializing handler errors: the client may receive a 404 while the callback has no usable error status/body. Such a callback never confirms removal. The isolated profile therefore keeps the child after exit until an explicit DELETE succeeds with 204. A later response-phase denial cannot undo the engine write. Create/start/remove responses are paired to the original principal/method/URI/body. Failed, missing, truncated, mismatched or oversized mutation responses leave the journal quarantined. A response-phase refusal never implies Docker rolled back a mutation. Another write cannot pass while a request is unresolved; restart refuses any unresolved or unfinished attempt. Used namespaces cannot be reinitialized. There is no repair, reset, release, retry or deletion RPC.

The private protocol bounds headers, requests, processing time and connections. Plugin errors/refusals remain generic and do not reflect payloads. Docker protocol compatibility is checked against the checksum-pinned Docker 29.8.2 source, including empty activation requests, `RequestUri`, flattened headers and base64-encoded peer certificate fields.

## Disposable integration proof

`tests/integration/engine_authz_acceptance.py` refuses execution outside explicitly enabled GitHub Linux AMD64 CI. It starts an additional daemon with a new nonce-owned data/exec root and no bridge, iptables, IP forwarding or masquerade. It leaves the runner's existing daemon untouched. A temporary private Unix bootstrap listener preloads only the pinned Bandit image, then stops. The same engine restarts with TLS client verification, a loopback-only TCP listener and the new authorization plugin; no raw bootstrap socket remains. This daemon alone is started with `GODEBUG=http2server=0`: the pinned daemon dispatches native HTTP/2 gRPC before HTTP authorization. The test directly probes read-only native gRPC using an unapproved CA-valid certificate and the legacy unversioned `/grpc` upgrade, requiring transport exclusion and policy denial respectively. One-day test certificates are private files and never published. The CA/server key are never supplied to a scanner client.

The real test challenges missing/unknown TLS clients, observer writes, broad read/write APIs, privileged creation, writable source, arbitrary IDs and late starts, then runs the actual guarded offline Bandit fixture using the shared profile and SDK wait. An exact observer inspection confirms the child's absence. Stopping the plugin must fail closed on a harmless engine read. After the private daemon stops, its separate plugin journal is inspected for settled intents. This is an automated reference test, not independent review or production deployment evidence.

## Remaining authority limits

The selected packaged broker still uses the earlier raw Unix daemon experiment. It is not connected to this TLS policy adapter, and its controller binding/lease/guard identities are not authenticated by the plugin. Source and guard paths are constrained but their original bytes are not independently attested here; the existing guard validates its supplied snapshot, while the broker remains trusted to provision it. TLS enrollment/rotation, stable host provisioning, late-allocation reconciliation, authenticated independent cleanup, no-active-lease proof, recovery/replacement and release remain unfinished. The CI fixture excludes native gRPC through its tested HTTP/2 disable setting and denies the legacy upgrade. Other deployments must establish the same transport exclusion and must not assume HTTP authorization is a universal daemon sandbox. Host administrators and the dedicated daemon/plugin are trusted. This is not the required disposable VM boundary for arbitrary repository or patch execution.

All engine-write mediation, controller-bound cleanup and cleanup-release authority flags remain false. Admission remains held after a suite and public beta remains NO-GO.

## Primary protocol references

- [Docker authorization plugins](https://docs.docker.com/engine/extend/plugins_authorization/)
- [Docker daemon TLS access](https://docs.docker.com/engine/security/protect-access/)
- [Pinned Docker 29.8.2 authorization implementation](https://github.com/moby/moby/tree/docker-v29.8.2/pkg/authorization)
- [Pinned Docker plugin activation client](https://github.com/moby/moby/blob/docker-v29.8.2/pkg/plugins/client.go)

- [Pinned native gRPC dispatcher outside the HTTP API middleware](https://github.com/moby/moby/blob/docker-v29.8.2/daemon/command/httphandler.go)

## Observed reference evidence

`docs/evidence/engine-authz-acceptance.json` records 255 local race-test pass events across 85 tests/subtests repeated three times, full source checks, static analysis, guarded CI context refusals, unchanged guard build identities and the plugin dependency separation. `docs/evidence/engine-authz-ci-acceptance.json` records thirteen real isolated-daemon checks, including native gRPC transport exclusion, legacy upgrade refusal, actual guarded Bandit B307, observer child absence, plugin-unavailable fail-closed behavior and a settled plugin-owned journal. Its exact hosted job/source revision is retained. These checks do not establish controller lease binding, exclusive deployed broker authority, independent cleanup release, publisher authenticity or independent security sign-off.
