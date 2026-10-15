# ADR 047: SDK preflight and an explicit packaged journaled worker

Status: implemented experimental one-shot profile; controller cleanup release remains unavailable.

## Decision

Make the selected journaled backend usable without a Docker CLI. Resolve an explicitly configured local Unix endpoint once; fetch Linux engine identity/architecture and the exact preloaded pinned image through a separate read-only SDK client using the existing pinned API and bounded direct transport. Permit only the two fixed GET paths. Require complete bounded responses and strict JSON before accepting metadata. Refuse missing images, digest/platform mismatches, malformed/ambiguous/trailing/oversized responses, redirects and remote endpoints. There is no pull or CLI fallback after a failed SDK preflight. Native context discovery remains available only when an explicit endpoint was not supplied.

Package the trusted one-shot worker, fixed rules, tool lock and both guards in a pinned non-root image with no Docker CLI. Offer a separate opt-in Compose worker profile. It receives only the private scanner channel, its dedicated read-only enrollment credential, approved read-only repositories, an explicitly provisioned private workspace path mirrored at the same absolute daemon-host path, and the operator-selected local engine socket. Its network is none, root filesystem read-only, capabilities dropped and restart disabled. Child scanner containers retain their existing independent guard, fixed argv/pins, non-root user and network-none restrictions; they receive neither the worker credential nor engine socket.

The orchestrator's engine socket grants substantial engine authority despite a read-only socket mount. This profile is a trusted operator worker, not an independent engine broker or evidence that all writes are mediated. No browser enrollment, raw Docker HTTP forwarding or arbitrary source execution is added. A separate controller-independent mediation/verification/release boundary remains required. One completed suite leaves dispatch cleanup held; no restart loop or automatic second claim bypasses that hold.

## Validation boundaries

Challenge SDK read method/path/query boundaries, full-response completion, duplicate/case-aliased JSON, budgets, errors/redirects, OS/architecture and pinned image identity. Prove an explicit endpoint works with an unavailable Docker executable. Run actual preloaded tools with no CLI fallback. Build the worker image and verify non-root execution, no Docker CLI, read-only/cap-drop/network-none settings and isolated private UID/socket enrollment. Use a new disposable reference project and owned temporary workspace only; never reuse the retained demo's volumes or credentials. Capture a real guarded receipt/result, then verify cleanup admission still blocks another job. Missing tool databases remain errors/stale rather than clean results.

## Limits

This does not provide background recovery, independent cleanup authority, a trusted all-engine-write broker, VM-backed arbitrary application/patch execution, advisory database provisioning, publisher signatures or independent release acceptance. Keep unresolved journals/workspaces; a changed/deleted namespace is not recovery. The full v4/H7 goal remains active.

## Disposable Linux CI engine

The [Ubuntu 24.04 runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md) advertised Docker 28.0.4 during implementation. Docker's [API matrix](https://docs.docker.com/reference/api/engine/) places 28.0 at API 1.48; the selected client intentionally requires 1.55. The dedicated packaged-worker job therefore prepares the exact official Linux AMD64 Docker 29.8.2 static archive pinned in `tools/ci-engine.lock.json`. It verifies archive length/SHA-256 and all nine bounded members before private extraction. Links, traversal, duplicate or unknown members and checksum/length faults are refused before destination creation. Unit fixtures are synthetic and separate from the actual archive check.

Only that disposable GitHub job stops its preinstalled daemon and starts a fresh daemon/data root using the pinned binaries. The helper refuses workstation execution; the workstation archive test only extracts and checks ELF headers, never runs Linux binaries or changes its daemon. This checksum pin is not a verified publisher signature. It is not an operator installation path, release support promise, or application VM boundary.

## Observed local execution

The final non-root package executes all six pinned tools in a fresh isolated owner/project, commits six receipts, and exposes the source-bound T0 results through the owner catalogue. Missing offline advisory databases remain tool errors. Exact child absence and six settled journal attempts still authorize no cleanup release; another queued job stays held and causes no new journal writes. The fixture uses private UID 10001 enrollment and the packaged Compose profile. All source tests pass and metadata fault tests pass repeatedly under the race detector. Bounded metadata receipts are schema-checked.

An initial acceptance-harness export failed because its destination inherited the data root's broader directory mode. Execution had already completed. The fixture was preserved; inspection confirmed a settled journal and exact child absence before removing only its nonce-owned resources. The corrected harness creates a private export directory before requesting launch context, and its completed runs pass. No dispatch admission was released during this correction. Evidence is in `docs/evidence/cli-free-worker-acceptance.json` and `docs/evidence/packaged-worker-acceptance.json`.

The exact implementation commit `5dd15a171ff23f74149559fecfb1fa31b47ad53f` passed all three [hosted Linux AMD64 jobs](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/38755538467): source/race/browser checks, trusted demo/recovery and actual packaged Bandit worker acceptance. The job successfully prepared/started the pinned disposable engine, executed the worker and stopped its own daemon. `docs/evidence/packaged-worker-linux-ci.json` records bounded step outcomes. This is automated reference acceptance, not independent installation or security sign-off.
