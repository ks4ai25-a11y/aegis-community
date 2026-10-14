# ADR 039: Original-engine sandbox observations

Status: read-only operator observation implemented. Authenticated cleanup verification and admission release remain unfinished.

## Decision

Add a separate read-only path that observes one exact Aegis scanner container on the original local Unix Docker engine. It compares selected engine metadata and reported host files with schema-1.1 launch context, configured private workspace registry and local approved tool lock. It never creates, starts, stops or removes containers, changes workspace leases, finalizes jobs or releases admission.

The operator exports owner-checked context with `aegisctl scanner-launch export JOB TOOL PRIVATE_FILE`. Output is new/exclusive mode 0600 inside a canonical operator-owned mode-0700 directory. Unknown jobs/tools, another owner, existing files and nonprivate directories are refused. Context contains no worker credential or lease capability and grants no cleanup authority. `aegis-research observe-sandbox PRIVATE_FILE REGISTRY SOURCE_ROOT [APPROVED_RULES_DIGEST]` reads a strict private regular file; symlinks, unknown/duplicate keys and nonprivate context files are refused.

## Actual checks

Require the original local Unix endpoint/engine-ID digest and architecture. Observe only the exact random Aegis name. For a present container, compare original image reference and actual local image config ID, fixed guard entrypoint/arguments, original absolute deadline, positive UID/GID, root filesystem, network names, PID/IPC/UTS/user namespace settings, capability/security options, device/group additions, resource limits, log driver, auto-remove and temporary filesystem. Selected safety keys are required; missing/null values cannot silently become safe Go zero values. Extra, duplicate, writable or out-of-registry mounts are refused.

Open only canonical owner-controlled registry/workspace directories and reported source/guard/rule children. Refuse symlinks/nonregular files, verify the reported guard file hash and validate exact bounded source manifest/file bytes against the launch snapshot and map. Semgrep requires a separate operator-approved rules digest; a worker receipt is not used as approval. Host paths are not emitted. These are point-in-time checks of selected metadata and reported files, not proof of process-memory bytes or mount-inode attestation.

Docker metadata stdout is bounded, including 32 KiB for the selected inspect template. Stderr is bounded and omitted, and commands have five-second deadlines. Context/engine/absence reads in the existing executor and local recovery use the same bounded helper. The observer does not query environment, labels, raw tool output, logs or unrelated containers.

## Explicit uncertainty

ScannerSandboxObservationV1 requires `controller_authority_verified`, `active_workspace_lease_excluded`, `late_start_excluded` and `cleanup_confirmed` to remain false. A supplied checksum detects changes, not origin: this path does not authenticate a separately enrolled controller verifier role. Current absence does not exclude a queued Docker request starting later. Matching reported files does not freeze the registry or prove that active leases/incomplete allocations are gone. Historical guard-less/relative-duration records are refused, not upgraded into proof.

Release still requires a separate authenticated authority path, provisioned original-engine/registry scope, active-lease/incomplete-allocation and queued late-start exclusion, and a bound cleanup record committed atomically. Worker claims, CLI observations, expired deadlines or absence alone cannot satisfy that boundary. No release endpoint is added.

## Evidence and remaining scope

Unit challenges cover changed image/user/command/deadline, root/privileged/network/namespace/capability/device/resource settings, missing/null/duplicate metadata, mount escapes, guard/source/rules byte changes, symlink/private-file failures and actual template parsing. A real-engine fixture creates but never starts uniquely owned stopped containers. It exercises the library/CLI, detects changed guard bytes and root-user metadata, then observes absence without claiming cleanup. Fixture setup/teardown is separate and touches only successfully created exact random names.

The first native probe refused a malformed template. Docker optional nil lists and separator syntax were corrected and covered by a template regression test. Refusals are retained rather than treated as success. See `docs/evidence/scanner-sandbox-observer-acceptance.json`.

Worker deployment, authenticated cleanup role/release, global finding catalogue/triage, richer source/proof workflows, offline databases, disposable VM execution, AI/MCP/desktop integration, supply-chain/legal/security review and independent H7 release gates remain unfinished.
