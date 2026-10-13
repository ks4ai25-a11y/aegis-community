# ADR 030: One-shot authorized static worker

Status: implemented for Linux/macOS operator fixtures; release gates remain open.

## Decision

The native research CLI exposes `worker-once` using `alpha/worker.Config.RunOnce`. It claims one owner-bound job through the private Unix channel, confines source access to an operator-provisioned asset root, renews its lease and submits normalized receipts through the existing authenticated boundary. It has no controller database dependency. Paths and credentials are provisioned by the operator; claims supply only a registered asset identifier, approved map and fixed scanner IDs.

Each scanner gets a new private workspace journal and a fresh capture of the same approved map. Capture time shares one 60-second budget across the suite. The executor verifies its locally resolved lock digest against the claim before execution. Immediately before container launch, the worker checks live authority and fsyncs the original container/engine binding. Workspace removal occurs only after no container launched or the executor confirmed that exact container absent. Unconfirmed cleanup preserves the journal and halts the suite.

The worker stops on capture, authority, execution, receipt or cleanup failure. A structured tool error can be recorded before a finite failure report; it cannot become a clean scan. Failure reporting has a separate five-second context and remains subject to server authorization. Raw output, credentials and lease capabilities are absent from the CLI report.

## Completion boundary

A successful one-shot operation reports `awaiting_controller_finalization`. Receipt acceptance persists evidence, and does not finalize the job, independently attest cleanup or release global dispatch admission. Renewal stops when this invocation returns; without a future finalization operation, the running job eventually times out with admission still held. This command is not a completed reusable scanner service.

The CLI requires the same host UID/private socket access as controller enrollment and a local Docker Unix endpoint. Native fixtures use an actual in-process controller with migrated SQLite and private transport under the operator UID. They do not demonstrate access to the demo Compose controller's UID 10001 socket from a workstation UID. Dedicated worker deployment, cross-host/VM transport, automatic recovery and background scheduling remain unfinished.

Only fixed static scanners execute here. Disposable VM/host isolation for arbitrary repository code execution remains absent. Offline database provisioning, signatures/license review, terminal aggregation, independent cleanup confirmation and full H7 release gates remain open.

## Verification

Default tests cover canonical operator roots, bounded asset references, symlink refusal, changed lock refusal before launch, empty queue and changed source refusal with retained admission. Explicit local Docker tests exercise real pinned Bandit and sequential Bandit/Gitleaks with distinct containers, identical approved inputs, removed workspaces, receipt persistence and retained dispatch. Missing offline OSV database support records a tool error with no clean-scan claim. See `docs/evidence/scanner-worker-execution-acceptance.json` for observed results.
