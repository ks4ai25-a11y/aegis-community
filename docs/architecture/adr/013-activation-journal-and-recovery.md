# ADR 013: Durable approval and crash reconciliation

Status: internal demo implementation; independent review pending.

Before privileged activation the controller records the owner's exact candidate/parent decision in the audit chain and commits an APPLYING policy plus activation journal to SQLite. If that transaction fails, it does not call the deployer. Startup compares the journal to the active gateway digest. When the gateway already runs a candidate that has the expected APPLYING state, matching immutable digest and prior parent, startup finishes the controller transaction and records reconciliation rather than silently reverting an approved Protect policy. A stale journal after a completed DB commit is cleaned up safely.

Tests cover recovery after confirmed gateway application but before database commit, and after commit but before journal cleanup. Unit tests do not establish every disk-full, corrupted-volume or multi-process failure case. Deployment remains single-controller/single-helper. The journal does not replace a future expiring approval capability or signed receipt.

A pending approval that cannot be recorded is rejected. Audit failure after confirmed activation freezes further changes and reports degraded state instead of a success receipt. Readiness includes the durable active policy, deployer-reported gateway revision and frozen state.
