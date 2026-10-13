# ADR 014: Durable fixture jobs and exact scope grants

Status: implemented and locally tested for the bundled trusted WAF fixture; broader research modes and independent review pending.

The operator prepares a fixed test_lab grant, reviews its immutable digest, then explicitly approves it. The grant binds the owner, application, owned fixture, protocols, routes, address, test ID, expiry, concurrency, total request count and maximum duration. Target URLs and production modes are rejected. A grant permits four requests total; the worker reserves that budget transactionally before execution. Reservation is not refunded after interruption, avoiding accidental expansion of authority.

Jobs persist in SQLite with owner-bound idempotency keys, immutable input identity, one active fixture lease, bounded duration, cancellation state and report reference. A worker checks authority every 250ms while executing. Revocation marks queued jobs cancelled and interrupts running work. Completed results cannot be committed after cancellation, expiry, lease loss or scope changes. A stale worker cannot finish a replacement lease. A controller crash expires the old lease to timeout; uncertain execution is not automatically retried. Retrying a test requires a fresh explicitly approved grant and job key.

Readiness opens and closes only the local gateway TCP listener, with no HTTP request or origin traffic. The baseline and candidate each issue the two declared corpus requests without redirects or environment proxies. Scoped execution uses the earlier of the grant expiry and the 30-second job deadline. Scratch creation failures abort execution. A unit test accepts the readiness connection and verifies EOF without any application bytes.

The independent fixture worker additionally validates the grant's fixed boundaries and expiry. Reports bind the job ID, scope ID and digest, policy digest, fixture digest and gateway binary identity. The controller rechecks baseline/candidate controls and expected CRS evidence rather than trusting a PASS summary. Read access to jobs, grants and reports is owner-scoped.

Migration 2 creates the queue, grants and report ownership mapping. Existing schemas are checksum-verified before any DDL. Existing reports are assigned only when exactly one owner exists, matching the previous single-owner product; ambiguous ownership is not guessed.

Evidence: `docs/evidence/scoped-jobs-acceptance.json`, plus queue/worker/API negative tests. The real container test covers idempotency, four-request budget, revocation interruption, controller SIGKILL and preserved history. Unit tests cover expired queued grants, stale workers, cancellation races, malformed reports, and cross-owner reads.

Limitations: the fixture digest currently identifies the declared request corpus; it does not attest the running origin image or implementation. Stronger origin artifact binding remains required. This grants no arbitrary staging access or user-code execution. Production staging needs signed authority and independently reviewed VM/network enforcement. Policy preview retains its separate synchronous fixed fixture path; integrating it into this queue and approval mechanism remains required. Scanner jobs, retention and restore/upgrade coverage remain incomplete. The helper and scope changes require independent security review before publication.

ADR 017 closes the authorization/audit transaction gap: scope and job changes, claims, reconciliation and report persistence commit with their audit append. Audit failure rolls back the complete state change. Claim revalidates immutable job and policy documents before consuming request budget.
