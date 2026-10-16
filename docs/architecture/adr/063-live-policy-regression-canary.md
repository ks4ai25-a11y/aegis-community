# ADR 063: Live policy-regression canary (DET-07)

Status: implemented; unit-tested and validated on a local stack.

## Problem

The isolated fixture verifies a candidate before activation, but nothing checked that the *live* gateway kept behaving as the active revision requires afterwards (manual E4 DET-07, E6 `monitored` state). A deployer fault, a gateway restart with stale configuration or a broken rule set could silently stop protection.

## Decision

`controller/internal/canary` sends the two bundled synthetic controls (`verify.Corpus`) through the live gateway, always with `Host: demo.example.test`, 30 s after start-up, about 3 s after every activation and every 15 minutes. It reads the gateway's revision header and waits up to 10 s for the ingested WAF record of the negative control, then applies the same `verify.Classify` rule as the fixture. A revision header that differs from the controller's active revision is a failure.

`FAIL` records one high-severity DET-07 incident per revision and hour, linked to the canary's evidence, with an audit record and an assumption that recommends verifying the fixture and rolling back; the deterministic assessor proposes `rollback`. `INCONCLUSIVE` (gateway unreachable, policy unavailable) records the result without an incident. The latest result is returned in `/system/status` and shown on the Overview.

Canary requests carry gateway-assigned IDs that the canary registers in memory; ingest marks matching events `canary: true` and skips DET-01 and the behavioural detectors, so the probe does not create demo incidents. A WAF record ingested before the canary registers its ID could still be counted; the ingest poll interval (500 ms) makes this unlikely.

## Consequences

- The canary covers the bundled demo site only; it says nothing about registered applications.
- About 200 synthetic requests per day reach the demo origin.
- The canary never changes policy.

## Validation

Canary tests cover an Observe pass, a regression that records exactly one urgent incident with a valid audit chain, revision drift and an unreachable gateway without an incident. An ingest test shows canary events are stored and marked but raise no incidents. The live stack reported `PASS` with no new demo incidents.
