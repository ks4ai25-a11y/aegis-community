# ADR 058: Deterministic behavioural detectors and keyed pseudonyms

Status: implemented; DET-01…06 unit-tested, DET-02 validated live. DET-07 is the live canary (ADR 063). DET-08 is implemented as an origin exposure check (below).

## Problem

Only DET-01 (one incident per CRS rule per minute) existed. The v4 catalogue (E4) requires bounded, reproducible detectors with explicit knobs, evidence and false-positive controls. Per-client detectors need a client key, but the sanitizer deliberately drops client addresses and raw paths.

## Decision

The gateway sanitizer adds two keyed pseudonyms to access records: `client_key` (client address) and `path_key` (raw path without query), each the first 8 bytes of HMAC-SHA-256 under a random key that exists only in gateway memory and is replaced every UTC day. Pseudonyms cannot be reversed without the key and cannot be linked across days or gateway restarts. Raw addresses and paths are still never written. Ingest accepts only 16-hex pseudonyms.

`controller/internal/detect` (version 1.0) runs in-process on each newly persisted access event, using event time, with LRU-bounded per-key windows (default 4096 keys). Eviction increments `detector_state_evicted` in `/system/status`; it is signal loss, never evidence of safety.

| ID | Signal (defaults) | Response |
| --- | --- | --- |
| DET-01 | CRS rule match (existing) | record only |
| DET-02 | ≥30 distinct `path_key` from one client in 60 s with ≥50 % failures | record only |
| DET-03 | ≥10 responses 401/403 to one client in 5 min | record only |
| DET-04 | ≥200 requests from one client in 10 s | record only (no automatic 429) |
| DET-05 | ≥20 site 5xx in 60 s that are ≥50 % of site responses | record only |
| DET-06 | successful response on a route with an `admin`/`debug`/`internal`/`actuator`/`.env` segment | info, record only |

Each signal fires at most once per detector, key and window bucket. The incident ID is derived from detector, site, key and bucket, so restarts do not duplicate it. The incident stores `{detector_id, detector_version, site_id, window_seconds, threshold, observed, assumption, response}` as JSON in the existing `incidents.notes` column (no migration; migration 014 is reserved by the scanner work). Evidence links are capped at 50 per incident. No detector blocks traffic or relies on a model.

## Consequences

- A gateway built with this change emits fields an older controller rejects (`ingest_rejected_total` rises). Upgrade the controller before, or together with, the gateway.
- Shared NAT, crawlers, load tests and deploys can trigger DET-02/03/04/05; every incident states its assumption.
- Routes are normalised conservatively, so DET-06 only recognises the listed segments.

## Validation

`controller/internal/detect` tests cover each detector's positive case, negative controls (successful browsing, failures spread across clients, slow failures, minority errors, refused admin routes, partial segment names), ineligible records and bounded cardinality. `gateway/telemetry` tests check that pseudonyms replace addresses and paths and are stable within a day and distinct across clients. `tests/integration/detector_acceptance.py` records a live DET-02 incident with pseudonymous evidence only (`docs/evidence/detector-acceptance.json`).

## Addendum: DET-08 origin exposure

On each canary cycle the controller attempts a 2-second TCP connection to every registered site's origin. In the reference deployment the controller shares no network with origins, so a successful connection means some clients may reach the application without passing the gateway. It records one DET-08 incident per site and day (record only) and reports results in `/system/status` as `origin_exposure`. A port published on the Docker host is not visible from inside the stack, so "unreachable" is not proof the origin is private. Live: a site whose origin shared a network with the controller was flagged; a site on the gateway-only network was not.
