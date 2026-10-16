# ADR 062: Per-site HTTPS and approved per-client rate limits

Status: implemented; validated with the real gateway binary and on the hardened container. Trusted proxy ranges (correct client addresses behind a CDN) remain open.

## Problem

Registered sites were served only over plain HTTP on a loopback listener, so Aegis could not front a real public application. The detector catalogue could observe bursts (DET-04) but no approved deterministic rate limit existed (manual E4 DET-04, B-003/004).

## Decision

`SitePolicy` gains optional `tls` (`acme` for a free public certificate, `internal` for an Aegis-local CA), `acme_email` (ACME only, strict pattern) and `rate_limit` (`requests` 10–100000 per `window_seconds` 1–3600, keyed by client address).

The production renderer (`policy.Render`) emits a separate HTTPS site block for each TLS site with the same ordered route chain, and an explicit `redir … 308` for its host names on the shared HTTP listener. Global options set `http_port` to the shared listener port, `https_port` 8443, `auto_https disable_redirects` (only Aegis-rendered redirects exist) and `skip_install_trust`. ACME HTTP-01 challenges are answered by Caddy before routes on the HTTP port. Certificates are stored in the gateway's private data volume. Without TLS sites the output is byte-identical to before. `policy.RenderFixture` keeps every site on plain HTTP so the isolated fixture never binds HTTPS or contacts a CA; the policy digest is unchanged.

Rate limits use the pinned `github.com/mholt/caddy-ratelimit` module (Apache-2.0, commit 5625512f, June 2026), placed in the route after request identity and before the body limit, WAF and origin; excess requests receive 429 and ingest records `rate_limited`. A DET-04 burst incident on a registered site now yields a `rate_limit` proposal (600 requests per minute) through the same preview-and-approve flow.

`deploy/compose.public.yaml` publishes host ports 80/443 to the unprivileged 8080/8443 listeners; the console stays on loopback.

## Consequences

- Client keys are the TCP peer address. Behind a CDN or load balancer all clients share one key until trusted proxy ranges are supported; the console states this.
- ACME requires public DNS for every host name and reachability on port 80.
- Recovery bundles render the production configuration, so TLS sites are captured and verified consistently.

## Validation

Policy tests cover TLS/email/rate-limit validation, byte-identical TLS-free rendering and offline `caddy validate` of an ACME + rate-limit site. A real-gateway test serves a TLS site from the internal CA, checks the site-prefixed request ID, the 308 redirect, 429 enforcement and that the plain-HTTP demo host is routed, not redirected. `tests/integration/multi_site_acceptance.py` repeats the rate-limit and HTTPS checks on the hardened container (`docs/evidence/multi-site-acceptance.json`). Proposal tests cover DET-04 rate-limit proposals.
