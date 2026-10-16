# ADR 056: Owner-registered sites behind one gateway revision

Status: implemented with unit, real-Caddy and local stack validation; production TLS and per-site rate limits remain open.

## Problem

The gateway, policy schema, telemetry attribution and console were fixed to the bundled `site_demo` and `demo-origin:8080`. An owner could not put their own application behind Aegis, which is the defence plane's primary purpose. A per-site revision model would have changed the activation, reconciliation, rollback and freeze semantics that already have crash and fault evidence.

## Decision

Keep one typed policy document and one gateway revision. Schema `1.1` adds `sites[]`; each entry has a `site_id`, display name, 1–8 exact DNS host names, a private `host:port` origin, mode, CRS settings and up to eight exclusions. The top-level fields continue to govern `site_demo`. A `1.0` document has no `sites` field when serialised, so existing digests, reports and evidence remain valid. Apply, reconcile, rollback, freeze and idempotency logic are unchanged because they operate on the whole revision.

Validation refuses: `site_demo` or malformed IDs; duplicate IDs; host names that are bare, wildcard, malformed or already claimed (including the demo hosts); origins that are loopback, link-local (including cloud metadata), unspecified, multicast, IPv6 literals, `*.localhost` or Aegis service names; exclusions outside CRS detection rules 920000–944999 (anomaly-scoring/blocking rules cannot be excluded); and non-exact or root exclusion routes. More than sixteen sites are refused. Every value reaching the Caddyfile is pattern-restricted, so a site cannot inject directives.

Protect is refused for a site that the parent revision did not already govern (`ProtectRequiresObservation`). A new site therefore always starts in Observe, and the console only offers Observe at registration.

The renderer emits one `host`-matched route per site with its own Coraza instance, mode, CRS values, exclusions and `reverse_proxy` origin, followed by the existing `421 Unknown host` fallback. Each registered site's gateway-assigned request ID is prefixed with its site ID (`site_shop.<uuid>`), both on the request header Coraza uses as its transaction ID and on the response header; `handle_errors` uses per-site blocks so blocked requests keep the prefix. Because the gateway strips every client-supplied request-ID header first, ingest can attribute access and WAF records to a site from the request ID without trusting client input. The demo keeps plain UUIDs, so verification fixtures and scanner channels are unaffected. Only demo traffic is labelled synthetic.

The API serves `/sites/{id}/events|events/stream|endpoints|incidents|policy|policies/...` for any site in the active policy and returns 404 otherwise. Incidents are attributed through their linked evidence; incidents whose evidence aged out remain under `site_demo`, where all pre-1.1 incidents originated. No database migration is used.

## Consequences and limits

- The isolated preview fixture still verifies only the bundled demo controls. A preview `PASS` for a revision that changes a registered site proves the revision is valid and the demo controls hold, not that the owner's application behaves correctly. The console states this.
- Origins must be reachable from the gateway's networks. Operators attach their application network to the gateway (see `docs/operators/sites.md`); Aegis does not open any new published port.
- TLS termination, ACME, trusted proxy ranges and per-site rate limits are not part of this decision.
- Route templates for registered sites use the same conservative analytics normaliser; unknown path segments are reported as `{segment}`.

## Validation

`controller/internal/policy` tests cover legacy digest stability, fifteen rejected site variants (including origin and display-name injection), the Observe-before-Protect rule and a rendered two-site Caddyfile validated by the real pinned gateway binary. `controller/internal/ingest` covers request-ID attribution including spoof-shaped IDs. Existing policy, research, API and recovery suites pass unchanged. Local stack evidence is recorded in `docs/evidence/multi-site-acceptance.json`.
