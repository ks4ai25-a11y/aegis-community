# Protecting your own applications

Aegis can front several applications with one gateway. Each registered site has its own host names, private origin, mode and CRS settings. All sites share one policy revision, so every change goes through the same preview, explicit approval, activation and rollback flow.

## 1. Make the origin reachable from the gateway

The gateway reaches origins over Docker networks. Attach your application to a network the gateway also joins. For an application in another Compose project, create an external network once and add it to both projects:

```sh
docker network create aegis_sites
```

In your application's Compose file:

```yaml
services:
  shop:
    networks: [aegis_sites]
networks:
  aegis_sites: {external: true}
```

Then start Aegis with the site overlay, which adds that network to the gateway only:

```sh
docker compose -f deploy/compose.demo.yaml -f deploy/compose.sites.yaml up -d
```

Do not publish your application's own port to the host if Aegis is meant to be the only entry point; otherwise clients can bypass the gateway.

## 2. Register the site in Observe

Open **Sites** in the console and enter:

- **Site ID** — becomes `site_<id>`; lowercase letters, digits and `_`.
- **Host names** — the exact DNS names clients use (no wildcards, up to eight).
- **Private origin** — `service-name:port` on the shared network. Loopback, link-local/metadata addresses, IPv6 literals and Aegis service names are refused.

Select **Validate and preview**. The pinned gateway validates the full candidate and the isolated fixture re-checks the bundled demo controls with that exact revision. The fixture does not exercise your application. Approve and activate.

New sites always start in **Observe**: Coraza records matches without blocking.

## 3. Review traffic, then enable Protect

Choose the site in the header **Site** selector. Live activity, Endpoints and Incidents now show only that site. When you have reviewed matches and added any narrowly scoped exclusions you need, open **Policies** with the site selected and preview **Protect**. Protect is refused for a site that the active revision does not already govern.

## Attribution and privacy

Registered sites' request IDs look like `site_shop.<uuid>`. The gateway removes any client-supplied request-ID header before assigning its own, so attribution does not trust client input. The same sanitizer applies to every site: no bodies, query values, cookies, authorization headers or client IPs are stored.

## Current limits

- The gateway listens on plain HTTP on loopback in the reference deployment; terminate TLS in front of it or wait for the TLS profile.
- Per-site rate limiting is not yet available.
- A generic WAF does not enforce your application's authorization or tenant ownership.
