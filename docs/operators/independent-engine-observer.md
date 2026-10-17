# Independent scanner engine observation

`alpha/engineobserve` provides a bounded read-only TLS client for the original scanner engine. It is a prerequisite for ADR057 independent reconciliation. It does **not** provide a cleanup-release command or authorize another scan.

Provision a distinct `aegis-engine-observer` client certificate signed by the dedicated engine's CA. Its identity directory must be canonical, owned by the reader's effective UID, mode0700, and contain exactly owned mode0600 single-link `ca.pem`, `client.pem`, and `client.key` files. Mount only this directory into the reader. Supply the broker's **public** certificate separately; do not mount a directory containing the broker private key. The observer cannot authenticate as the broker.

The reader uses explicit configuration and never reads Docker context, endpoint, API-version, certificate or proxy environment settings. `Endpoint` must be the original approved broker's logical `unix:///absolute/socket/path`, provided through the reader's own mount view or opaque TLS relay. It uses TLS1.3 and HTTP/1.1 over that socket, verifies the fixed `aegis-scanner-engine` server identity, disables proxying and redirects, and has no plaintext or remote-endpoint fallback. There is no arbitrary-request, list, create, start, remove, wait or attach API.

The public broker certificate is checked against the observer's CA and the exact broker principal. Its public identity digest matches the existing broker loader's digest. Expired broker certificates may identify historical scope; future certificates are refused. This does not allow an expired broker to authenticate. The observer and its CA must still be live. Every HTTP operation rechecks the original observer credential, including reused connections, and checks it again after reading the response.

## Typed interface

`Open(Config)` reads credentials and validates configuration without contacting an engine or creating persistent state. `Config` contains:

| Field | Required source |
| --- | --- |
| `Endpoint` | Original operator-approved broker logical Unix endpoint |
| `IdentityDirectory` | Reader's distinct private observer identity |
| `ExpectedEngine` | Original controller-approved engine digest |
| `BrokerCertificatePEM` | Original broker public certificate, bounded to16KiB |

`Reader.VerifyAbsent(ctx, []Target)` requires one to six distinct allocations, each with both the exact retained `aegis-scan-<32 lowercase hex>` name and full64-hex native engine ID. Invalid, missing or duplicate identities are refused before engine traffic. The caller must authenticate the complete generation membership; a caller-selected subset is not complete cleanup proof.

The read sequence is:

1. Read `/v1.55/info`; verify Linux, supported architecture and the original engine digest, including logical endpoint and original broker public identity.
2. For every allocation, read `/v1.55/containers/<full-ID>/json` and `/v1.55/containers/<exact-name>/json`. Both must return404 with a complete bounded JSON error object.
3. Read `/v1.55/info` again and verify the same original scope.

Responses are bounded to64KiB, ambiguous root keys and trailing JSON are refused, and transport/status/body uncertainty returns `ErrUnconfirmed`. A present container, denied request, unavailable engine, changed identity or malformed404 never becomes absence. Each operation has finite connect/handshake/header/total limits; the complete observation is bounded by30seconds and the caller's earlier deadline. `Close` refuses subsequent observations. Errors contain no endpoint, allocation identifier, certificate, key or response payload.

## Release boundary and acceptance

A successful observation is only a point-in-time engine read. The future reconciler must independently authenticate the original closed generation and complete launch/workspace/mutation membership, establish actual native mediation, settle every obligation, retain the original policy and namespace, and hold the original `WithBoundEmptyRegistry` barrier through the final controller transaction. Unknown create responses lack a confirmed native ID and cannot be discharged with this reader. Do not delete a SQL dispatch, reset journals, rotate a namespace or infer settled mutations from404.

Local tests use isolated TLS protocol servers over fresh Unix sockets. They cover exact ID/name requests, public-only broker scope, credential withdrawal/replacement, scope changes, malformed/denied/oversized/truncated responses, wrong CA, redirects, cancellation, unavailable engines and invalid membership/configuration. They are not actual-daemon or release proof.

Reproduce the local protocol and certificate checks from the repository root with `cd alpha && go test -race ./engineobserve ./enginetls`. These tests allocate only fresh test identities and Unix sockets; they do not start or reconfigure a daemon.

The guarded Linux CI native authorization fixture additionally prepares this reader before mutation and calls it after actual guarded Bandit creation/start/removal. It forwards opaque TLS through a private Unix relay to only that disposable fixture's loopback engine. The test retains `controller_bound=false`, `all_engine_writes_mediated=false` and `cleanup_release_authorized=false`. Exact commit `0cc2b09c8c6d284c572dc0a7bc153e31033db221` passed all four jobs in [hosted run39001548562](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39001548562), including this actual-reader check. It does not prove the new reconciler enrollment or release protocol. The native authorizer now recognizes exact retained allocation names and confirmed IDs from its complete bounded journal history, including after restart. This index is rebuilt from validated existing records and changes no on-disk format or digest. Historical reads are Observer-only; Broker reads keep their current-allocation limits. Pending or failed creates never acquire an invented native ID, reads never settle obligations, and restart still refuses unfinished or unresolved execution. Quarantined serving, independent release and two actual sequential packaged scans remain unfinished.
