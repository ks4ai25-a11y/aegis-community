# Selected scanner broker with a restricted TLS engine

This opt-in reference profile connects the selected broker to the isolated native authorization adapter. It remains an internal experiment: controller-authenticated plugin leases, independent cleanup release, approved recovery and arbitrary-code VM isolation are unfinished. The next scan remains held after a completed suite. Read [ADR 052](../architecture/adr/052-selected-broker-mutual-tls-engine.md).

Provision a separate Linux scanner daemon and the [authorization adapter](isolated-engine-authorization.md). Do not reconfigure Docker Desktop or a shared application daemon. The scanner daemon must expose only a verified TLS loopback listener after preloading its exact approved image pins and removing the bootstrap socket. Native HTTP/2 gRPC must be excluded (`GODEBUG=http2server=0` in the tested daemon profile); the adapter denies the legacy upgrade and all unapproved HTTP APIs. Keep its CA/server keys and plugin journal outside every broker mount. The daemon, host administrator and plugin are trusted.

Build the relay with `make engine-relay-build`. Run it as the owner of a canonical private mode-0700 socket directory:

```text
aegis-engine-relay PRIVATE_UNIX_SOCKET 127.0.0.1:DEDICATED_TLS_PORT
```

The socket is mode 0600; it forwards opaque TLS bytes and has no credential. The target must be the explicit loopback IPv4 address and a port from 1024 through 65535. Provision the socket as UID/GID 10001 for the packaged broker. Keep its process supervision outside the broker; it has no source, controller or engine API credentials. This command never starts or changes a daemon.

Provision `AEGIS_SCANNER_ENGINE_TLS_ROOT` as a canonical directory owned by UID 10001, mode 0700, containing `ca.pem`, `client.pem` and `client.key`, each owned mode 0600, regular and not linked. The CA must be self-signed with certificate-signing usage. The client certificate must validate for client authentication, have common name `aegis-engine-broker`, and match its private key. The server certificate must validate under that CA for DNS name `aegis-scanner-engine`. TLS 1.3 is required. Do not place the CA signing key, daemon server key or observer credential in this directory. Missing/changed identity refuses new cooperating SDK requests, including on existing HTTP connections; it does not attest termination of in-flight work.

Build the operator helper, broker and minimal dispatcher as in [broker operations](scanner-broker.md). Use the same private enrollment and repository provisioning, but set `AEGIS_SCANNER_ENGINE_SOCKET` to the relay socket and use this helper for engine/registry input and journal initialization:

```sh
aegis_tls_broker_provision() {
  docker run --rm --pull=never --network none --read-only --user 10001:10001 \
    --cap-drop ALL --security-opt no-new-privileges \
    --env DOCKER_HOST=unix:///run/engine/docker.sock --env DOCKER_CONTEXT= \
    --env AEGIS_SCANNER_ENGINE_TLS_DIR=/run/engine-tls \
    --mount "type=bind,src=$AEGIS_SCANNER_WORK_ROOT,dst=$AEGIS_SCANNER_WORK_ROOT" \
    --mount "type=bind,src=$AEGIS_SCANNER_ENGINE_SOCKET,dst=/run/engine/docker.sock,readonly" \
    --mount "type=bind,src=$AEGIS_SCANNER_ENGINE_TLS_ROOT,dst=/run/engine-tls,readonly" \
    aegis-community/scanner-worker:0.1.0-alpha.1 "$@"
}
aegis_tls_broker_provision engine-binding-input "$AEGIS_SCANNER_WORK_ROOT/aegis-scanner-workspaces-10001"
aegis_tls_broker_provision engine-journal-init "$AEGIS_SCANNER_WORK_ROOT/engine-journal"
```

No daemon group is added. Approve the returned engine/registry/journal hashes and enrolled broker ID with the existing immutable local controller commands. The TLS engine identity includes the public client/CA certificate identity; it differs from the raw Unix experiment. Existing holds or approvals cannot be bypassed by switching profiles, replacing certificates or creating another namespace.

With `AEGIS_SCANNER_WORK_ROOT`, `AEGIS_SCANNER_ASSET_ROOT`, `AEGIS_SCANNER_ENGINE_SOCKET`, `AEGIS_SCANNER_ENGINE_TLS_ROOT`, `AEGIS_SCANNER_OWNER` and `AEGIS_SCANNER_BROKER_ID` set, inspect and run only this explicit profile:

```sh
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker-tls.yaml --profile operator-broker-tls config
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker-tls.yaml --profile operator-broker-tls up -d --no-deps scanner-broker
docker compose -p aegis-community -f deploy/compose.demo.yaml -f deploy/compose.scanner-broker-tls.yaml --profile operator-broker-tls run --rm --no-deps scanner-dispatch
```

The dispatch client still receives only its own capability and broker socket. Inspect results through the owner Scans/Findings pages. Static findings stay T0; missing advisory databases stay tool errors. This transport uses explicit child removal and rejects the older CLI sandbox observer/recovery path in TLS mode. Failed removal or unanswered RPCs preserve both journal uncertainty and the controller hold. Stop only the named broker through this same Compose profile, retain uncertain state, and use the trusted operator recovery process when implemented. Do not enable restart loops, edit bindings or delete journals to clear a hold.
