# Isolated engine authorization experiment

This opt-in adapter is an unfinished prerequisite for exclusive scanner mediation. It does not enable cleanup release, provide a production scanner deployment or change the existing demo daemon. Read [ADR 051](../architecture/adr/051-isolated-daemon-authorization-adapter.md) for the exact trust boundary and open work.

Build with `make engine-authz-build`. The binary has two operator-only commands:

```text
aegis-engine-authz init CANONICAL_PLUGIN_JOURNAL ENGINE_DIGEST
aegis-engine-authz serve PRIVATE_PLUGIN_SOCKET CANONICAL_PLUGIN_JOURNAL ENGINE_DIGEST CANONICAL_WORK_ROOT SCANNER_UID SCANNER_GID PINNED_TOOL_LOCK
```

Journal initialization requires a positive process UID and a new canonical private namespace. Serving never creates/repairs state; an unresolved or unfinished journal refuses startup. Used state is retained, not reset. The plugin journal must be outside the broker work root and must never be mounted to the broker or dispatch client. The tool lock is bounded and must be a regular non-linked file containing exactly the six known pinned scanners. The configured positive scanner UID and GID must match the shared fixed scanner profile.

The listener implements only Docker's native plugin protocol. Its parent must be owned canonical mode 0700, socket mode 0600; it is not a client API and must never be exposed over TCP or through the controller. Host administrators and the dedicated daemon are trusted. Clients do not supply policy, paths, tool pins or journal parameters.

This profile disables daemon auto-removal so a successful explicit DELETE 204, rather than a client-only not-found error, settles the plugin journal. Unknown or failed removals remain quarantined. The earlier packaged worker retains its original auto-removal behavior.

The CI workflow's `isolated-engine-authz` job provisions a separate checksum-pinned daemon in a disposable Linux runner, preloads the exact Bandit image through a temporary bootstrap socket, then restarts that private data root with TLS client verification and this plugin. The runner's existing daemon is untouched. The test creates one-day private CA/server/broker/observer/unknown certificates, enforces the two permitted certificate common names, and rejects missing credentials or unapproved principals. It checks real scanner execution, unsafe API/profile refusals, child absence and fail-closed plugin failure. Private keys, source state and journals stay in the private runner fixture and are never included in the public evidence JSON.

Do not enable this on Docker Desktop or an existing shared daemon. The current packaged broker profile is not yet connected to this TLS experiment. Production provisioning, certificate rotation, controller/lease authentication and independent verifier/recovery integration remain unfinished. The reference test's all-engine-write and cleanup-release flags remain false, and public beta remains NO-GO.
