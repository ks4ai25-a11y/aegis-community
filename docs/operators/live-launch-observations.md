# Private observations of an approved live scanner launch

This operator-only read is a prerequisite for daemon authorization integration. It does not authorize an engine write or verify/release cleanup. The daemon plugin does not yet consume it. Read [ADR 053](../architecture/adr/053-fresh-controller-launch-observations.md).

Provision the existing private observer enrollment as described in [verifier context operations](scanner-verifier-context.md). Its owner, engine and registry must match the immutable engine/journal/selected-broker approval chain. The exact launch must already be registered as guarded revision 1.2, while its job and worker lease remain active. An old unbound launch, expired/cancelled job, changed scope or cleanup-held dispatch is refused.

Build with `make research-build`, then use the private capability file and exact proposed container name:

```text
aegis-research verifier-live-launch PRIVATE_SOCKET PRIVATE_CREDENTIAL_FILE OWNER VERIFIER_ID ENGINE_DIGEST REGISTRY_DIGEST CANONICAL_AEGIS_SOURCE_ROOT CONTAINER_NAME
```

The final argument is the original `aegis-scan-<32 hex>` name from the immutable launch context. No raw Docker ID, URL, command, image, lease token or filesystem override is accepted. Credential contents remain in the owned mode-0600 file; the existing mode-0700 private parent/socket requirements apply. Keep the returned scoped runtime metadata private. Public reference evidence records test statuses only.

The client generates a new 128-bit challenge, authenticates the observer identity, validates the digest/binding chain and refuses stale, expired, malformed or mismatched replies. Each read has a five-second ceiling and a 64 KiB response bound. It does not renew the worker lease or keep a job alive. The controller returns a read-only snapshot; revocation/cancellation may occur immediately after observation. Both engine-write and cleanup-release authority flags are false. Do not cache a reply as permission, clear a hold, delete a journal or promote static findings based on this response.

For integrations, the private request is `POST /internal/v1/scanner/verifier/live-launch` with `container_name` and a 32-character lowercase hexadecimal `challenge`. Use `workerchannel.VerifierClient.LiveLaunch` to get challenge generation, freshness, private capability rechecks and strict response validation. The endpoint is absent from browser routes. Observer and worker capability domains are separate. Independent durable engine authorization and cleanup remain unfinished.
