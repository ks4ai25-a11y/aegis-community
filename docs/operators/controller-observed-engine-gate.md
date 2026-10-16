# Controller-observed native daemon gate

This opt-in mode adds current controller observations and source/guard byte checks to the isolated native authorization plugin. It retains cleanup holds and does not provide atomic cancellation fencing or cleanup release. Read [ADR 054](../architecture/adr/054-controller-observed-daemon-launch-preconditions.md) and the existing [dedicated engine requirements](isolated-engine-authorization.md), including TLS-only principals, native HTTP/2 exclusion, finite profile and separate plugin journal.

Build with `make engine-authz-build`. The plugin runs as the same non-root UID/GID that owns the canonical scanner workspace registry and reported source/guard files. Give it a separate private observer credential scoped to the exact owner/engine/registry, and access to the controller's private Unix socket. Do not give either to a tool or dispatcher; the broker must not receive the plugin's observer capability or journal. The plugin needs no raw engine socket, Docker group, engine client key or network access.

Provision the engine/journal/selected-broker chain and observer enrollment through the existing operator operations. Initialize a fresh, separate plugin journal explicitly, then run:

```text
aegis-engine-authz init PLUGIN_JOURNAL ENGINE_DIGEST
aegis-engine-authz serve-bound PLUGIN_SOCKET PLUGIN_JOURNAL ENGINE_DIGEST CANONICAL_WORK_ROOT UID GID TOOL_LOCK CONTROLLER_SOCKET OBSERVER_CREDENTIAL OWNER VERIFIER_ID REGISTRY_DIGEST RULES_DIGEST_OR_DASH
```

`ENGINE_DIGEST` is the immutable controller-approved scanner engine identity, not an unrelated hash used by an earlier unbound experiment. `REGISTRY_DIGEST` must match the canonical work root and UID. `RULES_DIGEST_OR_DASH` is the independently approved Semgrep snapshot digest, or `-` to refuse Semgrep. A tool lock pin does not by itself pin rule bytes. Paths/configuration are local operator inputs; the engine caller cannot override them. The observer's owned mode-0600 file and mode-0700 parent/channel requirements still apply. Keep runtime metadata and configuration private.

The first bound open seals the exact local configuration in an unused journal. Reopening with the same configuration is supported. Unbound mode, changed paths, identities, rules or tool subset are refused on that namespace. A previously used unbound journal cannot be repurposed. Keep retained state; there is no rotation, repair or reset procedure that grants authority to a replacement namespace. Expired/revoked enrollment and missing controller access deny new creates/starts. Existing unresolved/unfinished plugin state still refuses restart and requires independent reconciliation, which is not implemented yet.

The controller launch must already exist as revision 1.2 and match the exact create profile, workspace, snapshot, guard, tool/version/image, duration/deadline and full current binding chain. Both create and start perform fresh observations before and after bounded byte checks. A tracked remove remains possible after a later start denial, but a settled local journal never proves controller cleanup or clears admission.

The baseline packaged broker/TLS regression retains its earlier mode. An additional [packaged authorizer profile and dedicated CI journey](packaged-controller-authorizer.md) now exercise this bound integration. Its controller socket is a private orchestration volume; copying an ambient host daemon path or adding broad daemon access is not a deployment solution. The separate package supplies narrowly mounted private channel/capability, read-only canonical workspace mirror and exclusive writable plugin journal/socket. Deployment-specific exclusive enforcement, mutation race/fault coverage and cleanup fencing remain required. Default services and public-beta status remain unchanged.
