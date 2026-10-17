# Native scanner mutation admission

This experimental mode connects the isolated scanner daemon's native authorization plugin to the controller's retained mutation ledger. It is a step toward ADR057 cleanup release. Independent reconciliation, release and two actual sequential packaged scans remain unfinished. Local protocol/policy tests are not proof that the packaged daemon path has passed.

Use only a separately provisioned scanner daemon and unprivileged native Linux scanner identity. Do not enable it on a workstation or shared application daemon. The plugin receives its own controller credential and private journal, with source/registry and controller socket mounts read-only. It needs no daemon socket, engine client certificates, network access or worker credential. Its controller role is `scanner-engine-authorizer`; existing observer credentials remain read-only.

## Provision the exact serving configuration

1. Initialize a fresh registry using `aegis-research workspace-registry-init CANONICAL_NEW_REGISTRY`. Retain its protocol2 namespace digest. Existing or partial registries cannot be promoted or reset. Provision the ordinary engine, broker-journal and worker bindings through the existing local operator commands.
2. Initialize a fresh private plugin journal using `aegis-engine-authz init JOURNAL ENGINE_DIGEST`.
3. Compute the policy input in the same path, UID/GID and filesystem view that the final plugin will use:

```text
aegis-engine-authz admitted-policy-input PLUGIN_SOCKET JOURNAL ENGINE_DIGEST WORK_ROOT UID GID TOOL_LOCK CONTROLLER_SOCKET AUTHORIZER_CREDENTIAL OWNER AUTHORIZER_ID REGISTRY_DIGEST REGISTRY_NAMESPACE_DIGEST RULES_DIGEST_OR_DASH
```

The command reads existing namespace/tool identities and returns a policy digest with authority flags false. It does not contact a controller or engine, create a credential, open a listener or write a serving-policy seal. The future credential/controller socket may be absent; their canonical parent paths must already exist. Compute inside the final container layout if using a container: host and container paths/UIDs are not interchangeable.

4. On the controller's trusted local operator surface, enroll and select that exact policy and registry namespace:

```text
aegisctl scanner-authorizer enroll AUTHORIZER_ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST POLICY_DIGEST PRIVATE_CREDENTIAL_FILE
aegisctl scanner-authorizer bind AUTHORIZER_ID REGISTRY_NAMESPACE_DIGEST
```

Enrollment writes only the private credential. Selection requires the existing engine/journal/broker scope and refuses adopting an outstanding dispatch or replacing active selection. Deliver the credential through an owned private directory and read-only mount. Its configured serving path is part of the policy input; do not expose bytes in logs or browser responses. Revocation retains history and revokes the selected binding without freeing a dispatch.

5. Start the plugin using the same arguments as the input command, replacing `admitted-policy-input` with `serve-admitted`. Configure only the dedicated daemon's authorization-plugin path. Successful startup authenticates the authorizer and selected binding, checks the original protocol2 namespace, and seals the journal to both the policy and selected binding digest. The selected binding is deliberately excluded from the earlier policy digest to avoid circular approval; it is included in the serving journal seal.

The existing Compose `serve-bound` overlay continues to provide its older observation-only mode. It does not activate this protocol. A generation-enabled dispatch refuses the old observer live-launch path, so the old serving mode cannot substitute for ledger admission. Packaged admitted-mode integration and daemon acceptance still need to be completed.

## Mutation and response ordering

For every create/start/remove, the plugin checks the exact allowed native request and obtains a challenge-bound lookup of the registered launch, original generation and selected scope. Create/start additionally verify fixed tool/profile and physical source/guard/rules snapshots. A local one-shot journal entry retains the exact proposed controller intent before admission is requested. The controller transaction rechecks authority and durably records an obligation before the plugin replies `Allow:true`. Admission replay never means another engine call.

A native successful response is synced locally first. The plugin then acknowledges the exact retained intent, native container ID/status and durable response digest to the controller. Only successful create201/start204/remove204 responses complete obligations. Denied, missing or uncertain responses remain held. Cancellation closes new create/start admission while allowing separately admitted removal of the exact tracked allocation after earlier mutations are settled.

A lost successful completion acknowledgement can be reconciled by repeating the exact native response callback metadata, without repeating the engine mutation or rewriting its local response record. Changed callback status/body is refused. Tests deliberately lose an acknowledgement after its controller transaction commits. Independent release must also account for this boundary before it is enabled.

Used journals cannot be downgraded to another serving configuration, mixed with legacy attempt records or relabelled to another generation. Restart still refuses unfinished/uncertain execution; a sealed quarantine-serving and explicit evidence-based repair protocol remain required. Preserve unknown state. Do not delete journals, rotate namespaces, clear SQL holds or retry native mutations to make another scan run.

No successful native callback, settled journal or controller ledger entry is independent proof of engine absence. The dispatch slot remains held until the unfinished reconciliation/release protocol supplies that proof under the original workspace barrier. Public beta and complete-v4 status remain NO-GO.
