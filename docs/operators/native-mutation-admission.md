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

The existing Compose `serve-bound` overlay continues to provide its older observation-only mode. The separate `deploy/compose.scanner-authorizer-admitted.yaml` overlay uses profile `operator-engine-admission` and `serve-admitted`. It requires `AEGIS_SCANNER_AUTHORIZER_ID`, `AEGIS_SCANNER_REGISTRY_NAMESPACE` and `AEGIS_SCANNER_ADMISSION_CREDENTIAL_VOLUME` in addition to the approved engine, registry, owner and authorizer-root settings. Its credential volume is mounted read-only at `/run/authorizer-credential`; no observer or worker credential is mounted there. Expand and review the configuration before starting only the dedicated daemon plugin. A generation-enabled dispatch refuses the old observer live-launch path. The new isolated Linux CI acceptance is configured to exercise actual Bandit through this admitted overlay, compare private controller/native records and retain the second-job hold; hosted run [38997831312](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/38997831312) passed for exact commit `47bf385821f9b937eb6213d765558d8e36fd41e3`, including this actual-daemon step and all existing regressions. This verifies that bounded admission test; independent reconciliation and cleanup release remain unfinished.

## Mutation and response ordering

For every create/start/remove, the plugin checks the exact allowed native request and obtains a challenge-bound lookup of the registered launch, original generation and selected scope. Create/start additionally verify fixed tool/profile and physical source/guard/rules snapshots. A local one-shot journal entry retains the exact proposed controller intent before admission is requested. The controller transaction rechecks authority and durably records an obligation before the plugin replies `Allow:true`. Admission replay never means another engine call.

A native successful response is synced locally first. The plugin then acknowledges the exact retained intent, native container ID/status and durable response digest to the controller. Only successful create201/start204/remove204 responses complete obligations. Denied, missing or uncertain responses remain held. Cancellation closes new create/start admission while allowing separately admitted removal of the exact tracked allocation after earlier mutations are settled.

A lost successful completion acknowledgement can be reconciled by repeating the exact native response callback metadata, without repeating the engine mutation or rewriting its local response record. Changed callback status/body is refused. Tests deliberately lose an acknowledgement after its controller transaction commits. The controller authenticates an exact already-completed acknowledgement against its original retained binding even after that generation is released or the dispatch is replaced. This read returns the retained response without writing an audit entry, settling any pending intent, consulting the successor dispatch or permitting an engine retry. Revoked or expired authorizers remain refused. Pending completion still requires the existing allocation checks. Tests simulate the future release state directly; they do not provide a production release endpoint or independent absence proof.

Used journals cannot be downgraded to another serving configuration, mixed with legacy attempt records or relabelled to another generation. Restart still refuses unfinished/uncertain execution; a sealed quarantine-serving and explicit evidence-based repair protocol remain required. Preserve unknown state. Do not delete journals, rotate namespaces, clear SQL holds or retry native mutations to make another scan run.

The TLS identity loader also accepts an explicitly requested `aegis-engine-observer` certificate and retains that role for every credential recheck and TLS refresh. Broker and observer certificates cannot substitute for each other. The bounded read-only client is documented in [Independent scanner engine observation](independent-engine-observer.md). It does not implement reconciliation or grant the observer any mutation or release authority.

No successful native callback, settled journal or controller ledger entry is independent proof of engine absence. The dispatch slot remains held until the unfinished reconciliation/release protocol supplies that proof under the original workspace barrier. Public beta and complete-v4 status remain NO-GO.
