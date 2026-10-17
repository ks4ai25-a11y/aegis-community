# Native scanner mutation admission

This experimental mode connects the isolated scanner daemon's native authorization plugin to the controller's retained mutation ledger. It is part of ADR 057 cleanup release. Independent reconciliation and release between two sequential packaged scans have passed hosted CI (see [reconciler operations](scanner-reconcilers.md)). Sealed crash repair passed hosted CI at `0f246ee` ([run 39032841061](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39032841061), `not_created` path) and gates CI. Local protocol and policy tests do not prove that the packaged daemon path has passed.

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

## API write mediation

The plugin is default-deny. On the dedicated daemon it allows only:

- exact reads: `/info`, the pinned tool images, the tracked child, and the observer's journal-known children;
- the broker's `wait` and output-only `attach` of its own tracked child;
- the journalled, controller-admitted create, start and remove of one registered launch.

It refuses every other method, path, version prefix, encoding alias and principal. Docker runs the authorization middleware before its version and experimental checks on every routed API handler (reviewed in the `docker-v29.0.0` source; CI pins 29.8.2). An unrouted path reaches no handler. A non-JSON or oversized body is left out of the plugin envelope. Create therefore requires an exact JSON body, and start and remove require an empty one.

What is tested:

- **Locally**, `alpha/engineauthz/mediation_test.go` sends 116 enumerated requests. They cover the Docker v1.55 write surface (containers, exec, images, build/session/grpc, volumes, networks, plugins, swarm services/nodes/secrets/configs and auth) plus version, case and encoding aliases of the admitted forms. Each is sent as the broker, the observer, an unknown principal and an anonymous one, in all seven lifecycle states, and also as a forged response callback. Every one is refused, and the journal and pending ticket do not change. A method sweep over every URI shows that the only allowed non-GET requests are the exact admitted forms.
- **In hosted CI**, on the admitted packaged path (`AEGIS_PACKAGED_ADMISSION_TEST`, including the two-scan reconcile step), the fixture sends the same surface to the real TLS daemon as both broker and observer. Each of the 94 routed requests must return 403 with this plugin's refusal message. The 22 aliases must not succeed. The plugin journal and a root-read digest of the daemon's data root (outside the API) must not change. The daemon must have exactly one TCP listener, the TLS port, and no Unix listener outside its private roots. Every other socket in the fixture root must be unreachable by the scanner UID.

This proves that, on that packaged path, a Docker Engine API request that would create, start, modify, exec into or delete engine state is either admitted against a controller intent or refused. It does not cover:

- root on the host, the daemon's private containerd socket, or editing the plugin spec or daemon configuration and reloading it;
- other Docker versions;
- exec against a *running* scanner child on the real daemon. CI probes non-existent targets, and the plugin refuses by path before the daemon looks the target up. Running-state refusal is a local test.

`all_engine_writes_mediated` therefore stays `false` in journal status and evidence. The narrower field `enumerated_unadmitted_api_writes_refused` records the CI result. It first passed at commit `52217c2` in hosted [run 39021222919](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39021222919). See [the evidence record](../evidence/packaged-api-write-mediation-ci.json).

## Mutation and response ordering

For every create/start/remove, the plugin checks the exact allowed native request and obtains a challenge-bound lookup of the registered launch, original generation and selected scope. Create/start additionally verify fixed tool/profile and physical source/guard/rules snapshots. A local one-shot journal entry retains the exact proposed controller intent before admission is requested. The controller transaction rechecks authority and durably records an obligation before the plugin replies `Allow:true`. Admission replay never means another engine call.

A native successful response is synced locally first. The plugin then acknowledges the exact retained intent, native container ID/status and durable response digest to the controller. Only successful create201/start204/remove204 responses complete obligations. Denied, missing or uncertain responses remain held. Cancellation closes new create/start admission while allowing separately admitted removal of the exact tracked allocation after earlier mutations are settled.

A lost successful completion acknowledgement can be reconciled by repeating the exact native response callback metadata, without repeating the engine mutation or rewriting its local response record. Changed callback status/body is refused. Tests deliberately lose an acknowledgement after its controller transaction commits. The controller authenticates an exact already-completed acknowledgement against its original retained binding even after that generation is released or the dispatch is replaced. This read returns the retained response without writing an audit entry, settling any pending intent, consulting the successor dispatch or permitting an engine retry. Revoked or expired authorizers remain refused. Pending completion still requires the existing allocation checks. Tests simulate the future release state directly; they do not provide a production release endpoint or independent absence proof.

Used journals cannot be downgraded to another serving configuration, mixed with legacy attempt records or relabelled to another generation. Admitted restart still refuses unfinished or uncertain execution. `serve-quarantine`, with the same arguments, reopens such a journal in sealed quarantine for the explicit, evidence-based repair in [the reconciler runbook](scanner-reconcilers.md#sealed-crash-repair) and ADR 057. Quarantine serving never allows a create or a start. `quarantine-settle` then records the controller's retained repairs locally so admitted serving can resume. Preserve unknown state. Do not delete journals, rotate namespaces, clear SQL holds or retry native mutations to make another scan run.

The TLS identity loader also accepts an explicitly requested `aegis-engine-observer` certificate and retains that role for every credential recheck and TLS refresh. Broker and observer certificates cannot substitute for each other. The bounded read-only client is documented in [Independent scanner engine observation](independent-engine-observer.md). It does not implement reconciliation or grant the observer any mutation or release authority.

No successful native callback, settled journal or controller ledger entry is independent proof of engine absence. The dispatch slot remains held until the unfinished reconciliation/release protocol supplies that proof under the original workspace barrier. Public beta and complete-v4 status remain NO-GO.

The native plugin rechecks the current validity interval, client-auth usage and exact role of the daemon-authenticated PEM certificate envelope for every request and response callback, including reused TLS connections. Missing, malformed, oversized, expired, future or mismatched peer envelopes are refused. Callback identity includes the original certificate bytes; a replacement same-name certificate cannot acknowledge a different peer’s pending request. Expiry during an operation retains the unresolved obligation. These checks rely on the dedicated daemon’s verified TLS session and private plugin socket; they do not establish complete engine mediation or cleanup authority.
