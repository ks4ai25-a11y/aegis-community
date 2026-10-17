# Scoped scanner reconciler enrollment

Migration 017 adds the separate `scanner-engine-reconciler` role. It explicitly reserves `confirm-fenced-cleanup-v1` for future evidence-based cleanup confirmation, scoped to one immutable retained mutation-binding digest. The protocol exposes identity, complete closed-generation metadata and one evidence-bound release operation. It has no reset, mutation-admission, response-completion or worker-lease operation. Existing worker, observer and authorizer tokens retain their existing permissions.

The local operator obtains the binding digest from the successful `scanner-authorizer bind` result, retains it privately with the original policy and namespace, and enrolls a separate credential:

```text
aegisctl scanner-reconciler enroll ID MINUTES BINDING_DIGEST ABSOLUTE_PRIVATE_FILE
aegisctl scanner-reconciler probe ABSOLUTE_PRIVATE_FILE
aegisctl scanner-reconciler revoke ID
```

Enrollment requires the provisioned repository owner and an internally consistent retained binding, including its original authorizer scope. It never selects a new binding or adopts a dispatch. A historical revoked binding remains inspectable for recovery; revocation does not turn unknown mutations into success. Lifetime is 1–1440 minutes, with at most one unexpired active reconciler per binding and 100 retained enrollments total. Identity, owner, binding, capability, credential hash, creation and expiry are immutable. Revocation is monotonic, retained and audited; exact repeated revocation is idempotent.

The new credential has a separate hash domain. The file must be new, canonical and absolute, in an owned mode 0700 directory. Delivery uses an owned single-link mode 0600 file, no replacement, positive file/directory sync and original parent identity checks before the database transaction commits. Failed validation, audit or delivery rolls back enrollment and removes only the newly owned partial file. Token bytes are never returned in JSON, command output or audit. Provision only this credential to a reconciler service; neither a worker token nor an observer or authorizer token substitutes for it.

## Private metadata protocol

The private scanner Unix socket accepts `POST /internal/v1/scanner/reconciler/identity` with an empty object, and `POST /internal/v1/scanner/reconciler/context` with exactly `job_id`, `generation_id` and a fresh 32-hex `challenge`. Cookies, browser origins, aliases, duplicates, nulls, omitted or extra fields, alternate methods and query parameters are refused. These endpoints are not mounted on the browser listener.

`alpha/workerchannel.NewReconciler` pins owner, reconciler ID, original binding, engine, registry, serving policy, protocol2 namespace and tool lock. It rereads the private credential, checks socket/parent identity, verifies canonical response shape and scope, generates a fresh request challenge and checks response freshness. Calls are bounded and cannot retry an engine mutation because this client has no engine-mutation API.

The controller reads one closed generation in one transaction and rechecks enrollment before returning. It verifies the original dispatch fingerprint, worker, deadline, guard and protocol identities. It enumerates **all** retained workspace reservations, launches and mutations for that job/generation, including pending obligations and orphaned records that must cause refusal. The caller supplies no list of tools, containers, workspaces or intents to filter. Bounds are six selected tools, six workspaces, six launches, 18 mutations and 63 KiB for the snapshot. Empty records are explicit arrays and remain metadata; they do not prove that no resources exist.

The stable `membership_digest` covers the complete original scope, dispatch fingerprint and every returned record/state. Observation time, challenge and reconciler enrollment are outside that stable digest, while the response binds all three separately. Completion of an intent, a new removal obligation or a dispatch/job change invalidates prior membership. Fresh reads of unchanged membership retain its digest and use distinct challenges. Neither a raw lease token nor its stored token hash is disclosed.

Every context retains `metadata_only=true`, `cleanup_required=true`, `cleanup_release_authorized=false` and `engine_writes_authorized=false`. Reading does not write an audit entry, renew a lease, close a generation, settle a pending response, remove a container or delete a dispatch. Original scope remains readable after authorizer withdrawal or removal of current host selections; it is not relabelled to a successor or a replacement namespace.

## Independent cleanup release (migration 018)

`POST /internal/v1/scanner/reconciler/confirm` takes exactly `job_id`, `generation_id`, `membership_digest`, `engine_digest`, `registry_namespace_digest` and `absent` (one `{tool_id, container, engine_id}` per retained launch, sorted by tool). In one transaction the controller rechecks the enrollment, recomputes complete membership, and refuses unless all of these hold:

- the job is terminal and its dispatch is `cleanup_required` with a closed generation;
- the recomputed membership digest equals the one the reconciler observed;
- every mutation obligation is completed, each confirmed create has a confirmed removal, and there is no start/remove without a create and no obligation without a launch;
- the absences equal exactly what membership requires;
- engine and namespace equal the original binding.

Only then does it record an immutable, retained confirmation (`scanner_cleanup_confirmations`), move the generation `closed`→`released`, delete the held dispatch and audit `scanner.cleanup_confirmed`. An exact replay returns the stored confirmation. A different request for a released job is refused. Unknown or pending mutations keep the hold indefinitely; there is no repair or override path.

The operator runs the release with the reconciler's own credential and the observer's own engine TLS identity:

```text
aegis-research reconcile-cleanup PRIVATE_RECONCILE_CONFIG JOB GENERATION
```

The private config (owner-only mode, at most 8 KiB, exact fields) names the controller socket, reconciler credential, original binding scope, canonical source root, original workspace registry, observer endpoint/identity and broker public certificate. The command reads a fresh snapshot while holding the original registry empty under its approved namespace (`workspace.WithBoundEmptyRegistry`). It derives the required absences, observes each exact engine ID and name absent on the original engine (bracketed by engine identity checks), and only then asks the controller to release. A launch whose create was never admitted is observed by name only. Run the reconciler as the scanner UID that owns the workspace registry (the barrier accepts only files owned by its caller), and give it only its own observer identity: never mount the broker's client key, worker credential or authorizer credential into it.

## Recovery

Recovery manifests support verified database prefixes 13–18 without offline upgrades. Versions 17 and 18 require the reconciler and confirmation tables respectively; older declared versions must not contain them. Restore revokes every active reconciler while preserving its immutable original scope, pending mutation records, confirmations and scanner cleanup holds. Restored credentials cannot authenticate.

Local checks include role/credential isolation, immutable scope, expiry/revocation, failed issuance and audit rollback, complete pending membership, stable/fresh snapshot identities, hostile wire shapes, actual controller/alpha Unix RPC, older migration preservation and restored-role revocation. Fixed contract samples use only synthetic labels and dates and contain no issued credential or runtime evidence.

Source commit `d9c695d67e262b2c3240bf24298e8c6af7b9a173` passed all four jobs in [hosted run39004111180](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39004111180), including local protocol checks and the existing guarded packaged/native regressions. This does not establish native mediation, repair, independent release or two sequential scans.
