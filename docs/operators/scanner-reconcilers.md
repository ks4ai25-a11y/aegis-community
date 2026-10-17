# Scoped scanner reconciler enrollment

Migration 017 adds the separate `scanner-engine-reconciler` role. It explicitly reserves `confirm-fenced-cleanup-v1` for future evidence-based cleanup confirmation, scoped to one immutable retained mutation-binding digest. The current protocol exposes identity and complete closed-generation metadata only. It has no release, reset, mutation-admission, response-completion or worker-lease operation. Existing worker, observer and authorizer tokens retain their existing permissions.

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

## Recovery and remaining release work

Recovery manifests now support verified database prefixes 13–17 without offline upgrades. Version 17 requires the reconciler table; older declared versions must not contain it. Restore revokes every active reconciler while preserving its immutable original scope, pending mutation records and scanner cleanup holds. Restored credentials cannot authenticate. Existing earlier-prefix compatibility and automatic-rescan consent quarantine remain in force.

The reconciler enrollment and metadata snapshot are prerequisites for ADR 057. Actual native mediation/fencing proof, sealed quarantine and explicit response repair, an independently observed complete allocation set, the original empty-registry barrier, and the final atomic/idempotent controller confirmation are still required before any release endpoint is enabled. A worker success, empty snapshot, settled journal, expired lease or404 alone cannot discharge an unknown mutation. Two actual sequential packaged scans with independent reconciliation remain unfinished.

Local checks include role/credential isolation, immutable scope, expiry/revocation, failed issuance and audit rollback, complete pending membership, stable/fresh snapshot identities, hostile wire shapes, actual controller/alpha Unix RPC, older migration preservation and restored-role revocation. Fixed contract samples use only synthetic labels and dates and contain no issued credential or runtime evidence.

Source commit `d9c695d67e262b2c3240bf24298e8c6af7b9a173` passed all four jobs in [hosted run39004111180](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39004111180), including local protocol checks and the existing guarded packaged/native regressions. This does not establish native mediation, repair, independent release or two sequential scans.
