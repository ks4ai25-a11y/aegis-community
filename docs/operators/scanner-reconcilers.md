# Scanner cleanup reconciler: enrol, release, recover

After a scan finishes, Aegis keeps the scanner slot **held** until something independent of the scan worker confirms that every container the scan created is gone. The reconciler does that check. It has its own credential, reads the controller's complete record of what the scan did, observes the original engine read-only, and only then asks the controller to release the slot. The controller re-checks everything itself before it releases.

A worker reporting success, an empty journal, an expired lease or a single "not found" never releases a slot on its own.

## Terms

- **Scanner slot (dispatch):** the single execution slot a scan holds. While it is held, no other scan can start.
- **Generation:** the identifier of one scan's allocation record. You pass it to the release command.
- **Mutation binding:** the operator-approved pairing of an authorizer, engine, registry and registry namespace that every engine write of a scan is admitted through. Its digest is printed by `aegisctl scanner-authorizer bind`.
- **Membership digest:** a fingerprint of everything the controller recorded for one scan. Release is refused if it changed after the reconciler looked.
- **Registry barrier:** the reconciler holds the original workspace registry locked and empty while it checks, so no new scan workspace can appear mid-check.

## Release a held scanner slot

1. **Enrol a reconciler** (once per binding; lifetime 1–1440 minutes):

   ```text
   aegisctl scanner-reconciler enroll reconciler-1 60 BINDING_DIGEST /private/aegis/reconciler/reconciler.credential
   aegisctl scanner-reconciler probe /private/aegis/reconciler/reconciler.credential
   ```

2. **Write the private config.** It must be an absolute path to a regular, single-link file owned by the reconciler's user with mode `0600`, at most 8 KiB, containing exactly these fields:

   ```json
   {
     "controller_socket": "/run/scanner/worker.sock",
     "reconciler_credential_file": "/run/reconciler-credential/reconciler.credential",
     "owner_id": "OWNER_ID",
     "reconciler_id": "reconciler-1",
     "binding_digest": "sha256:… (from scanner-authorizer bind)",
     "engine_digest": "sha256:… (the bound engine)",
     "registry_digest": "sha256:… (the bound registry)",
     "policy_digest": "sha256:… (the selected native policy)",
     "registry_namespace_digest": "sha256:… (from workspace-registry-init)",
     "canonical_aegis_source_root": "/opt/aegis",
     "canonical_workspace_registry": "/path/to/aegis-scanner-workspaces-10001",
     "observer_endpoint": "unix:///run/engine/docker.sock",
     "observer_identity_directory": "/private/aegis/observer-client",
     "broker_certificate_file": "/private/aegis/observer-public/broker.pem"
   }
   ```

   The observer identity directory holds the observer's own `ca.pem`, `client.pem` and `client.key`. Never put the broker's client key, a worker credential or an authorizer credential in the reconciler's reach.

3. **Find the held job and generation:**

   ```text
   aegisctl scanner-reconciler held
   ```

   It prints `Held for cleanup: job JOB generation GENERATION …`, or that no slot is held.

4. **Run the release** as the scanner user that owns the workspace registry, in the reconciler's own container:

   ```text
   aegis-research reconcile-cleanup /private/aegis/reconcile/config.json JOB GENERATION
   ```

5. **Check it worked.** The command prints the stored confirmation (`"dispatch_released": true`). The audit log records `scanner.cleanup_confirmed`. The Scans page shows the job's scanner slot as **Released**, and the next queued scan can be claimed.

Run the release after each finished scan, by hand or from a timer. A finished scan holds the slot until it is released.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Released. Repeating the command afterwards fails, because nothing is left to release. |
| 1 | Not released, or invalid arguments. The slot stays held; nothing was changed. |
| 3 | Released, but the registry barrier's closing check failed. Inspect the workspace registry before the next scan. |

## When a slot cannot be released

The controller refuses to release while any engine write of the scan is unresolved. Examples:

- a create, start or remove was admitted but its native response was never recorded;
- a created container has no recorded removal;
- the job is still running.

It also refuses when the observation does not match exactly. There is no override or reset. Scanning stays blocked for that owner until the cause is resolved.

- **If the job is still running or the lease is live:** wait. The controller closes the job when the lease expires, then retry.
- **If a write is unresolved:** inspect the engine and the authorizer's journal by hand. Supported repair of half-finished writes is not yet available. Until it is, a slot whose writes are unknown stays held, which is deliberate: releasing it could let a second scan run beside a container that still exists.
- **After a restore from a backup bundle:** the restored slot cannot be released, because restore revokes the binding and the restored record may be missing later scans. Start from a new binding.

## Limits of independence

- **Shared OS user.** The registry barrier and private-file checks require the reconciler to run as the scanner user. So its credential and observer key are owned by the same user as the worker's files, and only container and mount boundaries separate the roles. The controller cannot observe absence itself; anything that can read the reconciler credential could request a release. Run the reconciler in its own container and never mount its credential anywhere else. A reconciler under a separate OS user is future work.
- **Workspaces.** The controller checks container absence against the scan's recorded launches. Workspace cleanup is enforced by the reconciler holding the original registry empty.
- **What counts as absent.** Only the engine's own "No such container" answer for both the exact container ID and the exact name, with the engine identity checked before and after. A launch whose create was never admitted is checked by name only.
- **Lost replies.** If a confirmation reply is lost, any later reconciler enrolled on the same binding can read it back by repeating the request.

## Recovery

Recovery bundles support database versions 13–19. Restore revokes every active reconciler and keeps its original scope, every pending record, every confirmation and every held slot. Restored reconciler credentials cannot authenticate.

## Reference

### Enrollment

Enrollment requires the provisioned repository owner and an internally consistent retained binding, including its original authorizer scope. It never selects a new binding or adopts a dispatch. A historical revoked binding remains inspectable for recovery; revocation does not turn unknown mutations into success. Lifetime is 1–1440 minutes, with at most one unexpired active reconciler per binding and 100 retained enrollments total. Identity, owner, binding, capability, credential hash, creation and expiry are immutable. Revocation is monotonic, retained and audited; exact repeated revocation is idempotent.

The new credential has a separate hash domain. The file must be new, canonical and absolute, in an owned mode 0700 directory. Delivery uses an owned single-link mode 0600 file, no replacement, positive file/directory sync and original parent identity checks before the database transaction commits. Failed validation, audit or delivery rolls back enrollment and removes only the newly owned partial file. Token bytes are never returned in JSON, command output or audit. Provision only this credential to a reconciler service; neither a worker token nor an observer or authorizer token substitutes for it.

### Metadata snapshot

The private scanner Unix socket accepts `POST /internal/v1/scanner/reconciler/identity` with an empty object, and `POST /internal/v1/scanner/reconciler/context` with exactly `job_id`, `generation_id` and a fresh 32-hex `challenge`. Cookies, browser origins, aliases, duplicates, nulls, omitted or extra fields, alternate methods and query parameters are refused. These endpoints are not mounted on the browser listener.

The reconciler client pins owner, reconciler ID, original binding, engine, registry, serving policy, registry namespace and tool lock. It rereads the private credential, checks socket/parent identity, verifies canonical response shape and scope, generates a fresh request challenge and checks response freshness. Calls are bounded and cannot retry an engine mutation because this client has no engine-mutation API.

The controller reads one closed generation in one transaction and rechecks enrollment before returning. It verifies the original dispatch fingerprint, worker, deadline, guard and protocol identities. It enumerates **all** retained workspace reservations, launches and mutations for that job/generation, including pending obligations and orphaned records that must cause refusal. The caller supplies no list of tools, containers, workspaces or intents to filter. Bounds are six selected tools, six workspaces, six launches, 18 mutations and 63 KiB for the snapshot. Empty records are explicit arrays and remain metadata; they do not prove that no resources exist.

The stable `membership_digest` covers the complete original scope, dispatch fingerprint and every returned record/state. Observation time, challenge and reconciler enrollment are outside that stable digest, while the response binds all three separately. Completion of an intent, a new removal obligation or a dispatch/job change invalidates prior membership. Fresh reads of unchanged membership retain its digest and use distinct challenges. Neither a raw lease token nor its stored token hash is disclosed.

Every context retains `metadata_only=true`, `cleanup_required=true`, `cleanup_release_authorized=false` and `engine_writes_authorized=false`. Reading does not write an audit entry, renew a lease, close a generation, settle a pending response, remove a container or delete a dispatch. Original scope remains readable after authorizer withdrawal or removal of current host selections; it is not relabelled to a successor or a replacement namespace.

### Release transaction

`POST /internal/v1/scanner/reconciler/confirm` takes exactly `job_id`, `generation_id`, `membership_digest`, `engine_digest`, `registry_namespace_digest` and `absent` (one `{tool_id, container, engine_id}` per retained launch, sorted by tool). In one transaction the controller rechecks the enrollment, recomputes complete membership, and refuses unless all of these hold:

- the job is terminal and its dispatch is `cleanup_required` with a closed generation;
- the recomputed membership digest equals the one the reconciler observed;
- every mutation obligation is completed, each confirmed create has a confirmed removal, and there is no start/remove without a create and no obligation without a launch;
- the absences equal exactly what membership requires;
- engine and namespace equal the original binding.

Only then does it record an immutable, retained confirmation (`scanner_cleanup_confirmations`), move the generation `closed`→`released`, delete the held dispatch and audit `scanner.cleanup_confirmed`. An exact replay returns the stored confirmation. A different request for a released job is refused. Unknown or pending mutations keep the hold indefinitely; there is no repair or override path.

The database itself refuses to mark a generation released without a matching confirmation, and refuses confirmation rows that point at another job's generation or carry malformed digests.

### Evidence

Local checks include role/credential isolation, immutable scope, expiry/revocation, failed issuance and audit rollback, complete pending membership, stable/fresh snapshot identities, hostile wire shapes, actual controller/alpha Unix RPC, older migration preservation and restored-role revocation. Fixed contract samples use only synthetic labels and dates and contain no issued credential or runtime evidence.

Hosted CI run [39013987465](https://github.com/ks4ai25-a11y/aegis-community/actions/runs/39013987465) at commit `4a8c616` ran two real scans in a row through the packaged controller, authorizer and TLS engine path, with one independent release between them (26 checks). That step now gates CI. It does not prove that every engine write is mediated, and it does not cover repair of half-finished writes.
