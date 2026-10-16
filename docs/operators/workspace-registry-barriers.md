# Workspace registry barriers

The workspace package now provides a synchronous filesystem barrier for the remaining [ADR 057](../architecture/adr/057-scanner-allocation-fencing-and-cleanup-release.md) reconciliation work. It does not release a controller dispatch slot or establish engine absence.

On the dedicated scanner host, run the native tool as the actual unprivileged scanner UID:

```text
aegis-research workspace-registry-init CANONICAL_NEW_REGISTRY
```

The path must be absent, absolute and canonical. Its parent must be controlled by the operator or root, with no unprotected group/other write access. Trusted sticky temporary directories are supported. Existing, partial and linked registries are refused without repair or reset. Errors retain new partial state for explicit review. Never change an active registry to make initialization pass.

Successful initialization creates an owned mode-0700 directory, an empty single-link mode-0600 `.registry-lock`, and a single-link mode-0600 `.registry.json`. The canonical namespace document binds a fresh random nonce, path/UID digest, actual UID, device/inode and lease protocol `2.0`. File, registry and parent directory writes are synced. The JSON result includes `registry_namespace_digest`, with controller-binding, active-lease-exclusion and cleanup-release flags all false. A digest identifies local state; it is not a credential, signature or cleanup grant.

Namespace metadata is tied to the original directory and host filesystem view. Do not copy it to another directory, restore it over a replacement registry, or relabel an existing registry. Bind-mounted use requires the same original path, UID and filesystem identity. The packaged Linux acceptance is configured to exercise this layout; its new namespace provisioning still requires a successful hosted run; other host/mount mappings must not be assumed compatible. Legacy registries remain usable through existing operations but do not gain a namespace identity implicitly. The actual pre-barrier registry implementation from `7b21072` was compiled and tested: it refuses the extra namespace entry without allocating a workspace or changing namespace bytes.

`workspace.WithBoundEmptyRegistry(ctx, path, approvedNamespace, callback)` opens existing metadata read-only, validates the original approved namespace and holds the exclusive registry kernel lock throughout a synchronous callback. It refuses absent or changed locks/namespaces, unknown entries, pending creation and occupied registries. It creates, repairs and deletes no filesystem state. The expected namespace must come from independently approved controller/operator state, never from treating the current directory as authoritative merely because it appears empty. The unbound `WithEmptyRegistry` variant provides only a local empty-registry observation and must not substitute for namespace binding.

New session creation holds this global lock across controller reservation acknowledgement and directory/lease creation. Session close also takes the same lock, validates original root/lock/workspace/lease identity, closes the lifecycle lease before deleting the workspace through a confined directory handle, and syncs the registry before success. Lock contention or uncertain lease closure preserves the occupied workspace. Partial directory removal may finish on the same live session only after its lease was positively closed; unrelated/substituted paths are never selected for deletion. Unknown state continues to block later admission. Recovery remains a separate operator operation with its existing requirements.

A callback must finish synchronously while the lock is held. Returning from a standalone observation and later calling a release operation would lose this barrier. The filesystem primitive is not an atomic transaction with the controller or engine: durable generation closure, mutation admission/completion, independent exact-allocation observation, original namespace binding and a scoped reconciliation capability still need to be integrated and tested. Existing verifier credentials remain read-only. Full v4 and public beta remain NO-GO.
