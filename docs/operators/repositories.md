# Read-only repository connection

Start the bundled demo normally and sign into the local console. Open **Repositories**, select `safe` or `vulnerable`, review the read-only acknowledgement, then connect. The displayed map identifies included files and source content. The bundled fixtures have no Git commit metadata; the UI reports it as unavailable.

Connecting performs only static inventory. It never runs `postinstall`, git hooks, source code, tests or package installation. Declared routes come from Next.js file conventions and from literal route registrations in Express (`app.get('/x', ...)`, `router.post(...)` on objects created by `express()` / `Router()`), FastAPI (`@app.get`, `@router.post`, `api_route`, with `APIRouter(prefix=...)`) and Flask (`@app.route(..., methods=[...])`, `@bp.get`, with `Blueprint(url_prefix=...)`). Prefixes are resolved only within the same file; a router or blueprint registered from another file is marked low confidence because its real prefix is unknown. Path parameters become `{parameter}` so they can be compared with gateway route templates. The authorization signal is `auth_middleware_named` when a middleware, decorator or FastAPI dependency on that route has a name suggesting authentication (for example `requireAuth`, `login_required`, `Depends(get_current_user)`). That is a hint, not proof the check is correct or enforced. Computed paths, loops and dynamic registration are not read. An empty route list is not proof the app has no endpoints. Scanner scheduling and findings are not yet integrated into this page.

For a separate local checkout, provision a read-only bind mount as an operator in your deployment, with a parent containing clearly named repository directories. Set `AEGIS_REPOSITORY_ROOT` to its container mount point. Do not mount a home directory, credential store, Docker socket, or production filesystem. The browser accepts an asset ID only. Provisioning is a local deployment action; there is no browser host-path or remote-clone feature.

Mounts bind to the sole enrolled owner on first connection. Multi-owner mount ACLs are not available. The running process only reads the mounted tree, and the operator must enforce its read-only mount. Reconnect to capture changed source; prior maps remain immutable. A clean Git checkout is not inferred from a commit field. Conventional local `.git` refs are supported; linked worktree/external gitdir metadata is reported unavailable.

Inventory budgets and supported platforms are recorded in ADR 015. Larger maps fail explicitly. No source contents or session credentials are part of a displayed map. File paths, hashes and package/framework facts may still be sensitive owner data. Production staging and arbitrary source execution remain unavailable.

Local acceptance command, after demo authentication fixtures have been initialized:

```sh
python3 tests/integration/repository_acceptance.py
```

## Automatic rescans when a repository changes

An owner can turn on **Rescan on change** for a connected repository (console, or `POST /api/v1/repos/{id}/rescan` with `{"enabled": true, "tool_ids": [...], "tool_timeout_seconds": N}`; `GET` reads the setting). When it is on, the controller re-reads that repository every `AEGIS_RESCAN_INTERVAL` (default 5 minutes, 1 minute to 24 hours), at most 10 repositories per minute. A scan is queued only when the application map's content identity differs from the last scanned or acknowledged one. The scan is an ordinary owner scan: the same validation, queue budget and audit records apply. The setting's last check is shown as its outcome:

| Outcome | Meaning |
|---|---|
| `unchanged` | Same content identity; nothing queued |
| `enqueued` | A scan was queued for the new identity |
| `deferred_active_job` | A scan for this repository is queued or running; retried on the next check |
| `deferred_cleanup_held` | One of the owner's scanner cleanups is held; no new scan until it is resolved |
| `deferred_queue_full` | The owner's queue budget is exhausted |
| `retried_after_failure` | The last rescan ended in a tool error or timeout, so it was queued once more for the same identity |
| `refresh_failed_storage_budget` | Map storage is full even after pruning old history that no scan references |
| `refresh_failed` | The repository could not be re-read (for example, the mount was removed) |

The same identity and scanner set always map to the same job, so restarts do not create duplicates. Each repository keeps at most 100 application maps; when it reaches the cap, the oldest maps that no scan job references are removed. Unchanged periodic re-reads are not written to the audit log. Turning the setting off stops future scans but does not cancel queued ones. Rescans require the scanner service (`AEGIS_SCANNER_SOCKET`) and repository mounts to be provisioned.
