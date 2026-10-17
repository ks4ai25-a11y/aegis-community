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
