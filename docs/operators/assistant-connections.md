# Connecting a desktop AI app (MCP)

Aegis ships `aegis-mcp`, a local stdio MCP bridge. Paired assistants can check connection status, retrieve one owner-approved incident snapshot and return a draft when the owner allows it. The advanced connector adds read access to sites, incidents, evidence, assessments and mitigation proposals. Policy changes, scan jobs and verification jobs require separate owner workflows. The desktop app uses its own subscription and keeps its provider credentials. Installed client compatibility is verified separately from the bridge tests.

## 1. Build the bridge

```sh
make mcp-build        # produces bin/aegis-mcp (static, no network listener)
```

## 2. Pair a local device

In **AI Apps → Pair a desktop assistant**, choose a device name and access duration. The optional draft permission lets that device submit a report only when you separately approve it for a specific handoff. Create and copy the five-minute invitation. On the same Mac as the bridge, feed the copied invitation through standard input:

```sh
install -d -m 700 "$HOME/.config/aegis"
pbpaste | AEGIS_URL=http://127.0.0.1:7410 \
  AEGIS_CONNECTOR_TOKEN_FILE="$HOME/.config/aegis/work-device-token" ./bin/aegis-mcp pair
```

On other POSIX systems, provide the invitation from a private input file or a local clipboard tool. Use the fingerprint displayed by the bridge to confirm the device in the console. The bridge creates the designated file with mode 0600 after confirmation. Choose a fresh path for each pairing. Configure the desktop app with that path and the same Aegis URL, then start a new session and use `aegis_status` to check access. You can revoke the device from **Assistant connections**. Use owner-approved renewal while the credential is active. Pair again after expiry.

Use HTTPS for any non-loopback URL.

### Optional macOS Keychain storage

Build the native executable with `make mcp-keychain-build`. Choose a new local account label and run:

```sh
pbpaste | AEGIS_URL=http://127.0.0.1:7410 \
  AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT=work-device ./bin/aegis-mcp-keychain pair
```

Use the native executable and the same `AEGIS_URL` and account label in your MCP client configuration. Set either the account label or the token file setting. The native build uses the default macOS Keychain for that user, so run it from the same macOS account for pairing and regular use. macOS may prompt to unlock the Keychain or approve access.

### Advanced manual connector

Only use **AI Apps → Assistant connections → Advanced manual connector** when you need the legacy broader read scope. Name the connection and choose a lifetime (1–720 hours). Aegis shows the token **once**. Save it to a private file:

```sh
umask 077 && pbpaste > ~/.config/aegis/connector-token   # or paste with an editor
chmod 600 ~/.config/aegis/connector-token
```

The bridge refuses a token file that group or others can read.

## 3. Add it to your app

Most MCP clients accept a configuration like this (Claude Desktop: `claude_desktop_config.json`; Claude Code: `claude mcp add`; others: their MCP settings):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/aegis-community/bin/aegis-mcp",
      "env": {
        "AEGIS_URL": "http://127.0.0.1:7410",
        "AEGIS_CONNECTOR_TOKEN_FILE": "/Users/you/.config/aegis/connector-token"
      }
    }
  }
}
```

`AEGIS_URL` must be a loopback `http://` address or an `https://` URL. The bridge connects directly and rejects redirects. It caps each response at 512 KiB and surfaces only the HTTP status when the controller returns an error. Restart the app or start a new session so it loads the server.

## Tools

| Tool | Reads |
| --- | --- |
| `aegis_system_status` | gateway mode, revision health, telemetry loss |
| `aegis_list_sites` | registered sites and their modes |
| `aegis_list_incidents` | recent incidents for a site, with detector IDs |
| `aegis_get_incident` | one incident with detector record, sanitized evidence and unknowns |
| `aegis_get_assessment` | the latest advisory assessment generated in the console |
| `aegis_get_mitigation_proposals` | candidate policy changes (data only) |
| `aegis_list_endpoints` | observed route templates for a site |

Every result begins with a notice that the data is untrusted and may contain attacker-chosen text. To act on a proposal, open the incident in the Aegis console, preview it in the isolated fixture and approve it there.

## Revoking

Revoke a connection in the console at any time; the next tool call fails with 401. Connections also expire automatically, and an offline restore revokes all of them.

## Share one reviewed incident bundle

Open an incident and select **Preview what will be shared**. The preview contains the incident ID, severity, opening hour, and up to 20 retained observations with opaque evidence IDs, decisions and numeric rule IDs. Choose the intended active connector, then select **Approve once** and paste the generated investigation request into that desktop app. The selected connector can retrieve the approved snapshot once with `aegis_get_handoff` before the earlier of its credential expiry and five minutes. **Revoke handoff** prevents further use of the approval. A lost retrieval response requires a fresh approval.

The owner preview, approval, delivery and revocation use the controller. Approval, delivery and revocation are audited. Restoring a backup revokes existing approvals and connector credentials. The optional handoff uses the existing connector and its ordinary read permissions. Draft submission requires separate consent on each handoff.

### Receive and review an investigation draft

When approving a handoff, select **Allow one investigation draft in return** if you want the selected connector to submit a report. It must retrieve the approved bundle first and submit before the original expiry. The connector calls `aegis_submit_draft_analysis` with an idempotency key and the evidence IDs from the bundle. Repeating the same submission during that window returns the retained draft. A changed submission or an attempt to create another draft for that handoff is refused.

Use **Check for drafts** on the incident to review the report, its supporting evidence IDs, limitations and suggestions. A client label is self-reported. Every report starts unverified. **Dismiss draft** records your review decision. The assistant can read its own draft's review state using `aegis_get_draft_status`.


### Verify the installed bridge build

Run `make desktop-verify` to build the executable and test it against a disposable controller database on an ephemeral loopback port. The test drives the actual stdio process through pairing, owner-approved handoff, evidence-bound draft submission, replay, dismissal, renewal, and revocation. The macOS CI job runs the same journey with a disposable Keychain. It uses fixture data and an isolated test profile. Run the same journey inside each supported desktop application before claiming compatibility for that application.

The stdio bridge supports the `2025-06-18` MCP handshake. It offers that revision if a client requests an unsupported one and waits for the initialized notification before enabling tool calls. For a paired device, the tool list reflects its current controller permissions. See the [MCP lifecycle specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle).

### Renew a paired device

While the paired credential is still active, choose **Approve 60-minute renewal** next to the device in **Assistant connections**. Run `aegis-mcp renew` for a private file or `aegis-mcp-keychain renew` for macOS Keychain before the earlier of the five-minute approval deadline and the current credential expiry. Use the same executable, `AEGIS_URL` and credential setting that you used for pairing. Restart the desktop app session after the bridge confirms renewal. An expired or revoked device requires a new pairing.

The bridge keeps its device ID and permissions and replaces the token. The retired token loses access immediately. If the controller commits but its reply is lost, the bridge checks the saved replacement directly. Run the same command again if the bridge tells you to retry. The bridge keeps the pending replacement in the selected credential store until it verifies the rotation and installs the replacement. If you abandon renewal, revoke the device before removing the credential and any pending replacement from your Keychain or private directory.
