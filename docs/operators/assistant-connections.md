# Connecting a desktop AI app (MCP)

Aegis ships `aegis-mcp`, a small local stdio MCP server. Your desktop AI app (Claude Desktop or Claude Code, Codex/ChatGPT desktop, Kimi, Cursor or any MCP client) starts it and can then **read** Aegis sites, incidents, evidence, assessments and mitigation proposals. It cannot change policy, approve proposals, start scans or verification jobs, or read scanner, audit or credential data. The app uses its own subscription; Aegis never sees the app's credentials, and no model runs inside Aegis for this.

## 1. Build the bridge

```sh
make mcp-build        # produces bin/aegis-mcp (static, no network listener)
```

## 2. Create a connection in the console

Open **AI Apps → Assistant connections**, name the connection and choose a lifetime (1–720 hours). Aegis shows the token **once**. Save it to a private file:

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

The owner preview, approval, delivery and revocation use the controller. Approval, delivery and revocation are audited. Restoring a backup revokes existing approvals and connector credentials. The optional handoff uses the existing connector and its ordinary read permissions. Draft submission requires separate consent on each handoff. Guided pairing remains separate v4 work.

### Receive and review an investigation draft

When approving a handoff, select **Allow one investigation draft in return** if you want the selected connector to submit a report. It must retrieve the approved bundle first and submit before the original expiry. The connector calls `aegis_submit_draft_analysis` with an idempotency key and the evidence IDs from the bundle. Repeating the same submission during that window returns the retained draft. A changed submission or an attempt to create another draft for that handoff is refused.

Use **Check for drafts** on the incident to review the report, its supporting evidence IDs, limitations and suggestions. A client label is self-reported. Every report starts unverified. **Dismiss draft** records your review decision. The assistant can read its own draft's review state using `aegis_get_draft_status`.
