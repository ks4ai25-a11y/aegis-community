# Getting started with Aegis Community

Aegis Community puts a hardened web application firewall in front of your apps, explains what it sees, proposes changes and proves them in an isolated test before you approve anything. It runs on your machine or server with Docker. Nothing needs an account, a paid service or a model.

## 1. Start it (5 minutes)

```sh
scripts/quickstart.sh
```

The script builds the images, starts the stack and prints:

- the console at `http://127.0.0.1:7410` (loopback only),
- a one-time **bootstrap token** for creating the owner account.

Open the console, select **First installation? Enroll owner**, paste the token and pick a passphrase of at least 14 characters.

## 2. See it work on the bundled demo

The demo site (`demo.example.test`) is synthetic. On **Overview**, select **Run safe demo traffic**, then open **Live activity**: you will see a benign request and a request matching CRS rule 942100 (SQL-injection pattern). In Observe mode nothing is blocked.

Open **Incidents**, select the observation and:

1. Read the detector record and the stated unknowns.
2. Select **Deterministic assessment** for facts, hypotheses and next steps.
3. Review **Mitigation proposals**. Each one is a full candidate policy. **Validate and preview** runs it in an isolated copy of the gateway against fixed synthetic requests. An unsafe proposal fails here and cannot be activated.

To turn on blocking for the demo, open **Policies**, choose **Protect**, preview, tick the acknowledgement and approve. **Overview** shows the live canary, which re-checks the gateway after every change and every 15 minutes.

## 3. Protect your own application

Follow [protecting your applications](../operators/sites.md):

1. Put your app on the `aegis_sites` Docker network.
2. **Sites → Register an application** with its host names and private origin. It starts in Observe.
3. Review its traffic and incidents (use the **Site** selector in the header).
4. Enable Protect, HTTPS (free ACME certificate) and a rate limit when you are ready.

## 4. Optional extras

| Want | Do |
| --- | --- |
| A local AI assessor | `scripts/quickstart.sh --ai`, then use **Assess with llama3.2:3b** on an incident ([details](../operators/ai-assessment.md)) |
| Your desktop AI app to read Aegis | **AI Apps → Assistant connections**, then configure `aegis-mcp` ([details](../operators/assistant-connections.md)) |
| Code scanning | **Repositories** and **Scans** ([details](../operators/offline-scanners.md)) |
| Backups | [database snapshots](../operators/database-snapshots.md) and [recovery bundles](../operators/recovery-bundles.md) |

## What Aegis does not claim

A WAF match is not proof of an attack; a passing fixture is not proof your application is secure; a generic WAF does not enforce your application's authorization. Aegis says exactly what each piece of evidence shows and what it does not. See [known limitations](../KNOWN_LIMITATIONS.md).

Stop the stack with `scripts/quickstart.sh --down` (your data is kept).
