# Incident assessment (deterministic and optional local model)

Every incident has an **Assessment** panel. It produces an advisory `IncidentAssessmentV1`: observed facts, hypotheses with evidence references, uncertainties, proposed next steps and suggested tests. Nothing in an assessment changes the gateway.

## Deterministic (default, no setup)

**Deterministic assessment** works offline with no model, account or network access. It reads the incident's detector record, linked evidence, the site's current mode and CRS settings, its top observed routes and related incidents, and applies fixed, reviewable templates per detector.

## Optional free local model

Aegis can ask a model server you run yourself. Nothing is sent anywhere else, and Aegis never calls a model in the background.

### Ollama (bundled overlay)

```sh
# one-time: download a small model into a private volume (this job alone has internet access)
docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml --profile ai-pull run --rm ollama-pull
# run: the model server sits on an internal network reachable only by the controller
docker compose -f deploy/compose.demo.yaml -f deploy/compose.ai-local.yaml up -d
```

Choose a different model with `AEGIS_AI_MODEL=qwen2.5:7b` on both commands. Small models (1–3 B parameters) run on a laptop CPU; larger models give better hypotheses but need more memory.

### llama.cpp, LM Studio or another OpenAI-compatible server

Set on the controller:

```text
AEGIS_AI_PROVIDER=openai_compatible
AEGIS_AI_URL=http://llama-server:8080
AEGIS_AI_MODEL=<model name the server expects>
AEGIS_AI_KEY_FILE=/run/secrets/model_key   # optional, only if your server requires a key
```

The controller must be able to reach that URL. An invalid configuration is rejected at start-up and the controller falls back to deterministic assessments (`ai_configuration_rejected` in its log).

## What the model receives

Only the incident dossier: incident summary, detector identity and thresholds, up to 50 linked evidence records (method, route template, status, CRS rule IDs, decision, pseudonymous client key), the site mode and CRS settings, its top 20 route templates and a count of related incidents. No bodies, query values, headers, cookies, client addresses, source code or credentials are included, because Aegis never stores them.

The dossier is wrapped in explicit data markers and the model is told that everything inside is untrusted and may be attacker-written. The reply must be one JSON object. Aegis drops evidence references that are not in the dossier, unknown action kinds, invalid confidence values, control characters and oversized text, and always appends "Model output is advisory and was not independently verified." If the model is unreachable, slow (180 s default, `AEGIS_AI_TIMEOUT_SECONDS` 10–600) or returns unusable output, the deterministic assessment is returned with the fallback reason.

Each assessment is written to the audit chain with its dossier digest and model name. One assessment runs at a time. Results are cached in controller memory and can be regenerated from the same dossier.

## Patch drafts for code findings

On a static code finding, **How to fix → Draft a patch** asks the code model (`AEGIS_AI_CODE_MODEL`, default `qwen2.5-coder:3b` in the overlay; it is pulled by the same one-time job) for a small line edit near the finding. Aegis builds the diff, requires the edit to replace the finding's own line, checks that it applies to the exact inventoried file and keeps brackets balanced, and refuses edits that add anything a minimal fix does not need: finding-suppression comments (`# nosec`, `eslint-disable`, `noqa`, `nolint`…), URLs or IP addresses, code or command execution, network access, disabled TLS verification or long encoded literals. Then it lets you download the draft as a `.patch`. Text inside your files can try to steer the model, which is why these checks do not depend on what the model says. Aegis never changes your repository. Files that appear to contain credentials are never sent to a model.
