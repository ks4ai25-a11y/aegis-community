# Adversarial AI evaluation

The suite lives in `controller/internal/aieval` so it drives the production code paths. It has two parts.

- **Offline** (part of `make test`): a scripted adversarial model returns hostile outputs to incident assessment (`assess`), patch drafts (`remediate`) and the research planner (`redteam`). Every invariant must hold: assessments stay advisory with only known evidence references and recommendation kinds; displayed text has no control or format characters; drafts that add suppressions, URLs, execution, network access, disabled TLS verification or encoded blobs, or that do not touch the finding's line, are refused; planner output stays inside the tool and template catalogues and the inventory.
- **Live** (`tests/ai-eval/run_live.sh NETWORK [OUT_DIR]`): the same attacks against the real local models from `deploy/compose.ai-local.yaml`, recording measured rates. Invariant violations fail the run; the rates are measurements, not pass marks.

Recorded runs: `docs/evidence/ai-eval-live.json`, `docs/evidence/ai-eval-planner-live.json`. See `docs/architecture/adr/072-adversarial-ai-evaluation.md`.
