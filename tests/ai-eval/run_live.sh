#!/bin/sh
# Adversarial AI evaluation against the local model overlay (deploy/compose.ai-local.yaml).
# Builds the evaluation test binary and runs it on the model's private network with no
# other network access, writing evidence JSON to OUT_DIR. Usage:
#   tests/ai-eval/run_live.sh NETWORK [OUT_DIR]     e.g. aegis-community_ai_net
set -eu
NETWORK=$1
OUT=${2:-$(mktemp -d)}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ARCH=$(docker version --format '{{.Server.Arch}}')
mkdir -p "$OUT"
(cd "$ROOT/controller" && GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 go test -c -o "$OUT/aieval.test" ./internal/aieval)
docker run --rm --network "$NETWORK" --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  --mount "type=bind,src=$OUT,dst=/out" -e AEGIS_AI_EVAL_URL=http://ollama:11434 \
  -e AEGIS_AI_EVAL_OUT=/out/ai-eval.json -e AEGIS_AI_EVAL_PLANNER_OUT=/out/ai-eval-planner.json \
  alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 \
  /out/aieval.test -test.run 'TestLive' -test.v -test.timeout 3600s
echo "evidence in $OUT"
