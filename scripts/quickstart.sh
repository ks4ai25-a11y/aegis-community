#!/usr/bin/env sh
# Aegis Community quickstart: build and start the local stack, then print where to
# sign in. Uses only Docker; no account, paid service or model is required.
#   scripts/quickstart.sh            start (or restart) the local stack
#   scripts/quickstart.sh --ai       also start the optional local model (downloads ~2 GB once)
#   scripts/quickstart.sh --down     stop the stack (data volumes are kept)
set -eu
cd "$(dirname "$0")/.."
files="-f deploy/compose.demo.yaml"
ai=0
for arg in "$@"; do
  case "$arg" in
    --ai) ai=1 ;;
    --down) docker compose $files -f deploy/compose.ai-local.yaml down; exit 0 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/get-docker/" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }
if [ "$ai" = 1 ]; then
  files="$files -f deploy/compose.ai-local.yaml"
  echo "Downloading the local model once (this job alone has internet access)…"
  docker compose $files --profile ai-pull run --rm ollama-pull
fi
echo "Building images (first run takes a few minutes)…"
docker compose $files build
docker compose $files up -d
echo "Waiting for the console…"
i=0
until curl -fsS http://127.0.0.1:7410/api/v1/health/live >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "The console did not start; see: docker compose $files logs controller" >&2; exit 1; }
  sleep 1
done
token=$(docker compose $files logs --no-log-prefix controller 2>/dev/null | grep '"local_bootstrap_token"' | tail -1 | sed 's/.*"token":"\([^"]*\)".*/\1/')
echo
echo "Aegis Community is running."
echo "  Console:  http://127.0.0.1:7410"
echo "  Gateway:  http://127.0.0.1:8080  (demo host: demo.example.test)"
if [ -n "$token" ]; then
  echo "  First sign-in: choose 'Enroll the first owner' and use this one-time token"
  echo "  (valid for a short time, printed only to local logs):"
  echo "    $token"
else
  echo "  Sign in with your owner passphrase."
fi
echo "Next: docs/user/getting-started.md"
