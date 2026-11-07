#!/usr/bin/env bash
# Publish docker/README.md as the Docker Hub repository "Overview" (full_description).
# `docker push` does NOT do this — the overview is a separate API/UI field.
#
# Usage:
#   DOCKERHUB_TOKEN=dckr_pat_xxx docker/set-hub-overview.sh
# Optional overrides:
#   DOCKERHUB_USER (default: dagaltikick)  REPO (default: arise)
#
# The token is read from the environment and never written to disk or echoed.
set -euo pipefail

USER="${DOCKERHUB_USER:-dagaltikick}"
REPO="${REPO:-arise}"
TOKEN="${DOCKERHUB_TOKEN:?Set DOCKERHUB_TOKEN=<a valid Docker Hub PAT with Read/Write scope>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="$ROOT/docker/README.md"
[ -f "$README" ] || { echo "missing $README"; exit 1; }

echo "==> Authenticating to Docker Hub as $USER"
JWT=$(curl -fsS https://hub.docker.com/v2/users/login \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USER\",\"password\":\"$TOKEN\"}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')
[ -n "$JWT" ] || { echo "login failed (bad/expired token?)"; exit 1; }

PAYLOAD="$(mktemp)"; trap 'rm -f "$PAYLOAD"' EXIT
python3 - "$README" > "$PAYLOAD" <<'PY'
import sys, json
readme = open(sys.argv[1], encoding="utf-8").read()
short = ("AI-enabled EASM — attack-surface monitoring dashboard + offensive pipeline. "
         "Runs on :3333, login admin/admin.")[:100]
print(json.dumps({"full_description": readme, "description": short}))
PY

echo "==> Updating $USER/$REPO overview ($(wc -c < "$README" | tr -d ' ') bytes)"
curl -fsS -X PATCH "https://hub.docker.com/v2/repositories/$USER/$REPO/" \
     -H "Authorization: JWT $JWT" -H "Content-Type: application/json" \
     --data @"$PAYLOAD" \
     | python3 -c 'import sys,json;d=json.load(sys.stdin);print("OK — overview length:",len(d.get("full_description") or ""))'

echo "Done: https://hub.docker.com/r/$USER/$REPO"
