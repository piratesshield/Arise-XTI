#!/usr/bin/env bash
# Build the ARISE image and run it locally on port 3333 with admin/admin.
# Usage: docker/build-and-run.sh   (run from anywhere; it cd's to the repo root)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${IMAGE:-arise:local}"
NAME="${NAME:-arise}"
PORT="${PORT:-3333}"

echo "==> Building $IMAGE (context: $REPO_ROOT)"
docker build -f docker/Dockerfile -t "$IMAGE" .

echo "==> Removing any previous container named $NAME"
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> Running $NAME on host port $PORT"
docker run -d --name "$NAME" \
    -p "${PORT}:3333" \
    -e ARISE_ADMIN_USER=admin \
    -e ARISE_ADMIN_PASSWORD=admin \
    -e ARISE_DASHBOARD_PORT=3333 \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v arise-scans:/app/scans \
    "$IMAGE"

echo ""
echo "ARISE is starting at:  http://localhost:${PORT}"
echo "Login:                 admin / admin"
echo "Logs:                  docker logs -f ${NAME}"
