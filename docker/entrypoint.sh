#!/usr/bin/env bash
# ARISE container entrypoint — dispatches between the dashboard, the pipeline,
# and the CLI. Default: run the web dashboard.
set -euo pipefail

cd /app

cmd="${1:-dashboard}"
case "$cmd" in
    dashboard)
        echo "[arise] starting dashboard on port ${ARISE_DASHBOARD_PORT:-3333} (login: ${ARISE_ADMIN_USER:-admin})"
        exec python3 dashboard.py
        ;;
    pipeline)
        shift
        exec bash easm-pipeline.sh "$@"
        ;;
    cli)
        shift
        exec python3 arise.py "$@"
        ;;
    *)
        # Anything else: run it verbatim (e.g. `docker run arise bash`)
        exec "$@"
        ;;
esac
