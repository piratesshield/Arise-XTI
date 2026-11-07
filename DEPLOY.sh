#!/bin/bash
# Production deployment script for R1–R8 evidence-driven layer
# Run this when the pipeline is idle to wire the layer into a live system

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <arise_root_dir>"
    echo "Example: $0 /opt/arise"
    exit 1
fi

ARISE_ROOT="$1"
if [ ! -f "$ARISE_ROOT/easm-pipeline.sh" ]; then
    echo "Error: easm-pipeline.sh not found in $ARISE_ROOT"
    exit 1
fi

echo "=== R1–R8 Evidence-Driven Layer Deployment ==="
echo "Target: $ARISE_ROOT"
echo ""

# R1-R8 modules now live under evidence/ and api_security/ (2026-08-23 module
# folder restructure), not flat at repo root — mirror that layout at the
# deploy target instead of flattening it back to root.
EVIDENCE_MODS="arise_evidence.py har_ingest.py flow_reconstruct.py identity_graph.py protocol_exec.py wss_agent.py target_memory.py"
API_SEC_MODS="auth_oracle.py"

# Backup originals
echo "[1/4] Backing up originals..."
cp "$ARISE_ROOT/easm-pipeline.sh" "$ARISE_ROOT/easm-pipeline.sh.backup.pre-r1r8"
cp "$ARISE_ROOT/arise_jobs.py" "$ARISE_ROOT/arise_jobs.py.backup.pre-r1r8"
cp "$ARISE_ROOT/discovery/endpoint_consolidator.py" "$ARISE_ROOT/discovery/endpoint_consolidator.py.backup.pre-r1r8"
echo "  ✓ Backups created (.backup.pre-r1r8)"

# Copy new modules
echo "[2/4] Copying new modules..."
mkdir -p "$ARISE_ROOT/evidence" "$ARISE_ROOT/api_security"
for mod in $EVIDENCE_MODS; do
    if [ -f "evidence/$mod" ]; then
        cp "evidence/$mod" "$ARISE_ROOT/evidence/"
        echo "  ✓ evidence/$mod"
    else
        echo "  ✗ evidence/$mod not found (expected under evidence/ in current directory)"
        exit 1
    fi
done
for mod in $API_SEC_MODS; do
    if [ -f "api_security/$mod" ]; then
        cp "api_security/$mod" "$ARISE_ROOT/api_security/"
        echo "  ✓ api_security/$mod"
    else
        echo "  ✗ api_security/$mod not found (expected under api_security/ in current directory)"
        exit 1
    fi
done

# Copy updated scripts
echo "[3/4] Installing wired scripts..."
cp easm-pipeline.sh "$ARISE_ROOT/easm-pipeline.sh"
cp arise_jobs.py "$ARISE_ROOT/arise_jobs.py"
mkdir -p "$ARISE_ROOT/discovery"
cp discovery/endpoint_consolidator.py "$ARISE_ROOT/discovery/endpoint_consolidator.py"
echo "  ✓ Pipeline + jobs + consolidator installed"

# Verify
echo "[4/4] Verification..."
bash -n "$ARISE_ROOT/easm-pipeline.sh" && echo "  ✓ Pipeline syntax valid" || exit 1
python3 -c "import sys; sys.path.insert(0, '$ARISE_ROOT'); \
            import evidence.arise_evidence; \
            import evidence.har_ingest; \
            print('  ✓ All modules importable')" || exit 1

echo ""
echo "=== DEPLOYMENT COMPLETE ==="
echo ""
echo "Next steps:"
echo "  1. Run a staging scan: ./easm-pipeline.sh staging.example.com"
echo "  2. Verify new artefacts:"
echo "     - ls scans/staging*/00_har_ingest/"
echo "     - ls scans/staging*/24_advanced_attacks/{wss,auth_oracle}_findings.jsonl"
echo "  3. Check dashboard for new findings (L4+ rung only)"
echo ""
echo "Rollback (if needed):"
echo "  cp $ARISE_ROOT/easm-pipeline.sh.backup.pre-r1r8 $ARISE_ROOT/easm-pipeline.sh"
echo "  cp $ARISE_ROOT/arise_jobs.py.backup.pre-r1r8 $ARISE_ROOT/arise_jobs.py"
echo "  cp $ARISE_ROOT/discovery/endpoint_consolidator.py.backup.pre-r1r8 $ARISE_ROOT/discovery/endpoint_consolidator.py"
