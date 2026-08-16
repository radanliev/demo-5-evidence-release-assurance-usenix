#!/usr/bin/env bash
# ==============================================================================
# EviAssure: One-Command Reproducibility Entrypoint (USENIX Security 2027)
# ==============================================================================
set -euo pipefail

MODE="full"
if [[ "${1:-}" == "--quick" ]]; then
    MODE="quick"
fi

echo "================================================================================"
echo " EviAssure: Evidence-Backed Release Assurance for Autonomous Agent Deployments"
echo " USENIX Security 2027 Artifact Evaluation — Mode: ${MODE}"
echo "================================================================================"

# 1. Run Unit & Regression Tests
echo ""
echo "[Step 1/4] Running test suite (unit, crypto soundness, tamper resilience, regressions)..."
pytest tests/ -v

if [[ "${MODE}" == "quick" ]]; then
    echo ""
    echo "[Step 2/4] Running quick release benchmark (repeats=2)..."
    python3 scripts/run_release_benchmark.py --repeats 2
    
    echo ""
    echo "[Step 3/4] Running comparative baseline evaluation & 13-vector tamper harness..."
    python3 scripts/run_comparative_eval.py
    
    echo ""
    echo "[Step 4/4] Generating paper figures and compiling PDF..."
    python3 scripts/generate_paper_pdf.py
    
    echo ""
    echo "================================================================================"
    echo " [SUCCESS] Quick reproduction complete! (All tests pass & figures regenerated)"
    echo "================================================================================"
    exit 0
fi

# Full reproduction mode
echo ""
echo "[Step 2/4] Running comprehensive release benchmark (repeats=5, 1M trace scaling)..."
python3 scripts/run_release_benchmark.py --repeats 5

echo ""
echo "[Step 3/4] Running comparative evaluation and corpus-scale two-layer evaluation..."
python3 scripts/run_comparative_eval.py
python3 scripts/run_corpus_eval.py

echo ""
echo "[Step 4/4] Generating high-resolution paper figures and compiling PDF manuscript..."
python3 scripts/generate_paper_pdf.py
python3 scripts/prepare_anonymous_artifact.py

echo ""
echo "================================================================================"
echo " [SUCCESS] Full artifact reproduction complete! All paper numbers and plots verified."
echo "================================================================================"
