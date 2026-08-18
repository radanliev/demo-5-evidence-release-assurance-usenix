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
    echo "[Step 3/4] Running the deterministic security evaluation (17 tamper + 7 omission vectors, baselines, ablation, fuzzing, inspection)..."
    python3 scripts/run_security_eval.py --fuzz 300
    python3 scripts/write_security_macros.py
    
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
echo "[Step 3/4] Running the deterministic security evaluation (executed baselines required) and the corpus layered evaluation..."
python3 scripts/run_security_eval.py --require-executed
python3 scripts/write_security_macros.py
python3 scripts/generate_trace_corpus.py
python3 scripts/run_corpus_eval.py

echo ""
echo "[Step 4/4] Generating high-resolution paper figures and compiling PDF manuscript..."
python3 scripts/generate_paper_pdf.py
python3 scripts/prepare_anonymous_artifact.py

echo ""
echo "================================================================================"
echo " [SUCCESS] Full artifact reproduction complete! All paper numbers and plots verified."
echo "================================================================================"
