# EviAssure: Reproducibility & Artifact Evaluation Guide

This artifact package provides full reproduction materials for the paper **"Evidence-Backed Release Assurance for Autonomous Agent Deployments"** (USENIX Security 2027 Submission ID: `EVI-227`).

---

## 1. System Requirements & Environment Setup

- **Hardware**: Tested on multi-core workstations (x86_64 or Apple Silicon; 14 logical cores recommended for 16-worker concurrency tests).
- **Python**: Python $\ge 3.10$ (tested on Python 3.14).
- **LaTeX Distribution**: `pdflatex` & `bibtex` (TeX Live / MacTeX) for manuscript recompilation.
- **Dependencies**: `pytest`, `pyyaml`, `matplotlib`, `cryptography` (listed in `pyproject.toml`).

### Installation

```bash
# Clone or extract the artifact
cd eviassure

# Install the package in editable mode with dependencies
pip install -e .
```

---

## 2. One-Command Reproduction

The repository provides a unified reproduction entrypoint:

```bash
# Quick reproduction (~15 seconds: unit tests, fast benchmarks, and figure rendering)
./reproduce.sh --quick

# Full reproduction (~60 seconds: 1M trace scaling, 1,050 corpus evaluation, 13-vector tamper suite)
./reproduce.sh
```

---

## 3. Claim-to-Evidence Mapping Table

Every empirical claim, table, and figure in the manuscript maps directly to a deterministic script and artifact:

| Paper Item | Claim / Metric | Generation Script | Output Artifact | Expected Runtime |
|---|---|---|---|:---:|
| **Table 1** (Tamper Suite) | 100.0% block rate (13/13 vectors) | `scripts/run_comparative_eval.py` | `results/comparative_evaluation.json` | ~3s |
| **Table 2** (Corpus Eval) | 1,050 profiles (100% L1 integrity, 100% L2 gate, 100% L3 recall) | `scripts/run_corpus_eval.py` | `results/corpus_evaluation.json` | ~6s |
| **Table 3** (Capability Map) | Complete $\mathcal{A}_1$--$\mathcal{A}_5$ threat model coverage | `tests/test_tamper_resilience.py` | `tests/test_tamper_resilience.py` | ~1.5s |
| **Table 4** (Comparative Matrix) | Feature comparison across 12 frameworks | Qualitative Analysis | `docs/usenix_paper_manuscript.tex` | N/A |
| **Figure 1** (Architecture) | 4-Zone zero-trust attestation plane | TikZ Vector Model | `docs/usenix_paper_manuscript.pdf` (p. 3) | ~2s |
| **Figure 2** (Scaling) | $O(\log N)$ Merkle build to $N=10^6$ traces | `scripts/run_release_benchmark.py` | `docs/figures/merkle_scaling.png` | ~25s |
| **Figure 3** (Throughput) | Peak parallel throughput at \peakWorkers{} workers | `scripts/run_release_benchmark.py` | `docs/figures/parallel_throughput.png` | ~15s |
| **Figure 4** (Block Rate) | EviAssure (100%) vs Baselines (0%--30.8%) | `scripts/run_comparative_eval.py` | `docs/figures/comparative_block_rate.png` | ~2s |
| **Section 7.1** (Compression) | 99.999% bandwidth reduction (<5 KB proof) | `assurance/merkle_tree.py` | `results/benchmark_summary.json` | ~0.5s |
| **Test Suite** (45 Tests) | Cryptographic soundness, registry, tamper resilience | `pytest tests/ -v` | Console test log | ~1.5s |

---

## 4. Individual Script Workflows

For fine-grained artifact evaluation, individual components can be executed independently:

```bash
# 1. Run full unit and regression test suite (45 tests)
pytest tests/ -v

# 2. Re-run scaling & multi-core throughput benchmarks (generates benchmark_summary.json)
python3 scripts/run_release_benchmark.py --repeats 5

# 3. Re-run comparative baseline evaluations (generates comparative_evaluation.json)
python3 scripts/run_comparative_eval.py

# 4. Re-run corpus two-layer evaluation across 1,050 agent profiles (generates corpus_evaluation.json)
python3 scripts/run_corpus_eval.py

# 5. Regenerate 600 DPI figures and recompile LaTeX manuscript
python3 scripts/generate_paper_pdf.py

# 6. Package clean anonymous artifact archive and compute SHA-256 digest
python3 scripts/prepare_anonymous_artifact.py
```

---

## 5. Anonymous Open Science Release for Double-Blind Review

To satisfy USENIX Security 2027 Open Science requirements while preserving double-blind review anonymity:

1. **Anonymous Archive (`eviassure_usenix27_artifact.zip`)**:
   - The archive is generated via `python3 scripts/prepare_anonymous_artifact.py`.
   - All Git commit metadata, personal author identifiers, proprietary paths, and local build artifacts (`.pyc`, `.DS_Store`, `.paperloop`, `.git`) are stripped.
2. **SHA-256 Integrity Verification**:
   - The computed SHA-256 digest is embedded directly in Appendix B of the manuscript (`docs/artifact_digest.tex`).
   - Reviewers can verify artifact integrity with:
     ```bash
     shasum -a 256 eviassure_usenix27_artifact.zip
     ```
3. **Anonymous Online Repository**:
   - Anonymized online repository mirror hosted on `anonymous.4open.science` or clean GitHub organization for peer review access.
