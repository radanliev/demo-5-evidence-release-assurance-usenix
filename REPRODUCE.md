# EviAssure: Reproducibility & Artifact Evaluation Guide

This artifact package provides full reproduction materials for the paper **"Evidence-Backed Release Assurance for Autonomous Agent Deployments"** (USENIX Security 2027 submission).

---

## 1. System Requirements & Environment Setup

- **Hardware**: Tested on multi-core workstations (x86_64 or Apple Silicon; 14 logical cores recommended for 16-worker concurrency tests).
- **Python**: Python $\ge 3.10$ (tested on Python 3.14).
- **LaTeX Distribution**: `pdflatex` & `bibtex` (TeX Live / MacTeX) for manuscript recompilation.
- **Dependencies**: `pyyaml`, `matplotlib`, `cryptography`, `statsmodels`, `tuf` (python-tuf) — all declared in `pyproject.toml`; the `dev` extra adds `pytest` and `hypothesis`, which the test suite imports. The `opa` binary must be on `PATH` for the OPA baseline to run as *executed* rather than *modeled*.

### Installation

```bash
# Clone or extract the artifact
cd eviassure

# Install the package in editable mode with all dependencies, including the test extras
pip install -e ".[dev]"
```

---

## 2. One-Command Reproduction

The repository provides a unified reproduction entrypoint:

```bash
# Quick reproduction (~15 seconds: unit tests, fast benchmarks, and figure rendering)
./reproduce.sh --quick

# Full reproduction (~60 seconds: 1M trace scaling, 1075 corpus evaluation, 17-vector tamper suite + negative controls)
./reproduce.sh
```

---

## 3. Claim-to-Evidence Mapping Table

Every empirical claim, table, and figure in the manuscript maps directly to a deterministic script and artifact:

| Paper Item | Claim / Metric | Generation Script | Output Artifact | Expected Runtime |
|---|---|---|---|:---:|
| **Table 1** (Tamper vectors) | 16/17 blocked (94.1%, CI [73.0, 99.0]); V16 not blocked; 0/4 clean controls falsely blocked | `scripts/run_security_eval.py` | `results/security_evaluation.json` (`vectors`, `negative_controls`, `ablation`, `wire_fuzzing`) | ~10s |
| **Table 2** (Omission attacks, O1–O7) | EviAssure + WTC 7/7; without reconciliation 0/7; receipts 2/7; per-issuer chaining 2/7; DSSE 0/7; TUF 0/7; honest control OC1 approved by all | `scripts/run_security_eval.py` | `results/security_evaluation.json` (`omission`) | ~10s |
| **Table 3** (Corpus, layered) | 1,075 profiles / 5,450 records; L1 1075/1075; L2 clean 1000/1000 and anomalous 75/75 APPROVED; L3 held-out recall 50/50 overt, 0/25 stealth, 0/1000 false positives | `scripts/generate_trace_corpus.py`, `scripts/run_corpus_eval.py` | `corpus/agent_trace_corpus.json`, `results/corpus_evaluation.json` | ~6s |
| **Table 4** (Live agent sessions) | 31 of 42 requested sessions (5 model families, 4 providers; 11 lost to provider quota/credit/rate limits); 15 ran to completion; witness coverage 82.7% over completed sessions (91.6% pooled) — a property of the 4-of-5 witnessed tool set; honest control reconciles 31/31; 177/177 re-derived omission attacks detected over 6 of the 7 vectors (O7 derived pairwise across sessions; O5 needs a concurrent second session and was not constructed) | `scripts/run_live_agent_eval.py` (needs a provider API key; never simulated) | `results/live_agent_evaluation.json` | minutes, provider-bound |
| **Figure 1** (Architecture) | System model and trust boundaries | TikZ in the manuscript source | `docs/usenix_paper_manuscript.pdf` | — |
| **Figure 2** (Scaling) | Merkle build to $N=10^6$ traces (1,815.13 ms mean of 5 on Apple M4 Max) | `scripts/run_release_benchmark.py` | `results/benchmark_summary.json`, `docs/figures/merkle_scaling.png` | ~25s |
| **Figure 3** (Throughput) | Peak 6,963 ± 89 ops/s at 4 workers (three-trace bundles) | `scripts/run_release_benchmark.py` | `results/benchmark_summary.json`, `docs/figures/parallel_throughput.png` | ~15s |
| **Figure 4** (Block rate) | EviAssure 16/17 vs composed DSSE + TUF + OPA 10/17, Wilson 95% intervals (overlapping) | `scripts/run_security_eval.py`, drawn by `scripts/generate_paper_pdf.py` | `results/security_evaluation.json`, `docs/figures/comparative_block_rate.png` | ~2s |
| **Section 4.2** (Witness cost) | receipt issuance, closing and gate reconciliation cost for 30/300/3,000 witnessed actions over three in-process witnesses (platform recorded in the file and quoted by the manuscript macro) | `scripts/run_witness_overhead.py` (also run by `run_release_benchmark.py`) | `results/witness_overhead.json` | ~5s |
| **Sparse proofs** | 20-node, 1.93 KB proof at $N=10^6$; generated in 0.003 ms, verifies in 0.011 ms | `scripts/run_release_benchmark.py` (`assurance/crypto.py`) | `results/benchmark_summary.json` (`sparse_proof`) | ~0.5s |
| **Test Suite** (121 tests) | crypto soundness (property-based), registry, tamper/omission regressions, credential refusal, session substitution, CLI end-to-end reconciliation, out-of-process and container witnesses (the 5 container tests need a Docker daemon **and** the image: `docker build -f specimens/witness.Dockerfile -t eviassure-witness:latest .`; they skip, with that command, when either is absent) | `pytest tests/ -v` | Console test log | ~3s (+ ~10s with containers) |

Timings in `results/benchmark_summary.json` are platform-dependent and were recorded on Apple M4 Max / Python 3.14; block counts and verdicts are platform-independent. The timing figures quoted in this table and in `README.md` are copied from that file by hand and must be re-checked after any benchmark re-run (the manuscript's numbers are macros and cannot drift).

---

## 4. Individual Script Workflows

For fine-grained artifact evaluation, individual components can be executed independently:

```bash
# 0. OPTIONAL: live agent sessions against a real LLM (needs GROQ_API_KEY,
#    OPENROUTER_API_KEY, or HF_TOKEN). Skipped cleanly, never simulated, if
#    absent. Free-tier accounts are metered per minute; use --append to batch.
python3 scripts/run_live_agent_eval.py --sessions 5 --provider groq --append

#    Witnesses run out-of-process by default: each executes the tool itself and
#    signs a digest of the output IT produced, with a key that never leaves its
#    own address space. To run each witness in a container instead (own
#    filesystem/PID/network namespaces, non-root, repo read-only, no network),
#    build the image first; the run fails rather than falling back silently.
docker build -f specimens/witness.Dockerfile -t eviassure-witness:latest .
python3 scripts/run_live_agent_eval.py --sessions 5 --provider groq \
        --witness-isolation container --append

# 1. Run full unit and regression test suite (121 tests)
pytest tests/ -v

# 2. Re-run scaling & multi-core throughput benchmarks (generates benchmark_summary.json)
python3 scripts/run_release_benchmark.py --repeats 5

# 3. Re-run the deterministic security evaluation: 17 tamper vectors + clean
#    controls, 7 omission vectors + honest control, executed DSSE/TUF/OPA
#    baselines, ablation, wire fuzzing, held-out inspection
#    (generates security_evaluation.json; then regenerate the LaTeX macros)
python3 scripts/run_security_eval.py --require-executed
python3 scripts/write_security_macros.py

# 4. Re-run the corpus layered evaluation across 1,075 agent profiles (generates corpus_evaluation.json)
python3 scripts/generate_trace_corpus.py
python3 scripts/run_corpus_eval.py

# 5. Regenerate 600 DPI figures and recompile LaTeX manuscript
python3 scripts/generate_paper_pdf.py

# 6. Package clean anonymous artifact archive and compute SHA-256 digest
#    (refuses to package if results/ records a modeled DSSE/TUF/OPA baseline)
python3 scripts/prepare_anonymous_artifact.py

# 7. Exercise the shipped, witnessed release gate end to end: package a
#    witnessed bundle plus the release request that names its credentialed
#    session, then evaluate it (APPROVED); an unwitnessed bundle is BLOCKED.
python3 scripts/provision_witnesses.py                    # (re)writes governance/witness_registry.yaml (demo profile)
python3 scripts/package_evidence.py -o evidence_pack.json --format text
python3 scripts/verify_release_gate.py --evidence evidence_pack.json   # picks up evidence_pack.json.release_request.json
python3 scripts/package_evidence.py -o unwitnessed.json --unwitnessed --format text
python3 scripts/verify_release_gate.py --evidence unwitnessed.json     # exit 1: COMPLETENESS_VIOLATION
```

---

## 5. Anonymous Open Science Release for Double-Blind Review

To satisfy USENIX Security 2027 Open Science requirements while preserving double-blind review anonymity:

1. **Anonymous Archive (`eviassure_usenix27_artifact.zip`)**:
   - The archive is generated via `python3 scripts/prepare_anonymous_artifact.py`.
   - All Git commit metadata, personal author identifiers, proprietary paths, and local build artifacts (`.pyc`, `.DS_Store`, `.paperloop`, `.git`) are stripped.
2. **SHA-256 Integrity Verification**:
   - The computed SHA-256 digest is embedded directly in the Open Science Appendix of the manuscript (`docs/artifact_digest.tex`).
   - Reviewers can verify artifact integrity with:
     ```bash
     shasum -a 256 eviassure_usenix27_artifact.zip
     ```
3. **Anonymous Online Repository**:
   - Anonymized online repository mirror hosted at:
     [https://anonymous.4open.science/r/eviassure-artifact-781D/](https://anonymous.4open.science/r/eviassure-artifact-781D/) (the URL cited in the manuscript)
