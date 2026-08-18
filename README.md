# EviAssure: Evidence-Backed Release Assurance for Agentic Systems

[![USENIX Security Target](https://img.shields.io/badge/Research--Target-USENIX%20Security%202027-blue.svg)](https://www.usenix.org/conference/usenixsecurity27)
[![Paper PDF](https://img.shields.io/badge/Paper-USENIX%20Security%20PDF-red.svg)](docs/usenix_paper_manuscript.pdf)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

> **Double-Blind Review Artifact**  
> *Target Venue:* USENIX Security Symposium (USENIX Security 2027)  
> *Anonymous Repository Mirror:* [https://anonymous.4open.science/r/eviassure-artifact-781D/](https://anonymous.4open.science/r/eviassure-artifact-781D/) (the URL the manuscript cites; an earlier mirror name was `eviassure-release-assurance`)  
> *Primary Focus:* Witnessed Trace Completeness (sequence-bound witness receipts + signed closing counts, reconciled at the gate), SHA-256 Merkle trace attestation with RFC 6962 domain separation, Ed25519 evidence packaging, and a fail-closed, stateful release gate.

---

## 📌 Executive Summary

Autonomous agentic deployments require reproducible, cryptographically verifiable evidence before releasing model updates, expanding tool execution privileges, or authorizing automated workflow triggers in production. Relying on unauthenticated CI build logs or self-reported status labels exposes release pipelines to runner tampering, trace forgery, and evidence replay attacks.

**EviAssure** delivers a complete **USENIX Security 2027 Systems Security Framework**:
- **Cryptographic Attestation Engine** (`assurance/crypto.py`): Condenses $N$ agent execution traces into a SHA-256 Merkle tree root with $O(\log N)$ audit inclusion proof verification.
- **Sealed Evidence Bundler** (`assurance/evidence.py`, `scripts/package_evidence.py`): Generates Ed25519/HMAC-signed `EvidenceBundle` instances with nonces and timestamps for replay protection.
- **Fail-Closed Policy Engine** (`assurance/policy.py`, `scripts/verify_release_gate.py`): Enforces multi-factor release conditions against `governance/release_policy.yaml`.
- **Witness Protocol** (`assurance/witness.py`, `benchmark/omission_vectors.py`): orchestrator-issued session credentials, sequence-bound receipts with prev-links, signed closing counts; the gate reconciles them against the trace set for the credentialed session (Witnessed Trace Completeness). ON by default in `governance/release_policy.yaml`; the shipped registry (`scripts/provision_witnesses.py`) carries demo witnesses.
- **Adversarial Suites** (`benchmark/tamper_vectors.py`, `benchmark/omission_vectors.py`, `benchmark/baselines.py`): 17 scored tamper vectors plus clean negative controls, 7 omission vectors plus an honest control, executed DSSE/TUF/OPA baselines, and re-implemented receipt and hash-chain baselines.
- **Empirical Benchmark & Paper Generator** (`scripts/run_release_benchmark.py`, `scripts/run_security_eval.py`, `scripts/generate_paper_pdf.py`): Merkle scaling, verifier throughput, the deterministic security evaluation, and the manuscript figures/PDF (`docs/usenix_paper_manuscript.pdf`).

---

## 📊 Measured Results (must match `results/*.json`; every number in the paper is a macro generated from those files)

| Metric / Experiment | Result | Where it comes from |
| :--- | :---: | :--- |
| **Tamper vectors blocked** | **16 / 17 (94.1%, 95% CI [73.0, 99.0])** | `results/security_evaluation.json`; V16 (cross-replica nonce replay) is not blocked and is reported as such |
| **Composed DSSE + TUF + OPA baseline** | **10 / 17 (58.8%)** | same file; intervals overlap with EviAssure's, and the paper says so |
| **Omission attacks detected (with witness reconciliation)** | **7 / 7** (O1–O7, incl. session substitution); honest control approved | same file; per-action receipts 2/7, per-issuer chaining 2/7, EviAssure without reconciliation 0/7 |
| **Held-out inspection recall** | **50/50 overt, 0/25 stealth (66.7% overall), 0/1000 false positives** | `results/corpus_evaluation.json` |
| **Merkle build, $N=10^6$** | **378.00 ms** (mean of 5, Apple M4 Max) | `results/benchmark_summary.json` |
| **Peak verifier throughput** | **7,152 ± 179 ops/s at 4 workers** (three-trace bundles) | `results/benchmark_summary.json` |
| **Test suite** | **115 tests** (`pytest tests/`; needs `pip install -e ".[dev]"`) | `tests/` |


## 🚀 Quickstart & Reproduction

1. **Install Dependencies** (`pip install -r pyproject.toml` is not a valid pip invocation and was a documentation error):
   ```bash
   pip install -e ".[dev]"
   ```

2. **Run Test Suite:**
   ```bash
   pytest tests/ -v
   ```

3. **Run the deterministic security evaluation and the timed benchmarks:**
   ```bash
   python3 scripts/run_security_eval.py --require-executed   # needs python-tuf and the opa binary
   python3 scripts/run_release_benchmark.py --repeats 5
   ```

4. **Verify Release Gate (fail-closed, witnessed by default):**
   ```bash
   python3 scripts/verify_release_gate.py                          # witnessed demo pack -> APPROVED
   python3 scripts/package_evidence.py -o evidence_pack.json       # writes the bundle + evidence_pack.json.release_request.json
   python3 scripts/verify_release_gate.py --evidence evidence_pack.json
   ```

5. **Generate Benchmark Figures & Paper PDF:**
   ```bash
   python3 scripts/generate_paper_pdf.py
   # Outputs compiled PDF to docs/usenix_paper_manuscript.pdf
   ```

## 🤝 Multi-Agent Paper Workflow

The paperloop can run a read-only evaluator and an independent analytical
auditor in parallel before the writer receives their combined work order. The
role contracts, Antigravity copy/paste prompts, human data handoff, and stopping
criteria are in [`docs/AGENT_WORKFLOW.md`](docs/AGENT_WORKFLOW.md).

---

## 📄 Academic Citation & Paper

Manuscript PDF: [`docs/usenix_paper_manuscript.pdf`](docs/usenix_paper_manuscript.pdf)

```bibtex
@inproceedings{anonymous2027usenix,
  title={Evidence-Backed Release Assurance for Autonomous Agent Deployments: Cryptographic Attestation, Fail-Closed Gates, and Tamper-Resilient Audit Infrastructure},
  author={Anonymous Authors},
  booktitle={USENIX Security Symposium (USENIX Security 2027)},
  year={2027}
}
```
