# Demo 5: Evidence-Backed Release Assurance for Agentic Systems

[![USENIX Security Target](https://img.shields.io/badge/Research--Target-USENIX%20Security%202027-blue.svg)](https://www.usenix.org/conference/usenixsecurity27)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

> **Blind-Verification Research & Teaching Portfolio**  
> *Target Venue:* USENIX Security Symposium (USENIX Security 2027)  
> *Primary Focus:* Fail-closed automated release gates, cryptographic evidence packaging, policy validation, and audit trace verification for autonomous agent deployments.

---

## 📌 Executive Summary

Autonomous agentic deployments require reproducible evidence before releasing model updates, tool privileges, or workflow triggers to production. Claims of system safety must be backed by cryptographically verifiable evidence packs rather than self-reported status labels.

**Demo 5** introduces a fail-closed release gate engine (`scripts/verify_release_gate.py`), a release policy engine (`governance/release_policy.yaml`), an evidence bundler (`scripts/package_evidence.py`), and automated release gate unit tests (`tests/test_release_gate.py`).

---

## 🎓 Course Integration Runbooks

### Newcastle University — Practical 5
- **Practical Title:** Evidence-Backed Release Assurance & Deployment Gates
- **Learning Outcome:** Package evidence bundles, evaluate policy gates, and enforce fail-closed release controls.
- **Runbook Command:**
  ```bash
  python scripts/verify_release_gate.py --policy governance/release_policy.yaml --format text
  ```

### O'Reilly Bootcamp — Session 5
- **Session Title:** Release Gates & Cryptographic Evidence Bundling for AI Agents
- **Bootcamp Goal:** Generate sealed evidence packs, execute release policy validation, and verify audit compliance.
- **Live Specimen:**
  ```bash
  python scripts/package_evidence.py --output evidence_pack.json
  ```

### Pearson Video Course — Module 5
- **Module Title:** Module 5 — End-to-End Release Assurance & Policy Gates
- **Lab Exercise:** Execute the USENIX Security release gate suite and confirm release gate passes.
- **On-Screen Command:**
  ```bash
  pytest tests/test_release_gate.py -v
  ```

---

## 🚀 Quickstart

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Test Suite:**
   ```bash
   pytest tests/ -v
   ```

3. **Verify Release Gate:**
   ```bash
   python scripts/verify_release_gate.py
   ```
