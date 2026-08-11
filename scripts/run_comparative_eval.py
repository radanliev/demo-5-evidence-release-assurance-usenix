#!/usr/bin/env python3
"""
Comparative Baseline Evaluation Script for USENIX Security 2027.
Evaluates Demo 5 against Standard CI exit gates, OPA/Kyverno schema validators, and Sigstore/Cosign container signing.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import create_evidence_pack, DEFAULT_SECRET_KEY
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite, TAMPER_VECTOR_TAXONOMY


def eval_ci_exit_code_gate(payload: Dict[str, Any]) -> bool:
    """Standard unauthenticated CI exit code check: passes if test_pass_pct > 0 and no hard failure flag."""
    return payload.get("test_pass_pct", 0) > 0 and payload.get("status") != "HARD_FAILURE"


def eval_opa_schema_gate(payload: Dict[str, Any]) -> bool:
    """Unsigned JSON schema validator: checks test_pass_pct == 100 and unresolved_drift == 0."""
    return payload.get("test_pass_pct", 0.0) >= 100.0 and payload.get("unresolved_drift", 999) <= 0


def eval_sigstore_cosign_gate(payload: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY) -> bool:
    """Container digest signature validator: checks signature presence, but ignores execution trace Merkle root."""
    signed = payload.get("signed", False)
    sig = payload.get("signature")
    return signed and sig is not None and payload.get("test_pass_pct", 0.0) >= 100.0


def main():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)
    suite = generate_tampered_evidence_suite()

    print("=== Running Comparative Baseline Deployment Gate Evaluation ===")
    print(f"Adversarial Vectors Evaluated: {len(suite)}")

    results = []
    seen_nonces = set()

    for vector_id, meta, tampered_payload in suite:
        test_seen_nonces = seen_nonces.copy()
        if vector_id == "V4_REPLAYED_NONCE":
            test_seen_nonces.add(tampered_payload["nonce"])

        # 1. CI Exit Code
        ci_passed = eval_ci_exit_code_gate(tampered_payload)
        ci_blocked = not ci_passed

        # 2. OPA Schema Gate
        opa_passed = eval_opa_schema_gate(tampered_payload)
        opa_blocked = not opa_passed

        # 3. Sigstore Cosign Gate
        cosign_passed = eval_sigstore_cosign_gate(tampered_payload)
        cosign_blocked = not cosign_passed

        # 4. Demo 5 Evidence Assurance Gate
        demo5_passed, violations, _ = policy_engine.evaluate(tampered_payload, seen_nonces=test_seen_nonces)
        demo5_blocked = not demo5_passed

        results.append({
            "vector_id": meta["id"],
            "vector_name": meta["name"],
            "ci_exit_code_blocked": ci_blocked,
            "opa_schema_blocked": opa_blocked,
            "sigstore_cosign_blocked": cosign_blocked,
            "demo5_assurance_blocked": demo5_blocked
        })

    # Summary Statistics
    ci_block_rate = (sum(1 for r in results if r["ci_exit_code_blocked"]) / len(results)) * 100.0
    opa_block_rate = (sum(1 for r in results if r["opa_schema_blocked"]) / len(results)) * 100.0
    cosign_block_rate = (sum(1 for r in results if r["sigstore_cosign_blocked"]) / len(results)) * 100.0
    demo5_block_rate = (sum(1 for r in results if r["demo5_assurance_blocked"]) / len(results)) * 100.0

    print("\n--- Comparative Detection Rates Across 12 Tamper Attack Vectors ---")
    print(f"1. Standard CI Exit Code Gate:       {ci_block_rate:6.1f}% Block Rate ({sum(1 for r in results if r['ci_exit_code_blocked'])}/12)")
    print(f"2. OPA / Kyverno Schema Validator:  {opa_block_rate:6.1f}% Block Rate ({sum(1 for r in results if r['opa_schema_blocked'])}/12)")
    print(f"3. Sigstore / Cosign Artifact Gate: {cosign_block_rate:6.1f}% Block Rate ({sum(1 for r in results if r['sigstore_cosign_blocked'])}/12)")
    print(f"4. Demo 5 Evidence Assurance Gate:  {demo5_block_rate:6.1f}% Block Rate ({sum(1 for r in results if r['demo5_assurance_blocked'])}/12)")

    out_file = Path(__file__).parent.parent / "results" / "comparative_evaluation.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "ci_exit_code_block_rate_pct": ci_block_rate,
            "opa_schema_block_rate_pct": opa_block_rate,
            "sigstore_cosign_block_rate_pct": cosign_block_rate,
            "demo5_assurance_block_rate_pct": demo5_block_rate
        },
        "details": results
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, indent=2)

    print(f"\n[+] Comparative evaluation summary saved to: {out_file}")


if __name__ == "__main__":
    main()
