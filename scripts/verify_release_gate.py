#!/usr/bin/env python3
"""
USENIX Security Release Gate Verifier
"""

import sys
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.package_evidence import generate_evidence_pack

def evaluate_release_gate(policy_path: Path) -> dict:
    with open(policy_path, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)
        
    evidence = generate_evidence_pack()
    rc = policy.get("release_conditions", {})
    
    passed = (
        evidence["signed"] == rc.get("require_signed_evidence", True) and
        evidence["test_pass_pct"] >= rc.get("min_passing_tests_pct", 100) and
        evidence["unresolved_drift"] <= rc.get("allowed_drift_findings", 0)
    )
    
    return {
        "policy_name": policy.get("policy_name"),
        "evidence_id": evidence["evidence_id"],
        "signed": evidence["signed"],
        "passed": passed
    }

def main():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    res = evaluate_release_gate(policy_path)
    
    print("=== USENIX Security Release Gate Evaluation ===")
    print(f"Policy: {res['policy_name']}")
    print(f"Evidence ID: {res['evidence_id']} (Signed: {res['signed']})")
    
    if res["passed"]:
        print("STATUS: RELEASE APPROVED (Fail-Closed Gate Passed)")
        sys.exit(0)
    else:
        print("STATUS: RELEASE BLOCKED (Policy Violation)")
        sys.exit(1)

if __name__ == "__main__":
    main()
