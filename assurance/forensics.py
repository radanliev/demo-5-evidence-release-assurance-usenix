"""
Forensic Audit Engine for Evidence Bundle Verification and Audit Trail Inspection.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .crypto import (
    hash_sha256,
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    verify_signature_ed25519,
    verify_signature_hmac,
)
from .evidence import EvidenceBundle, DEFAULT_SECRET_KEY
from .policy import ReleasePolicyEngine


class ForensicAuditEngine:
    """Performs deep cryptographic audit and trace inclusion inspection on Evidence Bundles."""

    def __init__(self, policy_engine: Optional[ReleasePolicyEngine] = None):
        self.policy_engine = policy_engine

    def audit_bundle(
        self,
        evidence: EvidenceBundle | Dict[str, Any],
        secret_key: str = DEFAULT_SECRET_KEY,
        seen_nonces: Optional[set] = None
    ) -> Dict[str, Any]:
        """Perform comprehensive forensic inspection and return structured audit card."""
        if isinstance(evidence, EvidenceBundle):
            b = evidence.to_dict()
        else:
            b = evidence

        ev_id = b.get("evidence_id", "UNKNOWN")
        signed = b.get("signed", False)
        sig_alg = b.get("sig_alg", "ed25519")
        key_id = b.get("key_id", "UNKNOWN")
        pub_key = b.get("public_key")
        sig = b.get("signature")
        merkle_root = b.get("merkle_root", "")
        traces = b.get("traces", [])

        # 1. Signature Inspection
        sig_valid = False
        if signed and sig:
            payload = {
                "evidence_id": b.get("evidence_id", ""),
                "timestamp": b.get("timestamp", ""),
                "nonce": b.get("nonce", ""),
                "agent_system_version": b.get("agent_system_version", ""),
                "test_pass_pct": b.get("test_pass_pct", 0.0),
                "unresolved_drift": b.get("unresolved_drift", 0),
                "execution_traces_count": b.get("execution_traces_count", 0),
                "merkle_root": merkle_root,
                "artifact_digests": b.get("artifact_digests", {}),
                "sig_alg": sig_alg,
                "key_id": key_id,
                "kms_key_arn": b.get("kms_key_arn")
            }
            if sig_alg == "ed25519" and pub_key:
                sig_valid = verify_signature_ed25519(payload, sig, pub_key)
            else:
                sig_valid = verify_signature_hmac(payload, sig, secret_key)

        # 2. Merkle Tree & Inclusion Proof Inspection
        leaf_hashes = []
        for t in traces:
            raw = f"{t.get('trace_id')}:{t.get('agent_id')}:{t.get('action')}:{t.get('status')}:{t.get('output_hash')}"
            leaf_hashes.append(hash_sha256(raw))

        recalculated_root, levels = build_merkle_tree(leaf_hashes)
        merkle_valid = (recalculated_root == merkle_root)

        trace_audit = []
        for i, leaf_h in enumerate(leaf_hashes):
            proof = generate_merkle_proof(i, levels)
            proof_ok = verify_merkle_proof(leaf_h, proof, recalculated_root)
            trace_audit.append({
                "index": i,
                "trace_id": traces[i].get("trace_id"),
                "action": traces[i].get("action"),
                "status": traces[i].get("status"),
                "leaf_hash": leaf_h[:12] + "...",
                "inclusion_proof_valid": proof_ok
            })

        # 3. Policy Evaluation Integration
        policy_passed = False
        violations = []
        if self.policy_engine:
            policy_passed, violations, _ = self.policy_engine.evaluate(b, secret_key, seen_nonces)

        audit_result = {
            "evidence_id": ev_id,
            "audited_at": datetime.now(timezone.utc).isoformat(),
            "signature_valid": sig_valid,
            "signature_algorithm": sig_alg,
            "key_id": key_id,
            "merkle_root_claimed": merkle_root,
            "merkle_root_recalculated": recalculated_root,
            "merkle_integrity_valid": merkle_valid,
            "total_traces_inspected": len(traces),
            "trace_inclusion_proofs_valid": all(t["inclusion_proof_valid"] for t in trace_audit),
            "policy_passed": policy_passed,
            "policy_violations": violations,
            "forensic_status": "AUTHENTIC_AND_VERIFIED" if (sig_valid and merkle_valid and policy_passed) else "COMPROMISED_OR_TAMPERED",
            "trace_details": trace_audit
        }

        return audit_result
