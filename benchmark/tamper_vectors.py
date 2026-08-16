"""
Adversarial Release Tamper Vector Suite for USENIX Security Benchmark.
Defines 12 atomic attack scenarios targeting evidence-backed release gates.
"""

from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from typing import Dict, Any, List, Tuple

from assurance.evidence import create_evidence_pack, EvidenceBundle, DEFAULT_SECRET_KEY, DEMO_PRIV_KEY, DEMO_PUB_KEY_B64
from assurance.crypto import (hash_sha256, canonical_json, generate_ed25519_keypair,
                              sign_payload_ed25519)

TAMPER_VECTOR_TAXONOMY = {
    "V1_UNSIGNED_EVIDENCE": {
        "id": "V1",
        "name": "Unsigned Evidence Payload",
        "category": "Authentication",
        "description": "Evidence bundle submitted without a cryptographic signature.",
        "expected_result": "BLOCKED"
    },
    "V2_TAMPERED_TRACE_DIGEST": {
        "id": "V2",
        "name": "Tampered Trace Digest (Merkle Root Mismatch)",
        "category": "Integrity",
        "description": "An attacker modifies an execution trace log without updating the Merkle root.",
        "expected_result": "BLOCKED"
    },
    "V3_FORGED_SIGNATURE": {
        "id": "V3",
        "name": "Forged Signature",
        "category": "Authenticity",
        "description": "Evidence signed by an attacker-generated Ed25519 key that is not pinned in the trusted key registry.",
        "expected_result": "BLOCKED"
    },
    "V4_REPLAYED_NONCE": {
        "id": "V4",
        "name": "Replayed Evidence Nonce",
        "category": "Replay",
        "description": "Re-submitting a previously approved evidence pack nonce.",
        "expected_result": "BLOCKED"
    },
    "V5_EXPIRED_TIMESTAMP": {
        "id": "V5",
        "name": "Expired Evidence Timestamp",
        "category": "Freshness",
        "description": "Submitting an evidence pack created outside the allowed freshness window (>3600s).",
        "expected_result": "BLOCKED"
    },
    "V6_UNRESOLVED_DRIFT": {
        "id": "V6",
        "name": "Unresolved Security Drift",
        "category": "Policy Violation",
        "description": "Evidence bundle containing un-waived security drift findings.",
        "expected_result": "BLOCKED"
    },
    "V7_SUBTHRESHOLD_PASS_RATE": {
        "id": "V7",
        "name": "Sub-threshold Test Pass Rate",
        "category": "Quality Gate",
        "description": "Test suite pass percentage below policy requirement (<100%).",
        "expected_result": "BLOCKED"
    },
    "V8_FORGED_MERKLE_ROOT": {
        "id": "V8",
        "name": "Forged Merkle Root Digest",
        "category": "Integrity",
        "description": "Merkle root modified directly in the signed payload to conceal trace removal.",
        "expected_result": "BLOCKED"
    },
    "V9_REVOKED_KEY_SIGNATURE": {
        "id": "V9",
        "name": "Revoked Key ID Usage",
        "category": "Key Governance",
        "description": "Signature produced by a Key ID that has been explicitly revoked in CRL.",
        "expected_result": "BLOCKED"
    },
    "V10_JSON_MALLEABILITY": {
        "id": "V10",
        "name": "JSON Key Malleability Payload Injection",
        "category": "Serialization",
        "description": "Inserting uncanonicalized key fields into signed evidence dictionary.",
        "expected_result": "BLOCKED"
    },
    "V11_CLOCK_SKEW_FUTURE": {
        "id": "V11",
        "name": "Post-Dated Future Clock Skew",
        "category": "Freshness",
        "description": "Timestamp forged into the distant future to bypass freshness expiration.",
        "expected_result": "BLOCKED"
    },
    "V12_PARTIAL_MERKLE_TREE": {
        "id": "V12",
        "name": "Truncated Partial Merkle Proof Path",
        "category": "Integrity",
        "description": "Removing execution trace entries from the bundle while leaving count unchanged.",
        "expected_result": "BLOCKED"
    }
}


def generate_tampered_evidence_suite() -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """
    Generate clean baseline + 12 tampered evidence pack specimens.
    Returns list of tuples: (vector_id, metadata, evidence_dict_or_bundle).
    """
    clean_bundle = create_evidence_pack(use_ed25519=True, signed=True)
    clean_dict = clean_bundle.to_dict()

    suite = []

    # V1: Unsigned
    v1_dict = deepcopy(clean_dict)
    v1_dict["signed"] = False
    v1_dict["signature"] = None
    suite.append(("V1_UNSIGNED_EVIDENCE", TAMPER_VECTOR_TAXONOMY["V1_UNSIGNED_EVIDENCE"], v1_dict))

    # V2: Tampered Trace
    v2_dict = deepcopy(clean_dict)
    if v2_dict["traces"]:
        v2_dict["traces"][0]["status"] = "FORGED_SUCCESS"
        v2_dict["traces"][0]["output_hash"] = hash_sha256("TAMPERED_OUTPUT")
    suite.append(("V2_TAMPERED_TRACE_DIGEST", TAMPER_VECTOR_TAXONOMY["V2_TAMPERED_TRACE_DIGEST"], v2_dict))

    # V3: Forged Signature — the attacker generates a fresh Ed25519 keypair,
    # signs a well-formed payload, and embeds their own public key. The gate
    # must reject it because the key is not in the trusted registry (and a
    # spoofed trusted key_id fails the pinned-key comparison).
    att_priv, _, att_pub_b64, _ = generate_ed25519_keypair()
    v3_bundle = create_evidence_pack(use_ed25519=False, signed=False)
    v3_dict = v3_bundle.to_dict()
    v3_dict.update({
        "signed": True,
        "sig_alg": "ed25519",
        "key_id": "KEY-ATTACKER-UNTRUSTED",
        "public_key": att_pub_b64,
    })
    v3_payload = {
        "evidence_id": v3_dict["evidence_id"],
        "timestamp": v3_dict["timestamp"],
        "nonce": v3_dict["nonce"],
        "agent_system_version": v3_dict["agent_system_version"],
        "test_pass_pct": v3_dict["test_pass_pct"],
        "unresolved_drift": v3_dict["unresolved_drift"],
        "execution_traces_count": v3_dict["execution_traces_count"],
        "merkle_root": v3_dict["merkle_root"],
        "artifact_digests": v3_dict["artifact_digests"],
        "sig_alg": "ed25519",
        "key_id": "KEY-ATTACKER-UNTRUSTED",
        "kms_key_arn": v3_dict.get("kms_key_arn"),
    }
    v3_dict["signature"] = sign_payload_ed25519(v3_payload, att_priv)
    suite.append(("V3_FORGED_SIGNATURE", TAMPER_VECTOR_TAXONOMY["V3_FORGED_SIGNATURE"], v3_dict))

    # V4: Replayed Nonce
    v4_dict = deepcopy(clean_dict)
    suite.append(("V4_REPLAYED_NONCE", TAMPER_VECTOR_TAXONOMY["V4_REPLAYED_NONCE"], v4_dict))

    # V5: Expired Timestamp
    v5_dict = deepcopy(clean_dict)
    expired_dt = datetime.now(timezone.utc) - timedelta(seconds=7200)
    v5_dict["timestamp"] = expired_dt.isoformat()
    v5_eb = EvidenceBundle(**v5_dict)
    v5_eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    suite.append(("V5_EXPIRED_TIMESTAMP", TAMPER_VECTOR_TAXONOMY["V5_EXPIRED_TIMESTAMP"], v5_eb.to_dict()))

    # V6: Unresolved Drift
    v6_dict = deepcopy(clean_dict)
    v6_dict["unresolved_drift"] = 3
    v6_eb = EvidenceBundle(**v6_dict)
    v6_eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    suite.append(("V6_UNRESOLVED_DRIFT", TAMPER_VECTOR_TAXONOMY["V6_UNRESOLVED_DRIFT"], v6_eb.to_dict()))

    # V7: Sub-threshold Pass Rate
    v7_dict = deepcopy(clean_dict)
    v7_dict["test_pass_pct"] = 85.5
    v7_eb = EvidenceBundle(**v7_dict)
    v7_eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    suite.append(("V7_SUBTHRESHOLD_PASS_RATE", TAMPER_VECTOR_TAXONOMY["V7_SUBTHRESHOLD_PASS_RATE"], v7_eb.to_dict()))

    # V8: Forged Merkle Root Digest
    v8_dict = deepcopy(clean_dict)
    v8_dict["merkle_root"] = hash_sha256("FORGED_MERKLE_ROOT_STRING")
    v8_eb = EvidenceBundle(**v8_dict)
    v8_eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    suite.append(("V8_FORGED_MERKLE_ROOT", TAMPER_VECTOR_TAXONOMY["V8_FORGED_MERKLE_ROOT"], v8_eb.to_dict()))

    # V9: Revoked Key ID
    v9_dict = deepcopy(clean_dict)
    v9_dict["key_id"] = "KEY-REVOKED-9999"
    suite.append(("V9_REVOKED_KEY_SIGNATURE", TAMPER_VECTOR_TAXONOMY["V9_REVOKED_KEY_SIGNATURE"], v9_dict))

    # V10: JSON Key Malleability -- a genuine duplicate-key wire attack (N5).
    # The canonical bundle is signed with test_pass_pct=100.0. The attacker
    # ships a raw wire document that REPEATS the "test_pass_pct" key with a
    # second value (85.5): json.loads keeps the LAST occurrence (85.5) while
    # other parsers keep the FIRST (100.0), so the same signed bytes evaluate
    # differently per reader. The ingestion boundary must reject the document
    # as non-canonical before any policy or signature logic runs. The parsed
    # (last-wins) dict is passed alongside the raw wire text so the gate can
    # perform that check.
    v10_clean = deepcopy(clean_dict)
    v10_wire = canonical_json(v10_clean)
    assert '"test_pass_pct":100.0' in v10_wire, "expected signed canonical value in wire doc"
    v10_wire_dup = v10_wire[:-1] + ',"test_pass_pct":85.5}'
    v10_dict = json.loads(v10_wire_dup)
    assert v10_dict["test_pass_pct"] == 85.5, "last-wins parse must differ from signed value"
    v10_dict["raw_wire_json"] = v10_wire_dup
    suite.append(("V10_JSON_MALLEABILITY", TAMPER_VECTOR_TAXONOMY["V10_JSON_MALLEABILITY"], v10_dict))

    # V11: Future Clock Skew
    v11_dict = deepcopy(clean_dict)
    future_dt = datetime.now(timezone.utc) + timedelta(seconds=3600)
    v11_dict["timestamp"] = future_dt.isoformat()
    v11_eb = EvidenceBundle(**v11_dict)
    v11_eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    suite.append(("V11_CLOCK_SKEW_FUTURE", TAMPER_VECTOR_TAXONOMY["V11_CLOCK_SKEW_FUTURE"], v11_eb.to_dict()))

    # V12: Truncated Merkle Path
    v12_dict = deepcopy(clean_dict)
    if v12_dict["traces"]:
        v12_dict["traces"] = v12_dict["traces"][:1]
    suite.append(("V12_PARTIAL_MERKLE_TREE", TAMPER_VECTOR_TAXONOMY["V12_PARTIAL_MERKLE_TREE"], v12_dict))

    return suite
