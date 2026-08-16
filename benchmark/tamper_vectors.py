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
    },
    "V13_OUT_OF_BOUNDS_KMS": {
        "id": "V13",
        "name": "Out of Bounds KMS Key ARN",
        "category": "Key Governance",
        "description": "Evidence signed by a valid trusted key but issued from outside the allowed KMS boundary.",
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
    v9_payload = {
        "evidence_id": v9_dict["evidence_id"],
        "timestamp": v9_dict["timestamp"],
        "nonce": v9_dict["nonce"],
        "agent_system_version": v9_dict["agent_system_version"],
        "test_pass_pct": v9_dict["test_pass_pct"],
        "unresolved_drift": v9_dict["unresolved_drift"],
        "execution_traces_count": v9_dict["execution_traces_count"],
        "merkle_root": v9_dict["merkle_root"],
        "artifact_digests": v9_dict["artifact_digests"],
        "sig_alg": v9_dict["sig_alg"],
        "key_id": "KEY-REVOKED-9999",
        "kms_key_arn": v9_dict.get("kms_key_arn")
    }
    v9_dict["signature"] = sign_payload_ed25519(v9_payload, DEMO_PRIV_KEY)
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

    # V13: Out of Bounds KMS ARN
    v13_dict = deepcopy(clean_dict)
    invalid_arn = "kms://aws/arn:aws:kms:us-west-2:000000000000:key/UNAUTHORIZED"
    v13_dict["kms_key_arn"] = invalid_arn
    v13_payload = {
        "evidence_id": v13_dict["evidence_id"],
        "timestamp": v13_dict["timestamp"],
        "nonce": v13_dict["nonce"],
        "agent_system_version": v13_dict["agent_system_version"],
        "test_pass_pct": v13_dict["test_pass_pct"],
        "unresolved_drift": v13_dict["unresolved_drift"],
        "execution_traces_count": v13_dict["execution_traces_count"],
        "merkle_root": v13_dict["merkle_root"],
        "artifact_digests": v13_dict["artifact_digests"],
        "sig_alg": v13_dict["sig_alg"],
        "key_id": v13_dict["key_id"],
        "kms_key_arn": invalid_arn
    }
    v13_dict["signature"] = sign_payload_ed25519(v13_payload, DEMO_PRIV_KEY)
    suite.append(("V13_OUT_OF_BOUNDS_KMS", TAMPER_VECTOR_TAXONOMY["V13_OUT_OF_BOUNDS_KMS"], v13_dict))

    return suite


def generate_fuzzing_mutation_suite(count: int = 1000, seed: int = 42) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Generate randomized property-based mutation fuzzing payloads.
    Applies diverse corruptions across:
    - Random signature bit flips
    - Payload field mutations & deletions
    - Timestamp skew injections
    - Merkle leaf additions, omissions, and byte corruptions
    - Nonce perturbations
    - Quality threshold degradation
    """
    import random
    rng = random.Random(seed)
    fuzzed_suite = []

    clean_eb = create_evidence_pack(use_ed25519=True, signed=True)
    clean_dict = clean_eb.to_dict()

    mutation_types = [
        "sig_flip", "root_corrupt", "leaf_drop", "leaf_inject",
        "timestamp_drift", "pass_rate_drop", "nonce_corrupt",
        "key_id_spoof", "arn_tamper", "missing_field"
    ]

    for i in range(count):
        mut_type = rng.choice(mutation_types)
        fuzzed = deepcopy(clean_dict)
        mut_label = f"FUZZ_{i+1:04d}_{mut_type}"

        if mut_type == "sig_flip":
            sig = list(fuzzed.get("signature", ""))
            if sig:
                idx = rng.randint(0, len(sig) - 1)
                sig[idx] = "A" if sig[idx] != "A" else "B"
                fuzzed["signature"] = "".join(sig)
        elif mut_type == "root_corrupt":
            root = list(fuzzed.get("merkle_root", ""))
            if root:
                idx = rng.randint(0, len(root) - 1)
                root[idx] = "f" if root[idx] != "f" else "0"
                fuzzed["merkle_root"] = "".join(root)
        elif mut_type == "leaf_drop":
            if len(fuzzed.get("traces", [])) > 1:
                fuzzed["traces"] = fuzzed["traces"][:-1]
        elif mut_type == "leaf_inject":
            extra_leaf = deepcopy(fuzzed["traces"][0]) if fuzzed.get("traces") else {"trace_id": "injected"}
            if isinstance(extra_leaf, dict):
                extra_leaf["trace_id"] = f"injected_{i}"
                extra_leaf["output_hash"] = "0" * 64
            fuzzed.setdefault("traces", []).append(extra_leaf)
        elif mut_type == "timestamp_drift":
            shift = rng.choice([-7200, 7200, -86400, 86400])
            dt = datetime.now(timezone.utc) + timedelta(seconds=shift)
            fuzzed["timestamp"] = dt.isoformat()
        elif mut_type == "pass_rate_drop":
            fuzzed["test_pass_pct"] = rng.uniform(0.0, 99.9)
        elif mut_type == "nonce_corrupt":
            fuzzed["nonce"] = ""
        elif mut_type == "key_id_spoof":
            fuzzed["key_id"] = f"SPOOFED_KEY_{rng.randint(1000, 9999)}"
        elif mut_type == "arn_tamper":
            fuzzed["kms_key_arn"] = f"arn:aws:kms:us-east-1:{rng.randint(1000,9999)}:key/untrusted"
        elif mut_type == "missing_field":
            target = rng.choice(["merkle_root", "evidence_id", "execution_traces_count"])
            fuzzed.pop(target, None)

        fuzzed_suite.append((mut_label, fuzzed))

    return fuzzed_suite

