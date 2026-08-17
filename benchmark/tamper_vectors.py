"""
Adversarial Release Tamper Vector Suite for the USENIX Security benchmark.

Structure after the 2026-08-17 adversarial review (finding A3):

  * V1-V12 are the original *mechanism* vectors, each targeting one enforcement.
    They are, by construction, close to a 1:1 map onto EviAssure's checks, and
    the paper now says so plainly instead of claiming the map "proves complete
    coverage of the formal domain".
  * V13 (out-of-bounds KMS ARN) has been RETIRED from the adversarial count.
    `kms_key_arn` is self-declared metadata covered by the signature: against an
    adversary without a trusted key it adds nothing, and against one with a
    trusted key it is a string they control. It is retained as a configuration
    check, not scored as an attack (review C6).
  * V14-V18 are *independent* vectors written against the design rather than
    against the check list, including two that the implementation FAILED before
    this round. They exist so that the suite is capable of producing a negative
    result. Vectors are allowed to be UNBLOCKED, and unblocked outcomes are
    reported rather than removed.
  * C1-C4 are clean negative controls. A gate that blocks everything is not a
    gate; the suite now measures the false-block rate too (review B2).
"""

from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from typing import Dict, Any, List, Tuple

from assurance.evidence import (create_evidence_pack, EvidenceBundle, ExecutionTraceRecord,
                                DEMO_PRIV_KEY, DEMO_PUB_KEY_B64,
                                execution_trace_leaf_string)
from assurance.crypto import (hash_sha256, canonical_json, generate_ed25519_keypair,
                              sign_payload_ed25519, merkle_leaf_digest, build_merkle_tree)

from assurance.crypto import hash_sha256 as _h

_NO_WITNESS = _h("NO_WITNESS")

_SIGNED_FIELDS = ("evidence_id", "timestamp", "nonce", "agent_system_version",
                  "test_pass_pct", "unresolved_drift", "execution_traces_count",
                  "merkle_root", "artifact_digests", "session_id", "witness_digest",
                  "sig_alg", "key_id", "kms_key_arn")

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
        "name": "Out of Bounds KMS Key ARN (configuration check, not scored)",
        "category": "Configuration",
        "description": ("Evidence signed by a valid trusted key but declaring a KMS ARN outside "
                        "the allowed boundary. RETIRED from the adversarial score: the ARN is "
                        "self-declared metadata inside the signed payload, so it constrains "
                        "misconfiguration, not an adversary (2026-08-17 review, C6)."),
        "expected_result": "BLOCKED",
        "scored": False,
    },
    "V14_REGISTRY_DISABLED_ATTACKER_KEY": {
        "id": "V14",
        "name": "Attacker Key Accepted Under Disabled Registry",
        "category": "Authenticity",
        "description": ("Adversary generates their own Ed25519 keypair, attaches the public half "
                        "to the bundle and declares a policy-conformant KMS ARN, against a gate "
                        "whose trusted-key registry has been switched off. FAILED before "
                        "2026-08-17 (complete authentication bypass; review A2)."),
        "expected_result": "BLOCKED"
    },
    "V15_INTERNAL_NODE_AS_LEAF": {
        "id": "V15",
        "name": "Internal Merkle Node Presented as Leaf to a Third-Party Auditor",
        "category": "Integrity",
        "description": ("The CVE-2012-2459-family forgery: an internal node digest is offered as "
                        "a trace leaf with a shortened proof path. Targets the sparse-proof "
                        "auditor path (Sec 7 'store proofs on-chain'), not the gate. FAILED "
                        "before 2026-08-15 and only partially fixed until 2026-08-17 (C1/C2)."),
        "expected_result": "BLOCKED"
    },
    "V16_CROSS_REPLICA_REPLAY": {
        "id": "V16",
        "name": "Cross-Replica Nonce Replay",
        "category": "Replay",
        "description": ("The same approved bundle is submitted to a SECOND gate instance that "
                        "does not share the first one's nonce state -- the realistic ephemeral-CI "
                        "condition. Distinct from V4, which replays within one instance."),
        "expected_result": "BLOCKED"
    },
    "V17_LEAF_TYPE_CONFUSION": {
        "id": "V17",
        "name": "64-Character Leaf Type Confusion",
        "category": "Integrity",
        "description": ("A trace whose canonical leaf string is exactly 64 characters, exploiting "
                        "the `len(x) != 64` heuristic that decided whether a value was already a "
                        "digest. FAILED before 2026-08-17 (review C2)."),
        "expected_result": "BLOCKED"
    },
    "V18_POST_SIGNING_DOM_MUTATION": {
        "id": "V18",
        "name": "Post-Signing DOM Mutation with Recomputed Root",
        "category": "Integrity",
        "description": ("A browser-agent trace is mutated after collection (injected modal) and "
                        "the Merkle root is recomputed to match, but the bundle is re-signed with "
                        "a key the registry does not pin -- the strongest form of the Sec 6.4 "
                        "attack."),
        "expected_result": "BLOCKED"
    }
}

SCORED_VECTORS = [k for k, v in TAMPER_VECTOR_TAXONOMY.items() if v.get("scored", True)]


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
        "session_id": None,
        "witness_digest": _NO_WITNESS,
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
        "session_id": None,
        "witness_digest": _NO_WITNESS,
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
        "session_id": None,
        "witness_digest": _NO_WITNESS,
        "sig_alg": v13_dict["sig_alg"],
        "key_id": v13_dict["key_id"],
        "kms_key_arn": invalid_arn
    }
    v13_dict["signature"] = sign_payload_ed25519(v13_payload, DEMO_PRIV_KEY)
    suite.append(("V13_OUT_OF_BOUNDS_KMS", TAMPER_VECTOR_TAXONOMY["V13_OUT_OF_BOUNDS_KMS"], v13_dict))

    # ---------------------------------------------------------------- V14-V18
    # Independent vectors (2026-08-17 review, A3). These were written against
    # the design rather than against the check list; two of them broke the
    # implementation as it stood before this round.

    # V14: attacker keypair + policy-conformant KMS ARN, evaluated against a
    # gate whose trusted-key registry has been disabled. Carries the gate
    # override it needs so the harness can apply it.
    att14_priv, _, att14_pub, _ = generate_ed25519_keypair()
    v14_dict = deepcopy(clean_dict)
    v14_dict.update({
        "key_id": "KEY-ATTACKER-NOT-IN-REGISTRY",
        "public_key": att14_pub,
        "kms_key_arn": "kms://aws/arn:aws:kms:us-east-1:000000000000:key/attacker-forged",
        "signatures": [],
    })
    v14_dict["signature"] = sign_payload_ed25519(
        {k: v14_dict.get(k) for k in _SIGNED_FIELDS}, att14_priv)
    v14_dict["__gate_override__"] = {"require_trusted_key": False}
    suite.append(("V14_REGISTRY_DISABLED_ATTACKER_KEY",
                  TAMPER_VECTOR_TAXONOMY["V14_REGISTRY_DISABLED_ATTACKER_KEY"], v14_dict))

    # V15: internal-node-as-leaf forgery against the auditor proof path. The
    # payload carries the forged (leaf, proof) pair; the harness evaluates it
    # through verify_merkle_proof rather than through the policy gate, because
    # this vector targets third-party auditors (Sec 7), not the release gate.
    v15_dict = deepcopy(clean_dict)
    v15_leaves = [merkle_leaf_digest(execution_trace_leaf_string(t)) for t in v15_dict["traces"]]
    while len(v15_leaves) < 8:                      # need >= 3 levels to have an internal node
        v15_leaves.append(merkle_leaf_digest(f"pad-{len(v15_leaves)}"))
    v15_root, v15_levels = build_merkle_tree(v15_leaves)
    _internal = v15_levels[1][0]
    _path, _idx = [], 0
    for lvl in v15_levels[1:-1]:
        sib = lvl[_idx + 1] if _idx % 2 == 0 and _idx + 1 < len(lvl) else lvl[_idx - 1] if _idx % 2 else lvl[_idx]
        _path.append({"hash": sib, "position": "right" if _idx % 2 == 0 else "left"})
        _idx //= 2
    v15_dict["__auditor_challenge__"] = {
        "claimed_leaf": _internal,
        "proof_path": _path,
        "root": v15_root,
        "committed_leaf_count": len(v15_leaves),
    }
    suite.append(("V15_INTERNAL_NODE_AS_LEAF",
                  TAMPER_VECTOR_TAXONOMY["V15_INTERNAL_NODE_AS_LEAF"], v15_dict))

    # V16: the same approved bundle presented to a SECOND gate replica that does
    # not share replay state. The harness gives this vector a fresh nonce set,
    # which is precisely the ephemeral-CI condition.
    v16_dict = deepcopy(clean_dict)
    v16_dict["__fresh_replica__"] = True
    suite.append(("V16_CROSS_REPLICA_REPLAY",
                  TAMPER_VECTOR_TAXONOMY["V16_CROSS_REPLICA_REPLAY"], v16_dict))

    # V17: a trace whose canonical leaf string is exactly 64 characters.
    v17_traces = [ExecutionTraceRecord(
        trace_id="T", agent_id="a", action="x", status="S", duration_ms=1.0,
        output_hash="0" * 52)]
    assert len(execution_trace_leaf_string(v17_traces[0])) == 64, \
        f"vector requires a 64-char leaf string, got {len(execution_trace_leaf_string(v17_traces[0]))}"
    v17_bundle = create_evidence_pack(traces=v17_traces, use_ed25519=True, signed=True)
    v17_dict = v17_bundle.to_dict()
    # The adversary claims the raw leaf string is itself the leaf digest.
    v17_dict["__leaf_confusion_probe__"] = execution_trace_leaf_string(v17_traces[0])
    suite.append(("V17_LEAF_TYPE_CONFUSION",
                  TAMPER_VECTOR_TAXONOMY["V17_LEAF_TYPE_CONFUSION"], v17_dict))

    # V18: post-signing DOM mutation with a correctly recomputed root, re-signed
    # under an attacker key. Root recomputation alone does NOT catch this --
    # only signer authentication does.
    att18_priv, _, att18_pub, _ = generate_ed25519_keypair()
    v18_traces = [ExecutionTraceRecord(
        trace_id="UI-001", agent_id="web-agent", action="click",
        status="SUCCESS", duration_ms=3.0,
        output_hash=hash_sha256("<html>...<dialog id='phish'>Approve</dialog>...</html>"))]
    v18_bundle = create_evidence_pack(traces=v18_traces, use_ed25519=True, signed=False)
    v18_dict = v18_bundle.to_dict()
    v18_dict.update({"signed": True, "sig_alg": "ed25519",
                     "key_id": "KEY-6d1f9bcd0679",          # spoofs a REAL registry ID
                     "public_key": att18_pub,
                     "kms_key_arn": "kms://aws/arn:aws:kms:us-east-1:000000000000:key/usenix-release-gate"})
    v18_dict["signature"] = sign_payload_ed25519(
        {k: v18_dict.get(k) for k in _SIGNED_FIELDS}, att18_priv)
    suite.append(("V18_POST_SIGNING_DOM_MUTATION",
                  TAMPER_VECTOR_TAXONOMY["V18_POST_SIGNING_DOM_MUTATION"], v18_dict))

    return suite


def generate_negative_controls(count: int = 4) -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """Clean, well-formed bundles that MUST be approved.

    A suite made only of attacks cannot distinguish a working gate from
    `return BLOCKED` (2026-08-17 review, B2). These controls make the
    false-block rate measurable.
    """
    controls = []
    shapes = [
        ("C1_MINIMAL", [ExecutionTraceRecord("TR-1", "agent", "noop", "SUCCESS", 1.0,
                                             hash_sha256("OK"))]),
        ("C2_DEFAULT", None),
        ("C3_WIDE", [ExecutionTraceRecord(f"TR-{i}", "agent", "step", "SUCCESS",
                                          float(i), hash_sha256(f"O{i}")) for i in range(64)]),
        ("C4_ODD_COUNT", [ExecutionTraceRecord(f"TR-{i}", "agent", "step", "SUCCESS",
                                               float(i), hash_sha256(f"P{i}")) for i in range(7)]),
    ]
    for label, traces in shapes[:count]:
        b = create_evidence_pack(traces=traces, use_ed25519=True, signed=True)
        controls.append((label,
                         {"id": label.split("_")[0], "name": f"Negative control: {label}",
                          "category": "Control", "expected_result": "APPROVED"},
                         b.to_dict()))
    return controls


def generate_wire_fuzzing_suite(count: int = 1000, seed: int = 42,
                                clean_fraction: float = 0.2) -> List[Tuple[str, Dict[str, Any], bool]]:
    """Differential *wire-encoding* fuzzing with clean controls.

    Rationale (2026-08-17 review, B2). The previous campaign mutated fields
    *inside* the Ed25519-signed payload -- signature bytes, the Merkle root,
    the pass rate, the nonce. Every such mutation invalidates the signature or
    the root by construction, so "1000/1000 blocked" was an arithmetic identity,
    not a measurement, and the campaign contained no clean bundles so it could
    not detect false blocks either.

    This campaign instead perturbs the **serialization** of an otherwise valid,
    correctly signed bundle: key order, insignificant whitespace, unicode
    escaping, number formatting (``100.0`` vs ``1e2`` vs ``100``), duplicate
    keys, byte-order marks, trailing data. These are exactly the inputs a
    canonicalisation or parser-differential bug would let through, so a
    *passing* result is genuinely possible and a *failing* result is
    informative.

    Returns triples ``(label, payload, should_be_approved)``. Encoding-preserving
    mutations (key reordering, insignificant whitespace) MUST still be approved;
    semantics-changing ones (duplicate keys, number-value changes) MUST be
    blocked. ``clean_fraction`` of the corpus is untouched controls.
    """
    import random
    rng = random.Random(seed)
    out: List[Tuple[str, Dict[str, Any], bool]] = []

    clean_eb = create_evidence_pack(use_ed25519=True, signed=True)
    base = clean_eb.to_dict()
    wire = canonical_json(base)

    n_clean = int(count * clean_fraction)
    for i in range(n_clean):
        b = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
        out.append((f"CTRL_{i+1:04d}_clean", b, True))

    # (mutation name, transform, semantics_preserving)
    def _reorder(w):
        d = json.loads(w)
        items = list(d.items()); rng.shuffle(items)
        return json.dumps(dict(items), separators=(",", ":"))

    def _whitespace(w):
        return json.dumps(json.loads(w), indent=rng.choice([1, 2, 4]))

    def _unicode_escape(w):
        return json.dumps(json.loads(w), ensure_ascii=True, separators=(",", ":"))

    def _dup_key(w):
        return w[:-1] + ',"test_pass_pct":41.0}'

    def _number_form(w):
        return w.replace('"test_pass_pct":100.0', '"test_pass_pct":1e2')

    def _bom(w):
        return "﻿" + w

    def _trailing(w):
        return w + "\n\n   "

    def _null_pad(w):
        return w.replace('"unresolved_drift":0', '"unresolved_drift":-0')

    mutations = [
        ("reorder_keys", _reorder, True),
        ("insignificant_whitespace", _whitespace, True),
        ("unicode_escaping", _unicode_escape, True),
        ("trailing_whitespace", _trailing, True),
        ("negative_zero", _null_pad, True),
        ("duplicate_key", _dup_key, False),
        ("number_reformat", _number_form, True),
        ("utf8_bom", _bom, False),   # a BOM makes the document non-canonical: correctly rejected
    ]

    for i in range(count - n_clean):
        name, fn, preserving = mutations[rng.randrange(len(mutations))]
        try:
            mutated_wire = fn(wire)
            payload = json.loads(mutated_wire.lstrip("﻿"))
        except Exception:
            payload = {"__unparseable__": True}
            preserving = False
        payload["raw_wire_json"] = mutated_wire
        out.append((f"WIRE_{i+1:04d}_{name}", payload, preserving))

    rng.shuffle(out)
    return out


def generate_fuzzing_mutation_suite(count: int = 1000, seed: int = 42) -> List[Tuple[str, Dict[str, Any]]]:
    """DEPRECATED (2026-08-17 review, B2): retained only so the historical
    result in the paper's revision history remains reproducible. Every mutation
    here touches a signed field, so the block rate is 100% by construction and
    the experiment has no discriminative power. Use
    :func:`generate_wire_fuzzing_suite` instead.

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

