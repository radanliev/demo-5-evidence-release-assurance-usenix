"""
Unit and integration tests for the expanded N=1,050 agent trace corpus.

Corpus integrity, attestation leaf hashing, and gate behavior: all profiles
package into Merkle-consistent signed bundles; clean profiles pass policy
verification; planted anomalies are *semantic* signals (non-SUCCESS trace
statuses visible to forensic inspection), not cryptographic tampering, so
they do not trip the cryptographic gate.
"""

import json
from pathlib import Path
from assurance.crypto import build_merkle_tree
from assurance.evidence import ExecutionTraceRecord, create_evidence_pack
from assurance.policy import ReleasePolicyEngine

def test_expanded_corpus_loading():
    corpus_path = Path(__file__).parent.parent / "corpus" / "agent_trace_corpus.json"
    assert corpus_path.exists(), "Corpus JSON file must exist!"

    with open(corpus_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_profiles"] >= 1000, "Corpus must contain at least 1,000 profiles!"
    # The corpus gained 5 stealth anomaly classes on 2026-08-17 (review B3): the
    # overt classes alone were separable by a single out-of-vocabulary rule, so
    # the benchmark measured nothing. Assert the invariant, not a stale literal.
    assert data["total_anomalies"] == data["overt_anomalies"] + data["stealth_anomalies"]
    assert data["stealth_anomalies"] > 0, "corpus must retain in-vocabulary anomalies"
    assert len(data["profiles"]) == data["total_profiles"]
    assert len(data["agent_architectures"]) == 5, "Corpus must span five agent architectures"

def test_corpus_anomaly_detection_and_merkle_hashing():
    corpus_path = Path(__file__).parent.parent / "corpus" / "agent_trace_corpus.json"
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    with open(corpus_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    anomalies = 0
    clean_passed = 0
    distinct_anomaly_types = set()

    for prof in data["profiles"]:
        label = prof["label"]
        traces = [
            ExecutionTraceRecord(
                trace_id=t["trace_id"],
                agent_id=t["agent_id"],
                action=t["action"],
                status=t["status"],
                duration_ms=t["duration_ms"],
                output_hash=t["output_hash"]
            )
            for t in prof["traces"]
        ]

        bundle = create_evidence_pack(traces=traces, signed=True)
        bundle_dict = bundle.to_dict()

        # Every profile, clean or anomalous, is Merkle-consistent
        leaf_hashes = [t.to_hash() for t in traces]
        root, _ = build_merkle_tree(leaf_hashes)
        assert root == bundle.merkle_root, "Merkle root mismatch!"

        passed, violations, _ = policy_engine.evaluate(bundle_dict, seen_nonces=set())

        if label != "CLEAN":
            anomalies += 1
            distinct_anomaly_types.add(label)
            # Planted anomalies are semantic: at least one trace carries a
            # non-SUCCESS status that forensic inspection surfaces per-leaf.
            # 2026-08-17 (review B3): this used to assert that EVERY anomaly
            # carries a non-SUCCESS trace. That property is exactly what made
            # the corpus separable by one rule and the reported 50/50 recall
            # vacuous. The invariant now depends on the anomaly family:
            #   overt   -> out-of-vocabulary action AND status (the easy half)
            #   stealth -> action, status and duration all drawn from clean
            #              traffic, so no per-leaf test can separate them
            family = prof.get("anomaly_family")
            if family == "overt":
                assert any(t.status != "SUCCESS" for t in traces), (
                    f"Overt anomaly {prof['profile_id']} must carry a non-SUCCESS trace")
            elif family == "stealth":
                assert all(t.status == "SUCCESS" for t in traces), (
                    f"Stealth anomaly {prof['profile_id']} must be per-leaf "
                    "indistinguishable from clean traffic; if it is not, the "
                    "held-out recall number in the paper is measuring the wrong thing")
        else:
            clean_passed += 1
            assert passed, f"Clean profile {prof['profile_id']} failed the gate: {violations}"

    assert anomalies == data["total_anomalies"], (
        f"corpus header claims {data['total_anomalies']} anomalies, profiles contain {anomalies}")
    assert clean_passed == 1000, f"Expected 1,000 clean passes, got {clean_passed}"
    # 10 overt + 5 stealth classes since 2026-08-17 (review B3).
    overt = {c for c in distinct_anomaly_types if c.startswith("ANOMALY_")}
    stealth = {c for c in distinct_anomaly_types if c.startswith("STEALTH_")}
    assert len(overt) == 10, f"Expected 10 overt anomaly classes, got {len(overt)}"
    assert len(stealth) >= 1, "corpus must retain per-leaf-indistinguishable classes"
    assert overt | stealth == distinct_anomaly_types
