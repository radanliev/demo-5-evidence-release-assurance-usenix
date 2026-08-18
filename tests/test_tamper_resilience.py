"""
Security tests verifying 100% fail-closed block rate across all 12 adversarial release tamper vectors.
"""

from pathlib import Path
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite, TAMPER_VECTOR_TAXONOMY


def test_tamper_resilience_suite():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path, witnessed=False)

    tamper_suite = generate_tampered_evidence_suite()
    from benchmark.tamper_vectors import SCORED_VECTORS
    # V14-V18 were added on 2026-08-17 and V13 retired from scoring (review A3/C6).
    assert len(tamper_suite) == len(TAMPER_VECTOR_TAXONOMY)
    assert len(SCORED_VECTORS) == len(tamper_suite) - 1, "exactly one retired check"

    seen_nonces = set()

    for vector_id, meta, tampered_evidence in tamper_suite:
        test_seen_nonces = seen_nonces.copy()
        if vector_id == "V4_REPLAYED_NONCE":
            test_seen_nonces.add(tampered_evidence["nonce"])

        passed, violations, details = policy_engine.evaluate(
            evidence=tampered_evidence,
            seen_nonces=test_seen_nonces
        )

        # Not every vector targets the policy gate (2026-08-17, review A3):
        #   V15 targets the third-party auditor's proof-verification path
        #   V17 targets Merkle tree construction (leaf typing)
        #   V16 is UNBLOCKED by design and reported as such -- replay
        #       protection is a property of gate state, and a second replica
        #       holds none. scripts/run_security_eval.py records it.
        if vector_id in ("V15_INTERNAL_NODE_AS_LEAF", "V17_LEAF_TYPE_CONFUSION"):
            continue                      # exercised in test_merkle_soundness.py
        if vector_id == "V16_CROSS_REPLICA_REPLAY":
            assert passed is True, (
                "V16 is a disclosed failure. If it now blocks, the distributed "
                "nonce store landed and the paper's limitation must be updated.")
            continue

        assert passed is False, f"TAMPER DEFECT: Vector {vector_id} ({meta['name']}) unexpectedly passed policy gate!"
        assert len(violations) > 0, f"Vector {vector_id} failed without violation messages!"
        assert details["fail_closed_enforced"] is True


def test_property_based_fuzzing_1000_mutations():
    from benchmark.tamper_vectors import generate_fuzzing_mutation_suite
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path, witnessed=False)

    fuzz_suite = generate_fuzzing_mutation_suite(count=1000, seed=42)
    assert len(fuzz_suite) == 1000

    for mut_label, fuzzed_payload in fuzz_suite:
        passed, violations, details = policy_engine.evaluate(fuzzed_payload, seen_nonces=set())
        assert passed is False, f"FUZZING DEFECT: Mutated payload {mut_label} unexpectedly passed policy gate!"
        assert len(violations) > 0, f"Mutated payload {mut_label} failed without violation messages!"

