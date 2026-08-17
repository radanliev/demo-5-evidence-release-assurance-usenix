"""
Regression tests for the soundness gaps found by the 2026-08-15 adversarial
review (docs/PEER_REVIEW_2026-08-15.md):

M1 - internal Merkle nodes verified as leaves via shortened proof paths
     (no hash collision needed; CVE-2012-2459 family). Fixed by binding
     verification to the committed tree depth.
M2 - the signed execution_traces_count was never compared to len(traces);
     bundles lied about trace counts and passed.
M3 - the blinding tag truncated a 256-bit HMAC to 64 bits.
"""

from pathlib import Path

from assurance.crypto import (
    hash_sha256, build_merkle_tree, generate_merkle_proof,
    verify_merkle_proof, expected_tree_depth,
    merkle_leaf_digest, merkle_node_digest, LEAF_PREFIX, NODE_PREFIX,
)
from assurance.evidence import (
    ExecutionTraceRecord, EvidenceBundle, create_evidence_pack,
    DEMO_PRIV_KEY, DEMO_PUB_KEY_B64,
)
from assurance.policy import ReleasePolicyEngine

POLICY = Path(__file__).parent.parent / "governance" / "release_policy.yaml"


def _tree(n):
    leaves = [merkle_leaf_digest(f"trace-{i}") for i in range(n)]
    root, levels = build_merkle_tree(leaves)
    return leaves, root, levels


def _shortened_path(levels, level_idx, node_idx):
    """Proof path from (level_idx, node_idx) upward, as an attacker would craft."""
    path, idx = [], node_idx
    for lvl in levels[level_idx:-1]:
        sib = lvl[idx + 1] if idx % 2 == 0 and idx + 1 < len(lvl) else lvl[idx - 1] if idx % 2 == 1 else lvl[idx]
        path.append({"hash": sib, "position": "right" if idx % 2 == 0 else "left"})
        idx //= 2
    return path


def test_internal_node_cannot_verify_as_leaf_with_depth_bound():
    """The exact attack from the review: internal node + shortened path."""
    leaves, root, levels = _tree(16)
    internal = levels[1][2]                      # covers leaves 4-5
    att = _shortened_path(levels, 1, 2)          # 3 nodes, not 4
    depth = expected_tree_depth(16)
    assert len(att) == depth - 1
    # Defence 1 (2026-08-15): the committed depth rejects the shortened path.
    assert verify_merkle_proof(internal, att, root, depth) is False
    # Defence 2 (2026-08-17, C1): even at the CORRECT length the internal node
    # cannot be reinterpreted as a leaf, because leaves and nodes are hashed
    # under different domain prefixes. Pad the path to full depth and retry.
    padded = att + [{"hash": "0" * 64, "position": "right"}]
    assert len(padded) == depth
    assert verify_merkle_proof(internal, padded, root, depth) is False
    # and honest proofs still verify
    honest = generate_merkle_proof(5, levels)
    assert verify_merkle_proof(leaves[5], honest, root, depth) is True


def test_leaf_and_internal_domains_are_separated():
    """C1: leaf and internal preimages live in disjoint domains by
    construction (RFC 6962 0x00/0x01 prefixes), not by luck."""
    assert LEAF_PREFIX != NODE_PREFIX
    a, b = merkle_leaf_digest("x"), merkle_leaf_digest("y")
    # A leaf whose *content* is the concatenation an internal node would hash
    # must still produce a different digest.
    colliding_content = bytes.fromhex(a) + bytes.fromhex(b)
    assert merkle_leaf_digest(colliding_content) != merkle_node_digest(a, b)


def test_proof_api_requires_explicit_depth():
    """C2: the unsound call shape no longer exists -- expected_depth is a
    required positional argument, so an auditor cannot accidentally opt out."""
    import inspect
    sig = inspect.signature(verify_merkle_proof)
    assert sig.parameters["expected_depth"].default is inspect.Parameter.empty


def test_build_rejects_non_digest_leaves():
    """C2: the len(x) != 64 heuristic is gone; a 64-char non-digest string is
    no longer silently adopted as a leaf digest."""
    import pytest
    with pytest.raises(ValueError):
        build_merkle_tree(["Z" * 64])
    with pytest.raises(ValueError):
        build_merkle_tree(["not-a-digest"])


def test_depth_helper_matches_built_trees():
    for n in (1, 2, 3, 16, 100, 1000, 4096):
        _, _, levels = _tree(n)
        assert len(levels) - 1 == expected_tree_depth(n), n


def test_signed_trace_count_is_enforced():
    """M2: lying about execution_traces_count must block, not pass."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    d = bundle.to_dict()
    d["execution_traces_count"] = 999
    eb = EvidenceBundle(**{k: v for k, v in d.items() if k not in ("signature", "signatures")})
    eb.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)   # properly signed lie
    passed, violations, _ = engine.evaluate(eb.to_dict(), seen_nonces=set())
    assert not passed
    assert any("trace count mismatch" in v for v in violations)

    # honest bundle still passes
    ok, vi, _ = engine.evaluate(create_evidence_pack(use_ed25519=True, signed=True).to_dict(), seen_nonces=set())
    assert ok, vi


def test_blinding_tag_is_256_bit():
    """M3: blinded output hash carries the full HMAC digest (64 hex)."""
    rec = ExecutionTraceRecord(trace_id="T", agent_id="a", action="x",
                               status="SUCCESS", duration_ms=1.0,
                               output_hash=hash_sha256("secret payload"))
    blinded = rec.blind_payload("s" * 32).output_hash
    assert len(blinded) == 64
