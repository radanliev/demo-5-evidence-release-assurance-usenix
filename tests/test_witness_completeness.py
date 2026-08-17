"""
Witnessed Trace Completeness: the security property and its boundary.

These tests encode both halves of the claim. The positive half -- omission is
detected -- is the contribution. The negative half -- unwitnessed actions remain
invisible, and the guarantee is relative to the witness set -- is the boundary,
and it is tested explicitly so the paper cannot overstate it.
"""

import copy
from pathlib import Path


from assurance.crypto import hash_sha256, generate_ed25519_keypair, sign_payload_ed25519
from assurance.evidence import (ExecutionTraceRecord, create_evidence_pack,
                                DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
from assurance.policy import ReleasePolicyEngine
from assurance.witness import Closing, reconcile
from benchmark.omission_vectors import generate_omission_suite, witnessed_execution

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "governance" / "release_policy.yaml"


def _engine(registry, mediated, witnessed=True):
    e = ReleasePolicyEngine.from_yaml(POLICY)
    e.witness_registry = dict(registry)
    e.mediated_actions = dict(mediated)
    e.release_conditions.update({"require_witnessed_completeness": witnessed})
    return e


# ---------------------------------------------------------------- the property

def test_every_omission_vector_is_blocked_and_control_is_approved():
    """The headline result. Also asserts the control passes -- a reconciler that
    rejects everything would score 6/6 and be useless."""
    suite, registry, mediated = generate_omission_suite()
    results = {}
    for vid, _meta, bundle in suite:
        passed, violations, _ = _engine(registry, mediated).evaluate(
            copy.deepcopy(bundle), seen_nonces=set())
        results[vid] = (passed, violations)

    assert results["OC1"][0] is True, \
        f"honest witnessed execution must be approved: {results['OC1'][1]}"
    for vid in ("O1", "O2", "O3", "O4", "O5", "O6"):
        assert results[vid][0] is False, f"{vid} must be blocked"
        assert any(v.startswith("COMPLETENESS_VIOLATION") for v in results[vid][1]), \
            f"{vid} must be blocked BY the completeness check, not incidentally"


def test_omissions_are_invisible_without_witness_reconciliation():
    """The counterfactual that makes the contribution non-trivial: with
    reconciliation disabled, every omission is APPROVED by a gate that is
    otherwise fully enforcing (signatures, Merkle root, count binding, freshness,
    replay). Omission is not a tampering problem."""
    suite, registry, mediated = generate_omission_suite()
    for vid, _meta, bundle in suite:
        passed, violations, _ = _engine(registry, mediated, witnessed=False).evaluate(
            copy.deepcopy(bundle), seen_nonces=set())
        assert passed is True, f"{vid} unexpectedly blocked without WTC: {violations}"


def test_suffix_omission_defeats_hash_chaining_but_not_closing_counts():
    """The precise delta against AAS-1-style per-issuer chaining: a chain links
    records that are PRESENT, so truncating the end leaves it intact."""
    from benchmark.baselines import HashChainBaseline
    suite, registry, mediated = generate_omission_suite()
    by_id = {vid: b for vid, _m, b in suite}
    chain = HashChainBaseline(registry)

    assert chain.verify(by_id["O2"]) is True, "suffix truncation leaves a chain intact"
    assert chain.verify(by_id["O1"]) is False, "an interior gap does break a chain"
    for vid in ("O1", "O2"):
        assert _engine(registry, mediated).evaluate(
            copy.deepcopy(by_id[vid]), seen_nonces=set())[0] is False


def test_receipts_alone_do_not_give_completeness():
    """Against the 2026 receipt schemes: a bundle whose every recorded action
    carries a valid receipt can still be missing actions."""
    from benchmark.baselines import ReceiptsOnlyBaseline
    suite, registry, mediated = generate_omission_suite()
    by_id = {vid: b for vid, _m, b in suite}
    receipts_only = ReceiptsOnlyBaseline(registry, mediated)

    for vid in ("O1", "O2", "O3", "O4"):
        assert receipts_only.verify(by_id[vid]) is True, \
            f"{vid} should be invisible to a receipts-only verifier"
        assert _engine(registry, mediated).evaluate(
            copy.deepcopy(by_id[vid]), seen_nonces=set())[0] is False


# ---------------------------------------------------------------- the boundary

def test_unwitnessed_actions_remain_undetectable():
    """The stated limit of the guarantee. An action outside every witness's
    mediated set is invisible, and the paper must say so rather than implying
    unconditional completeness."""
    _, registry, mediated = generate_omission_suite()
    session = "sess-boundary"
    ws, traces, receipts, closings, reg, med = witnessed_execution(session)

    ghost = ExecutionTraceRecord("TR-UNMEDIATED", "ops-agent-v1",
                                 "write_local_scratch_file",   # no witness mediates this
                                 "SUCCESS", 2.0, hash_sha256("SIDE_EFFECT"))
    b = create_evidence_pack(traces=list(traces) + [ghost], use_ed25519=True, signed=False)
    b.session_id = session
    b.witness_receipts = [r.to_dict() for r in receipts]
    b.witness_closings = [c.to_dict() for c in closings]
    b.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)

    passed, _, _ = _engine(reg, med).evaluate(b.to_dict(), seen_nonces=set())
    assert passed is True, (
        "an unmediated action is expected to pass: completeness is relative to "
        "the witness set. If this ever fails, the paper's boundary claim is "
        "wrong in the OTHER direction and must be restated."
    )


def test_forging_a_closing_requires_the_witness_key():
    """The reduction the theorem rests on, exercised concretely."""
    session = "sess-forge"
    _ws, traces, receipts, closings, reg, med = witnessed_execution(session)
    att_priv, _, _att_pub, _ = generate_ed25519_keypair()

    forged = Closing("db-gateway", session, 0)
    forged.signature = sign_payload_ed25519(forged.payload(), att_priv)
    ok, violations, _ = reconcile(
        traces=[], receipts=[],
        closings=[forged.to_dict()] + [c.to_dict() for c in closings
                                       if c.witness_id != "db-gateway"],
        witness_registry=reg, session_id=session, mediated_actions=med)
    assert ok is False
    assert any("invalid closing signature" in v for v in violations)


# ---------------------------------------------------------------- integrity

def test_stripping_witness_evidence_breaks_the_bundle_signature():
    """Completeness would be trivially defeatable if a collector could delete
    receipts from a signed bundle, so the signature covers a digest of the
    witness set."""
    session = "sess-strip"
    _ws, traces, receipts, closings, reg, med = witnessed_execution(session)
    b = create_evidence_pack(traces=list(traces), use_ed25519=True, signed=False)
    b.session_id = session
    b.witness_receipts = [r.to_dict() for r in receipts]
    b.witness_closings = [c.to_dict() for c in closings]
    b.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)

    stripped = b.to_dict()
    stripped["witness_receipts"] = []
    stripped["witness_closings"] = []
    passed, violations, _ = _engine(reg, med).evaluate(stripped, seen_nonces=set())
    assert passed is False
    assert any("signature" in v.lower() for v in violations), \
        "deleting witness evidence must invalidate the signature, not merely fail reconciliation"


def test_baseline_signed_field_view_matches_the_signer():
    """Guards the methodological failure caught during development: if the
    baselines' view of the signed payload drifts from the signer's, they reject
    honest bundles and 'win' the comparison for the wrong reason."""
    from benchmark import baselines
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    signer_fields = set(bundle.payload_for_signing().keys())
    baseline_fields = set(baselines._SIGNED_FIELDS)
    assert signer_fields == baseline_fields, (
        f"signer signs {sorted(signer_fields - baseline_fields)} that baselines ignore; "
        f"baselines expect {sorted(baseline_fields - signer_fields)} that the signer omits"
    )
