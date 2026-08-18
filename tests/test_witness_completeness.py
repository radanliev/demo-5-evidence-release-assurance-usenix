"""
Witnessed Trace Completeness: the security property and its boundary.

These tests encode both halves of the claim. The positive half -- omission is
detected -- is the contribution. The negative half -- unwitnessed actions remain
invisible, and the guarantee is relative to the witness set -- is the boundary,
and it is tested explicitly so the paper cannot overstate it.

They also pin the two assumptions the reduction rests on: witnesses serve only
credentialed sessions (so session identity is not the adversary's to choose),
and the gate binds a release to the session it credentialed (vector O7).
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.crypto import (hash_sha256, generate_ed25519_keypair, sign_payload_ed25519,
                              build_merkle_tree, merkle_leaf_digest)
from assurance.evidence import (ExecutionTraceRecord, create_evidence_pack,
                                execution_trace_leaf_string,
                                DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
from assurance.policy import ReleasePolicyEngine
from assurance.witness import (Closing, CredentialError, SessionCredential, Witness,
                               action_digest, issue_session_credential, reconcile)
from benchmark.omission_vectors import generate_omission_suite, witnessed_execution

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "governance" / "release_policy.yaml"


def _engine(registry, mediated, witnessed=True):
    e = ReleasePolicyEngine.from_yaml(POLICY, witnessed=witnessed)
    e.witness_registry = dict(registry)
    e.mediated_actions = dict(mediated)
    return e


def _cred_for(session: str) -> SessionCredential:
    return issue_session_credential(f"release-for-{session}", session_id=session)


# ---------------------------------------------------------------- the property

def test_every_omission_vector_is_blocked_and_control_is_approved():
    """The headline result. Also asserts the control passes -- a reconciler that
    rejects everything would score 7/7 and be useless."""
    suite, registry, mediated = generate_omission_suite()
    results = {}
    for vid, meta, bundle in suite:
        passed, violations, _ = _engine(registry, mediated).evaluate(
            copy.deepcopy(bundle), seen_nonces=set(),
            expected_session_id=meta["expected_session_id"])
        results[vid] = (passed, violations)

    assert results["OC1"][0] is True, \
        f"honest witnessed execution must be approved: {results['OC1'][1]}"
    for vid in ("O1", "O2", "O3", "O4", "O5", "O6", "O7"):
        assert results[vid][0] is False, f"{vid} must be blocked"
        assert any(v.startswith("COMPLETENESS_VIOLATION") for v in results[vid][1]), \
            f"{vid} must be blocked BY the completeness check, not incidentally"


def test_omissions_are_invisible_without_witness_reconciliation():
    """The counterfactual that makes the contribution non-trivial: with
    reconciliation disabled, every omission is APPROVED by a gate that is
    otherwise fully enforcing (signatures, Merkle root, count binding, freshness,
    replay). Omission is not a tampering problem."""
    suite, registry, mediated = generate_omission_suite()
    for vid, meta, bundle in suite:
        passed, violations, _ = _engine(registry, mediated, witnessed=False).evaluate(
            copy.deepcopy(bundle), seen_nonces=set(),
            expected_session_id=meta["expected_session_id"])
        assert passed is True, f"{vid} unexpectedly blocked without WTC: {violations}"


def test_suffix_omission_defeats_hash_chaining_but_not_closing_counts():
    """The precise delta against AAS-1-style per-issuer chaining: a chain links
    records that are PRESENT, so truncating the end leaves it intact. A chain
    does catch an interior gap and a spliced foreign receipt (whose prev link
    names a receipt from another chain)."""
    from benchmark.baselines import HashChainBaseline
    suite, registry, mediated = generate_omission_suite()
    by_id = {vid: b for vid, _m, b in suite}
    meta = {vid: m for vid, m, _b in suite}
    chain = HashChainBaseline(registry)

    assert chain.verify(by_id["OC1"]) is True, "the honest control must chain-verify"
    assert chain.verify(by_id["O2"]) is True, "suffix truncation leaves a chain intact"
    assert chain.verify(by_id["O1"]) is False, "an interior gap does break a chain"
    assert chain.verify(by_id["O5"]) is False, "a spliced foreign receipt does not link"
    assert chain.verify(by_id["O7"]) is True, "a complete foreign session chains perfectly"
    for vid in ("O1", "O2", "O5", "O7"):
        assert _engine(registry, mediated).evaluate(
            copy.deepcopy(by_id[vid]), seen_nonces=set(),
            expected_session_id=meta[vid]["expected_session_id"])[0] is False


def test_receipts_alone_do_not_give_completeness():
    """Against the 2026 receipt schemes: a bundle whose every recorded action
    carries a valid receipt can still be missing actions -- and can be the
    wrong session entirely."""
    from benchmark.baselines import ReceiptsOnlyBaseline
    suite, registry, mediated = generate_omission_suite()
    by_id = {vid: b for vid, _m, b in suite}
    meta = {vid: m for vid, m, _b in suite}
    receipts_only = ReceiptsOnlyBaseline(registry, mediated)

    for vid in ("O1", "O2", "O3", "O4", "O7"):
        assert receipts_only.verify(by_id[vid]) is True, \
            f"{vid} should be invisible to a receipts-only verifier"
        assert _engine(registry, mediated).evaluate(
            copy.deepcopy(by_id[vid]), seen_nonces=set(),
            expected_session_id=meta[vid]["expected_session_id"])[0] is False


# ------------------------------------------------- session identity is not free

def test_witness_refuses_uncredentialed_and_forged_sessions():
    """The relabelling hole, closed at the witness: a bare session string, or a
    credential signed by anyone but the pinned orchestrator, is refused, so the
    adversary cannot get an action served under a session of its choosing."""
    w = Witness("db-gateway", mediates={"execute_read_only_query"})
    t = ExecutionTraceRecord("TR-X", "ops-agent-v1", "execute_read_only_query",
                             "SUCCESS", 1.0, hash_sha256("x"))
    with pytest.raises(CredentialError):
        w.observe("sess-i-just-made-up", t)                 # bare string
    att_priv, _, _pub, _ = generate_ed25519_keypair()
    forged = issue_session_credential("release-x", private_key=att_priv, session_id="sess-forged")
    with pytest.raises(CredentialError):
        w.observe(forged, t)                                  # attacker-signed credential
    with pytest.raises(CredentialError):
        w.close(forged)
    good = _cred_for("sess-good")
    r = w.observe(good, t)
    assert r.session_id == "sess-good" and r.seq == 1


def test_gate_requires_the_release_request_to_name_the_session():
    """Fail-closed: with witnessed completeness required, a bundle evaluated
    without an expected session is BLOCKED rather than reconciled against the
    session it declares -- otherwise O7 would be undetectable by construction."""
    suite, registry, mediated = generate_omission_suite()
    control = next(b for vid, _m, b in suite if vid == "OC1")
    passed, violations, _ = _engine(registry, mediated).evaluate(
        copy.deepcopy(control), seen_nonces=set())            # no expected_session_id
    assert passed is False
    assert any("no expected session" in v for v in violations)


def test_session_substitution_is_blocked_only_by_release_binding():
    """O7 in isolation: the presented bundle is complete and honestly witnessed
    for ITS session; reconciled against its own session it passes, reconciled
    against the credentialed one it fails."""
    suite, registry, mediated = generate_omission_suite()
    meta, bundle = next((m, b) for vid, m, b in suite if vid == "O7")
    own = bundle["session_id"]
    assert _engine(registry, mediated).evaluate(
        copy.deepcopy(bundle), seen_nonces=set(), expected_session_id=own)[0] is True
    passed, violations, _ = _engine(registry, mediated).evaluate(
        copy.deepcopy(bundle), seen_nonces=set(),
        expected_session_id=meta["expected_session_id"])
    assert passed is False
    assert any("session substitution" in v for v in violations)


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

    passed, _, _ = _engine(reg, med).evaluate(b.to_dict(), seen_nonces=set(),
                                              expected_session_id=session)
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
        witness_registry=reg, session_id=session, mediated_actions=med,
        expected_session_id=session)
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
    passed, violations, _ = _engine(reg, med).evaluate(stripped, seen_nonces=set(),
                                                       expected_session_id=session)
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


# ------------------------------------------- the SHIPPED gate, not the harness

def test_shipped_policy_blocks_unwitnessed_bundles():
    """The deployable default: with no override, an otherwise valid bundle that
    carries no witness attestations is BLOCKED by the completeness check."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)          # policy default, no override
    assert engine.release_conditions.get("require_witnessed_completeness") is True
    assert engine.witness_registry, "the shipped witness registry must not be empty"
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    passed, violations, _ = engine.evaluate(bundle, seen_nonces=set(),
                                            expected_session_id="sess-any")
    assert passed is False
    assert any(v.startswith("COMPLETENESS_VIOLATION") for v in violations)


def test_shipped_policy_approves_the_witnessed_demo_pack():
    """...and approves the demo pack that the packaging script and the CLI
    produce, reconciled against the session its credential names."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    pack = create_evidence_pack(use_ed25519=True, signed=True, witnessed=True)
    passed, violations, details = engine.evaluate(pack.to_dict(), seen_nonces=set(),
                                                  expected_session_id=pack.session_id)
    assert passed is True, violations
    assert details["witness"]["witnessed"] is True
    assert details["witness"]["closings_valid"] == 3


def _resign_as_collector(bundle_dict):
    """The adversary holds the collector key: re-sign whatever it presents."""
    b = create_evidence_pack(traces=[], use_ed25519=True, signed=False)
    for k, v in bundle_dict.items():
        if hasattr(b, k) and k not in ("signed", "signature", "signatures"):
            setattr(b, k, v)
    b.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    return b.to_dict()


def test_omission_vectors_blocked_through_the_shipped_cli(tmp_path):
    """End to end: the demo witnesses of governance/witness_registry.yaml, a
    release request, and scripts/verify_release_gate.py. Interior/suffix
    omission and session substitution are rebuilt against the demo pack; each
    must exit 1 with a COMPLETENESS violation, and the honest pack must exit 0."""
    pack = create_evidence_pack(use_ed25519=True, signed=True, witnessed=True)
    d = pack.to_dict()
    sid = pack.session_id
    counter = {"n": 0}

    def run(bundle, expected):
        counter["n"] += 1
        ev = tmp_path / f"b{counter['n']}.json"
        ev.write_text(json.dumps(bundle))
        rr = tmp_path / f"rr{counter['n']}.json"
        rr.write_text(json.dumps({"release_id": "release-demo", "session_id": expected}))
        r = subprocess.run(
            [sys.executable, "scripts/verify_release_gate.py", "--evidence", str(ev),
             "--release-request", str(rr), "--nonce-store", str(tmp_path / f"n{counter['n']}.json"),
             "--format", "json"],
            capture_output=True, text=True, cwd=str(ROOT))
        assert r.stdout, r.stderr
        return r.returncode, json.loads(r.stdout)

    code, out = run(d, sid)
    assert code == 0 and out["status"] == "APPROVED", out["violations"]
    assert out["witnessed_completeness_required"] is True

    # O1 / O2: drop a witnessed action and its receipt, recompute, re-sign honestly
    for drop in (1, 2):
        b2 = copy.deepcopy(d)
        victim = b2["traces"][drop]
        b2["traces"] = [t for i, t in enumerate(b2["traces"]) if i != drop]
        b2["execution_traces_count"] = len(b2["traces"])
        b2["witness_receipts"] = [r for r in b2["witness_receipts"]
                                  if r["action_digest"] != action_digest(victim)]
        b2["merkle_root"], _ = build_merkle_tree(
            [merkle_leaf_digest(execution_trace_leaf_string(t)) for t in b2["traces"]])
        code, out = run(_resign_as_collector(b2), sid)
        assert code == 1, out
        assert any(v.startswith("COMPLETENESS_VIOLATION") for v in out["violations"]), out

    # O7: the same honest pack presented for a different credentialed session
    code, out = run(d, "sess-some-other-release")
    assert code == 1 and any("session substitution" in v for v in out["violations"]), out
