"""A witness must attest the action it served, not the record it was handed.

These tests exist because the live-agent harness used to execute the tool
itself, build the trace record, and then ask a `Witness` object to sign that
record. The receipt proved the collector had signed its own claim twice. The
tests below pin the property that fixes it, and -- deliberately -- also pin
the failure of the old arrangement, so nobody reintroduces it believing the
two are equivalent.

Everything here is offline and deterministic: no model provider is involved.
"""
from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import ExecutionTraceRecord, hash_sha256   # noqa: E402
from assurance.witness import (                                    # noqa: E402
    CredentialError, Witness, issue_session_credential, reconcile,
)
from specimens.live_agent_runner import TOOL_WITNESSES             # noqa: E402
from specimens.witness_process import (                            # noqa: E402
    ProcessWitness, ProcessWitnessPool, WitnessProcessError,
)

ACTION = "execute_read_only_query"
ARGS = {"sql": "SELECT * FROM releases"}
AGENT = "live-agent/test"
DOCTORED = hash_sha256('{"rows": []}')


@pytest.fixture
def pool():
    p = ProcessWitnessPool(TOOL_WITNESSES)
    try:
        yield p
    finally:
        p.shutdown()


@pytest.fixture
def cred():
    return issue_session_credential("release-oop-test", session_id="live-oop-test")


def _reconcile(traces, receipts, closings, registry, mediated, sid):
    ok, violations, _detail = reconcile(
        [asdict(t) for t in traces],
        [r.to_dict() if hasattr(r, "to_dict") else r for r in receipts],
        [c.to_dict() if hasattr(c, "to_dict") else c for c in closings],
        registry, sid, require_witness=True,
        mediated_actions=mediated, expected_session_id=sid)
    return ok, violations


def _serve(pool, cred, trace_id="TR-000"):
    """Have the real witness serve one action; return (served, collector_trace)."""
    from assurance.witness import Receipt
    w = pool.for_action(ACTION)
    served = w.serve(cred.to_dict(), ACTION, ARGS, trace_id, AGENT)
    trace = ExecutionTraceRecord(
        trace_id=trace_id, agent_id=AGENT, action=ACTION, status=served["status"],
        duration_ms=served["witness_duration_ms"],
        output_hash=hash_sha256(served["result"]))
    return Receipt(**served["receipt"]), trace


def _closings(pool, cred):
    from assurance.witness import Closing
    return [Closing(**c) for c in pool.close_all(cred.to_dict())]


# ---------------------------------------------------------------------------
# The independence property itself
# ---------------------------------------------------------------------------

def test_collector_never_holds_a_witness_signing_key(pool):
    """The parent can ask for a signature. It cannot produce one."""
    w = pool.for_action(ACTION)
    assert isinstance(w, ProcessWitness)
    assert w.public_key_b64
    # No private key material of any name is reachable from the client handle.
    assert not any("priv" in a.lower() or "secret" in a.lower()
                   for a in vars(w)), vars(w).keys()
    # And it really is another OS process.
    assert w.pid != __import__("os").getpid()


def test_witness_hashes_its_own_output_not_the_collectors(pool, cred):
    """The attested digest is over bytes the witness produced."""
    w = pool.for_action(ACTION)
    served = w.serve(cred.to_dict(), ACTION, ARGS, "TR-000", AGENT)
    assert served["attested"]["output_hash"] == hash_sha256(served["result"])
    # The collector was never asked what the output was.
    assert "v1.4.1" in served["result"]        # the witness read the DB itself


def test_honest_session_reconciles(pool, cred):
    receipt, trace = _serve(pool, cred)
    ok, violations = _reconcile([trace], [receipt], _closings(pool, cred),
                                pool.registry, pool.mediated, cred.session_id)
    assert ok, violations


# ---------------------------------------------------------------------------
# The two adversarial collectors
# ---------------------------------------------------------------------------

def test_altered_output_hash_is_caught(pool, cred):
    """Collector rewrites the record after the witness served it."""
    receipt, trace = _serve(pool, cred)
    trace.output_hash = DOCTORED                      # "the query returned nothing"
    ok, violations = _reconcile([trace], [receipt], _closings(pool, cred),
                                pool.registry, pool.mediated, cred.session_id)
    assert not ok
    assert violations


def test_dropped_trace_is_caught(pool, cred):
    """Collector omits the record. The witness already counted the action."""
    receipt, _trace = _serve(pool, cred)
    ok, violations = _reconcile([], [receipt], _closings(pool, cred),
                                pool.registry, pool.mediated, cred.session_id)
    assert not ok
    assert violations


# ---------------------------------------------------------------------------
# Why the in-process harness could not show any of the above
# ---------------------------------------------------------------------------

def test_in_process_witness_attests_the_doctored_record(cred):
    """Pins the DEFECT, so the two arrangements are never confused again.

    With the witness inside the collector, the collector doctors the record
    *before* handing it over. The witness signs the lie, reconciliation is
    perfectly consistent, and the gate approves. This test asserting `ok is
    True` is the reason specimens/witness_process.py exists.
    """
    witnesses = {wid: Witness(wid, mediates=set(acts))
                 for wid, acts in TOOL_WITNESSES.items()}
    w = next(x for x in witnesses.values() if ACTION in x.mediates)

    trace = ExecutionTraceRecord(
        trace_id="TR-000", agent_id=AGENT, action=ACTION, status="SUCCESS",
        duration_ms=1.0, output_hash=DOCTORED)        # doctored BEFORE signing
    receipt = w.observe(cred, trace)

    registry = {wid: x.public_key_b64 for wid, x in witnesses.items()}
    mediated = {wid: set(x.mediates) for wid, x in witnesses.items()}
    closings = [x.close(cred) for x in witnesses.values()]

    ok, violations = _reconcile([trace], [receipt], closings, registry,
                                mediated, cred.session_id)
    assert ok, violations          # the defect: a doctored session reconciles


# ---------------------------------------------------------------------------
# The witness refuses what it must refuse
# ---------------------------------------------------------------------------

def test_witness_refuses_action_it_does_not_mediate(pool, cred):
    w = pool.for_action(ACTION)
    with pytest.raises(WitnessProcessError, match="NotMediated"):
        w.serve(cred.to_dict(), "vector_search_policy_docs", {"query": "x"},
                "TR-001", AGENT)


def test_witness_refuses_an_uncredentialed_session(pool):
    """A bare session string is not a credential (vector O7)."""
    w = pool.for_action(ACTION)
    with pytest.raises(WitnessProcessError, match="CredentialError"):
        w.serve({"session_id": "live-forged", "release_id": "r", "signature": "AA=="},
                ACTION, ARGS, "TR-002", AGENT)


def test_witness_refuses_to_serve_a_closed_session(pool, cred):
    _serve(pool, cred)
    _closings(pool, cred)
    w = pool.for_action(ACTION)
    with pytest.raises(WitnessProcessError):
        w.serve(cred.to_dict(), ACTION, ARGS, "TR-003", AGENT)
