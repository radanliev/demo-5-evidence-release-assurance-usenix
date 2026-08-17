"""The live-agent harness must be trustworthy even when it cannot run.

The whole point of Section "live agent evaluation" is to replace a synthetic
result with a real one. That is only worth anything if the harness fails loudly
when no model is reachable, rather than quietly substituting scripted behaviour
and reporting it as a live measurement -- which would be a worse version of the
defect it exists to fix.

These tests need no API key and no network. They exercise the tool layer, the
witness mediation boundary, and the omission-vector construction against a
synthesised session whose shape matches what a real run produces.
"""

from __future__ import annotations

import sqlite3
import uuid

import pytest

from assurance.crypto import hash_sha256
from assurance.evidence import ExecutionTraceRecord
from assurance.witness import Witness
from specimens.live_agent_runner import (TOOL_SCHEMA, TOOL_WITNESSES,
                                         UNMEDIATED_ACTIONS, LiveSession,
                                         ProviderError, _audit_db, _run_tool,
                                         _witness_for, run_live_session)


@pytest.fixture
def conn():
    c = _audit_db()
    yield c
    c.close()


@pytest.fixture
def session():
    """A session shaped like a real run: several mediated actions and one that
    no witness serves."""
    sid = f"live-{uuid.uuid4().hex[:12]}"
    ws = {w: Witness(w, mediates=set(a)) for w, a in TOOL_WITNESSES.items()}
    s = LiveSession(sid, "test-model", "test",
                    registry={w: x.public_key_b64 for w, x in ws.items()},
                    mediated={w: set(x.mediates) for w, x in ws.items()})
    for i, action in enumerate(["authenticate_jwt_claims", "vector_search_policy_docs",
                                "execute_read_only_query", "collect_table_stats",
                                "execute_read_only_query", "emit_summary"]):
        t = ExecutionTraceRecord(f"TR-{i:03d}", "test", action, "SUCCESS",
                                 1.0 + i, hash_sha256(f"{sid}:{i}"))
        s.traces.append(t)
        w = _witness_for(action, ws)
        if w:
            s.receipts.append(w.observe(sid, t))
        else:
            s.unmediated_actions.append(action)
    s.closings = [w.close(sid) for w in ws.values()]
    return s


# --- fails closed, never fabricates -------------------------------------------

def test_missing_key_raises_rather_than_simulating(monkeypatch):
    """No key must mean no result. If this ever returns a session instead of
    raising, the harness has started inventing data."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        run_live_session(provider="groq")


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError):
        run_live_session(provider="not-a-provider")


# --- the tool layer -----------------------------------------------------------

def test_read_only_path_refuses_mutating_sql(conn):
    """The broker is the enforcement point. A refusal is a real outcome and is
    recorded with status DENIED, not dropped -- a dropped refusal would be an
    omission the witness protocol is supposed to make impossible."""
    for sql in ("DROP TABLE releases", "DELETE FROM releases",
                "UPDATE releases SET gate='APPROVED'", "INSERT INTO releases VALUES (9,'x','y',0)"):
        status, _ = _run_tool("execute_read_only_query", {"sql": sql}, conn)
        assert status == "DENIED", f"{sql!r} should be refused"


def test_read_only_path_allows_select(conn):
    status, result = _run_tool("execute_read_only_query",
                               {"sql": "SELECT version, gate FROM releases"}, conn)
    assert status == "SUCCESS"
    assert "v1.4.0" in result


def test_unknown_table_is_refused(conn):
    status, _ = _run_tool("collect_table_stats", {"table": "secrets"}, conn)
    assert status == "DENIED"


def test_unknown_tool_is_refused(conn):
    status, _ = _run_tool("rm_rf_slash", {}, conn)
    assert status == "DENIED"


def test_tool_exception_becomes_a_recorded_error(conn):
    """A tool that raises must produce a trace, not vanish."""
    status, result = _run_tool("execute_read_only_query",
                               {"sql": "SELECT * FROM does_not_exist"}, conn)
    assert status == "ERROR"
    assert "error" in result


# --- the mediation boundary ---------------------------------------------------

def test_every_declared_tool_is_either_mediated_or_declared_unmediated():
    """No tool may be silently outside the guarantee. Either a witness serves
    it, or it is named in UNMEDIATED_ACTIONS and therefore reported."""
    ws = {w: Witness(w, mediates=set(a)) for w, a in TOOL_WITNESSES.items()}
    for spec in TOOL_SCHEMA:
        name = spec["function"]["name"]
        mediated = _witness_for(name, ws) is not None
        assert mediated or name in UNMEDIATED_ACTIONS, \
            f"{name} is neither witnessed nor declared unmediated"


def test_at_least_one_action_is_deliberately_unmediated():
    """If every tool were witnessed, coverage would be trivially 100% and the
    experiment could not measure the honest boundary of Definition (WTC)."""
    assert UNMEDIATED_ACTIONS, "the run must exercise an unwitnessed action"


def test_coverage_excludes_unmediated_actions(session):
    assert 0.0 < session.coverage < 1.0
    assert session.mediated_count == len(session.traces) - len(session.unmediated_actions)


# --- omission detection over a realistic session ------------------------------

def test_honest_session_reconciles(session):
    from scripts.run_live_agent_eval import omission_vectors_on
    assert omission_vectors_on(session)["OC1_control_approved"] is True


def test_every_omission_vector_is_detected_on_a_realistic_session(session):
    """Deliberately a loop rather than @pytest.mark.parametrize.

    The manuscript prints \\testCount beside the literal command `pytest tests/`,
    and the generator counts `def test_` occurrences. A parametrized test
    collects as N tests but counts as one, so it silently desynchronises the
    paper from the suite. If you re-add parametrize here, fix
    scripts/write_security_macros.py to use real pytest collection first.
    """
    from scripts.run_live_agent_eval import omission_vectors_on
    result = omission_vectors_on(session)
    problems = []
    for vector in ("O1", "O2", "O3", "O4", "O6"):
        if vector not in result:
            problems.append(f"{vector}: could not be constructed for this session")
        elif result[vector] is not True:
            problems.append(f"{vector}: NOT detected")
    assert not problems, "omission vectors failed:\n  " + "\n  ".join(problems)


def test_unconstructable_vectors_are_omitted_not_counted_as_passes():
    """A one-action session cannot host an interior omission. Reporting that as
    'detected' would inflate the score with attacks that were never run."""
    from scripts.run_live_agent_eval import omission_vectors_on
    sid = f"live-{uuid.uuid4().hex[:12]}"
    ws = {w: Witness(w, mediates=set(a)) for w, a in TOOL_WITNESSES.items()}
    s = LiveSession(sid, "m", "t",
                    registry={w: x.public_key_b64 for w, x in ws.items()},
                    mediated={w: set(x.mediates) for w, x in ws.items()})
    t = ExecutionTraceRecord("TR-000", "t", "authenticate_jwt_claims", "SUCCESS",
                             1.0, hash_sha256("x"))
    s.traces.append(t)
    s.receipts.append(_witness_for("authenticate_jwt_claims", ws).observe(sid, t))
    s.closings = [w.close(sid) for w in ws.values()]
    result = omission_vectors_on(s)
    assert "O1" not in result, "an unbuildable interior omission must not be scored"


# --- provider errors must not carry account identity into results/ ------------

def test_scrub_removes_provider_account_identifiers():
    """results/live_agent_evaluation.json ships inside the anonymous artifact,
    and a free-tier rate-limit error embeds the caller's organization ID. This
    is the leak path nobody re-reads."""
    from scripts.run_live_agent_eval import scrub
    org = "org_" + "01kzp8ygxtey8vetxx6pc0kv30"
    text = f"HTTP 429: Rate limit reached in organization `{org}` service tier"
    out = scrub(text)
    assert org not in out
    assert "org_<redacted>" in out


def test_scrub_removes_api_keys_and_home_paths():
    from scripts.run_live_agent_eval import scrub
    key = "gsk_" + "AbCdEf0123456789abcdefXY"
    home = "/" + "Users" + "/someone/Projects"
    out = scrub(f"auth {key} failed reading {home}/.env")
    assert key not in out and home not in out


def test_scrub_leaves_ordinary_error_text_intact():
    """Over-scrubbing would hide the failure mode the run is meant to report."""
    from scripts.run_live_agent_eval import scrub
    text = "HTTP 400: Parsing failed. The model generated output that could not be parsed."
    assert scrub(text) == text
