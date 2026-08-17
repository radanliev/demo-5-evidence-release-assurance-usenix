"""
Omission attack class (O1-O6): the adversary controls the agent AND the evidence
collector, but not the witnesses.

This is the attack class that motivates the paper. In every prior system --
in-toto's runtime-trace predicate, SLSA, TUF, AAS-1, per-action receipt schemes,
and EviAssure before this revision -- the collector is the sole observer, so
"do the action but do not record it" produces a bundle that is *internally
consistent* and passes every cryptographic check. There is no tampering to
detect, because nothing was tampered with; evidence was simply never created.

Each vector below is a concrete instance. Every one of them is APPROVED by a
gate without witness reconciliation, which is the point: this class is not a
harder version of the tamper vectors, it is a different axis that the tamper
vectors cannot reach.

  O1  interior omission        drop a witnessed action from the middle
  O2  suffix omission          drop the trailing action(s) -- defeats hash
                               chains that only link consecutive records
  O3  whole-witness omission   drop every action served by one witness
  O4  count downgrade          forge a lower closing count to match a short trace
  O5  cross-session splice     import receipts from a different, benign session
  O6  fabricated action        record an action no witness ever served

Control: OC1, a fully witnessed honest execution, which must be APPROVED.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Tuple

from assurance.crypto import hash_sha256, sign_payload_ed25519, generate_ed25519_keypair
from assurance.evidence import (ExecutionTraceRecord, create_evidence_pack,
                                DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
from assurance.witness import Witness, Closing

OMISSION_TAXONOMY = {
    "O1": {"id": "O1", "name": "Interior action omission", "class": "A6 collector omission",
           "description": "A witnessed action is performed and then not recorded. The bundle "
                          "is internally consistent: every recorded action has a receipt."},
    "O2": {"id": "O2", "name": "Suffix (trailing) omission", "class": "A6 collector omission",
           "description": "The final witnessed action(s) are dropped. Defeats inter-record "
                          "hash chaining, which only links records that are present."},
    "O3": {"id": "O3", "name": "Whole-witness omission", "class": "A6 collector omission",
           "description": "Every action served by one witness is dropped, along with that "
                          "witness's receipts -- the trace looks like the tool was never used."},
    "O4": {"id": "O4", "name": "Closing count downgrade", "class": "A6 collector omission",
           "description": "The adversary forges a closing statement with a lower final "
                          "sequence so the truncated receipt set reconciles."},
    "O5": {"id": "O5", "name": "Cross-session receipt splice", "class": "A6 collector omission",
           "description": "Receipts from a different, benign session are spliced in to fill "
                          "the gap left by an omitted action."},
    "O6": {"id": "O6", "name": "Fabricated unwitnessed action", "class": "A6 collector omission",
           "description": "A trace records a witness-MEDIATED action that no witness ever "
                          "served, inflating the evidence rather than truncating it."},
    "OC1": {"id": "OC1", "name": "Control: fully witnessed honest execution",
            "class": "control",
            "description": "An honest, completely witnessed execution. MUST be approved; "
                           "without this the omission suite could not distinguish a working "
                           "reconciler from one that rejects everything."},
}


def _actions(session: str, n: int = 6) -> List[ExecutionTraceRecord]:
    kinds = [("db-gateway", "execute_read_only_query"),
             ("payments-api", "process_ledger_transfer"),
             ("db-gateway", "collect_table_stats"),
             ("shell-broker", "spawn_shell_subprocess"),
             ("payments-api", "fetch_fx_rate"),
             ("db-gateway", "verify_schema_lock")]
    return [ExecutionTraceRecord(
        trace_id=f"TR-{session[:6]}-{i:03d}",
        agent_id="ops-agent-v1",
        action=kinds[i % len(kinds)][1],
        status="SUCCESS",
        duration_ms=float(4 + i),
        output_hash=hash_sha256(f"{session}:{i}"),
    ) for i in range(n)]


def _witness_of(trace: ExecutionTraceRecord) -> str:
    return {"execute_read_only_query": "db-gateway",
            "collect_table_stats": "db-gateway",
            "verify_schema_lock": "db-gateway",
            "process_ledger_transfer": "payments-api",
            "fetch_fx_rate": "payments-api",
            "spawn_shell_subprocess": "shell-broker"}[trace.action]


def witnessed_execution(session_id: str, n: int = 6):
    """Run an execution through witnesses, returning everything the collector
    would legitimately hold."""
    mediates = {
        "db-gateway": {"execute_read_only_query", "collect_table_stats", "verify_schema_lock"},
        "payments-api": {"process_ledger_transfer", "fetch_fx_rate"},
        "shell-broker": {"spawn_shell_subprocess"},
    }
    witnesses = {w: Witness(w, mediates=m) for w, m in mediates.items()}
    traces = _actions(session_id, n)
    receipts = [witnesses[_witness_of(t)].observe(session_id, t) for t in traces]
    closings = [w.close(session_id) for w in witnesses.values()]
    registry = {wid: w.public_key_b64 for wid, w in witnesses.items()}
    mediated = {wid: set(w.mediates) for wid, w in witnesses.items()}
    return witnesses, traces, receipts, closings, registry, mediated


def _package(traces, receipts, closings, session_id) -> Dict[str, Any]:
    """Sign a bundle over the given trace/attestation set, honestly. The
    adversary in this threat model *can* sign -- they hold the collector's key.
    What they cannot do is produce witness signatures."""
    b = create_evidence_pack(traces=list(traces), use_ed25519=True, signed=False)
    b.session_id = session_id
    b.witness_receipts = [r.to_dict() for r in receipts]
    b.witness_closings = [c.to_dict() for c in closings]
    b.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    return b.to_dict()


def generate_omission_suite():
    """Returns (suite, witness_registry, mediated_actions)."""
    session = f"sess-{uuid.uuid4().hex[:12]}"
    _, traces, receipts, closings, registry, mediated = witnessed_execution(session)
    suite: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []

    # ---- OC1: honest, fully witnessed --------------------------------------
    suite.append(("OC1", OMISSION_TAXONOMY["OC1"], _package(traces, receipts, closings, session)))

    # ---- O1: drop an interior witnessed action -----------------------------
    drop = 2
    kept_t = [t for i, t in enumerate(traces) if i != drop]
    kept_r = [r for i, r in enumerate(receipts) if i != drop]
    suite.append(("O1", OMISSION_TAXONOMY["O1"], _package(kept_t, kept_r, closings, session)))

    # ---- O2: drop the trailing action --------------------------------------
    suite.append(("O2", OMISSION_TAXONOMY["O2"],
                  _package(traces[:-1], receipts[:-1], closings, session)))

    # ---- O3: drop every action served by shell-broker -----------------------
    keep = [(t, r) for t, r in zip(traces, receipts) if _witness_of(t) != "shell-broker"]
    suite.append(("O3", OMISSION_TAXONOMY["O3"],
                  _package([t for t, _ in keep], [r for _, r in keep],
                           [c for c in closings if c.witness_id != "shell-broker"], session)))

    # ---- O4: forge a lower closing count ------------------------------------
    # The adversary drops the last db-gateway action and mints a closing that
    # matches -- using their OWN key, since they do not have the witness key.
    att_priv, _, att_pub, _ = generate_ed25519_keypair()
    db_idx = [i for i, t in enumerate(traces) if _witness_of(t) == "db-gateway"]
    victim = db_idx[-1]
    kept_t4 = [t for i, t in enumerate(traces) if i != victim]
    kept_r4 = [r for i, r in enumerate(receipts) if i != victim]
    forged = Closing("db-gateway", session, len(db_idx) - 1)
    forged.signature = sign_payload_ed25519(forged.payload(), att_priv)
    closings4 = [c for c in closings if c.witness_id != "db-gateway"] + [forged]
    suite.append(("O4", OMISSION_TAXONOMY["O4"], _package(kept_t4, kept_r4, closings4, session)))

    # ---- O5: splice receipts from a benign second session -------------------
    other = f"sess-{uuid.uuid4().hex[:12]}"
    _, o_traces, o_receipts, _, _, _ = witnessed_execution(other)
    kept_t5 = [t for i, t in enumerate(traces) if i != drop]
    kept_r5 = [r for i, r in enumerate(receipts) if i != drop] + [o_receipts[drop]]
    suite.append(("O5", OMISSION_TAXONOMY["O5"],
                  _package(kept_t5 + [o_traces[drop]], kept_r5, closings, session)))

    # ---- O6: record an action no witness served -----------------------------
    # The meaningful fabrication is claiming a *mediated* operation that no
    # witness served -- "I ran a read-only query" when nothing was queried.
    # Inventing an action outside every witness's mediated set is NOT detectable
    # and we say so in the paper rather than testing a strawman.
    ghost = ExecutionTraceRecord("TR-GHOST", "ops-agent-v1", "execute_read_only_query",
                                 "SUCCESS", 1.0, hash_sha256("NEVER_HAPPENED"))
    suite.append(("O6", OMISSION_TAXONOMY["O6"],
                  _package(list(traces) + [ghost], receipts, closings, session)))

    return suite, registry, mediated
