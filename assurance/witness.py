"""
Witnessed Trace Completeness (WTC).

The problem this closes
-----------------------
Every attested-execution system for agents -- in-toto's runtime-trace predicate,
APAS, AAS-1, and EviAssure's own earlier revisions -- shares one hole: the
evidence collector is the sole observer, so an adversary who controls the
recording path can simply *not record* an action. Nothing downstream can tell an
action that was never recorded from one that never happened. APAS states this
about itself ("at L1-L2, this is the fox guarding the henhouse"); AAS-1's
per-issuer hash chains detect omission only *between consecutive records of one
issuer*, which an adversary who drops a contiguous suffix evades.

The 2026 literature has converged on **per-action receipts** signed by the
receiving service (Notarized Agents; PipeLab Agent Action Receipts; and similar
proposals). Receipts are necessary but *not sufficient*, and the reason is the
core observation of this module:

    A receipt proves an action HAPPENED.
    A set of receipts does not prove that no OTHER action happened.

An adversary who drops action a_i also drops receipt r_i. The remaining bundle
is internally consistent: every recorded action has a valid receipt, every
receipt matches a recorded action. Receipt-based schemes accept it.

The mechanism
-------------
Make each witness stateful and make its state auditable:

  * every witness W_j keeps a **monotonic per-session counter**; receipt r_i
    carries (session_id, seq, action_digest) and is signed by W_j;
  * at session end W_j emits a **signed closing statement** (session_id,
    final_seq) -- a commitment to how many actions it served;
  * the gate **reconciles**: for each witness with a closing, the receipts
    present must be exactly the contiguous run 1..final_seq, each must verify
    under a registry-pinned witness key, and each must bind to a leaf in the
    Merkle tree.

Now omission is detectable. Dropping a middle action leaves a sequence gap;
dropping a suffix contradicts final_seq; dropping a whole witness leaves a
closing with no receipts; lowering final_seq requires forging a witness
signature. None of these is available to an adversary who controls the collector
and the agent but not the witnesses.

The honest boundary
-------------------
Completeness is achieved **relative to the witness set**. An action that touches
no witness is still invisible -- but that is a precisely stated, deployment-
controllable condition ("mediate every externally observable effect"), not the
unbounded assumption "the collector observed everything". Section
`sec:completeness` of the paper states this as a definition rather than a hope.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import (hash_sha256, compute_key_id,
                     sign_payload_ed25519, verify_signature_ed25519)


# --------------------------------------------------------------------------
# Receipts and closings
# --------------------------------------------------------------------------

def action_digest(trace: Any) -> str:
    """The action identity a witness attests.

    Deliberately NOT the full Merkle leaf: a witness sees the action it served
    (who asked, what was asked, what it returned) but not collector-side fields
    such as duration measured at the agent. Binding on this digest is what lets
    a receipt be matched to a leaf without the witness having to observe the
    leaf's every field.
    """
    if hasattr(trace, "trace_id"):
        t = (trace.trace_id, trace.agent_id, trace.action, trace.output_hash)
    else:
        t = (trace["trace_id"], trace["agent_id"], trace["action"], trace["output_hash"])
    return hash_sha256(":".join(map(str, t)))


@dataclass
class Receipt:
    witness_id: str
    session_id: str
    seq: int
    action_digest: str
    signature: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        return {"witness_id": self.witness_id, "session_id": self.session_id,
                "seq": self.seq, "action_digest": self.action_digest,
                "type": "eviassure.witness.receipt/v1"}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Closing:
    """A witness's commitment to how many actions it served in a session.

    This is the field that makes suffix-truncation detectable, and it is the
    single most important difference between this scheme and per-action receipts
    as currently proposed.
    """
    witness_id: str
    session_id: str
    final_seq: int
    signature: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        return {"witness_id": self.witness_id, "session_id": self.session_id,
                "final_seq": self.final_seq,
                "type": "eviassure.witness.closing/v1"}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# The witness itself
# --------------------------------------------------------------------------

class Witness:
    """A stateful observer at an externally observable boundary.

    In production this is the tool endpoint, API gateway, or sandbox syscall
    broker that actually serves the agent's action -- not a component of the
    agent runtime. The security argument depends on exactly one property: the
    adversary who controls the agent and the collector does not hold the
    witness's signing key.
    """

    def __init__(self, witness_id: str, mediates: Optional[Set[str]] = None,
                 private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self.witness_id = witness_id
        # The action names this witness is authoritative for. A trace claiming
        # one of these actions MUST carry a receipt from this witness, which is
        # what stops an adversary from *fabricating* a mediated action (claiming
        # a safe read that never happened) as opposed to omitting a real one.
        self.mediates: Set[str] = set(mediates or ())
        self._priv = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key_b64 = base64.b64encode(
            self._priv.public_key().public_bytes_raw()).decode()
        self._counters: Dict[str, int] = {}
        self._closed: Set[str] = set()

    def observe(self, session_id: str, trace: Any) -> Receipt:
        if session_id in self._closed:
            raise RuntimeError(f"{self.witness_id}: session {session_id} already closed")
        self._counters[session_id] = self._counters.get(session_id, 0) + 1
        r = Receipt(self.witness_id, session_id, self._counters[session_id],
                    action_digest(trace))
        r.signature = sign_payload_ed25519(r.payload(), self._priv)
        return r

    def close(self, session_id: str) -> Closing:
        self._closed.add(session_id)
        c = Closing(self.witness_id, session_id, self._counters.get(session_id, 0))
        c.signature = sign_payload_ed25519(c.payload(), self._priv)
        return c

    def registry_entry(self) -> Dict[str, Any]:
        return {"public_key": self.public_key_b64,
                "key_id": compute_key_id(self.public_key_b64),
                "mediates": sorted(self.mediates)}


# --------------------------------------------------------------------------
# Gate-side reconciliation
# --------------------------------------------------------------------------

WITNESS_VIOLATION = "COMPLETENESS_VIOLATION"


def reconcile(traces: List[Dict[str, Any]],
              receipts: List[Dict[str, Any]],
              closings: List[Dict[str, Any]],
              witness_registry: Dict[str, str],
              session_id: str,
              require_witness: bool = True,
              mediated_actions: Optional[Dict[str, Set[str]]] = None
              ) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Verify witnessed completeness of `traces` against witness attestations.

    Returns (complete, violations, detail). The checks, in order, and the
    omission attack each one closes:

      1. every receipt and closing verifies under a REGISTRY-PINNED witness key
         -- a key carried in the bundle is never trusted            (O4 forged closing)
      2. every receipt and closing belongs to THIS session          (O5 cross-session replay)
      3. for each witness with a closing, the receipt sequence is
         exactly 1..final_seq with no gaps and no duplicates        (O1 middle drop, O2 suffix drop)
      4. every witness in the registry that closed the session is
         represented                                                (O3 whole-witness drop)
      5. every receipt binds to a recorded trace, and every trace
         whose action is witness-mediated carries a receipt         (O6 fabricated leaf)
    """
    violations: List[str] = []
    detail: Dict[str, Any] = {}

    if not require_witness:
        return True, [], {"witnessed": False,
                          "note": "witness reconciliation disabled by policy"}

    if not witness_registry:
        return False, [f"{WITNESS_VIOLATION}: no witness registry configured; "
                       "witnessed completeness cannot be established (fail-closed)"], \
               {"witnessed": False}

    # ---- 1 & 2: authenticate and scope every attestation -------------------
    good_receipts: List[Receipt] = []
    for raw in receipts:
        r = Receipt(witness_id=str(raw.get("witness_id") or ""),
                    session_id=str(raw.get("session_id") or ""),
                    seq=int(raw.get("seq") or 0),
                    action_digest=str(raw.get("action_digest") or ""),
                    signature=raw.get("signature"))
        pk = witness_registry.get(r.witness_id)
        if pk is None:
            violations.append(f"{WITNESS_VIOLATION}: receipt from unregistered witness "
                              f"'{r.witness_id}'")
            continue
        if not r.signature or not verify_signature_ed25519(r.payload(), r.signature, pk):
            violations.append(f"{WITNESS_VIOLATION}: invalid receipt signature from "
                              f"'{r.witness_id}' seq {r.seq}")
            continue
        if r.session_id != session_id:
            violations.append(f"{WITNESS_VIOLATION}: receipt from foreign session "
                              f"'{r.session_id}' (expected '{session_id}')")
            continue
        good_receipts.append(r)

    good_closings: Dict[str, Closing] = {}
    for raw in closings:
        c = Closing(witness_id=str(raw.get("witness_id") or ""),
                    session_id=str(raw.get("session_id") or ""),
                    final_seq=int(raw.get("final_seq") or 0),
                    signature=raw.get("signature"))
        pk = witness_registry.get(c.witness_id)
        if pk is None:
            violations.append(f"{WITNESS_VIOLATION}: closing from unregistered witness "
                              f"'{c.witness_id}'")
            continue
        if not c.signature or not verify_signature_ed25519(c.payload(), c.signature, pk):
            violations.append(f"{WITNESS_VIOLATION}: invalid closing signature from "
                              f"'{c.witness_id}'")
            continue
        if c.session_id != session_id:
            violations.append(f"{WITNESS_VIOLATION}: closing from foreign session "
                              f"'{c.session_id}'")
            continue
        good_closings[c.witness_id] = c

    if not good_closings:
        violations.append(f"{WITNESS_VIOLATION}: no valid witness closing statement; "
                          "the served-action count is unattested, so a truncated "
                          "trace set is indistinguishable from a short execution")

    # ---- 3: contiguous sequence per witness --------------------------------
    per_witness: Dict[str, List[Receipt]] = {}
    for r in good_receipts:
        per_witness.setdefault(r.witness_id, []).append(r)

    seq_report = {}
    for wid, closing in good_closings.items():
        seqs = sorted(r.seq for r in per_witness.get(wid, []))
        expected = list(range(1, closing.final_seq + 1))
        missing = sorted(set(expected) - set(seqs))
        extra = sorted(set(seqs) - set(expected))
        dupes = sorted({s for s in seqs if seqs.count(s) > 1})
        seq_report[wid] = {"final_seq": closing.final_seq, "present": len(seqs),
                           "missing": missing, "extra": extra, "duplicates": dupes}
        if missing:
            violations.append(
                f"{WITNESS_VIOLATION}: witness '{wid}' attested {closing.final_seq} "
                f"served action(s); sequence number(s) {missing} are absent from the "
                f"submitted trace set (omitted action)")
        if extra:
            violations.append(f"{WITNESS_VIOLATION}: witness '{wid}' receipts {extra} "
                              f"exceed the attested final sequence {closing.final_seq}")
        if dupes:
            violations.append(f"{WITNESS_VIOLATION}: duplicate receipt sequence(s) "
                              f"{dupes} from witness '{wid}'")

    # ---- 4: EVERY registered witness must close the session -----------------
    #
    # Requiring a closing only from witnesses that appear in the bundle was a
    # design flaw: an adversary could drop a witness's actions *and* its
    # closing, and the trace then looked like a session in which that tool was
    # simply never used (vector O3). A witness that served nothing issues a
    # closing with final_seq = 0, so silence is no longer indistinguishable
    # from absence.
    for wid in sorted(witness_registry):
        if wid not in good_closings:
            violations.append(
                f"{WITNESS_VIOLATION}: registered witness '{wid}' produced no closing "
                f"statement for session '{session_id}'; a session in which a witness "
                "served nothing must still carry its final_seq=0 closing, so a missing "
                "closing is an omitted witness rather than an unused tool")

    # ---- 5: bind receipts to recorded leaves, both directions --------------
    trace_digests = {action_digest(t) for t in traces}
    receipt_digests = {r.action_digest for r in good_receipts}

    unmatched = receipt_digests - trace_digests
    if unmatched:
        violations.append(f"{WITNESS_VIOLATION}: {len(unmatched)} witness receipt(s) "
                          "have no corresponding recorded trace (action performed but "
                          "not recorded)")

    # ---- 6: a trace claiming a MEDIATED action must carry a receipt ---------
    #
    # Omission truncates evidence; fabrication inflates it. Without this check a
    # collector could invent a benign-looking mediated action -- "I ran a
    # read-only query" -- that no witness ever served (vector O6). Actions
    # outside every witness's mediated set remain undetectable, and that is the
    # stated boundary of the guarantee, not an oversight.
    mediated_actions = mediated_actions or {}
    all_mediated = set().union(*mediated_actions.values()) if mediated_actions else set()
    fabricated = []
    for t in traces:
        act = t.get("action") if isinstance(t, dict) else getattr(t, "action", None)
        if act in all_mediated and action_digest(t) not in receipt_digests:
            fabricated.append(act)
    if fabricated:
        violations.append(
            f"{WITNESS_VIOLATION}: {len(fabricated)} recorded action(s) claim a "
            f"witness-mediated operation ({sorted(set(fabricated))}) but carry no witness "
            "receipt (fabricated action)")

    detail = {
        "witnessed": True,
        "session_id": session_id,
        "witnesses_registered": sorted(witness_registry),
        "receipts_valid": len(good_receipts),
        "closings_valid": len(good_closings),
        "sequence_report": seq_report,
        "receipts_without_trace": len(unmatched),
        "fabricated_mediated_actions": len(fabricated),
        "mediated_action_count": len(all_mediated),
    }
    return (len(violations) == 0), violations, detail


def witness_registry_from_yaml(data: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for wid, info in (data or {}).get("witnesses", {}).items():
        if isinstance(info, dict) and info.get("public_key"):
            out[wid] = info["public_key"]
        elif isinstance(info, str):
            out[wid] = info
    return out


def mediated_actions_from_yaml(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for wid, info in (data or {}).get("witnesses", {}).items():
        if isinstance(info, dict) and info.get("mediates"):
            out[wid] = set(info["mediates"])
    return out
