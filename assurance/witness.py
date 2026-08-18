"""
Witnessed Trace Completeness (WTC).

The problem this closes
-----------------------
Every attested-execution system for agents -- in-toto's runtime-trace predicate,
APAS, AAS-1, receiver-attested receipt schemes, and EviAssure's own earlier
revisions -- shares one hole: the evidence collector is the sole observer, so an
adversary who controls the recording path can simply *not record* an action.
Nothing downstream can tell an action that was never recorded from one that
never happened. APAS states this about itself ("at L1-L2, this is the fox
guarding the henhouse"); AAS-1's per-issuer hash chains detect omission only
*between consecutive records of one issuer*, which an adversary who drops a
contiguous suffix evades; Notarized Agents (arXiv:2606.04193) publishes
service-signed receipts to a transparency log and names the "suppression
attack" as unsolved.

Receipts are necessary but *not sufficient*, and the reason is the core
observation of this module:

    A receipt proves an action HAPPENED.
    A set of receipts does not prove that no OTHER action happened.

An adversary who drops action a_i also drops receipt r_i. The remaining bundle
is internally consistent: every recorded action has a valid receipt, every
receipt matches a recorded action. Receipt-based schemes accept it.

The mechanism
-------------
Make each witness stateful and make its state auditable:

  * every witness W_j keeps a **monotonic per-session counter**; receipt r_i
    carries (session_id, seq, action_digest, prev) and is signed by W_j;
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

Session identity is not the adversary's to choose
--------------------------------------------------
The guarantee is stated per session, so it is only as strong as the binding
between an action and its session identifier. If a witness accepted whatever
session string the caller supplied, an adversary who owns the agent and the
collector could label the actions it wants to hide with a *different* session
and submit a complete, honestly-reconciling bundle for the benign one --
omission without a forgery. Three rules close that:

  1. a session is opened by a **session credential** signed by the release
     orchestrator (the trusted CI controller that later runs the gate);
     witnesses verify the credential under a pinned orchestrator key and
     serve only credentialed requests;
  2. the orchestrator issues one credential per release evaluation, bound to a
     release identifier;
  3. the gate reconciles the bundle against the session it credentialed for
     that release, not against the session the bundle declares (vector O7).

Relabelling an action to another session then requires forging an
orchestrator signature, and the reduction in the paper's Theorem gains one
EUF-CMA term for the orchestrator key.

The honest boundary
-------------------
Completeness is achieved **relative to the witness set**. An action that touches
no witness is still invisible -- but that is a precisely stated, deployment-
controllable condition ("mediate every externally observable effect"), not the
unbounded assumption "the collector observed everything".
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import (hash_sha256, canonical_json, compute_key_id,
                     sign_payload_ed25519, verify_signature_ed25519)


# --------------------------------------------------------------------------
# Static demo keys (DEMO/TEST ONLY -- never use in production).
#
# Fixed so that the packager, the witnesses, the CLI and the tests derive the
# same keys across processes; the public halves are pinned in
# governance/witness_registry.yaml, and nothing else is trusted. A deployment
# replaces them via scripts/provision_witnesses.py --fresh.
# --------------------------------------------------------------------------

def _priv(seed_hex: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def _pub_b64(priv: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode()


DEMO_ORCHESTRATOR_PRIV = _priv("5b7c1f6b0d3f4a2e9c8b7a6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f")
DEMO_ORCHESTRATOR_PUB_B64 = _pub_b64(DEMO_ORCHESTRATOR_PRIV)

# witness_id -> (private-key seed, mediated action set). The three actions are
# the ones the default demo evidence pack records, so the shipped CLI can
# demonstrate an end-to-end witnessed release without any provisioning step.
DEMO_WITNESS_SEEDS: Dict[str, Tuple[str, Set[str]]] = {
    "auth-gateway":   ("a1f0c3d2e5b4a7968877665544332211ffeeddccbbaa99887766554433221100",
                       {"verify_user_token"}),
    "policy-service": ("b2e1d4c3f6a5b8079988776655443322eeddccbbaa998877665544332211ffee",
                       {"evaluate_rbac"}),
    "db-gateway":     ("c3d2e5f4a7b6c9180099887766554433ddccbbaa99887766554433221100ffee",
                       {"execute_db_query"}),
}


class CredentialError(RuntimeError):
    """A witness was asked to serve a session it cannot authenticate."""


# --------------------------------------------------------------------------
# Session credentials
# --------------------------------------------------------------------------

@dataclass
class SessionCredential:
    """The orchestrator's statement that session `session_id` is the evaluation
    run for release `release_id`. Witnesses serve only requests that carry one,
    which is what stops an adversary from relabelling actions into a session
    the gate will never look at."""
    session_id: str
    release_id: str
    issued_at: str
    signature: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        return {"session_id": self.session_id, "release_id": self.release_id,
                "issued_at": self.issued_at,
                "type": "eviassure.session.credential/v1"}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SessionCredential":
        return cls(session_id=str(d.get("session_id") or ""),
                   release_id=str(d.get("release_id") or ""),
                   issued_at=str(d.get("issued_at") or ""),
                   signature=d.get("signature"))


def issue_session_credential(release_id: str,
                             private_key: ed25519.Ed25519PrivateKey = DEMO_ORCHESTRATOR_PRIV,
                             session_id: Optional[str] = None) -> SessionCredential:
    """Orchestrator side: open one credentialed session for one release."""
    cred = SessionCredential(session_id=session_id or f"sess-{uuid.uuid4().hex[:12]}",
                             release_id=release_id,
                             issued_at=datetime.now(timezone.utc).isoformat())
    cred.signature = sign_payload_ed25519(cred.payload(), private_key)
    return cred


def verify_session_credential(cred: SessionCredential | Dict[str, Any],
                              orchestrator_public_key_b64: str) -> bool:
    if isinstance(cred, dict):
        cred = SessionCredential.from_dict(cred)
    if not cred.signature or not cred.session_id:
        return False
    return verify_signature_ed25519(cred.payload(), cred.signature, orchestrator_public_key_b64)


def _coerce_credential(session: Any) -> SessionCredential:
    if isinstance(session, SessionCredential):
        return session
    if isinstance(session, dict):
        return SessionCredential.from_dict(session)
    raise CredentialError(
        "witnesses serve only credentialed sessions: pass a SessionCredential issued "
        "by the release orchestrator, not a bare session identifier "
        f"(got {type(session).__name__})")


# --------------------------------------------------------------------------
# Receipts and closings
# --------------------------------------------------------------------------

def action_digest(trace: Any) -> str:
    """The action identity a witness attests.

    Deliberately NOT the full Merkle leaf: a witness sees the action it served
    (who asked, what was asked, what it returned) but not collector-side fields
    such as duration measured at the agent. Binding on this digest is what lets
    a receipt be matched to a leaf without the witness having to observe the
    leaf's every field. The fields are (trace_id, agent_id, action,
    output_hash); `status` and `duration_ms` are collector-side and are NOT
    attested by the witness.
    """
    if hasattr(trace, "trace_id"):
        t = (trace.trace_id, trace.agent_id, trace.action, trace.output_hash)
    else:
        t = (trace["trace_id"], trace["agent_id"], trace["action"], trace["output_hash"])
    return hash_sha256(":".join(map(str, t)))


GENESIS = "genesis"


@dataclass
class Receipt:
    witness_id: str
    session_id: str
    seq: int
    action_digest: str
    prev: str = GENESIS          # digest of this witness's previous receipt in the session
    signature: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        return {"witness_id": self.witness_id, "session_id": self.session_id,
                "seq": self.seq, "action_digest": self.action_digest,
                "prev": self.prev,
                "type": "eviassure.witness.receipt/v1"}

    def digest(self) -> str:
        """Chain link: what the next receipt from this witness carries as prev."""
        return hash_sha256(canonical_json(self.payload()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Receipt":
        return cls(witness_id=str(raw.get("witness_id") or ""),
                   session_id=str(raw.get("session_id") or ""),
                   seq=int(raw.get("seq") or 0),
                   action_digest=str(raw.get("action_digest") or ""),
                   prev=str(raw.get("prev") or GENESIS),
                   signature=raw.get("signature"))


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
    agent runtime. The security argument depends on exactly two properties: the
    adversary who controls the agent and the collector holds neither the
    witness's signing key nor the orchestrator's credential-signing key.
    """

    def __init__(self, witness_id: str, mediates: Optional[Set[str]] = None,
                 private_key: Optional[ed25519.Ed25519PrivateKey] = None,
                 orchestrator_public_key: str = DEMO_ORCHESTRATOR_PUB_B64):
        self.witness_id = witness_id
        # The action names this witness is authoritative for. A trace claiming
        # one of these actions MUST carry a receipt from this witness, which is
        # what stops an adversary from *fabricating* a mediated action (claiming
        # a safe read that never happened) as opposed to omitting a real one.
        self.mediates: Set[str] = set(mediates or ())
        self._priv = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key_b64 = base64.b64encode(
            self._priv.public_key().public_bytes_raw()).decode()
        # The key under which session credentials must verify. A witness that
        # does not pin this key would serve any session string the caller
        # names, which is the relabelling hole described in the module docstring.
        self.orchestrator_public_key = orchestrator_public_key
        self._counters: Dict[str, int] = {}
        self._last_digest: Dict[str, str] = {}
        self._closed: Set[str] = set()

    def _authenticate(self, session: Any) -> SessionCredential:
        cred = _coerce_credential(session)
        if not verify_session_credential(cred, self.orchestrator_public_key):
            raise CredentialError(
                f"{self.witness_id}: session credential for '{cred.session_id}' does "
                "not verify under the pinned orchestrator key; request refused")
        return cred

    def observe(self, session: SessionCredential | Dict[str, Any], trace: Any) -> Receipt:
        """Serve one action inside a credentialed session and return its receipt."""
        cred = self._authenticate(session)
        sid = cred.session_id
        if sid in self._closed:
            raise RuntimeError(f"{self.witness_id}: session {sid} already closed")
        self._counters[sid] = self._counters.get(sid, 0) + 1
        r = Receipt(self.witness_id, sid, self._counters[sid], action_digest(trace),
                    prev=self._last_digest.get(sid, GENESIS))
        r.signature = sign_payload_ed25519(r.payload(), self._priv)
        self._last_digest[sid] = r.digest()
        return r

    def close(self, session: SessionCredential | Dict[str, Any]) -> Closing:
        """End-of-session broadcast from the orchestrator: every registered
        witness closes every credentialed session, including with final_seq=0,
        so a witness that served nothing is distinguishable from an omitted one."""
        cred = self._authenticate(session)
        sid = cred.session_id
        self._closed.add(sid)
        c = Closing(self.witness_id, sid, self._counters.get(sid, 0))
        c.signature = sign_payload_ed25519(c.payload(), self._priv)
        return c

    def registry_entry(self) -> Dict[str, Any]:
        return {"public_key": self.public_key_b64,
                "key_id": compute_key_id(self.public_key_b64),
                "mediates": sorted(self.mediates)}


def demo_witnesses(orchestrator_public_key: str = DEMO_ORCHESTRATOR_PUB_B64) -> Dict[str, Witness]:
    """The three static demo witnesses whose public keys are pinned in
    governance/witness_registry.yaml."""
    return {wid: Witness(wid, mediates=set(acts), private_key=_priv(seed),
                         orchestrator_public_key=orchestrator_public_key)
            for wid, (seed, acts) in DEMO_WITNESS_SEEDS.items()}


def demo_witness_registry() -> Dict[str, Any]:
    """What scripts/provision_witnesses.py writes for the demo profile."""
    ws = demo_witnesses()
    return {
        "orchestrator": {"public_key": DEMO_ORCHESTRATOR_PUB_B64,
                         "key_id": compute_key_id(DEMO_ORCHESTRATOR_PUB_B64)},
        "witnesses": {wid: w.registry_entry() for wid, w in ws.items()},
    }


def witness_for(action: str, witnesses: Dict[str, Witness]) -> Optional[Witness]:
    for w in witnesses.values():
        if action in w.mediates:
            return w
    return None


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
              mediated_actions: Optional[Dict[str, Set[str]]] = None,
              expected_session_id: Optional[str] = None,
              ) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Verify witnessed completeness of `traces` against witness attestations.

    `session_id` is what the bundle declares; `expected_session_id` is the
    session the orchestrator credentialed for the release under evaluation.
    Returns (complete, violations, detail). The checks, in order, and the
    omission attack each one closes:

      0. the bundle is for the session credentialed for THIS release      (O7 session substitution)
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

    # ---- 0: release-session binding ---------------------------------------
    #
    # The gate must be told which session it is adjudicating by the party that
    # opened it (the release request), never by the bundle. Otherwise a
    # complete, honestly witnessed bundle for a *different* session -- one in
    # which the dangerous action was never performed -- passes for this
    # release (vector O7).
    if expected_session_id is None:
        violations.append(
            f"{WITNESS_VIOLATION}: no expected session supplied by the release request; "
            "the gate cannot bind this bundle to the release under evaluation "
            "(fail-closed). Pass the credentialed session identifier.")
    elif session_id != expected_session_id:
        violations.append(
            f"{WITNESS_VIOLATION}: bundle declares session '{session_id}' but the release "
            f"under evaluation was credentialed as '{expected_session_id}' "
            "(session substitution)")

    # ---- 1 & 2: authenticate and scope every attestation -------------------
    good_receipts: List[Receipt] = []
    for raw in receipts:
        r = Receipt.from_dict(raw)
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
        "expected_session_id": expected_session_id,
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


def orchestrator_key_from_yaml(data: Dict[str, Any]) -> Optional[str]:
    orch = (data or {}).get("orchestrator") or {}
    if isinstance(orch, dict):
        return orch.get("public_key")
    if isinstance(orch, str):
        return orch
    return None
