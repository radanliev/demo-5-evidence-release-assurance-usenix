"""
Core Release Gate Evaluator for Evidence Assurance.
"""

import json
from pathlib import Path
from typing import Any, Dict, MutableSet, Optional

from .policy import ReleasePolicyEngine, PersistentNonceStore
from .evidence import create_evidence_pack, EvidenceBundle, DEFAULT_SECRET_KEY

DEFAULT_NONCE_STORE = ".eviassure/nonce_ledger.json"


def load_release_request(path: Path | str) -> Dict[str, Any]:
    """The release request is the orchestrator's statement of WHICH session it
    credentialed for the release under evaluation. It is written by the party
    that opened the session (in the demo, scripts/package_evidence.py plays
    both roles) and read by the gate, so the bundle can never nominate its own
    session (vector O7)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_release_gate(
    policy_path: Path | str,
    evidence: Optional[EvidenceBundle | Dict[str, Any]] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
    seen_nonces: Optional[MutableSet[str]] = None,
    output_decision_file: Optional[Path | str] = None,
    nonce_store_path: Optional[Path | str] = DEFAULT_NONCE_STORE,
    release_request: Optional[Dict[str, Any]] = None,
    expected_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate release policy gate against evidence pack.
    Returns release decision payload dictionary and writes decision JSON if path provided.

    Replay state is materialised HERE rather than left to the caller. Prior to
    the 2026-08-17 review this function defaulted ``seen_nonces`` to ``None``
    and the policy engine treated that as "skip the replay check", so the
    shipped gate approved the same signed bundle on every submission while the
    manuscript claimed replay protection was enforced integrally. The gate now
    persists nonces to ``nonce_store_path`` by default; pass
    ``nonce_store_path=None`` only together with an explicit ``seen_nonces``.

    Session binding works the same way: the shipped policy requires witnessed
    completeness, and the session the gate adjudicates comes from the release
    request (or ``expected_session_id``), never from the bundle. With no
    evidence supplied, a witnessed demo pack is created and its own credential
    is used, so ``python scripts/verify_release_gate.py`` exercises the full
    witnessed path end to end.
    """
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    if evidence is None:
        evidence = create_evidence_pack(secret_key=secret_key, signed=True, witnessed=True)
        if expected_session_id is None and release_request is None:
            expected_session_id = evidence.session_id

    if release_request is not None and expected_session_id is None:
        expected_session_id = release_request.get("session_id")

    if seen_nonces is None and nonce_store_path is not None:
        seen_nonces = PersistentNonceStore(nonce_store_path)

    passed, violations, details = policy_engine.evaluate(
        evidence=evidence,
        secret_key=secret_key,
        seen_nonces=seen_nonces,
        expected_session_id=expected_session_id,
    )

    ev_id = evidence.evidence_id if isinstance(evidence, EvidenceBundle) else evidence.get("evidence_id", "UNKNOWN")
    signed_status = evidence.signed if isinstance(evidence, EvidenceBundle) else evidence.get("signed", False)

    decision = {
        "status": "APPROVED" if passed else "BLOCKED",
        "passed": passed,
        "policy_name": policy_engine.policy_name,
        "policy_profile": getattr(policy_engine, "profile", "policy-default"),
        "evidence_id": ev_id,
        "signed": signed_status,
        "violations": violations,
        "enforcement": "FAIL_CLOSED",
        "replay_state": (str(nonce_store_path) if isinstance(seen_nonces, PersistentNonceStore)
                         else ("caller-supplied" if seen_nonces is not None else "absent")),
        "witnessed_completeness_required": bool(
            policy_engine.release_conditions.get("require_witnessed_completeness", False)),
        "session_binding": (f"release request -> {expected_session_id}"
                            if expected_session_id is not None else "absent"),
        "witness": details.get("witness"),
    }

    if output_decision_file:
        out_p = Path(output_decision_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(decision, f, indent=2)

    return decision
