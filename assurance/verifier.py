"""
Core Release Gate Evaluator for Evidence Assurance.
"""

import json
from pathlib import Path
from typing import Any, Dict, MutableSet, Optional

from .policy import ReleasePolicyEngine, PersistentNonceStore
from .evidence import create_evidence_pack, EvidenceBundle, DEFAULT_SECRET_KEY

DEFAULT_NONCE_STORE = ".eviassure/nonce_ledger.json"


def evaluate_release_gate(
    policy_path: Path | str,
    evidence: Optional[EvidenceBundle | Dict[str, Any]] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
    seen_nonces: Optional[MutableSet[str]] = None,
    output_decision_file: Optional[Path | str] = None,
    nonce_store_path: Optional[Path | str] = DEFAULT_NONCE_STORE,
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
    """
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)

    if evidence is None:
        evidence = create_evidence_pack(secret_key=secret_key, signed=True)

    if seen_nonces is None and nonce_store_path is not None:
        seen_nonces = PersistentNonceStore(nonce_store_path)

    passed, violations, details = policy_engine.evaluate(
        evidence=evidence,
        secret_key=secret_key,
        seen_nonces=seen_nonces
    )

    ev_id = evidence.evidence_id if isinstance(evidence, EvidenceBundle) else evidence.get("evidence_id", "UNKNOWN")
    signed_status = evidence.signed if isinstance(evidence, EvidenceBundle) else evidence.get("signed", False)

    decision = {
        "status": "APPROVED" if passed else "BLOCKED",
        "passed": passed,
        "policy_name": policy_engine.policy_name,
        "evidence_id": ev_id,
        "signed": signed_status,
        "violations": violations,
        "enforcement": "FAIL_CLOSED",
        "replay_state": (str(nonce_store_path) if isinstance(seen_nonces, PersistentNonceStore)
                         else ("caller-supplied" if seen_nonces is not None else "absent")),
    }

    if output_decision_file:
        out_p = Path(output_decision_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(decision, f, indent=2)

    return decision
