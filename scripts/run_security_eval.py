#!/usr/bin/env python3
"""
Deterministic security evaluation for the USENIX Security '27 submission.

Split out from run_release_benchmark.py (2026-08-17 review, P1.7) because these
results are platform-independent -- block counts, not timings -- so they can be
regenerated on any machine without disturbing the timing measurements taken on
the author platform.

Produces results/security_evaluation.json:

  * vectors            -- 17 scored adversarial vectors + 1 retired configuration
                          check, each evaluated against EviAssure and every
                          baseline, with Wilson 95% intervals on all rates.
  * negative_controls  -- clean bundles that must be APPROVED, so the
                          false-block rate is measurable (review B2).
  * wire_fuzzing       -- differential encoding fuzzing with clean controls,
                          replacing the campaign that could not fail (B2).
  * inspection         -- leave-one-class-out semantic inspection over the
                          corpus, with the overt/stealth breakdown (B3).
  * ablation           -- per-check marginal contribution, with the empty
                          registry variant that the previous matrix mislabelled.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from statsmodels.stats.proportion import proportion_confint

from assurance.crypto import build_merkle_tree, verify_merkle_proof, expected_tree_depth
from assurance.inspection import leave_one_class_out
from assurance.policy import ReleasePolicyEngine
from benchmark.baselines import build_baselines, build_completeness_baselines
from benchmark.omission_vectors import generate_omission_suite
from benchmark.tamper_vectors import (
    TAMPER_VECTOR_TAXONOMY, SCORED_VECTORS,
    generate_tampered_evidence_suite, generate_negative_controls,
    generate_wire_fuzzing_suite,
)

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "governance" / "release_policy.yaml"
CORPUS = ROOT / "corpus" / "agent_trace_corpus.json"
OUT = ROOT / "results" / "security_evaluation.json"

_CONTROL_KEYS = ("__gate_override__", "__auditor_challenge__",
                 "__fresh_replica__", "__leaf_confusion_probe__")


def wilson(k: int, n: int) -> Dict[str, float]:
    if n == 0:
        return {"rate_pct": 0.0, "ci95_low_pct": 0.0, "ci95_high_pct": 0.0, "k": 0, "n": 0}
    lo, hi = proportion_confint(k, n, alpha=0.05, method="wilson")
    return {"rate_pct": round(k / n * 100.0, 1),
            "ci95_low_pct": round(lo * 100.0, 1),
            "ci95_high_pct": round(hi * 100.0, 1),
            "k": k, "n": n}


def _strip(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in payload.items() if k not in _CONTROL_KEYS}


def _eviassure_verdict(vector_id: str, payload: Dict[str, Any],
                       seen_nonces: set) -> tuple[bool, List[str]]:
    """Return (blocked, violations). Handles the vectors that target surfaces
    other than the policy gate."""
    clean = _strip(payload)

    # V15 targets the third-party auditor proof path, not the gate.
    if "__auditor_challenge__" in payload:
        ch = payload["__auditor_challenge__"]
        accepted = verify_merkle_proof(
            ch["claimed_leaf"], ch["proof_path"], ch["root"],
            expected_tree_depth(ch["committed_leaf_count"]))
        return (not accepted,
                [] if accepted else ["AUDITOR: internal-node-as-leaf proof rejected "
                                     "(committed depth + 0x00/0x01 domain separation)"])

    # V17 targets leaf/internal type confusion in tree construction.
    if "__leaf_confusion_probe__" in payload:
        probe = payload["__leaf_confusion_probe__"]
        try:
            build_merkle_tree([probe])
            return False, []          # accepted a non-digest as a leaf: UNBLOCKED
        except ValueError:
            return True, ["MERKLE: 64-char non-digest leaf rejected (explicit digest typing)"]

    engine = ReleasePolicyEngine.from_yaml(POLICY)
    if "__gate_override__" in payload:
        engine.release_conditions.update(payload["__gate_override__"])

    # V16 models a SECOND gate replica that does not share replay state.
    if payload.get("__fresh_replica__"):
        first = ReleasePolicyEngine.from_yaml(POLICY)
        first.evaluate(deepcopy(clean), seen_nonces=set())      # approved on replica A
        passed, violations, _ = engine.evaluate(clean, seen_nonces=set())  # replica B
        return (not passed), violations

    passed, violations, _ = engine.evaluate(clean, seen_nonces=seen_nonces)
    return (not passed), violations


def evaluate_vectors(baselines) -> Dict[str, Any]:
    suite = generate_tampered_evidence_suite()
    rows, seen = [], set()

    for vector_id, meta, payload in suite:
        nonces = set(seen)
        if vector_id == "V4_REPLAYED_NONCE":
            nonces.add(payload["nonce"])

        evi_blocked, violations = _eviassure_verdict(vector_id, payload, nonces)
        clean = _strip(payload)

        row = {
            "vector_id": meta["id"],
            "name": meta["name"],
            "category": meta["category"],
            "scored": meta.get("scored", True),
            "eviassure_blocked": evi_blocked,
            "eviassure_violations": violations[:3],
        }
        for b in baselines:
            row[b.name] = not b.verify(clean)
        rows.append(row)

    scored_ids = {TAMPER_VECTOR_TAXONOMY[k]["id"] for k in SCORED_VECTORS}
    scored = [r for r in rows if r["vector_id"] in scored_ids]
    n = len(scored)

    summary = {"eviassure": wilson(sum(r["eviassure_blocked"] for r in scored), n)}
    for b in baselines:
        summary[b.name] = wilson(sum(r[b.name] for r in scored), n)

    return {
        "n_scored_vectors": n,
        "n_retired_checks": len(rows) - n,
        "note": ("V1-V12 map close to 1:1 onto EviAssure's enforcement checks and are "
                 "reported as mechanism coverage, not as evidence of resilience to novel "
                 "attacks. V14-V18 were written independently of the check list; two of "
                 "them (V14, V17) broke the implementation before 2026-08-17. V13 is "
                 "retired from the score: the KMS ARN is self-declared metadata inside the "
                 "signed payload and constrains misconfiguration, not an adversary."),
        "summary": summary,
        "per_vector": rows,
    }


def evaluate_omission(tamper_baselines) -> Dict[str, Any]:
    """The completeness axis: omission attacks that no prior system detects.

    Reported separately from the tamper suite because it is a different attack
    class, not a harder instance of the same one. Every entry is also evaluated
    with witness reconciliation DISABLED, which is the counterfactual that shows
    the result is due to the mechanism rather than to some other check.
    """
    suite, registry, mediated = generate_omission_suite()
    comp = build_completeness_baselines(registry, mediated)
    dsse = next(b for b in tamper_baselines if "DSSE" in b.name)
    tuf = next(b for b in tamper_baselines if "TUF" in b.name)

    def evi(witnessed: bool, bundle):
        e = ReleasePolicyEngine.from_yaml(POLICY)
        e.witness_registry = dict(registry)
        e.mediated_actions = dict(mediated)
        e.release_conditions.update({"require_witnessed_completeness": witnessed})
        passed, violations, _ = e.evaluate(deepcopy(bundle), seen_nonces=set())
        return (not passed), violations

    systems = [dsse.name, tuf.name, comp[0].name, comp[1].name,
               "EviAssure without witness reconciliation", "EviAssure + WTC"]
    rows, tally = [], {s: 0 for s in systems}
    control_ok = {}

    for vid, meta, bundle in suite:
        blocked = {
            dsse.name: not dsse.verify(bundle),
            tuf.name: not tuf.verify(bundle),
            comp[0].name: not comp[0].verify(bundle),
            comp[1].name: not comp[1].verify(bundle),
            "EviAssure without witness reconciliation": evi(False, bundle)[0],
            "EviAssure + WTC": evi(True, bundle)[0],
        }
        if vid == "OC1":
            control_ok = {k: (not v) for k, v in blocked.items()}
        else:
            for k, v in blocked.items():
                tally[k] += int(v)
        rows.append({"vector_id": vid, "name": meta["name"], "class": meta["class"],
                     "description": meta["description"],
                     "blocked_by": {k: bool(v) for k, v in blocked.items()},
                     "eviassure_wtc_violation": (evi(True, bundle)[1] or [None])[0]})

    n = len(suite) - 1
    return {
        "note": ("Omission attacks: the adversary controls the agent and the evidence "
                 "collector but not the witnesses, and performs actions without recording "
                 "them. No tampering occurs, so no integrity check can fire. OC1 is an "
                 "honest fully-witnessed execution that every system must APPROVE."),
        "n_omission_vectors": n,
        "control_approved_by": control_ok,
        "summary": {k: wilson(v, n) for k, v in tally.items()},
        "per_vector": rows,
    }


def evaluate_negative_controls(baselines) -> Dict[str, Any]:
    controls = generate_negative_controls()
    rows = []
    for label, meta, payload in controls:
        engine = ReleasePolicyEngine.from_yaml(POLICY)
        passed, violations, _ = engine.evaluate(payload, seen_nonces=set())
        rows.append({"control": label, "approved": passed, "violations": violations[:2]})
    k = sum(1 for r in rows if not r["approved"])
    return {
        "note": "clean, well-formed bundles that MUST be approved; measures the false-block rate",
        "false_block": wilson(k, len(rows)),
        "per_control": rows,
    }


def evaluate_wire_fuzzing(count: int = 1000, seed: int = 42) -> Dict[str, Any]:
    suite = generate_wire_fuzzing_suite(count=count, seed=seed)
    engine = ReleasePolicyEngine.from_yaml(POLICY)

    tp = fp = fn = tn = 0
    disagreements = []
    for label, payload, should_approve in suite:
        passed, violations, _ = engine.evaluate(deepcopy(payload), seen_nonces=set())
        if should_approve and passed:
            tn += 1
        elif should_approve and not passed:
            fp += 1
            if len(disagreements) < 8:
                disagreements.append({"case": label, "expected": "APPROVED",
                                      "got": "BLOCKED", "why": violations[:2]})
        elif not should_approve and not passed:
            tp += 1
        else:
            fn += 1
            if len(disagreements) < 8:
                disagreements.append({"case": label, "expected": "BLOCKED", "got": "APPROVED"})

    return {
        "note": ("differential wire-encoding fuzzing: mutations perturb the SERIALIZATION of a "
                 "validly signed bundle (key order, whitespace, unicode escaping, number "
                 "formatting, duplicate keys, BOM) rather than signed fields, so a passing "
                 "outcome is reachable and the experiment can fail. 20% of cases are clean "
                 "controls. Replaces the campaign whose 1000/1000 result was an identity."),
        "n_cases": len(suite),
        "semantics_changing_blocked": wilson(tp, tp + fn),
        "semantics_preserving_approved": wilson(tn, tn + fp),
        "disagreements": disagreements,
    }


def evaluate_ablation() -> Dict[str, Any]:
    suite = [(vid, m, p) for vid, m, p in generate_tampered_evidence_suite()
             if vid in SCORED_VECTORS]
    variants = [
        ("full_gate", {}, None),
        ("no_signature_check", {"require_signed_evidence": False}, None),
        ("empty_key_registry", {}, "empty_registry"),
        ("no_crl", {}, "empty_crl"),
        ("no_kms_arn_bound", {"kms_key_arn_pattern": None}, None),
        ("no_merkle_check", {"verify_merkle_root": False}, None),
        ("no_count_binding", {"enforce_trace_count": False}, None),
        ("no_quality_gate", {"min_passing_tests_pct": 0.0}, None),
        ("no_drift_gate", {"allowed_drift_findings": 999}, None),
        ("no_freshness", {"max_evidence_age_seconds": 10**9,
                          "max_future_clock_skew_seconds": 10**9}, None),
        ("no_replay_state", {"require_replay_state": False}, "no_nonce_state"),
    ]

    rows = []
    for label, conds, attr in variants:
        blocked, escaped = 0, []
        for vid, meta, payload in suite:
            engine = ReleasePolicyEngine.from_yaml(POLICY)
            engine.release_conditions.update(conds)
            if attr == "empty_registry":
                engine.trusted_keys = {}
            elif attr == "empty_crl":
                engine.revoked_key_ids = set()

            if "__auditor_challenge__" in payload or "__leaf_confusion_probe__" in payload:
                is_blocked, _ = _eviassure_verdict(vid, payload, set())
            else:
                clean = _strip(payload)
                if "__gate_override__" in payload:
                    engine.release_conditions.update(payload["__gate_override__"])
                nonces = None if attr == "no_nonce_state" else set()
                if vid == "V4_REPLAYED_NONCE" and nonces is not None:
                    nonces.add(payload["nonce"])
                passed, _, _ = engine.evaluate(clean, seen_nonces=nonces)
                is_blocked = not passed

            if is_blocked:
                blocked += 1
            else:
                escaped.append(meta["id"])
        rows.append({"variant": label, "blocked": blocked,
                     "of": len(suite), "escaped_vectors": escaped})
    return {"note": "one enforcement disabled per row; full_gate is the shipped configuration",
            "rows": rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--require-executed", action="store_true",
                    help="fail if any baseline would fall back to a modeled implementation")
    ap.add_argument("--fuzz", type=int, default=1000)
    args = ap.parse_args()

    engine = ReleasePolicyEngine.from_yaml(POLICY)
    baselines = build_baselines(engine.trusted_keys, engine.revoked_key_ids,
                                require_executed=args.require_executed)

    print("=== Deterministic Security Evaluation ===")
    for b in baselines:
        print(f"  baseline: {b.name}\n            [{b.execution_mode}]")

    vectors = evaluate_vectors(baselines)
    controls = evaluate_negative_controls(baselines)
    omission = evaluate_omission(baselines)
    fuzz = evaluate_wire_fuzzing(count=args.fuzz)
    corpus = json.loads(CORPUS.read_text())
    inspection = leave_one_class_out(corpus["profiles"])
    ablation = evaluate_ablation()

    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": sys.version.split()[0],
        "determinism": ("platform-independent: every figure here is a block count or a "
                        "verdict, not a timing. Regenerate on any machine."),
        "baseline_execution": {b.name: b.execution_mode for b in baselines},
        "vectors": vectors,
        "omission": omission,
        "negative_controls": controls,
        "wire_fuzzing": fuzz,
        "semantic_inspection": inspection,
        "ablation": ablation,
        "corpus": {k: corpus[k] for k in
                   ("total_profiles", "clean_profiles", "overt_anomalies",
                    "stealth_anomalies", "total_trace_records", "provenance")},
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2))

    s = vectors["summary"]
    print(f"\n--- Block rates over {vectors['n_scored_vectors']} scored vectors ---")
    for name, st in s.items():
        print(f"  {name[:52]:54s} {st['k']:2d}/{st['n']}  {st['rate_pct']:5.1f}%  "
              f"CI[{st['ci95_low_pct']:.1f},{st['ci95_high_pct']:.1f}]")
    unblocked = [r["vector_id"] for r in vectors["per_vector"]
                 if r["scored"] and not r["eviassure_blocked"]]
    print(f"\n  EviAssure UNBLOCKED: {unblocked or 'none'}")
    print(f"\n--- Omission attacks ({omission['n_omission_vectors']} vectors, "
          f"control approved by all: {all(omission['control_approved_by'].values())}) ---")
    for name, st in omission["summary"].items():
        print(f"  {name[:52]:54s} {st['k']}/{st['n']}")
    fb = controls["false_block"]
    print(f"  false-block rate on clean controls: {fb['k']}/{fb['n']}")
    ins = inspection
    print(f"  inspection recall: {ins['recall_overall']}/{ins['n_anomalous']} "
          f"({ins['recall_overall_pct']}%), FP {ins['clean_flagged']}/{ins['n_clean']}")
    print(f"\n[+] {OUT}")


if __name__ == "__main__":
    main()
