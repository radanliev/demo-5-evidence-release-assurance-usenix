"""
Per-leaf semantic inspection with a *held-out* evaluation protocol.

Why this module exists (2026-08-17 adversarial review, finding B3).

The previous inspection layer keyed off ``forensics.SENSITIVE_ACTIONS`` -- a
hard-coded list of twelve action names -- while ``scripts/generate_trace_corpus.py``
planted anomalies drawn from that same list, with a comment saying so:

    "Every action below is on the forensics engine's sensitive-action list, so
     Layer-3 inspection flags exactly these leaves."

The reported 50/50 recall and 0/1000 false-positive rate were therefore
consequences of the generator, not measurements of a detector. This module
replaces that arrangement with a detector that never sees the anomaly list:

  * ``fit_from_clean``    -- learns the action vocabulary and the per-action
    duration envelope from CLEAN profiles only.
  * ``score``             -- flags a trace whose action is out-of-vocabulary,
    whose status is outside the clean status vocabulary, or whose duration lies
    far outside the clean envelope for that action.
  * ``leave_one_class_out`` -- the evaluation protocol: for each anomaly class,
    fit on clean data and evaluate on that class *without* it having influenced
    anything. Recall is then measured against classes the detector has no prior
    knowledge of, which is the number the paper should report.

The resulting recall is expected to be **below** 100%. That is the honest
result, and it is worth more than a tautological one.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class CleanBehaviourModel:
    """Everything the detector knows, derived exclusively from clean traces."""
    action_vocabulary: Set[str] = field(default_factory=set)
    status_vocabulary: Set[str] = field(default_factory=set)
    duration_envelope: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    n_traces_fitted: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "n_traces_fitted": self.n_traces_fitted,
            "n_actions_learned": len(self.action_vocabulary),
            "n_statuses_learned": len(self.status_vocabulary),
            "actions": sorted(self.action_vocabulary),
            "statuses": sorted(self.status_vocabulary),
        }


def fit_from_clean(clean_profiles: Iterable[Dict[str, Any]],
                   sigma: float = 6.0) -> CleanBehaviourModel:
    """Fit the behaviour model on clean profiles only.

    ``sigma`` sets the duration envelope width in standard deviations. It is
    deliberately wide: the detector should fire on *structural* novelty, not on
    ordinary timing variation.
    """
    model = CleanBehaviourModel()
    durations: Dict[str, List[float]] = {}

    for prof in clean_profiles:
        for t in prof.get("traces", []):
            action = t.get("action")
            model.action_vocabulary.add(action)
            model.status_vocabulary.add(t.get("status"))
            durations.setdefault(action, []).append(float(t.get("duration_ms", 0.0)))
            model.n_traces_fitted += 1

    for action, xs in durations.items():
        if len(xs) >= 2:
            mu = statistics.mean(xs)
            sd = statistics.pstdev(xs)
            # Clean durations are quantised, so the sample sd for a given action
            # can be ~0 and the envelope collapses to a point -- at which any
            # deviation whatsoever "detects" an anomaly. That is a detector
            # artifact, not a signal: it would report near-perfect recall for
            # reasons that have nothing to do with the behaviour being anomalous.
            # Floor the half-width at the larger of sigma*sd, 25% of the mean,
            # and 1 ms, so duration only fires on genuinely large deviations.
            half = max(sigma * sd, 0.25 * abs(mu), 1.0)
            model.duration_envelope[action] = (mu - half, mu + half)
        else:
            model.duration_envelope[action] = (float("-inf"), float("inf"))

    return model


def score_trace(trace: Dict[str, Any], model: CleanBehaviourModel) -> Optional[str]:
    """Return a reason string if this trace is anomalous, else None."""
    action = trace.get("action")
    status = trace.get("status")

    if action not in model.action_vocabulary:
        return f"out-of-vocabulary action '{action}'"
    if status not in model.status_vocabulary:
        return f"out-of-vocabulary status '{status}'"

    lo, hi = model.duration_envelope.get(action, (float("-inf"), float("inf")))
    d = float(trace.get("duration_ms", 0.0))
    if not (lo <= d <= hi):
        return f"duration {d}ms outside clean envelope [{lo:.2f}, {hi:.2f}] for '{action}'"
    return None


def score_profile(profile: Dict[str, Any], model: CleanBehaviourModel) -> List[Dict[str, Any]]:
    flags = []
    for i, t in enumerate(profile.get("traces", [])):
        reason = score_trace(t, model)
        if reason:
            flags.append({"index": i, "trace_id": t.get("trace_id"),
                          "action": t.get("action"), "status": t.get("status"),
                          "reason": reason})
    return flags


def leave_one_class_out(profiles: List[Dict[str, Any]],
                        sigma: float = 6.0) -> Dict[str, Any]:
    """Held-out evaluation.

    For each anomaly class C: fit on clean profiles only (the detector never
    sees any anomaly, so C is doubly held out), then measure recall on C and
    the false-positive rate on the clean profiles.

    Because the model is fitted on clean data alone, the fit is identical across
    folds; the folds differ in which anomaly class is scored. This is the
    strongest available protocol on a corpus with only two traces per profile,
    and it removes the detector/generator identity that made the previous
    numbers vacuous.
    """
    clean = [p for p in profiles if p.get("label") == "CLEAN"]
    anomalous = [p for p in profiles if p.get("label") != "CLEAN"]
    classes = sorted({p["label"] for p in anomalous})

    model = fit_from_clean(clean, sigma=sigma)

    clean_flagged = sum(1 for p in clean if score_profile(p, model))
    per_class = []
    total_hits = 0
    for cls in classes:
        members = [p for p in anomalous if p["label"] == cls]
        hits = sum(1 for p in members if score_profile(p, model))
        total_hits += hits
        per_class.append({
            "anomaly_class": cls,
            "n": len(members),
            "detected": hits,
            "recall_pct": round(hits / len(members) * 100.0, 1) if members else 0.0,
            "example_reason": next(
                (f["reason"] for p in members for f in score_profile(p, model)), None),
        })

    return {
        "protocol": ("leave-one-class-out; the detector is fitted on CLEAN profiles only "
                     "and never observes any anomaly action, status or duration, so every "
                     "anomaly class is held out (2026-08-17 review, B3)"),
        "sigma": sigma,
        "model": model.as_dict(),
        "n_clean": len(clean),
        "n_anomalous": len(anomalous),
        "n_classes": len(classes),
        "recall_overall": total_hits,
        "recall_overall_pct": round(total_hits / len(anomalous) * 100.0, 1) if anomalous else 0.0,
        "clean_flagged": clean_flagged,
        "false_positive_rate_pct": round(clean_flagged / len(clean) * 100.0, 2) if clean else 0.0,
        "per_class": per_class,
    }
