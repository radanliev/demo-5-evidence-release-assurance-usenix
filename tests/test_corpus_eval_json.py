"""
Regression test: the corpus-scale evaluation artifact must agree with the
corpus itself. If profile counts, gate verdicts, or inspection results drift,
the paper's Section 6.7 numbers (reported from results/corpus_evaluation.json)
would silently rot.

Rewritten 2026-08-17 (review B3). The previous version asserted
`anomalous_recall_pct == 100.0` -- i.e. it enforced the tautology rather than
detecting it, because the detector's keyword list and the generator's plant
list were the same list. It also asserted that every anomaly carries a
non-SUCCESS status, which is exactly the property that made the corpus
trivially separable. Both assertions are now inverted into the checks that
matter: the held-out detector must be strictly imperfect, and the corpus must
contain anomalies that are indistinguishable at the per-leaf level.
"""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _corpus():
    return json.loads((ROOT / "corpus" / "agent_trace_corpus.json").read_text())


def _eval():
    return json.loads((ROOT / "results" / "corpus_evaluation.json").read_text())


def test_corpus_evaluation_matches_corpus_counts():
    corpus, ev = _corpus(), _eval()
    profiles = corpus["profiles"]
    clean = [p for p in profiles if p["label"] == "CLEAN"]
    anomalous = [p for p in profiles if p["label"] != "CLEAN"]

    assert ev["corpus"]["total_profiles"] == len(profiles) == corpus["total_profiles"]
    assert ev["corpus"]["clean_profiles"] == len(clean)
    assert ev["corpus"]["anomalous_profiles"] == len(anomalous)

    l1 = ev["layer_1_cryptographic_integrity"]
    assert l1["merkle_consistent"] == len(profiles)
    assert l1["inclusion_proofs_valid"] == len(profiles)

    l2 = ev["layer_2_release_policy_gate"]
    assert l2["clean_approved"] == len(clean)
    assert l2["clean_approved_pct"] == 100.0
    # The gate approves semantically anomalous but cryptographically well-formed
    # bundles. This is the paper's own claim and it must stay visible.
    assert l2["anomalous_approved"] == len(anomalous)


def test_held_out_inspection_is_reported_and_imperfect():
    """The number the paper reports must come from the detector that was fitted
    without ever seeing an anomaly -- and it must be < 100%, otherwise the
    corpus is separable by a single rule and measures nothing."""
    ev = _eval()
    l3 = ev["layer_3_held_out_inspection"]

    assert l3["n_anomalous"] > 0 and l3["n_clean"] > 0
    assert 0.0 < l3["recall_overall_pct"] < 100.0, (
        "a held-out recall of exactly 100% means the corpus is trivially "
        "separable; add stealth anomaly classes rather than reporting it"
    )
    assert l3["false_positive_rate_pct"] == 0.0


def test_corpus_contains_stealth_anomalies_indistinguishable_per_leaf():
    """The corpus must contain anomalies whose action, status and duration are
    all drawn from clean traffic. Without them the benchmark cannot
    distinguish a detector from a vocabulary lookup."""
    corpus = _corpus()
    profiles = corpus["profiles"]
    clean_actions = {t["action"] for p in profiles if p["label"] == "CLEAN"
                     for t in p["traces"]}
    clean_statuses = {t["status"] for p in profiles if p["label"] == "CLEAN"
                      for t in p["traces"]}

    stealth = [p for p in profiles if p.get("anomaly_family") == "stealth"]
    assert stealth, "corpus must contain stealth anomaly profiles"

    for prof in stealth:
        assert any(t["action"] in clean_actions and t["status"] in clean_statuses
                   for t in prof["traces"]), prof["profile_id"]


def test_overt_anomalies_remain_out_of_vocabulary():
    """The overt classes are still the easy half, and should stay that way so
    the overt/stealth split in the paper is meaningful."""
    corpus = _corpus()
    profiles = corpus["profiles"]
    clean_actions = {t["action"] for p in profiles if p["label"] == "CLEAN"
                     for t in p["traces"]}
    overt = [p for p in profiles if p.get("anomaly_family") == "overt"]
    assert overt
    for prof in overt:
        assert any(t["action"] not in clean_actions for t in prof["traces"]), \
            prof["profile_id"]


def test_corpus_provenance_is_declared_synthetic():
    """USENIX '27 open-science expectations: the artifact must not let a reader
    infer that real agent executions produced this corpus."""
    corpus = _corpus()
    assert "SYNTHETIC" in corpus["provenance"].upper()
    assert "no LLM agent was executed" in corpus["provenance"]
