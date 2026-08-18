#!/usr/bin/env python3
"""Emit docs/security_metrics.tex from the deterministic security artifacts.

Same discipline as frozen_metrics.tex: every security numeral in the prose is a
generated macro bound to results/, so a re-run can never leave a stale number in
the manuscript (the numeric-drift class E1/E7 from the 2026-08-15 plan).
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
sec = json.loads((ROOT / "results" / "security_evaluation.json").read_text())
corp = json.loads((ROOT / "results" / "corpus_evaluation.json").read_text())

V = sec["vectors"]
S = V["summary"]
INS = sec["semantic_inspection"]
WF = sec["wire_fuzzing"]
NC = sec["negative_controls"]["false_block"]

def name(sub):
    return next(k for k in S if sub.lower() in k.lower())

evi, comp = S["eviassure"], S[name("Composed")]
tuf, dsse, opa, ci = S[name("TUF")], S[name("DSSE")], S[name("OPA")], S[name("status gate")]
ov = [c for c in INS["per_class"] if c["anomaly_class"].startswith("ANOMALY")]
st = [c for c in INS["per_class"] if c["anomaly_class"].startswith("STEALTH")]

def rate(m, k):
    return [(f"{k}Blocked", m["k"]), (f"{k}Total", m["n"]),
            (f"{k}Pct", f"{m['rate_pct']:.1f}"),
            (f"{k}CIlo", f"{m['ci95_low_pct']:.1f}"), (f"{k}CIhi", f"{m['ci95_high_pct']:.1f}")]

rows = []
for m, k in ((evi, "evi"), (comp, "comp"), (tuf, "tuf"), (dsse, "dsse"), (opa, "opa"), (ci, "cigate")):
    rows += rate(m, k)
rows += [
    ("scoredVectors", V["n_scored_vectors"]),
    ("eviUnblocked", ", ".join(r["vector_id"] for r in V["per_vector"]
                               if r["scored"] and not r["eviassure_blocked"]) or "none"),
    ("falseBlockK", NC["k"]), ("falseBlockN", NC["n"]),
    ("fuzzCases", WF["n_cases"]),
    ("fuzzBlockedK", WF["semantics_changing_blocked"]["k"]),
    ("fuzzBlockedN", WF["semantics_changing_blocked"]["n"]),
    ("fuzzApprovedK", WF["semantics_preserving_approved"]["k"]),
    ("fuzzApprovedN", WF["semantics_preserving_approved"]["n"]),
    ("corpusProfiles", f"{corp['corpus']['total_profiles']:,}"),
    ("corpusClean", f"{corp['corpus']['clean_profiles']:,}"),
    ("corpusRecords", f"{corp['corpus']['total_trace_records']:,}"),
    ("corpusOvert", corp["corpus"]["overt_anomalies"]),
    ("corpusStealth", corp["corpus"]["stealth_anomalies"]),
    ("corpusClasses", INS["n_classes"]),
    ("insRecallK", INS["recall_overall"]), ("insRecallN", INS["n_anomalous"]),
    ("insRecallPct", f"{INS['recall_overall_pct']:.1f}"),
    ("insOvertK", sum(c["detected"] for c in ov)), ("insOvertN", sum(c["n"] for c in ov)),
    ("insStealthK", sum(c["detected"] for c in st)), ("insStealthN", sum(c["n"] for c in st)),
    ("insFPK", INS["clean_flagged"]), ("insFPN", INS["n_clean"]),
]

import re
# Count EVERY test function, including the docs-consistency guard. The
# manuscript prints this number next to the literal command `pytest tests/`,
# so it has to equal what that command reports -- excluding the guard made the
# paper claim 80 where a reviewer running the stated command sees 83.
n_tests = sum(len(re.findall(r"^def (test_\w+)", f.read_text(), re.M))
              for f in sorted((ROOT / "tests").glob("test_*.py")))
rows.append(("testCount", n_tests))

# --- omission / witnessed-completeness macros ------------------------------
OM = sec["omission"]
OS = OM["summary"]
def om(sub):
    return next(v for k, v in OS.items() if sub.lower() in k.lower())
rows += [
    ("omVectors", OM["n_omission_vectors"]),
    ("omWtc", om("EviAssure + WTC")["k"]),
    ("omNoWtc", om("without witness")["k"]),
    ("omReceipts", om("Per-action receipts")["k"]),
    ("omChain", om("hash chaining")["k"]),
    ("omDsse", om("DSSE")["k"]),
    ("omTuf", om("TUF")["k"]),
    ("omControlOk", "yes" if all(OM["control_approved_by"].values()) else "NO"),
]

# --- inspection recall CI ------------------------------------------------------
# The manuscript typed "CI [55.4, 76.3]" as a literal. The bounds happened to be
# right, but a typed interval is precisely what frozen_metrics.tex exists to
# prevent -- it survives a re-run that changes the underlying counts. Compute
# the Wilson interval from the recorded counts instead.
def _wilson(k, n, z=1.959963984540054):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - m) * 100.0, (c + m) * 100.0

_lo, _hi = _wilson(INS["recall_overall"], INS["n_anomalous"])
rows += [("insRecallCIlo", f"{_lo:.1f}"), ("insRecallCIhi", f"{_hi:.1f}")]

# --- live agent macros ------------------------------------------------------
# Optional: present only after scripts/run_live_agent_eval.py has run against a
# real model endpoint. Absent rather than zeroed when it has not, so the paper
# cannot quote a live-agent number that no live agent produced.
_ATTACK = re.compile(r"O\d+")
live_path = ROOT / "results" / "live_agent_evaluation.json"
if live_path.exists():
    LA = json.loads(live_path.read_text())["summary"]
    od = LA["omission_detection"]
    rows += [
        ("liveSessions", LA["sessions_completed"]),
        ("liveRequested", LA["sessions_requested"]),
        ("liveFailures", len(LA["session_failures"])),
        ("liveModel", LA["model"].replace("_", r"\_")),
        ("liveDistinctSeq", LA["distinct_action_sequences"]),
        ("liveNondetPct", f"{LA['nondeterminism_ratio'] * 100:.0f}"),
        ("liveActionsMean", LA["actions_mean"]),
        ("liveActionsStd", LA["actions_stdev"]),
        ("liveActionsTotal", LA["actions_total"]),
        ("liveCoverageMean", f"{LA['witness_coverage_mean'] * 100:.1f}"),
        ("liveCoverageMin", f"{LA['witness_coverage_min'] * 100:.1f}"),
        ("liveUnmediated", ", ".join(LA["unmediated_actions_seen"]).replace("_", r"\_") or "none"),
        ("liveControlOk", f"{od['OC1_control_approved']['detected']}/{od['OC1_control_approved']['of']}"),
        # Attack vectors only. "OC1_control_approved" also starts with "O" --
        # counting the honest control as a detected attack would inflate the
        # numerator with the one case that must NOT be detected.
        ("liveOmDetected", sum(v["detected"] for k, v in od.items() if _ATTACK.fullmatch(k))),
        ("liveOmTotal", sum(v["of"] for k, v in od.items() if _ATTACK.fullmatch(k))),
    ]
    # Coverage split by how the session ended. A session truncated by the turn
    # cap never reaches the unmediated bookkeeping call, so its coverage is
    # 100% by construction of the cap rather than by property of the witness
    # set. Reporting only the pooled mean would repeat the error that produced
    # the old 50/50 recall figure: a number that describes the harness.
    _S = json.loads(live_path.read_text())["sessions"]
    _done = [x for x in _S if x["stopped_reason"].startswith("agent emitted")]
    _trunc = [x for x in _S if not x["stopped_reason"].startswith("agent emitted")]
    _cov = lambda xs: (sum(x["coverage"] for x in xs) / len(xs) * 100.0) if xs else 0.0
    # The dataset now spans more than one model, and \liveModel is singular by
    # construction. Emitting the count and the list separately stops the paper
    # describing a multi-model sample as if one model produced it.
    _models = sorted({x["model"] for x in _S})
    _modes = sorted({x.get("witness_mode", "in-process") for x in _S})
    _provs = sorted({x["provider"] for x in _S})
    # Sessions recorded before witness_isolation existed ran with the only
    # option there was then: a child process on the host. Defaulting them to
    # "process" states what happened; it does not backfill the data file.
    _iso = [x.get("witness_isolation", "process") for x in _S]
    rows += [
        ("liveCompleted", len(_done)),
        ("liveTruncated", len(_trunc)),
        ("liveCoverageCompleted", f"{_cov(_done):.1f}"),
        ("liveCoverageTruncated", f"{_cov(_trunc):.1f}"),
        ("liveModelCount", len(_models)),
        ("liveModels", ", ".join(_models).replace("_", r"\_")),
        # Which harness produced the sample. A coverage figure from the
        # in-process harness measures the harness, not a deployment, so the
        # mode belongs in the paper next to the number.
        ("liveWitnessMode", ", ".join(_modes)),
        ("liveProviderCount", len(_provs)),
        ("liveProviders", ", ".join(_provs)),
        ("liveIsoContainer", _iso.count("container")),
        ("liveIsoProcess", _iso.count("process")),
    ]
    # How many of the six omission vectors the live harness can actually build.
    # O5 (cross-session splice) needs a second concurrent session, which the
    # runner does not create -- sessions are independent. Reporting 69/69 while
    # implying all six would overclaim; the count is generated so it cannot
    # drift if the harness later gains the missing vector.
    rows += [
        ("liveOmVectorsRun", len([k for k in od if _ATTACK.fullmatch(k)])),
        ("liveOmVectorsSuite", sec["omission"]["n_omission_vectors"]),
        ("liveOmMissing", ", ".join(sorted(
            {f"O{i}" for i in range(1, sec["omission"]["n_omission_vectors"] + 1)}
            - {k for k in od if _ATTACK.fullmatch(k)})) or "none"),
    ]
    print(f"[+] live-agent macros from {LA['sessions_completed']} session(s)")
else:
    print("[i] no live_agent_evaluation.json -- live-agent macros omitted")

out = ["% GENERATED by scripts/write_security_macros.py -- do not edit by hand.",
       "% Bound to results/security_evaluation.json and results/corpus_evaluation.json.",
       f"% Generated {sec['timestamp']}"]
out += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in rows]
(ROOT / "docs" / "security_metrics.tex").write_text("\n".join(out) + "\n")
print(f"[+] docs/security_metrics.tex ({len(rows)} macros)")
