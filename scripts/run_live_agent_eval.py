#!/usr/bin/env python3
"""
Run real LLM agent sessions through the witness protocol and evaluate them.

This is the experiment that answers the paper's own strongest objection. Every
number in Section "Systems Security Evaluation" was, until now, computed over a
synthetic templated corpus; a reviewer is entitled to ask whether witnessed
completeness survives contact with an actual non-deterministic agent, and
whether a real agent's actions are witness-mediated often enough for the
guarantee to mean anything.

Three things are measured, in increasing order of what they cost us to be wrong
about:

  1. Reconciliation soundness on real traces. An honest, fully witnessed live
     session must reconcile. If it does not, the protocol is broken.
  2. Omission detection on real traces. The O1-O6 vectors are re-derived
     against each live session rather than against generated templates.
  3. Witness coverage -- the fraction of executed actions a witness served.
     Definition (WTC) states the guarantee relative to the witness set and
     leaves that fraction open; this measures it. A tool the agent reaches for
     that no witness fronts is outside the guarantee, and the run reports which
     ones those were.

Usage:
    python3 scripts/run_live_agent_eval.py --sessions 10 --provider groq
    python3 scripts/run_live_agent_eval.py --require-live   # fail rather than skip

Results are written to results/live_agent_evaluation.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from assurance.evidence import (create_evidence_pack, DEMO_PRIV_KEY,   # noqa: E402
                                DEMO_PUB_KEY_B64)
from assurance.witness import reconcile, Closing                        # noqa: E402
from assurance.crypto import (sign_payload_ed25519,                     # noqa: E402
                              generate_ed25519_keypair)
from specimens.live_agent_runner import (run_live_session, ProviderError,  # noqa: E402
                                         PROVIDERS, LiveSession)

TASKS = [
    "Did the most recent release pass its gate?",
    "How many releases are recorded, and which ones were blocked?",
    "Check whether any release has unresolved drift findings.",
    "Summarise the release history and flag anything that failed its gate.",
    "Which release version is the newest, and what was its gate outcome?",
]


def _load_dotenv() -> List[str]:
    """Read keys from the usual places. Returns the names loaded, never values."""
    loaded: List[str] = []
    for base in (Path.home() / "Projects", Path.home() / "mnt" / "Projects", Path.home(), ROOT):
        for fname in (".env", ".paperloop-env"):
            f = base / fname
            if not f.exists():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.replace("export", "").strip()
                v = v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v
                    loaded.append(k)
    return sorted(set(loaded))


_SCRUB = [
    (re.compile(r"org_[A-Za-z0-9]{8,}"), "org_<redacted>"),
    (re.compile(r"\b(gsk|sk-or-v1|sk-proj|sk)-?[A-Za-z0-9_-]{16,}"), "<redacted-key>"),
    (re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+"), "<home>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
]


def scrub(text: str) -> str:
    """Strip account-identifying detail from provider error text before it is
    written to results/.

    Not paranoia: a free-tier 429 from Groq embeds the caller's organization ID
    in the message body, and results/ ships inside the anonymous review
    artifact. A rate-limit error is exactly the kind of incidental failure an
    author never re-reads, which is what makes it a good place to leak from.
    """
    for rx, repl in _SCRUB:
        text = rx.sub(repl, text)
    return text


def _package(traces, receipts, closings, session_id) -> Dict[str, Any]:
    """Sign a bundle honestly. The omission adversary holds the collector key --
    what they cannot produce is a witness signature."""
    b = create_evidence_pack(traces=list(traces), use_ed25519=True, signed=False)
    b.session_id = session_id
    b.witness_receipts = [r.to_dict() for r in receipts]
    b.witness_closings = [c.to_dict() for c in closings]
    b.sign_ed25519(DEMO_PRIV_KEY, DEMO_PUB_KEY_B64)
    return b.to_dict()


def _check(bundle: Dict[str, Any], sess: LiveSession) -> bool:
    ok, _viol, _d = reconcile(
        bundle["traces"], bundle["witness_receipts"], bundle["witness_closings"],
        sess.registry, sess.session_id, require_witness=True,
        mediated_actions=sess.mediated)
    return ok


def omission_vectors_on(sess: LiveSession) -> Dict[str, bool]:
    """Re-derive the omission attacks against THIS real session.

    Returns {vector_id: detected}. A vector that cannot be constructed for a
    given session (e.g. no interior action to drop) is omitted from the dict
    rather than counted as a pass -- scoring an unbuildable attack as detected
    would inflate the result.
    """
    out: Dict[str, bool] = {}
    T, R, C = sess.traces, sess.receipts, sess.closings
    mediated_idx = [i for i, t in enumerate(T)
                    if any(t.action in m for m in sess.mediated.values())]

    # OC1 control: the honest session must reconcile, or nothing below means anything.
    out["OC1_control_approved"] = _check(_package(T, R, C, sess.session_id), sess)

    if len(mediated_idx) >= 3:                      # O1 interior omission
        drop = mediated_idx[len(mediated_idx) // 2]
        rpos = mediated_idx.index(drop)
        out["O1"] = not _check(_package(
            [t for i, t in enumerate(T) if i != drop],
            [r for j, r in enumerate(R) if j != rpos], C, sess.session_id), sess)

    if len(mediated_idx) >= 2:                      # O2 suffix omission
        last = mediated_idx[-1]
        out["O2"] = not _check(_package(
            [t for i, t in enumerate(T) if i != last], R[:-1], C, sess.session_id), sess)

    # O3 whole-witness omission: drop a witness's actions AND its closing.
    for wid, acts in sess.mediated.items():
        idx = [i for i, t in enumerate(T) if t.action in acts]
        if idx:
            keep_r = [r for r in R if r.witness_id != wid]
            out["O3"] = not _check(_package(
                [t for i, t in enumerate(T) if i not in set(idx)], keep_r,
                [c for c in C if c.witness_id != wid], sess.session_id), sess)
            break

    if mediated_idx:                                # O4 forged closing count
        victim = mediated_idx[-1]
        wid = next(w for w, a in sess.mediated.items() if T[victim].action in a)
        n_for_w = sum(1 for r in R if r.witness_id == wid)
        priv, _, _pub, _ = generate_ed25519_keypair()
        forged = Closing(wid, sess.session_id, max(n_for_w - 1, 0))
        forged.signature = sign_payload_ed25519(forged.payload(), priv)
        keep_r, seen = [], 0
        for r in R:
            if r.witness_id == wid and r.seq == n_for_w:
                continue
            keep_r.append(r)
        out["O4"] = not _check(_package(
            [t for i, t in enumerate(T) if i != victim], keep_r,
            [c for c in C if c.witness_id != wid] + [forged], sess.session_id), sess)

    if mediated_idx:                                # O6 fabricated mediated action
        from assurance.evidence import ExecutionTraceRecord
        from assurance.crypto import hash_sha256
        ghost_action = T[mediated_idx[0]].action
        ghost = ExecutionTraceRecord("TR-GHOST", "live-agent", ghost_action,
                                     "SUCCESS", 1.0, hash_sha256("NEVER_HAPPENED"))
        out["O6"] = not _check(_package(list(T) + [ghost], R, C, sess.session_id), sess)

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=10)
    ap.add_argument("--provider", default="groq", choices=sorted(PROVIDERS))
    ap.add_argument("--model", default=None)
    ap.add_argument("--require-live", action="store_true",
                    help="exit non-zero instead of skipping when no key is available")
    ap.add_argument("--append", action="store_true",
                    help="merge with an existing results file instead of replacing it. "
                         "Free-tier provider accounts are metered per minute, so a "
                         "meaningful sample often has to be gathered in batches; "
                         "sessions are independent, so merging them is sound.")
    args = ap.parse_args()

    names = _load_dotenv()
    if names:
        print(f"[*] loaded credentials from environment files: {', '.join(names)}")

    env_var = PROVIDERS[args.provider]["env"]
    if not os.environ.get(env_var):
        msg = (f"[!] {env_var} is not set, so no live agent can be run.\n"
               f"    This experiment is SKIPPED; nothing is substituted for it.\n"
               f"    Provide the key, or re-run with --provider "
               f"{'openrouter' if args.provider == 'groq' else 'groq'}.")
        print(msg)
        return 2 if args.require_live else 0

    sessions: List[LiveSession] = []
    failures: List[str] = []
    for i in range(args.sessions):
        task = TASKS[i % len(TASKS)]
        try:
            s = run_live_session(provider=args.provider, model=args.model, task=task)
        except ProviderError as e:
            msg = scrub(str(e))
            failures.append(f"session {i}: {msg}")
            print(f"  [{i+1}/{args.sessions}] FAILED: {msg}")
            continue
        sessions.append(s)
        print(f"  [{i+1}/{args.sessions}] {len(s.traces)} actions, "
              f"{s.mediated_count} witnessed ({s.coverage:.0%}), "
              f"{s.turns} turns, stop={s.stopped_reason}")

    if not sessions:
        print("[!] no live session completed; refusing to emit results")
        for f in failures:
            print("   ", f)
        return 1

    # ---- aggregate -------------------------------------------------------
    per_session = []
    vector_tally: Dict[str, List[bool]] = {}
    for s in sessions:
        vec = omission_vectors_on(s)
        for k, v in vec.items():
            vector_tally.setdefault(k, []).append(v)
        per_session.append({
            "session_id": s.session_id, "model": s.model, "provider": s.provider,
            "turns": s.turns, "actions": len(s.traces),
            "witnessed": s.mediated_count, "coverage": round(s.coverage, 4),
            "unmediated_actions": sorted(set(s.unmediated_actions)),
            "action_sequence": [t.action for t in s.traces],
            "statuses": sorted({t.status for t in s.traces}),
            "stopped_reason": s.stopped_reason,
            "omission_vectors": vec,
        })

    out_path = ROOT / "results" / "live_agent_evaluation.json"
    if args.append and out_path.exists():
        prior = json.loads(out_path.read_text()).get("sessions", [])
        known = {p["session_id"] for p in per_session}
        merged = [p for p in prior if p["session_id"] not in known] + per_session
        print(f"[*] merging {len(prior)} prior session(s) -> {len(merged)} total")
        per_session = merged
        prior_requested = json.loads(out_path.read_text()).get(
            "summary", {}).get("sessions_requested", len(prior))
        vector_tally = {}
        for p in per_session:
            for k, v in p.get("omission_vectors", {}).items():
                vector_tally.setdefault(k, []).append(v)

    try:
        requested_total = prior_requested + args.sessions
    except NameError:
        requested_total = args.sessions

    seqs = {tuple(p["action_sequence"]) for p in per_session}
    coverages = [p["coverage"] for p in per_session]
    action_counts = [p["actions"] for p in per_session]
    n_sessions = len(per_session)

    summary = {
        "sessions_completed": n_sessions,
        "sessions_requested": requested_total,
        "session_failures": failures,
        "provider": args.provider,
        "model": sessions[0].model,
        "distinct_action_sequences": len(seqs),
        "nondeterminism_ratio": round(len(seqs) / n_sessions, 4),
        "actions_total": sum(action_counts),
        "actions_mean": round(statistics.mean(action_counts), 2),
        "actions_stdev": round(statistics.stdev(action_counts), 3) if len(action_counts) > 1 else 0.0,
        "witness_coverage_mean": round(statistics.mean(coverages), 4),
        "witness_coverage_min": round(min(coverages), 4),
        "unmediated_actions_seen": sorted({a for p in per_session
                                           for a in p["unmediated_actions"]}),
        "omission_detection": {k: {"detected": sum(v), "of": len(v)}
                               for k, v in sorted(vector_tally.items())},
    }

    out = out_path
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "sessions": per_session},
                              indent=2, sort_keys=True))

    print("\n=== live agent evaluation ===")
    print(f"  sessions              : {summary['sessions_completed']}/{summary['sessions_requested']}")
    print(f"  distinct sequences    : {summary['distinct_action_sequences']} "
          f"({summary['nondeterminism_ratio']:.0%} of sessions unique)")
    print(f"  actions/session       : {summary['actions_mean']} ± {summary['actions_stdev']}")
    print(f"  witness coverage      : {summary['witness_coverage_mean']:.1%} "
          f"(min {summary['witness_coverage_min']:.1%})")
    print(f"  outside the guarantee : {summary['unmediated_actions_seen'] or 'none'}")
    for k, v in summary["omission_detection"].items():
        print(f"  {k:24s}: {v['detected']}/{v['of']}")
    print(f"\n[+] {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
