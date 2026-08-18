#!/usr/bin/env python3
"""Measure the cost of the witness protocol (Section 4.2 of the manuscript).

The Merkle-scaling and verifier-throughput benchmarks time the *unwitnessed*
gate. This script times the mechanism the paper is actually about:

  * receipt issuance at the witness -- one Ed25519 signature over the receipt
    payload (session, sequence number, action digest, prev-link);
  * the closing -- one signature per witness per session;
  * gate-side reconciliation -- verifying every receipt and closing under the
    registry-pinned keys and checking the 1..n_j sequence, the trace binding
    and the mediated-action rule (assurance.witness.reconcile).

Everything is measured in-process on the reference (Python) witnesses over
the same three-witness deployment the omission suite uses, so the numbers are
an upper bound on protocol overhead rather than a network cost model. Timings
are platform-dependent; the platform is recorded in the output and quoted by
the manuscript macro next to the numbers, so a re-run on another machine
cannot leave a stale platform label behind.

Output: results/witness_overhead.json (read by scripts/generate_paper_pdf.py).
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.crypto import hash_sha256                      # noqa: E402
from assurance.evidence import ExecutionTraceRecord            # noqa: E402
from assurance.witness import Witness, issue_session_credential, reconcile  # noqa: E402
from benchmark.omission_vectors import MEDIATES, _witness_of   # noqa: E402

ACTION_COUNTS = (30, 300, 3000)


def _cpu_model() -> str:
    try:
        if sys.platform == "darwin":
            import subprocess
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, check=True, timeout=5).stdout.strip()
            return out or "unknown"
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _traces(session: str, n: int) -> List[ExecutionTraceRecord]:
    kinds = ["execute_read_only_query", "process_ledger_transfer", "collect_table_stats",
             "spawn_shell_subprocess", "fetch_fx_rate", "verify_schema_lock"]
    return [ExecutionTraceRecord(trace_id=f"TR-{session[:6]}-{i:05d}", agent_id="ops-agent-v1",
                                 action=kinds[i % len(kinds)], status="SUCCESS",
                                 duration_ms=float(4 + i % 7),
                                 output_hash=hash_sha256(f"{session}:{i}"))
            for i in range(n)]


def _one_run(n: int) -> Dict[str, Any]:
    witnesses = {w: Witness(w, mediates=m) for w, m in MEDIATES.items()}
    session = f"sess-bench-{n}"
    cred = issue_session_credential(f"release-bench-{n}", session_id=session)
    traces = _traces(session, n)

    t0 = time.perf_counter()
    receipts = [witnesses[_witness_of(t)].observe(cred, t) for t in traces]
    t1 = time.perf_counter()
    closings = [w.close(cred) for w in witnesses.values()]
    t2 = time.perf_counter()

    registry = {wid: w.public_key_b64 for wid, w in witnesses.items()}
    mediated = {wid: set(w.mediates) for wid, w in witnesses.items()}
    trace_dicts = [{k: v for k, v in asdict(t).items() if k != "raw_payload"} for t in traces]
    receipt_dicts = [r.to_dict() for r in receipts]
    closing_dicts = [c.to_dict() for c in closings]

    t3 = time.perf_counter()
    ok, violations, _detail = reconcile(traces=trace_dicts, receipts=receipt_dicts,
                                        closings=closing_dicts, witness_registry=registry,
                                        session_id=session, require_witness=True,
                                        mediated_actions=mediated, expected_session_id=session)
    t4 = time.perf_counter()
    if not ok:
        raise RuntimeError(f"honest reconciliation failed: {violations}")

    receipt_bytes = statistics.mean(len(json.dumps(r, separators=(",", ":"), sort_keys=True))
                                    for r in receipt_dicts)
    return {
        "actions": n,
        "witnesses": len(witnesses),
        "issue_us_per_receipt": (t1 - t0) / n * 1e6,
        "close_us_per_witness": (t2 - t1) / len(witnesses) * 1e6,
        "reconcile_ms": (t4 - t3) * 1e3,
        "reconcile_us_per_action": (t4 - t3) / n * 1e6,
        "receipt_bytes": receipt_bytes,
        "closing_bytes": statistics.mean(len(json.dumps(c, separators=(",", ":"), sort_keys=True))
                                         for c in closing_dicts),
    }


def measure(repeats: int = 5) -> Dict[str, Any]:
    rows = []
    for n in ACTION_COUNTS:
        runs = [_one_run(n) for _ in range(repeats)]
        agg: Dict[str, Any] = {"actions": n, "witnesses": runs[0]["witnesses"],
                               "receipt_bytes": round(runs[0]["receipt_bytes"]),
                               "closing_bytes": round(runs[0]["closing_bytes"])}
        for key in ("issue_us_per_receipt", "close_us_per_witness", "reconcile_ms",
                    "reconcile_us_per_action"):
            vals = [r[key] for r in runs]
            agg[key] = round(statistics.mean(vals), 3)
            agg[key + "_std"] = round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0
        rows.append(agg)
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {"python_version": sys.version.split()[0],
                     "logical_cores": os.cpu_count(), "cpu_model": _cpu_model()},
        "repeats": repeats,
        "note": ("In-process reference witnesses (assurance.witness.Witness), three witnesses, "
                 "actions round-robin over six mediated action types; receipt issuance is one "
                 "Ed25519 signature, reconciliation verifies every receipt and closing under the "
                 "registry-pinned keys (assurance.witness.reconcile). No network cost is modelled."),
        "rows": rows,
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()
    res = measure(max(1, args.repeats))
    out = Path(__file__).parent.parent / "results" / "witness_overhead.json"
    out.write_text(json.dumps(res, indent=2))
    for r in res["rows"]:
        print(f"  |T|={r['actions']:5d}  issue {r['issue_us_per_receipt']:7.1f} us/receipt  "
              f"close {r['close_us_per_witness']:7.1f} us/witness  "
              f"reconcile {r['reconcile_ms']:8.2f} ms ({r['reconcile_us_per_action']:.1f} us/action)  "
              f"receipt {r['receipt_bytes']} B")
    print(f"[+] {out} ({res['platform']['cpu_model']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
