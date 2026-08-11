#!/usr/bin/env python3
"""
Empirical Release Assurance Benchmark Runner for USENIX Security 2027.
Measures packaging latency, multi-process verifier throughput, 100K Merkle scaling, and 12-vector tamper resilience.
"""

import sys
import time
import json
import statistics
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import create_evidence_pack, ExecutionTraceRecord, DEFAULT_SECRET_KEY
from assurance.crypto import hash_sha256, build_merkle_tree
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite


def _eval_worker(task: Tuple[str, Dict[str, Any]]) -> bool:
    policy_path = task[0]
    evidence_dict = task[1]
    engine = ReleasePolicyEngine.from_yaml(policy_path)
    passed, _, _ = engine.evaluate(evidence_dict)
    return passed


def measure_merkle_scaling() -> List[Dict[str, Any]]:
    results = []
    trace_counts = [10, 100, 1000, 10000, 100000]

    for count in trace_counts:
        traces = [
            ExecutionTraceRecord(
                trace_id=f"TR-{i:06d}",
                agent_id="agent-worker",
                action="execute_step",
                status="SUCCESS",
                duration_ms=1.5,
                output_hash=hash_sha256(f"OUTPUT_{i}")
            )
            for i in range(count)
        ]

        t0 = time.perf_counter()
        bundle = create_evidence_pack(traces=traces, use_ed25519=True, signed=True)
        t_pkg = (time.perf_counter() - t0) * 1000.0

        leaf_hashes = [t.to_hash() for t in traces]
        t1 = time.perf_counter()
        root, levels = build_merkle_tree(leaf_hashes)
        t_merkle = (time.perf_counter() - t1) * 1000.0

        results.append({
            "trace_count": count,
            "packaging_latency_ms": round(t_pkg, 3),
            "merkle_tree_build_ms": round(t_merkle, 3),
            "merkle_tree_depth": len(levels),
            "bundle_size_kb": round(len(json.dumps(bundle.to_dict())) / 1024.0, 2),
            "packaging_overhead_pct": round((t_pkg / (count * 1.5)) * 100.0, 4)
        })

    return results


def measure_parallel_throughput() -> Dict[str, Any]:
    policy_path = str(Path(__file__).parent.parent / "governance" / "release_policy.yaml")
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    b_dict = bundle.to_dict()

    workers_list = [1, 2, 4, 8]
    total_evals = 1000
    parallel_results = {}

    for num_workers in workers_list:
        tasks = [(policy_path, b_dict) for _ in range(total_evals)]
        t0 = time.perf_counter()

        with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
            res = list(executor.map(_eval_worker, tasks))

        elapsed_s = time.perf_counter() - t0
        ops_per_sec = total_evals / elapsed_s if elapsed_s > 0 else 0.0

        parallel_results[f"workers_{num_workers}"] = {
            "num_workers": num_workers,
            "total_evaluations": total_evals,
            "elapsed_seconds": round(elapsed_s, 4),
            "throughput_ops_sec": round(ops_per_sec, 2),
            "mean_latency_per_eval_ms": round((elapsed_s / total_evals) * 1000.0, 4)
        }

    return parallel_results


def evaluate_tamper_resilience() -> Dict[str, Any]:
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    policy_engine = ReleasePolicyEngine.from_yaml(policy_path)
    suite = generate_tampered_evidence_suite()

    vector_results = []
    blocked_count = 0

    seen_nonces = set()

    for vector_id, meta, tampered_evidence in suite:
        test_seen_nonces = seen_nonces.copy()
        if vector_id == "V4_REPLAYED_NONCE":
            test_seen_nonces.add(tampered_evidence["nonce"])

        t0 = time.perf_counter()
        passed, violations, details = policy_engine.evaluate(
            evidence=tampered_evidence,
            seen_nonces=test_seen_nonces
        )
        eval_ms = (time.perf_counter() - t0) * 1000.0

        if not passed:
            blocked_count += 1

        vector_results.append({
            "id": meta["id"],
            "name": meta["name"],
            "category": meta["category"],
            "passed": passed,
            "blocked": not passed,
            "violations": violations,
            "eval_latency_ms": round(eval_ms, 3)
        })

    block_rate = (blocked_count / len(suite)) * 100.0

    return {
        "total_vectors": len(suite),
        "blocked_vectors": blocked_count,
        "fail_closed_block_rate_pct": round(block_rate, 2),
        "vector_details": vector_results
    }


def main():
    print("=== Running USENIX Security Release Assurance Empirical Benchmark ===")

    print("\n1. Measuring Merkle Tree & Packaging Scaling (up to N=100,000)...")
    merkle_scaling = measure_merkle_scaling()
    for row in merkle_scaling:
        print(f"   Traces: {row['trace_count']:6d} | Pkg Latency: {row['packaging_latency_ms']:7.2f} ms | Merkle Build: {row['merkle_tree_build_ms']:6.2f} ms | Bundle: {row['bundle_size_kb']:8.2f} KB | Overhead: {row['packaging_overhead_pct']:.4f}%")

    print("\n2. Measuring Multi-Process Parallel Verifier Throughput...")
    parallel_throughput = measure_parallel_throughput()
    for k, v in parallel_throughput.items():
        print(f"   Workers: {v['num_workers']:2d} | Total Evals: {v['total_evaluations']} | Time: {v['elapsed_seconds']}s | Throughput: {v['throughput_ops_sec']} ops/sec")

    print("\n3. Evaluating 12-Vector Adversarial Release Tamper Resilience Suite...")
    tamper_res = evaluate_tamper_resilience()
    print(f"   Fail-Closed Block Rate: {tamper_res['fail_closed_block_rate_pct']}% ({tamper_res['blocked_vectors']}/{tamper_res['total_vectors']} blocked)")
    for v in tamper_res["vector_details"]:
        status_str = "PASS (BLOCKED)" if v["blocked"] else "FAIL (UNBLOCKED)"
        print(f"   [{v['id']:3s}] {v['name']:45s} -> {status_str}")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "merkle_scaling": merkle_scaling,
        "parallel_throughput": parallel_throughput,
        "tamper_resilience": tamper_res
    }

    out_file = Path(__file__).parent.parent / "results" / "benchmark_summary.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Empirical benchmark summary saved to: {out_file}")


if __name__ == "__main__":
    main()
