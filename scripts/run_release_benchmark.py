#!/usr/bin/env python3
"""
Empirical Release Assurance Benchmark Runner for USENIX Security 2027.
Measures packaging latency, multi-process verifier throughput, Merkle scaling,
sparse inclusion proof costs, blinding overhead, UI attestation hashing costs,
and 12-vector tamper resilience.
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
from assurance.crypto import hash_sha256, build_merkle_tree, generate_merkle_proof, verify_merkle_proof
from assurance.policy import ReleasePolicyEngine
from benchmark.tamper_vectors import generate_tampered_evidence_suite


def _eval_worker(task: Tuple[str, Dict[str, Any]]) -> bool:
    policy_path = task[0]
    evidence_dict = task[1]
    engine = ReleasePolicyEngine.from_yaml(policy_path)
    passed, _, _ = engine.evaluate(evidence_dict)
    return passed


def measure_merkle_scaling(repeats: int = 5) -> List[Dict[str, Any]]:
    """Packaging latency and Merkle build time per trace count.

    Each point is the mean over `repeats` runs; the standard deviation across
    runs is recorded alongside so the paper can report dispersion honestly.
    """
    results = []
    trace_counts = [10, 100, 1000, 10000, 100000, 1000000]

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
        leaf_hashes = [t.to_hash() for t in traces]

        pkg_times, merkle_times, sizes = [], [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            bundle = create_evidence_pack(traces=traces, use_ed25519=True, signed=True)
            pkg_times.append((time.perf_counter() - t0) * 1000.0)

            t1 = time.perf_counter()
            _, levels = build_merkle_tree(leaf_hashes)
            merkle_times.append((time.perf_counter() - t1) * 1000.0)

            sizes.append(len(json.dumps(bundle.to_dict())) / 1024.0)

        t_pkg = statistics.mean(pkg_times)
        t_merkle = statistics.mean(merkle_times)

        results.append({
            "trace_count": count,
            "packaging_latency_ms": round(t_pkg, 3),
            "packaging_latency_ms_std": round(statistics.stdev(pkg_times), 3) if repeats > 1 else 0.0,
            "merkle_tree_build_ms": round(t_merkle, 3),
            "merkle_tree_build_ms_std": round(statistics.stdev(merkle_times), 3) if repeats > 1 else 0.0,
            "merkle_tree_depth": len(levels),
            "bundle_size_kb": round(statistics.mean(sizes), 2),
            "packaging_overhead_pct": round((t_pkg / (count * 1.5)) * 100.0, 4)
        })

    return results


def measure_parallel_throughput(repeats: int = 5) -> Dict[str, Any]:
    policy_path = str(Path(__file__).parent.parent / "governance" / "release_policy.yaml")
    bundle = create_evidence_pack(use_ed25519=True, signed=True)
    b_dict = bundle.to_dict()

    workers_list = [1, 2, 4, 8, 16]
    total_evals = 1000
    parallel_results = {}

    for num_workers in workers_list:
        tasks = [(policy_path, b_dict) for _ in range(total_evals)]
        rates = []
        elapsed_s = 0.0
        for _ in range(repeats):
            t0 = time.perf_counter()

            with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                list(executor.map(_eval_worker, tasks))

            elapsed_s = time.perf_counter() - t0
            rates.append(total_evals / elapsed_s if elapsed_s > 0 else 0.0)

        ops_per_sec = statistics.mean(rates)

        parallel_results[f"workers_{num_workers}"] = {
            "num_workers": num_workers,
            "total_evaluations": total_evals,
            "elapsed_seconds": round(elapsed_s, 4),
            "throughput_ops_sec": round(ops_per_sec, 2),
            "throughput_ops_sec_std": round(statistics.stdev(rates), 2) if repeats > 1 else 0.0,
            "mean_latency_per_eval_ms": round((elapsed_s / total_evals) * 1000.0, 4)
        }

    return parallel_results


def measure_sparse_proof(n_traces: int = 1_000_000, repeats: int = 5) -> Dict[str, Any]:
    """Sparse Merkle inclusion proof generation/verification cost at scale.

    Proof sizes and node counts are deterministic (fixed tree geometry); the
    generation and verification latencies are means over `repeats` runs.
    """
    traces = [
        ExecutionTraceRecord(
            trace_id=f"TR-{i:06d}", agent_id="agent-worker", action="execute_step",
            status="SUCCESS", duration_ms=1.5, output_hash=hash_sha256(f"OUTPUT_{i}")
        )
        for i in range(n_traces)
    ]
    leaves = [t.to_hash() for t in traces]
    root, levels = build_merkle_tree(leaves)

    gen_ms, ver_ms, sizes_kb = [], [], []
    for _ in range(repeats):
        for idx in (0, n_traces // 2, n_traces - 1):
            t0 = time.perf_counter()
            proof = generate_merkle_proof(idx, levels)
            gen_ms.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            ok = verify_merkle_proof(leaves[idx], proof, root,
                                     expected_depth=max(len(levels) - 1, 0))
            ver_ms.append((time.perf_counter() - t0) * 1000.0)
            assert ok, "inclusion proof failed verification"

            sizes_kb.append(len(json.dumps(proof)) / 1024.0)

    return {
        "trace_count": n_traces,
        "tree_depth": len(levels),
        "proof_nodes": len(proof),
        "proof_size_kb": round(statistics.mean(sizes_kb), 3),
        "gen_latency_ms": round(statistics.mean(gen_ms), 4),
        "gen_latency_ms_std": round(statistics.stdev(gen_ms), 4) if repeats > 1 else 0.0,
        "verify_latency_ms": round(statistics.mean(ver_ms), 4),
        "verify_latency_ms_std": round(statistics.stdev(ver_ms), 4) if repeats > 1 else 0.0,
        "repeats": repeats,
    }


def measure_blinding_overhead(n_traces: int = 10_000, repeats: int = 5) -> Dict[str, Any]:
    """Per-record cost of salted HMAC parameter blinding (blind_payload)."""
    salt = "s" * 32
    records = [
        ExecutionTraceRecord(
            trace_id=f"T{i}", agent_id="agent-worker", action="execute_step",
            status="SUCCESS", duration_ms=1.0, output_hash=hash_sha256(f"PII_PAYLOAD_{i}")
        )
        for i in range(n_traces)
    ]
    totals = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        blinded = [r.blind_payload(salt) for r in records]
        totals.append((time.perf_counter() - t0) * 1000.0)
        assert all(r.output_hash.startswith("BLINDED-") for r in blinded)

    total_ms = statistics.mean(totals)

    return {
        "trace_count": n_traces,
        "total_ms": round(total_ms, 2),
        "total_ms_std": round(statistics.stdev(totals), 2) if repeats > 1 else 0.0,
        "per_record_ms": round(total_ms / n_traces, 5),
        "repeats": repeats,
    }


def measure_ui_attestation_hashing(n_steps: int = 1_000, repeats: int = 5) -> Dict[str, Any]:
    """Cost of the DOM serialization digest and screenshot digest per UI step.

    Mirrors specimens/web_app_runner.py: deterministic HTML serialization is
    SHA-256 hashed for DOM state, and the screenshot digest is computed over
    the canonical render reference string.
    """
    dom_steps, shot_steps = [], []
    for _ in range(repeats):
        t0 = time.perf_counter()
        for i in range(n_steps):
            dom = f"<html><body><div id='app'>Dashboard Loaded for https://app/{i}</div></body></html>"
            hash_sha256(dom)
        dom_steps.append(((time.perf_counter() - t0) * 1000.0) / n_steps)

        t0 = time.perf_counter()
        for i in range(n_steps):
            hash_sha256(f"SCREENSHOT_PNG_CLICK_btn-{i}")
        shot_steps.append(((time.perf_counter() - t0) * 1000.0) / n_steps)

    return {
        "ui_steps": n_steps,
        "dom_hash_ms_per_step": round(statistics.mean(dom_steps), 5),
        "dom_hash_ms_per_step_std": round(statistics.stdev(dom_steps), 5) if repeats > 1 else 0.0,
        "screenshot_digest_ms_per_step": round(statistics.mean(shot_steps), 5),
        "screenshot_digest_ms_per_step_std": round(statistics.stdev(shot_steps), 5) if repeats > 1 else 0.0,
        "repeats": repeats,
    }


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
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5,
                        help="number of repetition runs for timed measurements "
                             "(deterministic checks such as the tamper suite run once)")
    args = parser.parse_args()
    repeats = max(1, args.repeats)

    print(f"=== Running USENIX Security Release Assurance Empirical Benchmark "
          f"(repeats={repeats}) ===")

    print("\n1. Measuring Merkle Tree & Packaging Scaling (up to N=100,000)...")
    merkle_scaling = measure_merkle_scaling(repeats)
    for row in merkle_scaling:
        print(f"   Traces: {row['trace_count']:6d} | Pkg Latency: {row['packaging_latency_ms']:7.2f} ms | Merkle Build: {row['merkle_tree_build_ms']:6.2f} ms | Bundle: {row['bundle_size_kb']:8.2f} KB | Overhead: {row['packaging_overhead_pct']:.4f}%")

    print("\n2. Measuring Multi-Process Parallel Verifier Throughput...")
    parallel_throughput = measure_parallel_throughput(repeats)
    for k, v in parallel_throughput.items():
        print(f"   Workers: {v['num_workers']:2d} | Total Evals: {v['total_evaluations']} | Time: {v['elapsed_seconds']}s | Throughput: {v['throughput_ops_sec']} ops/sec")

    print("\n3. Measuring Sparse Merkle Inclusion Proof Costs (N=1,000,000)...")
    sparse_proof = measure_sparse_proof(repeats=repeats)

    print("\n4. Measuring Salted Parameter Blinding Overhead (N=10,000)...")
    blinding = measure_blinding_overhead(repeats=repeats)

    print("\n5. Measuring Browser UI Attestation Hashing Costs (1,000 steps)...")
    ui_hashing = measure_ui_attestation_hashing(repeats=repeats)

    print("\n6. Evaluating 12-Vector Adversarial Release Tamper Resilience Suite...")
    tamper_res = evaluate_tamper_resilience()
    print(f"   Fail-Closed Block Rate: {tamper_res['fail_closed_block_rate_pct']}% ({tamper_res['blocked_vectors']}/{tamper_res['total_vectors']} blocked)")
    for v in tamper_res["vector_details"]:
        status_str = "PASS (BLOCKED)" if v["blocked"] else "FAIL (UNBLOCKED)"
        print(f"   [{v['id']:3s}] {v['name']:45s} -> {status_str}")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "python_version": sys.version.split()[0],
            "logical_cores": __import__("os").cpu_count(),
        },
        "benchmark_params": {
            "synthetic_step_duration_ms": 1.5,
            "throughput_evals_per_worker": 1000,
            "repeats": repeats,
        },
        "merkle_scaling": merkle_scaling,
        "parallel_throughput": parallel_throughput,
        "sparse_proof": sparse_proof,
        "blinding_overhead": blinding,
        "ui_attestation_hashing": ui_hashing,
        "tamper_resilience": tamper_res
    }

    out_file = Path(__file__).parent.parent / "results" / "benchmark_summary.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Empirical benchmark summary saved to: {out_file}")


if __name__ == "__main__":
    main()
