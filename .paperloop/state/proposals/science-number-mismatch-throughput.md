# Science Proposal: Update Throughput Benchmark Metric

**Finding ID:** `20076b110c1b9844` (`science.number_mismatch`)  
**File:** `docs/usenix_paper_manuscript.tex` (Line 59 & Line 255)  

## Description
The manuscript reports 8-worker parallel verifier throughput as `5,883.86 operations/second`. The latest empirical execution of `scripts/run_release_benchmark.py` (timestamped `2026-08-12T19:23:47Z`) recorded `5,841.27 ops/sec` in `results/benchmark_summary.json::parallel_throughput.workers_8.throughput_ops_sec`.

## Proposed Diff

```diff
--- a/docs/usenix_paper_manuscript.tex
+++ b/docs/usenix_paper_manuscript.tex
@@ -59,1 +59,1 @@
-while processing policy gate evaluations at up to 5,883.86 operations/second across 8 parallel cores
+while processing policy gate evaluations at up to 5,841.27 operations/second across 8 parallel cores
@@ -255,1 +255,1 @@
-Figure~\ref{fig:throughput} demonstrates linear throughput scaling up to 5,883.86 operations/second on 8 cores.
+Figure~\ref{fig:throughput} demonstrates linear throughput scaling up to 5,841.27 operations/second on 8 cores.
```

## Required Decision
Approve updating the throughput figure from `5,883.86` to `5,841.27 ops/sec` (or rounding to `5,841 ops/sec`) to reflect the latest benchmark artifact.
