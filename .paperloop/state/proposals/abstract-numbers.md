# EviAssure abstract: three numbers, three different problems

Source of truth: `results/benchmark_summary.json`, timestamp `2026-08-11T22:54:26Z`.
All three claims are in the abstract, line 54 of `docs/usenix_paper_manuscript.tex`.

## 1. Throughput — the paper is 2.2% too high

> "processing policy gate evaluations at up to **5,981 operations/second** across 8 parallel cores"

```
parallel_throughput.workers_1  = 1460.14 ops/sec
parallel_throughput.workers_2  = 2580.12
parallel_throughput.workers_4  = 4189.77
parallel_throughput.workers_8  = 5850.09   <- the 8-core figure
```

5,981 appears nowhere in the artifact. Throughput rises monotonically with
worker count, so 5850.09 is also the maximum across *every* configuration — the
"up to" phrasing cannot rescue it either.

**Correct value: 5,850 ops/sec.** Change `5,981` to `5,850`.

## 2. Packaging overhead — right number, wrong row

> "for **N=100,000** execution traces ... a negligible packaging overhead of **0.123%**"

```
merkle_scaling[2]  trace_count=1000     packaging_overhead_pct = 0.1284
merkle_scaling[3]  trace_count=10000    packaging_overhead_pct = 0.1217
merkle_scaling[4]  trace_count=100000   packaging_overhead_pct = 0.1186   <- N=100,000
```

The sentence claims N=100,000, but 0.123 is closest to the **N=10,000** row
(0.1217). The actual N=100,000 overhead is **0.1186%**.

This is the more serious of the two: not a stale value but a figure lifted from
a different experimental condition than the sentence describes. A reviewer
checking the artifact will find the mismatch immediately.

**Correct value: 0.119%** for the N=100,000 claim. (0.1217 rounds to 0.122, not
0.123, so 0.123 does not match that row either.)

## 3. Merkle build time — unsourced

> "scaling Merkle tree construction for N=100,000 execution traces in under **43.30 ± 0.45 ms**"

```
merkle_scaling[4]  trace_count=100000
                   merkle_tree_build_ms   = 39.776
                   packaging_latency_ms   = 177.863
```

Neither 43.30 nor the ±0.45 appears anywhere in the artifact. The claim "under
43.30 ms" is *technically true* of the 39.776 ms build time, but the specific
value and its uncertainty have no recorded source, and the benchmark stores a
single measurement rather than a distribution — so a ± interval cannot be
derived from this file at all.

Either cite the measured **39.8 ms**, or re-run with repetitions and report a
real mean ± SD. Do not keep a ± on a single-run measurement.

## Recommended edit

```
-  at up to \textbf{5,981 operations/second} across 8 parallel cores, scaling
-  Merkle tree construction for $N=100,000$ execution traces in under
-  $43.30 \pm 0.45\text{ ms}$ (representing a negligible packaging overhead of
-  **0.123%**)
+  at up to \textbf{5,850 operations/second} across 8 parallel cores, scaling
+  Merkle tree construction for $N=100,000$ execution traces in
+  $39.8\text{ ms}$ (a packaging overhead of \textbf{0.119\%})
```

Note the abstract also uses Markdown `**0.123%**` inside LaTeX, which will not
render as bold — it prints the asterisks literally. Worth fixing regardless.

None of this changes the paper's argument: overhead is still negligible and
throughput still scales near-linearly to 8 cores. It changes only whether the
numbers survive a reviewer opening the artifact.
