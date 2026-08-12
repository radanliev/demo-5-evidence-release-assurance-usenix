# Science Proposal: Update Merkle Packaging Overhead Metric

**Finding ID:** `a8d2a14cade3b429` (`science.number_mismatch`)  
**File:** `docs/usenix_paper_manuscript.tex` (Line 59 & Line 245)  

## Description
The manuscript reports Merkle packaging overhead for $N=100,000$ traces as `0.1221%` (or `0.12%`). The latest run in `results/benchmark_summary.json` yields `0.1206%` for $N=100,000$ (`merkle_scaling[4].packaging_overhead_pct`) and `0.1208%` for $N=10,000$ (`merkle_scaling[3].packaging_overhead_pct`).

## Proposed Diff

```diff
--- a/docs/usenix_paper_manuscript.tex
+++ b/docs/usenix_paper_manuscript.tex
@@ -59,1 +59,1 @@
-scaling Merkle tree construction for $N=100,000$ execution traces in $39.59\text{ ms}$ (representing a packaging overhead of 0.1221\%)
+scaling Merkle tree construction for $N=100,000$ execution traces in $39.08\text{ ms}$ (representing a packaging overhead of 0.1206\%)
@@ -245,1 +245,1 @@
-Merkle tree construction scales efficiently to 100,000 traces in $39.59\text{ ms}$, representing a packaging overhead of 0.1221\%
+Merkle tree construction scales efficiently to 100,000 traces in $39.08\text{ ms}$, representing a packaging overhead of 0.1206\%
```

## Required Decision
Approve updating the packaging overhead metric to `0.1206%` (and build time to `39.08 ms`) to align with the current benchmark summary artifact.
