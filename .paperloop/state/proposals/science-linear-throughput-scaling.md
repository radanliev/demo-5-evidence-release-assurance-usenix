# science.claim: linear throughput scaling

## Finding

`docs/usenix_paper_manuscript.tex:255` calls the 1--8 worker throughput trend linear, although the plotted values rise from 1,387 to 5,883 ops/s (4.24x at 8x workers).

## Correct claim

The available values support a 4.24x measured speedup from one to eight workers, not linear scaling.

## Exact proposed diff

```diff
- Figure~\ref{fig:throughput} demonstrates linear throughput scaling up to 5,883.86 operations/second on 8 cores.
+ Figure~\ref{fig:throughput} shows a measured 4.24x throughput increase from one to eight workers, reaching 5,883.86 operations/second on 8 cores.
```

## Evidence needed

Preserved repeated-run samples for each worker count, plus a predeclared speedup calculation and uncertainty intervals.
