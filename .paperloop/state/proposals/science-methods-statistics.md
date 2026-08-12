# science.methods_statistics: repeated-run claim

## Finding

The manuscript reports means across 1,000 runs and standard-error bounds, while the benchmark records a single timing or batch per configuration.

## Correct claim

The stated mean and standard-error claims are unsupported by the current artifact.

## Exact proposed diff

```diff
- Reported metrics represent mean values across 1,000 runs with standard error bounds $\pm 0.05\text{ ms}$.
+ [Replace with a human-approved repeated-run protocol and reported uncertainty, or describe the measurements as single-run observations.]
```

## Evidence needed

Per-run samples, warm-up and exclusion policy, environment/load metadata, and an aggregation script producing the reported statistics.
