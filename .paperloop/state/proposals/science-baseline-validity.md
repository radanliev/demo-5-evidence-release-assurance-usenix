# science.baseline_validity: named baseline comparison

## Finding

The OPA/Sigstore comparison uses local predicate functions rather than version-pinned OPA, Kyverno, Sigstore, or Cosign installations.

## Correct claim

The available results apply only to the local illustrative predicates, not the named external systems.

## Exact proposed diff

```diff
- Figure~\ref{fig:comparative} compares EviAssure against standard CI exit code gates, OPA schema validators, and Sigstore/Cosign container gates.
+ [Relabel as illustrative local predicates, or retain named systems only after real baseline evaluations are available.]
```

## Evidence needed

Version-pinned real baseline configurations, equivalent inputs, invocation logs, and per-vector decisions.
