# science.corpus_provenance: corpus size and anomaly claims

## Finding

The manuscript claims 50 profiles, 15 anomalies, and 15/15 blocked, while the audited corpus contains five profiles and two anomalies.

## Correct claim

The correct claim is unknown until an immutable 50-profile corpus is supplied or a human approves a revision to the audited corpus counts.

## Exact proposed diff

```diff
- A 50-profile benchmark corpus ... contains 15 planted anomaly variants ... EviAssure successfully blocked 100.0\% (15/15) of anomaly trace profiles.
+ [Replace with human-approved corpus counts and per-anomaly evaluation result.]
```

## Evidence needed

A versioned corpus with 50 profiles and 15 anomaly rows, profile IDs, labels, trace inputs, and per-profile gate outputs.
