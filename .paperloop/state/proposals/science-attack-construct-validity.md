# science.attack_construct_validity: V10 mechanism

## Finding

V10 is described as JSON-key malleability but changes only `test_pass_pct`, so it does not test the claimed serialization mechanism.

## Correct claim

The V10 mechanism claim is unsupported by the current vector.

## Exact proposed diff

```diff
- \item \textbf{V10 (JSON Malleability)}: Canonical JSON sorting prevents parameter injection attacks.
+ [Replace with a human-approved statement after an executable serialization-malleability vector is evaluated at the signed-byte parser boundary.]
```

## Evidence needed

A specified alternate serialization or duplicate-key adversary, success criterion, and regression result against the signed-byte parser boundary.
