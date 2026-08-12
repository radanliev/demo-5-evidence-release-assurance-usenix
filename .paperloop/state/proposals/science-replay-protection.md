# science.replay_protection: durable nonce enforcement

## Finding

The manuscript claims replayed evidence is rejected, but the deployable verifier accepts no durable nonce store and does not record a nonce after an approval. The current V4 result pre-populates benchmark-supplied state rather than exercising a second production gate invocation.

## Correct claim

The replay-protection claim and its V4 attribution are unsupported until replay state is atomically persisted across gate invocations and evaluated through the production entry point.

## Exact proposed diff

```diff
- \item \textbf{V4 (Replayed Nonce)}: Replayed nonces are identified against the verifier memory cache and rejected.
+ [Replace with a human-approved statement after an atomic durable replay store, expiry behavior, and a two-invocation production-gate evaluation are implemented.]
```

## Evidence needed

An implementation that commits a nonce only after approval, defines expiry and failure behavior, and shares durable state across gate invocations; a regression test that submits the same fresh bundle twice through `evaluate_release_gate`; and a versioned result artifact for that evaluation.
