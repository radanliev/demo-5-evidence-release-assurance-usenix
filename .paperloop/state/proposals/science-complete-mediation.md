# science.complete_mediation: trust binding and trace completeness

## Finding

The audit reports approval of an attacker-generated signing key and an empty trace bundle that claims three traces, contradicting the fail-closed claim for unauthenticated evidence and modified histories.

## Correct claim

The current security guarantee is unsupported until the policy independently binds trusted signers and validates declared trace count against the submitted trace set.

## Exact proposed diff

```diff
- The release gate enforces a strict fail-closed guarantee: any evidence payload that is unsigned, tampered, replayed, expired, revoked, or non-compliant with policy constraints is rejected.
+ [Replace with a human-approved, implementation-validated security claim after trusted-key binding and trace-count validation are added.]
```

## Evidence needed

Implementation changes enforcing an independent trusted-key or issuer allowlist and trace-count/empty-root validation, with regression vectors demonstrating both reported bypasses are rejected.
