# science.technical_accuracy: Merkle root and proof size

## Finding

The manuscript calls a SHA-256 root 64 bytes and claims proofs smaller than 5 KB without a proof-size artifact.

## Correct claim

The implemented SHA-256 hexadecimal root is 64 characters representing 32 digest bytes; the proof-size bound is not established.

## Exact proposed diff

```diff
- transmitting the 64-byte root $R_M$ ... reducing transmission size to $<5\text{ KB}$.
+ transmitting the 64-character hexadecimal encoding of the 32-byte root $R_M$ ... [add a human-approved measured proof-size statement or remove the bound].
```

## Evidence needed

Proof-byte measurements and the producing command for the trace counts claimed in the paper.
