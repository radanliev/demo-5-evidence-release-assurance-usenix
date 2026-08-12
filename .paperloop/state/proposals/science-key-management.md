# science.key_management: signer authority and KMS binding

## Finding

The manuscript claims Ed25519, KMS-rooted, multi-signature assurance, while the accepted policy permits HMAC-SHA256 with a source-embedded default symmetric secret and requires neither a trusted key nor a KMS identity.

## Correct claim

The claimed asymmetric, KMS-rooted signer authority is unsupported by the current policy and verifier.

## Exact proposed diff

```diff
- EviAssure introduces an evidence-backed release assurance architecture that replaces informal release signals with cryptographically authenticated Evidence Bundles backed by Merkle inclusion proofs, timestamp freshness windows, Ed25519 digital signatures, KMS key ARNs, and SLSA v1.0 provenance envelopes.
+ [Replace with a human-approved statement after policy-pinned Ed25519 trusted keys and independently verified KMS identities are enforced, or explicitly scope the system to its symmetric-key demonstration mode.]
```

## Evidence needed

Either a policy and verifier that reject HMAC and unknown keys while binding key IDs, public keys, and KMS identities to governance-controlled trust roots, or a human-approved scope reduction. Both paths require unknown-key, key-compromise, and KMS-binding regression results.
