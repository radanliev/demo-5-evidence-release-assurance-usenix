# Security Governance Rule

## Fail-Closed Release Policy Gates & Attestation Requirements

1. **Mandatory Fail-Closed Policy Enforcement**:
   - Any unauthenticated, un-signed, or tampered evidence bundle MUST be rejected with exit code 1 (`BLOCKED`).
   - Default release gate policy decision MUST evaluate to `BLOCKED` unless all verification conditions pass.

2. **Cryptographic Attestation Standards**:
   - All evidence digests MUST use SHA-256 binary Merkle tree roots ($R_M$).
   - Digital signatures MUST use Ed25519 asymmetric cryptography over canonicalized JSON payloads.
   - Evidence timestamps MUST strictly satisfy freshness window $\Delta T_{\text{max}} = 3,600\text{ s}$ with maximum clock skew $\delta_{\text{skew}} = 30\text{ s}$.

3. **Zero-Trust Key Isolation & Governance**:
   - Key Revocation Lists ($\mathcal{K}_{\text{rev}}$) MUST be evaluated on every release gate verification.
   - Keys listed in $\mathcal{K}_{\text{rev}}$ or failing Cloud KMS ARN boundary pattern matching MUST trigger immediate fail-closed rejection.
   - Nonces MUST be verified against the stateful memory cache $N_{\text{seen}}$ to prevent replay attacks.
