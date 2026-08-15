# Custom semgrep rules

Run with `semgrep --config semgrep/ assurance/`.

- `verifier-trusts-payload-supplied-key.yml` — flags cryptographic
  verification that uses key material taken from the object being verified.
  Written after the 2026-08 audit found the release gate authenticating
  bundles with attacker-embedded public keys (fixed in 98fc6f1); it fires on
  the pre-fix `policy.py` and on any regression of that shape. Verifiers must
  resolve keys from a trusted registry (governance/trusted_keys.yaml), never
  from the payload under verification.
