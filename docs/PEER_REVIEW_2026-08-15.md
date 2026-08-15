# Adversarial Peer Review — 2026-08-15

Acting reviewer: hostile PC member, USENIX Security standards. Scope: the
science (construction, proofs, evaluation), not formatting.

## Summary

The paper proposes Merkle-attested, Ed25519-signed release evidence with a
fail-closed policy gate and a 12-vector adversarial evaluation. The system
engineering is clean, the evaluation is honest about baselines, and prior
artifacts (registry-enforced key trust, fail-closed parsing) hold up under
attack. However, the core cryptographic construction does not support the
paper's soundness theorem in two concrete ways, both demonstrable.

## Major findings (each independently rejection-grade)

### M1 — Sparse inclusion proofs are unsound: internal nodes verify as leaves

Claim under attack: Definition 2 (Merkle Trace Inclusion Soundness) and
Theorem 1, Game 2, which bound forgery by SHA-256 collision resistance alone.

Demonstrated (this repository, `assurance/crypto.py`):

- Build a 16-leaf tree. Take the level-1 *internal* node digest covering
  leaves 4–5, present it as a "leaf", and supply the path from level 1
  upward (one shorter than the honest proof).
- `verify_merkle_proof(internal_node, shortened_path, root)` returns
  **True**. No collision is needed; this is the classic Merkle
  leaf/internal ambiguity (CVE-2012-2459 family).

Impact: the gate recomputes the full tree, so *today's* gate decision is
unaffected — but the paper's actual claims for sparse proofs are third-party
audit claims ("store lightweight inclusion proofs on-chain or in immutable
ledger databases", §7; §6.3 audit-latency results). A prover can "prove" any
internal digest is a trace leaf. `verify_merkle_proof` also re-hashes inputs
shorter than 64 hex chars (`len(leaf_hash) != 64` branch), a second ambiguity
in the same function.

Required fix: bind proofs to tree geometry — verify `len(proof)` equals the
depth committed with the root (derivable from the signed
`execution_traces_count`), and restate Game 2 with that assumption. Definition
2 must quantify over leaves of a committed-size tree.

### M2 — The signed trace count is never enforced

The signature covers `execution_traces_count`, but the gate never compares it
to `len(traces)`: a bundle claiming 999 traces with 5 present is **APPROVED**
(demonstrated). Auditors binding proofs to the signed count (the M1 fix) need
the gate itself to enforce that binding. Add the count check + regression
test.

### M3 — Blinding tag truncates a 256-bit HMAC to 64 bits

`blind_payload` emits `BLINDED-` + 16 hex chars. The paper's
indistinguishability claim (Definition 3) is stated with a 256-bit salt, but
the tag carries 64 bits: payload-aliasing collisions become likely at ~2^32
blinded records, undermining audit uniqueness the Merkle tree is supposed to
provide. Use the full digest (or state and justify the tag length in the
text). Fix: 64-hex (256-bit) tag; update §3.2 formula and property tests.

## Minor findings

- Table 4 (capability map) lists V10 under both A2 and A5.
- §3.2's formula hashes `P_i` ("raw output payload") while the implementation
  HMACs the existing output-hash string; harmless but imprecise — state that
  blinding applies to the trace's output hash.
- `_NONCE_TIMESTAMPS` is process-local module state; replay protection resets
  on restart. Disclosed only implicitly via the validity-window discussion —
  one sentence in Limitations would close it.

## What survives attack (credit where due)

Trusted-key registry (attacker key: rejected; spoofed key_id: rejected);
fail-closed on malformed input (hypothesis-verified); canonical-JSON signature
binding; the 12/12 block rate with the honest V3; executed OPA baseline;
numeric macros + drift gate.

## Verdict as submitted

Reject, solely on M1–M3: the theorem is stronger than the construction. All
three are fixable without changing any measured result (gate decisions and
benchmarks are unaffected by depth-binding and tag length), after which the
paper's claims and implementation would match.


## Resolution (same day)

- M1 fixed: `verify_merkle_proof` accepts `expected_depth`; auditors derive it
  from the signed trace count via `expected_tree_depth(n)`. The demonstrated
  attack (internal node, shortened path) now fails; honest proofs verify.
  Definition 2 and Game 2 restated with the committed-depth assumption.
- M2 fixed: the policy engine enforces `execution_traces_count == len(traces)`
  (signed lies now BLOCKED); regression test included.
- M3 fixed: blinding emits the full 256-bit HMAC digest; §3.2 formula and
  property tests updated; benchmark re-run (per-record cost unchanged at the
  reported precision).
- Minors fixed: capability table V10 de-duplicated; blinding prose states it
  applies to the trace output digest; nonce-state process-locality disclosed
  in Limitations.
- Post-fix state: 34 tests pass; mypy/semgrep clean; 12/12 tamper block rate
  unchanged; gates 0 BLOCKER / 5 MAJOR (known citation coverage gaps).
