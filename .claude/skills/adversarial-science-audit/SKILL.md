---
name: adversarial-science-audit
description: Checklist for auditing a paper's empirical claims by re-derivation and active attack, not by reading — numbers, baselines, attack vectors, security proofs, and test honesty
---

# Adversarial Science Audit

Use when asked to verify the science of a paper whose code and data sit in the
repo. The premise: **every claim is false until re-derived from the artifact.**
Two full audits of the EviAssure paper found fabricated statistics, fabricated
references, wrong units, an unmeasured methodology, and an authentication
bypass — none caught by the paper's own review loop.

## 1. Bind every number to an artifact

- Extract every numeral in the abstract, results, and discussion.
- For each: which file/JSON path produced it? If none — it is fabricated or
  stale. (Found this way: "±0.05 ms stderr", "0.14 ms DOM hashing", "tree
  depth 18".)
- Recompute derived values: percentages, ratios, reductions. Check units:
  `overhead%` must not divide milliseconds by nanoseconds; "99.999%
  reduction" must match `1 - (sparse_kb / full_kb)`.
- Flag non-monotone scaling: an $O(N)$ or $O(\log N)$ curve that dips at
  $N=100{,}000$ indicates cache artifacts or different hardware between data
  points.

## 2. Check the test suite for honesty

- Read the assertions, not the green checkmarks. Look for:
  - Assertions that pass on any non-empty string or dict (`assert result`)
  - Tests that catch their own exceptions and pass
  - `expected` values that are hardcoded literals instead of recomputed values
  - Tests that pass with dummy keys because the engine didn't validate
    signatures at all
  - Mocks that replace the system under test rather than its dependencies

## 3. Verify the threat model is closed

- For every attack vector the paper claims to mitigate:
  - Can an attacker bypass it by mutating a field the check doesn't cover?
  - Does the verifier check the sender's identity, or only that *some* key
    signed it?
  - Is the trusted-key registry actually consulted, or is the bundle key
    trusted? (EviAssure: the Ed25519 verifier used the public key *inside the
  submitted bundle* — attacker-signed bundles were APPROVED. The test passed
  because it tested HMAC-with-wrong-secret instead of an Ed25519 forgery.)
- **Fail-closed claims**: feed malformed input (wrong types, truncated
  structures). Crashes and exceptions must become BLOCKED verdicts — test it,
  don't assume it.
- **Vector honesty**: for each attack vector, read the code that constructs
  it. Does the implementation match its description and the paper's stated
  blocking mechanism? (Three of twelve didn't.) Is the vector near-tautological
  (tests a check the gate was written to implement)? Say so in the audit.
- **Key/secret hygiene**: per-process random demo keys, hardcoded shared
  secrets, and "demo" credentials committed in source all invalidate
  key-management claims.

## 4. Baselines: real or modeled?

- If the paper compares against other tools, find the actual invocations.
  3-line Python re-implementations of OPA/cosign are *modeled baselines* —
  the paper must say so; otherwise the comparison numbers are fiction.
  (Caught this way: "OPA/Sigstore block 25%" was simulated, undisclosed.)

## 5. Corpus and data claims

- Count what the artifact actually contains: profiles, distinct labels,
  architectures. "50 distinct anomaly variants" was 10 types × 5 profiles.
- Gate outcomes on the corpus: run the gate over every profile and count
  APPROVED/BLOCKED yourself. A claimed 100% block rate was actually 0/50
  blocked — anomalies were semantic, and the "test" asserted nothing.
- Statistical claims: repetitions, error bars, sample sizes — verify they
  exist in the harness, not just the prose.

## 6. Proofs and formal claims

- Each game-hop assumption must correspond to an enforced check in the code
  (fixed PK, nonce memory scope, revocation). "Identically zero" style claims
  need scoping (nonce replay was only zero *within the validity window*).
- Mechanism bullets ("blocked by X") must match the implementation's actual
  rejection path.

## 7. Fix honestly

- Prefer fixing the *system* to match its claimed security properties (add
  the trusted-key registry; implement the ARN check), then re-run everything
  and confirm results still hold — report if they change.
- Add regression tests for each flaw (attacker key rejected; spoofed key_id
  rejected; malformed input fails closed). A vacuous test (`assert True`,
  unconditional counters) is itself a finding — replace with real assertions.
- Disclose what can't be fixed (modeled baselines) in the text.

Tooling now installed: `python3 -m pytest`, `semgrep` (write a rule for
verifying with payload-supplied key material), `bandit`, `mypy`, `hypothesis`
(property tests for parsers/verifiers), `mutmut` (a test suite that kills no
mutants tests nothing).
