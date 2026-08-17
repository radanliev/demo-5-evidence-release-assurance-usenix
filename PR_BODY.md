## What this is

Two rounds of adversarial peer review of the USENIX Security '27 submission,
both reproduced against the artifact before any change was made.

`main` is a direct ancestor of this branch (52 ahead, 0 behind), so the merge is
a fast-forward with no conflict surface. This is a PR rather than a direct merge
because `ci.yml` only triggers on `main`/`master` — nothing has run CI against
these commits yet, and a broken `main` is worse than a red PR for a repo that
becomes the published review artifact.

## Round 3 — claims contradicted by our own code

Each was reproduced before being fixed, and each has a regression test.

| Finding | Fix |
|---|---|
| Replay protection was a no-op in the shipped CLI: the same signed bundle was APPROVED on every submission | missing replay state is now a violation; the CLI persists a nonce ledger |
| `--format json` exited 0 on BLOCKED — fail-open in exactly the mode the GitHub Action uses | exit code set on every output path |
| `require_trusted_key=False` verified against the key inside the submitted bundle — a complete auth bypass the 13-vector suite missed | bundle-supplied keys are never consulted |
| `verify_merkle_proof` made its depth bound optional, and a `len(x)!=64` heuristic accepted any 64-char string as a leaf digest | depth required; leaves must be explicit digests |
| Merkle nodes claimed domain separation and length-extension resistance without either | RFC 6962 `0x00`/`0x01` prefixes |
| `references.bib` carried two incorrect author lists — the CFP names this as misconduct grounds | corrected against Crossref/arXiv; Ed25519 EUF-CMA now cites Brendel et al. |

Evaluation rebuilt: executed in-toto/DSSE and TUF baselines replace one-line
presence-check models; differential wire fuzzing with clean controls replaces a
campaign in which every mutation touched a signed field; the anomaly detector no
longer shares its keyword list with the corpus generator. Wilson intervals
throughout. The new fuzzer found a real bug — the duplicate-key detector counted
keys globally, rejecting every legitimate multi-trace bundle.

## Round 4 — the contribution the earlier rounds left on the table

**Witnessed Trace Completeness.** Witnesses issue receipts carrying a monotonic
per-session sequence number plus a signed closing count; the gate reconciles
rather than verifies. Omission now requires a witness-key forgery instead of
collector control. Two theorems: WTC soundness by reduction, and a separation
result showing no verifier that is a pure function of one submitted document can
achieve replay-freedom or witnessed completeness.

New omission attack class O1–O6, with an honest-execution control every system
must approve:

| System | Omissions detected |
|---|---|
| in-toto/DSSE | 0/6 |
| TUF | 0/6 |
| Per-issuer hash chaining (AAS-1 style) | 1/6 |
| Per-action receipts (2026 schemes) | 2/6 |
| EviAssure *without* reconciliation | 0/6 |
| **EviAssure + WTC** | **6/6** |

## Failures kept rather than removed

V16 cross-replica nonce replay is unblocked; held-out inspection recalls 0/25
stealth anomalies; the corpus declares itself synthetic — no LLM agent is
executed anywhere in this work.

## Verification

- 70 tests pass under CI's exact dependency set (`pyyaml cryptography ".[dev]"`)
- `semgrep scan --config semgrep/ --error assurance/ scripts/` — 0 findings
- `python scripts/verify_release_gate.py` — exit 0
- manuscript builds with 0 undefined references and 0 overfull boxes

## Before merging

Timing macros are untouched and must be regenerated on the author platform
(Apple M4 Max / Python 3.14.7); `run_security_eval.py --require-executed` should
be re-run with `opa` on PATH. Both change committed numbers.
