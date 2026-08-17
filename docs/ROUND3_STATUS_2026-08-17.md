# Round 3 status — 2026-08-17

Target: **USENIX Security '27 Cycle 1**. Registration **Tue 18 Aug 2026**,
paper **Tue 25 Aug 2026**, artifacts **Fri 28 Aug 2026**.

Apply with: `cd ~/Projects/demo-5-evidence-release-assurance-usenix && tar xzf ../eviassure-round3-2026-08-17.tgz`
(40 files; do it on a branch).

---

## Findings fixed

| # | Finding | Fix | Regression test |
|---|---|---|---|
| A1 | Replay protection was a no-op in the shipped CLI — the same signed bundle was APPROVED indefinitely | missing replay state is now itself a violation; `verify_release_gate.py` persists nonces to `--nonce-store` (default `.eviassure/nonce_ledger.json`) | `test_a1_replay_blocked_through_the_shipped_cli` |
| A1b | **New, found while testing A1:** `--format json` exited 0 on BLOCKED, so any pipeline reading the exit status was fail-open in the mode the GitHub Action uses | exit code set on every output path | `test_a1b_exit_code_is_set_on_every_output_path` |
| A2 | `require_trusted_key: False` redirected verification to the bundle-supplied public key — a complete authentication bypass the 13-vector suite missed | the fallback is gone; no configuration reaches verification with a non-registry key | `test_a2_*` (3 tests) + vector V14 |
| A3 | Suite claimed to "prove complete coverage without gaps" | 5 independent vectors added (V14–V18), three of which broke the code; claim replaced with what the suite actually shows | `results/security_evaluation.json` |
| A4 | Manuscript/README claimed 44 tests; suite collected 29 and was red | count is generated into `security_metrics.tex` and asserted against collection | `test_docs_consistency.py` (3 tests) |
| A5 | "tree depth 21" contradicted Definition 2's ⌈log₂N⌉=20 | one definition of depth; artifact field renamed `tree_levels` | — |
| B1 | Baselines were 1-line strawmen ("is there a signature field?") | executed in-toto/DSSE (securesystemslib) and TUF (python-tuf) baselines; status gate relabelled a floor | `benchmark/baselines.py` |
| B2 | Fuzzing campaign could not fail — every mutation touched a signed field | differential **wire-encoding** fuzzing + 20% clean controls; both outcomes reachable | found a real bug, below |
| B2b | **New, found by the new fuzzer:** duplicate-key detector counted keys globally, so any deployment supplying `raw_wire_json` rejected every multi-trace bundle | per-object counting | `test_duplicate_key_detector_is_per_object` |
| B3 | Detector's keyword list == corpus generator's plant list; 50/50 recall was a tautology | detector fitted on clean profiles only; 5 **stealth** anomaly classes added that reuse clean vocabulary | `test_corpus_eval_json.py` now *fails* if recall is 100% |
| B4 | §5 titled "Real-World Case Study" containing only simulations | retitled; "no LLM agent is executed anywhere in this paper" stated in the body | — |
| B5 | Packaging "overhead" divided a constant by 1.5 ms × N; throughput measured on 3-trace bundles but juxtaposed with N=10⁶ | overhead metric withdrawn; throughput caveated; unsupported "memory bandwidth" explanation removed | — |
| B6 | No confidence intervals | Wilson 95% on every rate, in the artifact and the prose | — |
| C1 | Claimed "domain separation" and "thwarts length-extension" with neither implemented | RFC 6962 `0x00`/`0x01` prefixes implemented; false claim replaced with what the construction actually does | `test_leaf_and_internal_domains_are_separated` |
| C2 | `expected_depth` was optional, so the obvious auditor call was the unsound one; `len(x)!=64` leaf heuristic | depth is a required positional arg; leaves must be explicit digests | `test_proof_api_requires_explicit_depth`, `test_build_rejects_non_digest_leaves`, vectors V15/V17 |
| C3 | Definition 3 false for >1 record (deterministic HMAC leaks equality) | restated over the function, with the leak stated | — |
| C4 | Blinding sold as an architectural pillar; §3.2 admitted it isn't | demoted from abstract and contributions to a §3.2 hardening measure with an honest account | — |
| C5 | Game hops asserted without reductions; two vacuous hops; Definition 4 quantifier wrong; asymptotic bound on fixed-parameter primitives | explicit simulator for Game₀→Game₁; vacuous hops folded; quantifier fixed; concrete 128-bit reading | — |
| C6 | V13 (KMS ARN) scored as an attack on self-declared metadata | retired from the score, retained as a configuration check | — |
| D1 | Appendix claimed EviAssure "prevents indirect prompt injection" while §6.7 showed all injection profiles APPROVED | claim withdrawn; reframed as undeniability, not prevention | — |
| D2 | "completeness-carrying binding" contradicted Definition 5 | renamed truncation-resistant throughout | — |
| D3/D4 | Self-graded comparison table; 14 logical vs 14 physical cores | table removed; cores made consistent | — |
| E1 | **`carlini2024poisoning` had a fabricated author list** — CFP names "incorrect authors" as academic misconduct grounds | corrected against Crossref/arXiv | — |
| E1b | **`yang2024swebench` also wrong** (Likhomanenko is not an author; Kexin Pei missing) | corrected; key renamed `jimenez2024swebench` | — |
| E2 | Ed25519 EUF-CMA cited to BLS signatures and to Random Oracles; LLM-as-a-judge and CleverHans cited for a statement about determinism | Brendel et al. S&P'21 + GMR'88 added; irrelevant entries deleted | — |
| E4 | Fake `Submission ID: EVI-227` | removed | — |

`bellare1993random`, `boneh2001short`, `taly2011definitive`, `zheng2023judging`,
`papernot2016cleverhans` were removed from the bibliography entirely.

The three 2026 draft standards (in-toto #554, APAS v0.2.1, AAS-1) were
**verified against live sources and are cited accurately**. No fabrication there.

## Headline numbers, before → after

| | Before | After |
|---|---|---|
| EviAssure block rate | 100.0% (13/13) | **16/17 (94.1%, CI [73.0, 99.0])** — V16 fails |
| Strongest baseline | 30.8% (4/13, presence-check model) | **10/17 (58.8%)** executed DSSE+TUF+OPA |
| TUF alone | not evaluated | **8/17 (47.1%)** |
| False-block rate | not measured | **0/4** clean controls |
| Fuzzing | 1000/1000 (tautological) | 215/215 semantics-changing blocked, 785/785 preserving approved |
| Inspection recall | 50/50 (circular) | **50/50 overt, 0/25 stealth → 50/75 (66.7%)** |
| Corpus | 1,050 profiles / 2,100 records | 1,075 profiles / 5,450 records, 15 classes |

State: **47 tests pass**, ruff clean, mypy clean, paper builds with 0 undefined
references and 0 overfull boxes.

---

## What still needs you, before 25 Aug

1. **Page limit.** Body is 13 pages plus ~2,800 characters spilling onto p.14
   (about a third of a column). Cut one paragraph — the §7.1 Merkle-scaling
   prose or the §8.3 AAS-1 bullet are the softest targets.
2. **Re-run the timings on your M4 Max.** I could not: this session is
   Linux/Python 3.11 and re-running would have silently replaced your
   Apple M4 Max / Python 3.14.7 numbers with different-platform ones.
   `frozen_metrics.tex` is untouched and still matches your recorded platform,
   but `measure_merkle_scaling` now times the full packaging path, so:
   ```
   python3 scripts/run_release_benchmark.py --repeats 5
   python3 scripts/generate_paper_pdf.py
   ```
   Note the throughput figure was removed from the paper; if you re-add it,
   re-generate it from the new JSON.
3. **Re-run the security eval with OPA on PATH.** No `opa` binary was reachable
   here, so the OPA baseline currently records itself as *modeled*:
   ```
   python3 scripts/run_security_eval.py --require-executed
   python3 scripts/write_security_macros.py
   ```
   `--require-executed` fails loudly rather than shipping a modeled number.
4. **Artifact zip and digest — DONE (2026-08-17, round 4).** An earlier version
   of this note claimed `scripts/prepare_anonymous_artifact.py` was missing. It
   was not: it exists in the repository and was simply absent from the working
   copy this session was given. It has now been run, and
   `docs/artifact_digest.tex` carries a current digest. Re-run it once more
   after regenerating the timing benchmarks, since the zip contains
   `results/`.
5. **Run the CFP's hallucinator over the .bib.** The CFP explicitly recommends
   `github.com/gianlucasb/hallucinator`. I verified every entry against
   Crossref/arXiv/live pages and found two bad author lists; run their tool too
   before submitting.
6. **Register by tomorrow (18 Aug)** — fixed title, fixed author list, ORCIDs,
   tentative non-blank abstract.

## What I did not fix, and you should decide about

**There are still no real agent executions.** The corpus is synthetic, the
collector is unimplemented, and the paper now says both plainly in §7.9. A
reviewer can reject on this alone and would be within their rights. Eight days
is not enough to collect real traces. The Cycle 1 bet is that an honest,
falsifiable evaluation of a working mechanism beats an inflated one — the paper
now reports a vector it fails and a detector blind spot it cannot close, which
is a much harder thing to attack than 100% versus 30.8%. If that bet feels
wrong, Cycle 2 (26 Jan 2027) is where SWE-bench or OSWorld trace collection
would go, and it is the single change that would most improve this paper.
