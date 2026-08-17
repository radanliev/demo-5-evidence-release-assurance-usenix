# Implementation Plan — Round 3 (2026-08-17)

**Target:** USENIX Security '27 **Cycle 1** — registration Tue 18 Aug 2026,
paper Tue 25 Aug 2026, artifacts Fri 28 Aug 2026.
**Scope decision:** rebuild the evaluation (not just the claims).
**Input:** `docs/PEER_REVIEW_2026-08-17.md` (findings A1–A5, B1–B6, C1–C6,
D1–D4, E1–E4, F).

---

## 0. Hard constraints that shape the plan

| Constraint | Consequence |
|---|---|
| Body is already **13/13 pages** | Every added paragraph must be paid for by a deletion. Budget tracked in §5. |
| Timing benchmarks were taken on **Apple M4 Max / Python 3.14.7**; this session runs on Linux/Python 3.11 | **Do not regenerate timing macros here.** Deterministic security results are split into their own artifact so they can be refreshed without clobbering timings. One command re-runs timings on the author machine. |
| No `opa` binary reachable from this environment | OPA baseline keeps its Rego policy and executes when the binary is present; a `--require-executed` flag makes the final run fail loudly rather than silently shipping modeled numbers. Final regeneration happens on the author machine (OPA 1.19.0). |
| `in-toto` 3.1.0, `securesystemslib`, `python-tuf` 7.0.0 **are** installable | Two genuinely-executed strong baselines replace the two 3-line models. |

## 1. Tooling — installed and smoke-tested this session

| Tool | Status | Used for |
|---|---|---|
| pytest 8.x + hypothesis | ✅ ran (29 collected, 1 failing) | regression tests for every fix |
| cryptography 46.0.7 | ✅ | Ed25519, SHA-256 |
| **in-toto 3.1.0 + securesystemslib** | ✅ `Envelope` import verified | **executed DSSE/in-toto baseline (replaces the presence-only Cosign model)** |
| **python-tuf 7.0.0** | ✅ `Root/Targets/Snapshot/Timestamp` verified | **executed TUF baseline — real expiry, thresholds, key revocation** |
| statsmodels 0.14 | ✅ Wilson + Clopper–Pearson verified | confidence intervals (B6) |
| TeX Live 2023 + lmodern + tikz + latexmk + chktex | ✅ **paper builds clean, 19pp, 0 undefined refs** | rebuild + lint |
| mypy 1.20, ruff 0.15, semgrep 1.173 | ✅ | static checks |
| habanero (Crossref), pyalex (OpenAlex), DBLP via requests | ✅ | bibliography re-verification (E1/E2) |
| WebFetch against live sources | ✅ (used on #554, APAS, AAS-1, runtime-trace, arXiv 2302.10149) | citation ground truth |
| `opa`, `cosign`, `bandit`, `mutmut` | ❌ not reachable | OPA runs on author machine; cosign superseded by the in-toto/DSSE baseline |

## 2. Work items, in execution order

Ordered so that anything that changes Merkle roots or gate verdicts lands
**before** the artifacts are regenerated.

### P0 — misconduct risk and security bugs (do first, day 1)

| # | Finding | Change | Verified by |
|---|---|---|---|
| P0.1 | **E1** | Correct `carlini2024poisoning` to the 9 real authors; re-verify every entry in `references.bib` against Crossref/OpenAlex/DBLP/live pages; delete unusable entries | new `check_citations` run; hand-check log committed |
| P0.2 | **E2** | Add Brendel et al. *The Provable Security of Ed25519* (S&P'21) and cite it for EUF-CMA; drop `boneh2001short` and `bellare1993random` from that sentence; delete `zheng2023judging` + `papernot2016cleverhans` from the dispersion sentence; retire `taly2011definitive` from Table 5 | build with 0 undefined citations |
| P0.3 | **A1** | Replay state becomes **mandatory**: `evaluate()` treats `seen_nonces=None` as a violation, not a skip. `evaluate_release_gate` / `verify_release_gate.py` default to a `PersistentNonceStore` under `--nonce-store` (default `.eviassure/nonces.json`) | `test_replay_blocked_through_cli` — submit the same bundle twice through the shipped CLI, second must exit 1 |
| P0.4 | **A2** | Remove the `pinned_pub or s_pub` fallback — a bundle-supplied key is **never** used. `require_trusted_key: False` now means "registry absent ⇒ fail closed", matching the paper's sentence. Ablation variant `no_key_registry` switched to an empty registry (the dead `empty_registry` branch is wired up) | `test_attacker_key_rejected_with_registry_disabled`; new vector V14 |
| P0.5 | **C2** | `verify_merkle_proof(leaf, proof, root, expected_depth)` — `expected_depth` becomes **required**. Delete the `len(x) != 64` heuristic; leaves must be passed as digests (`build_merkle_tree` gains `leaves_are_digests: bool`) | `test_proof_api_requires_depth`; new vectors V15, V17 |
| P0.6 | **C1** | RFC 6962 domain separation: `leaf = SHA256(0x00 ‖ leaf_bytes)`, `node = SHA256(0x01 ‖ L ‖ R)`. Delete the "delimiter thwarts length-extension / guarantees domain separation" claim and replace with the honest statement (depth binding + explicit prefixes) | `test_leaf_internal_domain_separation`; **all Merkle roots change ⇒ corpus + results regenerate after this lands** |
| P0.7 | **A4** | Test count in `REPRODUCE.md`, `README.md` and Appendix B.2 becomes a generated value; `test_docs_consistency` goes green | `pytest tests/ -q` fully green |

### P1 — evaluation rebuild (days 2–5)

| # | Finding | Change |
|---|---|---|
| P1.1 | **B1** | New `benchmark/baselines.py` with **executed** gates: (a) **in-toto/DSSE** — real `Envelope` verification against a `securesystemslib` trust root; (b) **TUF** — real `python-tuf` Root/Timestamp metadata with `expires`, key thresholds and root-driven revocation; (c) OPA Rego (executed when the binary is present, `--require-executed` otherwise fails); (d) CI exit-code kept, relabelled *"unauthenticated status gate (lower bound, not a competitor)"*. TUF is expected to **win V5, V9 and possibly V11** — that is the point: the benchmark must be losable. |
| P1.2 | **A3** | Five new vectors that are not 1:1 with EviAssure's checks: **V14** attacker key under disabled registry, **V15** internal-node-as-leaf proof against a third-party auditor, **V16** cross-replica nonce replay (two engine instances), **V17** 64-char leaf type confusion, **V18** post-signing DOM mutation with a re-signed root. Vectors are allowed to be *unblocked* and are reported as such. |
| P1.3 | **B2** | Fuzzing redesigned as **differential wire fuzzing**: mutate only the encoding (key order, whitespace, unicode escapes, number formats `1e2`/`100.0`, duplicate keys, BOM, trailing data) — i.e. mutations a canonicalisation bug would let through — plus **200 clean control bundles**. Report block rate *and* false-block rate, both with CIs. |
| P1.4 | **B3** | L3 becomes a **leave-one-class-out** evaluation: the sensitive-action set is derived from *clean* corpus statistics, five anomaly classes are held out entirely, and recall is measured on unseen classes. The hard-coded `SENSITIVE_ACTIONS ≡ ANOMALY_TYPES` identity is removed. Expected result is **below** 100%, and that is the honest, publishable number. |
| P1.5 | **B6** | `results/*.json` gain `ci95_wilson` for every rate; new macros `\tamperBlockCI` etc.; abstract and §6 quote intervals. |
| P1.6 | **B5** | `measure_merkle_scaling` times the **whole** packaging path (leaf hashing + tree + serialization + signing) inside the timed region; the meaningless `packaging_overhead_pct` is deleted; throughput is measured at **N ∈ {3, 100, 1000}** traces/bundle so it is commensurable with the scaling claim. **Re-run on the author machine.** |
| P1.7 | infra | `results/security_evaluation.json` (deterministic, regenerated anywhere) is split from `results/benchmark_summary.json` (timings, author machine only). `--only {timings,security,all}` on the benchmark runner. |

### P2 — prose (days 5–7)

| # | Finding | Rewrite |
|---|---|---|
| P2.1 | **D1** | Delete the prompt-injection prevention claim from Appendix A.3; §1 reframed: EviAssure makes an injected agent's behaviour *undeniable*, it does not prevent it. |
| P2.2 | **D2** | "completeness-carrying binding" → "truncation-resistant binding" everywhere (abstract, contribution 2, §2.3). |
| P2.3 | **A5** | One definition of depth: $d=\lceil\log_2 N\rceil$; artifact field renamed `tree_levels`; §6.3 says depth 20. |
| P2.4 | **C3/C4** | Definition 3 restated over distinct inputs (or blinding made randomised); blinding demoted from the contribution list and the abstract to a §3.2 mechanism with an honest statement of what it buys. |
| P2.5 | **C5** | Theorem 1 proof gains an actual reduction sketch for Game₀→Game₁ (simulator, signing-oracle handling); vacuous Games 3–4 folded into a "deterministic checks" remark; Definition 4 quantifier fixed; Theorem 2(ii) restated non-tautologically; asymptotic-vs-fixed-parameter caveat added. |
| P2.6 | **C6** | V13 removed from the adversarial vector count; the KMS ARN check reframed as a **configuration** control with its limitation stated. Headline becomes **17 vectors** (13 − V13 + 5 new). |
| P2.7 | **B4** | §5 retitled *"Deployment Integration and Workload Specimens"*; the word "real-world" removed where nothing real-world is measured. |
| P2.8 | **D3/D4/F** | Table 5 grades sourced or deleted; cores made consistent; stale "12-vector" docstrings fixed; dead ablation branch removed. |
| P2.9 | **E4** | Drop the fake `Submission ID: EVI-227`. |

### P3 — final gate (day 7–8, author machine)

```bash
python3 scripts/run_release_benchmark.py --repeats 5 --only all --require-executed
python3 scripts/run_comparative_eval.py --require-executed
python3 scripts/run_corpus_eval.py
python3 -m pytest tests/ -q          # must be fully green
python3 scripts/generate_paper_pdf.py
python3 scripts/prepare_anonymous_artifact.py
```

## 3. What this plan does **not** fix (state as limitations, do not paper over)

1. **No real agent executions.** The corpus remains synthetic. In 8 days this
   cannot change. §6.9 must say plainly: *no LLM agent was executed in this
   evaluation; all traces are synthetic.* A reviewer who rejects on this is
   entitled to, and Cycle 2 is where a SWE-bench/OSWorld trace collection would
   go.
2. **The collector is still unimplemented.** eBPF complete-mediation stays an
   architectural proposal. The paper must stop describing it in the present
   tense.
3. **No real KMS round-trip.** Already disclosed; keep it disclosed.

## 4. Ordering hazard

P0.6 (domain separation) changes **every Merkle root in the repository**. It must
land before `corpus/agent_trace_corpus.json`, `results/*.json` and
`docs/artifact_digest.tex` are regenerated, or the artifact digest and the
corpus will disagree with the code.

## 5. Page budget

Additions: reduction sketch (~12 lines), new-vector rows (~8), TUF/in-toto
baseline description (~10), LOCO methodology (~10), CIs (~4) ≈ **44 lines**.
Deletions: the length-extension/domain-separation paragraph (~6), the
`packaging_overhead` sentence (~4), the ablation "structural results" paragraph
that A2 falsifies (~8), Table 5 → move to appendix (~14), §5's simulated
"case study" framing (~8), redundant related-work prose (~10) ≈ **50 lines**.
Net **−6 lines**. Body stays ≤ 13 pages.
