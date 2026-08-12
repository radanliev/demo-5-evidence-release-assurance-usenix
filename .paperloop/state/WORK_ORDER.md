You are the paper-writer agent for `demo-5-evidence-release-assurance-usenix`, targeting **USENIX Security 2027**.

A deterministic gate just measured the compiled manuscript. Your job is to make
the findings below go away by editing the paper — not by editing the gate, not
by relaxing the venue spec, and not by touching anything marked GATED.

Manuscript: `docs/usenix_paper_manuscript.tex`
Full report: `.paperloop/state/FINDINGS.md`
Machine-readable: `.paperloop/state/findings.json`

## Your mandate

Fix every finding in the **Auto-fix mandate** section. For each one:
  1. Read the surrounding source before editing. Never blind-replace.
  2. Apply the smallest change that resolves the measurement.
  3. Preserve meaning. If a page-limit cut would remove a technical
     contribution, cut redundancy and prose bloat instead and say what you cut.

## Hard prohibitions

- Do not shrink margins, fonts, line spacing, or float separation to fit a
  page limit. Those are themselves violations and the gate will catch them.
- Do not change any number, statistic, or empirical claim. If a number is
  wrong, that is a GATED finding: write a proposal, do not edit the paper.
- Do not delete a check, loosen `venue.yaml`, or add a suppression to make a
  gate pass. If you believe a finding is a false positive, write it to
  `.paperloop/state/disputed.md` with your reasoning and leave the paper alone.
- Do not invent citations, results, or artifacts.

## Gated findings (3 of them)

For each, write `.paperloop/state/proposals/<id>.md` containing: the finding,
what you believe the correct value or claim is, the exact diff you would apply,
and the evidence you would need to be sure. Then stop on those. A human decides.

## When you are done

Re-run `python3 .paperloop/run_gates.py --build` yourself and confirm the count
dropped. Then write a two-line summary of what you changed to
`.paperloop/state/round-6-writer.md`.

---

## AUTO-FIX MANDATE


- [BLOCKER] (venue.margins) p.5
  bottom margin violated on p.5
  found: 0.797in
  expected: >= 0.9in (tolerance 0.02in)
  remedy: Content intrudes into the bottom margin on p.5. Usually a wide table, figure, algorithm block, or unbroken URL. Wrap it, scale it to \columnwidth, or rebreak the line — do not move the margin.
  id: fb3b9ae2f3ae3b71

- [BLOCKER] (venue.margins) p.4
  top margin violated on p.4
  found: 0.731in
  expected: >= 0.9in (tolerance 0.02in)
  remedy: Content intrudes into the top margin on p.4. Usually a wide table, figure, algorithm block, or unbroken URL. Wrap it, scale it to \columnwidth, or rebreak the line — do not move the margin.
  id: 2a4189e5b25dbf93

- [MAJOR] (venue.pagecount) 
  paper is well under the 13-page budget
  found: 8 body pages
  expected: competitive submissions use 11-13 pages
  remedy: Expand evaluation, threat model, or related work; reviewers read a short paper as an underdeveloped one.
  id: 6cfb9be7880c8171


## GATED — PROPOSE ONLY, DO NOT EDIT THE PAPER


- [BLOCKER] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59
  manuscript says 5,883.86 but the nearest recorded result is 5841.27 — likely a stale number from an earlier run
  found: …% for OPA/Sigstore) while processing policy gate evaluations at up to 5,883.86 operations/second across 8 parallel cores, scaling Merkle tree constr…
  expected: 5841.27  (source: results/benchmark_summary.json::parallel_throughput.workers_8.throughput_ops_sec)
  remedy: Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
  id: 20076b110c1b9844

- [BLOCKER] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59
  manuscript says 0.1221% but the nearest recorded result is 0.1208 — likely a stale number from an earlier run
  found: …ion for   execution traces in   (representing a packaging overhead of 0.1221\%) with   sparse proof compression.…
  expected: 0.1208  (source: results/benchmark_summary.json::merkle_scaling[3].packaging_overhead_pct)
  remedy: Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
  id: a8d2a14cade3b429

- [MAJOR] (science.stale_artifact) 
  2 result artifact(s) changed after the manuscript was last edited
  found: results/benchmark_summary.json; results/comparative_evaluation.json
  expected: manuscript newer than the data it reports
  remedy: Re-read those artifacts and confirm every dependent number, table and figure in the paper still matches.
  id: 1399079e29b05206


## REVIEWER FINDINGS (from the evaluator agents this round)


These come from an agent that read the paper rather than measured it. Apply the same split: `science.*` are gated and you may only propose; everything else is yours to fix.


### from review-round-6-science-auditor.md

- [BLOCKER] (science.complete_mediation) docs/usenix_paper_manuscript.tex:111,200-218 — The fail-closed guarantee and theorem remain false for the implemented verifier: a payload signed by an attacker-selected Ed25519 key is accepted, and an empty trace list is accepted without checking the signed nonzero `execution_traces_count`.
  evidence: This is the round-2/3 blocker still present because the implementation and evaluation suite were not changed. `assurance/policy.py:130-137` verifies against the evidence-supplied `public_key`, while `governance/release_policy.yaml:6-21` pins neither trusted issuers nor keys; `assurance/policy.py:150-161` bypasses the Merkle check for `traces=[]` and never compares the list length to `execution_traces_count`. `benchmark/tamper_vectors.py:101-186` contains neither falsifying attack. The producing validation command is `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests -v`, but its tests do not cover these inputs.
  remedy: Human-gated proposal: bind allowed Ed25519 key IDs, public keys, and KMS identities to policy-controlled trust roots; require `execution_traces_count == len(traces)` and validate the defined empty-tree root; add approved-attacker-key, empty-list, and count-mismatch vectors that invoke `evaluate_release_gate`; then narrow or re-prove the theorem against that implemented boundary.
- [BLOCKER] (science.replay_protection) docs/usenix_paper_manuscript.tex:59,111,283-300 — The claimed replay blocking and V4 attribution are not exercised by the deployable gate: it has no durable nonce store and never records an accepted nonce, so a fresh bundle can be approved repeatedly across invocations.
  evidence: This round-3 blocker remains unfixed. `assurance/verifier.py:13-33` defaults `seen_nonces` to `None`; `assurance/policy.py:194-221` only tests a caller-supplied set and never adds a successful nonce. V4 is forced to fail only by pre-populating a copied set in `scripts/run_release_benchmark.py:109-118` and `tests/test_tamper_resilience.py:17-27`. The stored 12/12 at `results/benchmark_summary.json:75-216` is produced by `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py`, not an end-to-end replay experiment.
  remedy: Human-gated proposal: add an atomic durable nonce store shared by gate invocations, persist a nonce only after approval, specify expiration and store-failure behavior, and measure first and second submissions through `evaluate_release_gate` without benchmark-injected state; otherwise remove replay-protection claims and V4's mechanism attribution.
- [BLOCKER] (science.key_management) docs/usenix_paper_manuscript.tex:59,67,76,85-86 — The claimed asymmetric KMS-rooted multi-signature authority conflicts with the accepted configuration: the policy permits HMAC-SHA256 using a source-embedded secret and does not require a KMS ARN, trusted key, or signature threshold.
  evidence: This round-3 blocker remains unfixed. `governance/release_policy.yaml:7-16` allows `hmac-sha256` and has no key/KMS allowlist or `min_required_signatures`; `assurance/evidence.py:27,107-121` embeds `DEFAULT_SECRET_KEY` and emits optional KMS metadata; `assurance/policy.py:79,106-142` accepts HMAC and reads `kms_key_arn` only into the signed payload, never validates it. `tests/test_release_gate_policy.py:61-77` confirms a threshold can be satisfied with an HMAC signature. Reproduce with `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/test_release_gate_policy.py -v`.
  remedy: Human-gated proposal: remove HMAC demonstration mode from the claimed deployment policy, require a policy-pinned Ed25519 issuer/key set and independently validated KMS identity and threshold, then add unknown-key, HMAC, KMS-substitution, and key-compromise falsification vectors; alternatively explicitly scope all system and theorem claims to a demonstration mode.
- [BLOCKER] (science.corpus_provenance) docs/usenix_paper_manuscript.tex:221-226 — The claimed 50-profile/five-architecture corpus, 15 planted anomalies, and 15/15 block result remain unsupported and contradicted by the released raw corpus; no producing script evaluates corpus profiles.
  evidence: This round-2/3 blocker remains unfixed. Although `corpus/agent_trace_corpus.json:4` declares 50 profiles, its `profiles` array at lines 12-58 has five entries, two non-`CLEAN` labels, ten total traces, and only three architectures. `benchmark/tamper_vectors.py:101-186` synthesizes a distinct 12-vector suite and never reads this corpus. Independent aggregation using `PYTHONDONTWRITEBYTECODE=1 python3 -c "import json; c=json.load(open('corpus/agent_trace_corpus.json')); print(len(c['profiles']), sum(p['label'] != 'CLEAN' for p in c['profiles']), sum(len(p['traces']) for p in c['profiles']), len({p['architecture'] for p in c['profiles']}))"` yields `5 2 10 3`.
  remedy: Human-gated proposal: release the claimed versioned corpus with all profile and anomaly IDs plus a corpus-to-gate evaluator that emits one preserved decision per profile, or revise every corpus count and block-rate claim to the audited data; include the resulting artifact and exact regeneration command before making a corpus result claim.
- [MAJOR] (science.methods_statistics) docs/usenix_paper_manuscript.tex:59,231,234,244 — The performance claim ledger has drifted and the stated statistical methodology remains unsupported: the current artifact stores 39.081 ms and 0.1206% at 100K plus 5,841.27 ops/s at eight workers, while the manuscript prints 39.59 ms, 0.1221%, and 5,883.86; the producer retains no repeated samples or standard-error calculation.
  evidence: The two stale abstract values are also current gate blockers. `results/benchmark_summary.json:37-42,67-72` is the artifact/key source; its 100K overhead is derived as `180.859 / (100000 * 1.5) * 100 = 0.1205727%`, where the 1.5-ms denominator is code-assigned at `scripts/run_release_benchmark.py:36-63`, not measured workload time. `scripts/run_release_benchmark.py:31-96` takes one timing per scale point and one 1,000-request aggregate per worker count, despite line 231's mean/SE claim. Independent re-aggregation gives `1000 / 0.1712 = 5841.12` ops/s (rounded artifact 5,841.27) and `5841.27 / 1476.14 = 3.96x`, not linear eight-worker scaling. Regenerate with `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py`.
  remedy: Human-gated proposal: predefine warm-up, repetitions, exclusions, and environment/load metadata; retain raw samples and report an appropriately rounded estimate, interval, and actual speedup; measure a real end-to-end trace-execution denominator or remove the packaging-overhead percentage; only then update all dependent headline values from a frozen artifact.
- [MAJOR] (science.baseline_validity) docs/usenix_paper_manuscript.tex:59,79,299-300 — The 0.0% CI and 25.0% OPA/Sigstore results are reproducible only for hand-written local predicates, not the named systems, so the comparison neither isolates EviAssure's claimed cause nor uses a deployable baseline under equivalent configurations.
  evidence: This round-2/3 finding remains unfixed. Independent aggregation of `results/comparative_evaluation.json:3-106` yields 0/12 CI, 3/12 OPA, 3/12 Sigstore, and 12/12 EviAssure blocks, produced by `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_comparative_eval.py`. But `scripts/run_comparative_eval.py:20-34` implements all three named baselines as in-process field predicates and imports or invokes neither OPA/Kyverno nor Sigstore/Cosign; the experiment that could falsify the claimed advantage against version-pinned real configurations was not run.
  remedy: Human-gated proposal: execute version-pinned OPA/Kyverno and Sigstore/Cosign configurations on identical signed inputs with archived policies, commands, versions, and per-vector decision logs, and report a paired mechanism-specific analysis; otherwise relabel the comparison as illustrative local predicate behavior and remove claims about the named systems.
- [MAJOR] (science.attack_construct_validity) docs/usenix_paper_manuscript.tex:283-300 — The 12/12 denial rate does not support the claimed canonical-JSON or sparse-proof defenses: V10 changes the pass-rate field rather than submitting a parser-level malleability payload, and V12 truncates full traces even though the verifier never consumes sparse proofs.
  evidence: This round-2/3 finding remains unfixed. `benchmark/tamper_vectors.py:167-184` implements V10 as `test_pass_pct=99.9` and V12 as a shortened `traces` list; `assurance/policy.py:149-161` does not parse raw JSON bytes or inspect `sparse_proofs`. Correspondingly, `results/benchmark_summary.json:182-214` records V10's invalid-signature/sub-threshold-pass violations and V12's Merkle mismatch, not canonicalization or proof-path rejection. The producer is `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py`.
  remedy: Human-gated proposal: construct executable duplicate/alternate-key JSON inputs at the parser boundary and malformed sparse proofs at a proof-verifier boundary, require each vector to reach its stated defense, preserve vector-specific rejection reasons, and separate mechanism coverage from an aggregate denial count.
- [MAJOR] (science.technical_accuracy) docs/usenix_paper_manuscript.tex:125,134 — The efficiency claim still calls a SHA-256 root 64 bytes and gives a sub-5-KB sparse-proof bound without a producing measurement; the root is 32 bytes represented as 64 hexadecimal characters and no benchmark serializes proofs.
  evidence: This round-2/3 finding remains unfixed. `assurance/crypto.py:16-20` returns a 64-character hex digest, and `assurance/evidence.py:185-206` has a proof generator that is never called by `scripts/run_release_benchmark.py:31-66`; neither result JSON contains proof size. The claimed `<5 KB` value therefore has no artifact key or regeneration command.
  remedy: Human-gated proposal: correct the byte/hex distinction and add a versioned proof-size artifact generated from serialized proofs for named trace counts, audit-set sizes, trace schemas, and encodings; do not retain a concrete transmission bound until that measurement is available.

### from review-round-5-venue-compliance-auditor.md

- [BLOCKER] (venue.template) docs/usenix_paper_manuscript.tex:1-2 — The manuscript still uses the locally modified 2019 style rather than the mandatory USENIX Security 2027 template and therefore has a 7 x 9.5-inch text block instead of the CFP-required 7 x 9-inch text block.
  evidence: This is the round-4 blocker still present because the writer reported that the local 2019 style remained in use. The live CFP requires the linked 2027 template/style files, letter paper, two columns, 10-point Times on 12-point leading, and a 7 x 9-inch-deep text block; `docs/usenix-2019_v3.sty` identifies itself as 2019 and applies `margin=0.75in`, yielding 9.5 inches of usable vertical space. The rendered pages retain the 2019-style date and oversized 9.5-inch body area. The writer could not remedy this through float movement because correcting it requires a template migration, not a local geometry adjustment.
  remedy: Replace `usenix-2019_v3` with the unmodified style file from `https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip`; remove the local style file and all geometry/layout overrides, then rebuild and recheck the resulting PDF.
- [MAJOR] (venue.open_science) docs/usenix_paper_manuscript.tex:350-352 — The mandatory Open Science Appendix still gives no anonymous artifact access path and does not state a concrete, item-specific reason why the listed implementation, corpus, harnesses, scripts, and results are unavailable.
  evidence: This is the round-4 finding still present: the live CFP requires an Open Science Appendix to describe artifacts and access, or explicitly explain omissions, and requires anonymous non-tracking links for supplied artifacts. The rendered appendix inventories the materials and commands but states only that no archive is currently available; it gives neither an anonymous URL nor a licensing, NDA, safety, or other concrete restriction for each unavailable item. The writer did not resolve it because an archive and the factual basis for withholding each item cannot be invented in manuscript text.
  remedy: Provide a tested anonymous, non-tracking, frozen review archive URL with access and reproduction instructions for every shareable item; for every unavailable item, state its scope and concrete reason in the appendix.
- [MAJOR] (layout.float) docs/usenix_paper_manuscript.tex:312-335 — The related-work Table 2 floats to a standalone final page after the Open Science Appendix, separating it from the section that introduces it and disrupting the required appendix's document order.
  evidence: In the rendered PDF, page 7 is the Open Science Appendix and page 8 contains only Table 2, although the table is introduced in Related Work at line 310 and defined before the bibliography. The `[b]` placement on the `table*` at line 312 permits LaTeX to defer it past the bibliography and appendix. This visual finding was not reported in earlier rounds.
  remedy: Change the wide table's float placement and, if necessary, reduce its vertical footprint so it is placed with Related Work before the bibliography and `\appendix`; rebuild and verify that no main-body float follows the Open Science Appendix.

### from review-round-4-literature-venue-verifier.md

- [BLOCKER] (venue.template) docs/usenix_paper_manuscript.tex:1-2 — The manuscript uses a locally modified 2019 style file rather than the mandatory USENIX Security 2027 template, and its 0.75-inch all-around margins create a 7 x 9.5-inch text block rather than the CFP-required 7 x 9-inch block.
  evidence: The official CFP checked 2026-08-12 requires the linked 2027 template/style files, letter paper, two columns, 10-point Times on 12-point leading, and a 7 x 9-inch-deep text block; it forbids changing formatting defaults. `docs/usenix-2019_v3.sty:1-10` identifies itself as the 2019 style and loads `geometry` with `margin=0.75in`, which gives 9.5 inches of usable vertical space on letter paper.
  remedy: Replace `usenix-2019_v3` with the unmodified style file from `https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip`; remove the local style file and any geometry/layout overrides, then rebuild and recheck the resulting PDF.
- [BLOCKER] (refs.bibliography) docs/references.bib:53-59 — The Sigstore/Cosign reference has a DOI for an unrelated paper, so the paper’s central comparison and related-work table cite a fabricated bibliographic identity.
  evidence: `sigstore2022cosign` is cited at `docs/usenix_paper_manuscript.tex:75,335,348` as “Sigstore: Software Signing and Transparency for Everyone,” but Crossref resolves DOI `10.1145/3548606.3560702` to Cong et al., “SortingHat: Efficient Private Decision Tree Evaluation via Homomorphic Encryption and Transciphering,” CCS 2022, pp. 563-577. The cited title, authorship, venue, and DOI therefore cannot all be true.
  remedy: Remove this invalid record and cite the authoritative Sigstore/Cosign documentation or a verified peer-reviewed Sigstore paper; update every related-work statement and table cell to claims supportable by that source.
- [BLOCKER] (refs.bibliography) docs/references.bib:94-107 — The OPA and Kyverno citations are not bibliographically verifiable primary sources and point to Zenodo DOIs that do not resolve as the claimed projects, leaving both named baselines without a valid citation.
  evidence: `opa2021openpolicy` and `kyverno2022policy` are cited at `docs/usenix_paper_manuscript.tex:336,348`. The records attribute generic project descriptions to named individuals/teams and supply `10.5281/zenodo.5562141` and `10.5281/zenodo.6891024`; the former DOI resolves to “Financing Policies for Inclusive Education Systems: Policy Guidance Framework,” and Crossref returns 404 for both Zenodo identifiers. Neither is an authoritative OPA or Kyverno release/specification.
  remedy: Replace both records with versioned official OPA and Kyverno documentation/release references that match the evaluated versions, and revise the table to cite those sources rather than unsupported implementation properties.
- [MAJOR] (refs.bibliography) docs/references.bib:180-193,239-252 — Four citations used to motivate the agent-security problem or deployment-gate novelty are unverified and likely non-existent, exposing the submission to the CFP’s explicit desk-rejection risk for fabricated references.
  evidence: The records `li2023securing`, `zhao2024evaluating`, `shao2024prompt`, and `kumar2023adversarial` are cited at `docs/usenix_paper_manuscript.tex:63,75,341,348`; Crossref returns no work for each supplied DOI (`10.5555/3675400.3675450`, `10.1145/3658644.3690100`, `10.1145/3670001`, and `10.1109/TSE.2023.3289100`). The official USENIX Security '27 CFP states that fabricated references or incorrect authors may be desk-rejected.
  remedy: Verify each title, author list, venue, pages, and DOI against its publisher before submission; replace any unverifiable item with an actual primary source or delete the dependent statement. Add verified current agent-security literature, including Greshake et al. (AISec 2023) and the primary documentation/papers for the concrete agent systems and supply-chain tools discussed.
- [MAJOR] (refs.primary_source) docs/usenix_paper_manuscript.tex:72,75,157-176,305 — The manuscript makes standards-conformance claims without citing the governing primary specifications, and the reference set omits the canonical standards needed to assess the proposed signed JSON format.
  evidence: Lines 72 and 75 claim Ed25519 and in-toto v0.2/SLSA v1.0 compatibility; lines 157-176 emit an in-toto Statement `v0.1`; line 305 attributes JSON malleability resistance to canonical sorting. `docs/references.bib` cites a research paper for Ed25519 and a generic SLSA report, but contains no RFC 8032 (EdDSA/Ed25519), RFC 8785 (JSON Canonicalization Scheme), current in-toto Statement/Attestation Framework specification, or official SLSA Provenance v1 specification. These standards define the syntax and verification rules that the paper claims to implement.
  remedy: Add and cite RFC 8032, RFC 8785, the official in-toto Statement and Attestation Framework specifications, and `https://slsa.dev/provenance/v1`; then submit a science proposal to reconcile the claimed in-toto version with the `_type` actually emitted and to delimit compatibility to the fields and validation rules implemented.
- [MAJOR] (venue.open_science) docs/usenix_paper_manuscript.tex:360-363 — The Open Science Appendix identifies materials but does not give the required anonymous, non-tracking access link for shareable artifacts or explicitly scope why each specific item is unavailable.
  evidence: This improves on the round-1 missing-appendix finding, but the official CFP requires an appendix describing artifacts and how to access them, with anonymous, non-tracking URLs in the paper; when artifacts cannot be provided, omissions must be explained explicitly. Lines 361-363 list implementation, corpus, harnesses, scripts, and results, then give a single unqualified statement that no archive is available and no artifact URL/access credential exists, without stating whether each item is unavailable due to a concrete restriction or simply not prepared.
  remedy: Add a tested anonymous, non-tracking artifact URL and precise access/reproduction instructions for every shareable item; for each unavailable item, state its scope and concrete reason (for example licensing, NDA, or safety risk) in the appendix. Keep the link and archive frozen through the CFP-required review period.


## ANALYTICAL AUDIT (independent recomputation)


These findings come from the read-only analytical agent. Treat every `science.*` item as gated: do not change numbers, statistics, datasets, or experimental claims. You may repair only `repro.*`, `figure.*`, and other non-scientific presentation/documentation items.


### from analysis-round-6.md

# Analytical audit — round 6

## Executive decision
NOT YET SUPPORTED. The documented tests, default gate, deterministic 12-vector harness, and local comparison reproduce, but four independently constructed bundles that violate the stated trust boundary are approved. The corpus claim is contradicted by raw data, while the named-baseline and performance claims lack the artifacts and repeated observations required to support their scope and precision.

## Claim ledger

| Claim | Source | Recomputation | Result | Status |
|---|---|---|---|---|
| 100.0% (12/12) tamper block rate | `docs/usenix_paper_manuscript.tex:59,283`; `results/benchmark_summary.json:75-216`, `tamper_resilience`; producer `scripts/run_release_benchmark.py:evaluate_tamper_resilience`; input `benchmark/tamper_vectors.py`; `python3 scripts/run_release_benchmark.py` | Count `vector_details[*].blocked`; rerun producer in memory | 12/12 deterministic curated specimens denied; Wilson 95% lower bound 75.75% | VERIFIED only for this suite |
| CI 0/12, OPA/Sigstore 3/12, EviAssure 12/12 | `docs/usenix_paper_manuscript.tex:59,300`; `results/comparative_evaluation.json:3-106`; producer `scripts/run_comparative_eval.py:main`; same 12 inputs; `python3 scripts/run_comparative_eval.py` | Sum each raw Boolean column; invoke producer predicates in memory | 0, 3, 3, 12 denials | VERIFIED for local predicates, not named systems |
| 5,883.86 ops/s at 8 cores and linear scaling | `docs/usenix_paper_manuscript.tex:59,244`; `results/benchmark_summary.json:67-72`, `parallel_throughput.workers_8`; producer `measure_parallel_throughput`; 1,000 tasks; `python3 scripts/run_release_benchmark.py` | `1000 / elapsed_seconds`; 8-worker/1-worker ratio; fresh in-memory producer call | Stored 5,841.27 ops/s (5,841.12 from displayed time), 3.96x speedup; fresh 5,872.13 ops/s | CONTRADICTED / statistically unsupported |
| 100K traces in 39.59 ms and 0.1221% overhead | `docs/usenix_paper_manuscript.tex:59,234`; `results/benchmark_summary.json:37-42`, `merkle_scaling[4]`; producer `measure_merkle_scaling`; synthetic 1.5-ms traces; `python3 scripts/run_release_benchmark.py` | `packaging_latency_ms/(trace_count*1.5)*100`; fresh in-memory producer call | Stored 39.081 ms and 0.1206%; fresh 41.160 ms and 0.1187%; denominator is synthetic | CONTRADICTED / DRIFTED |
| 50 profiles, 15 anomalies, 15/15 blocked | `docs/usenix_paper_manuscript.tex:225-226`; `corpus/agent_trace_corpus.json:4-58`; no producer/result artifact | Parse raw profiles, labels, traces, architectures | 5 profiles, 2 anomalies, 10 traces, 3 architectures; no corpus evaluator | CONTRADICTED |
| Gate rejects unauthenticated or modified evidence | `docs/usenix_paper_manuscript.tex:111,200-218`; `assurance/policy.py:77-228`, `assurance/verifier.py:13-33`; adversarial construction command below | Evaluate attacker-key, trace-omission, replay, and HMAC bundles | All four are approved | CONTRADICTED |
| Ed25519/KMS-rooted threshold assurance | `docs/usenix_paper_manuscript.tex:59,67,73,76,85-86`; `governance/release_policy.yaml:6-21`; `assurance/evidence.py:27,107-121` | Inspect policy and evaluate HMAC bundle | HMAC with source-embedded secret is accepted; no trusted-key/KMS binding; default threshold is 1 | CONTRADICTED |
| 64-byte root, sub-5-KB sparse proof transmission, and O(log N) paths | `docs/usenix_paper_manuscript.tex:125-134`; `assurance/crypto.py:16-20,55-85`; `EvidenceBundle.generate_sparse_proofs`; no result artifact | Decode root; generate and compact-serialize one 10K-trace proof | 64 hex characters = 32 bytes; 14 proof steps and 1,435 bytes for one proof; O(log N) path verified | Root unit CONTRADICTED; aggregate bound UNSOURCED |

## Independent calculations

- Tamper result: `12 blocked / 12 vectors * 100 = 100.0%`. Wilson 95% CI: `75.7506%` to `100.0%`. Each vector is one deterministic constructed payload, not an independent sampled attack or a 1,000-run experiment.
- Comparative result from all raw detail rows: CI `0/12 = 0.0%`; local OPA-schema predicate `3/12 = 25.0%`; local Sigstore/Cosign predicate `3/12 = 25.0%`; EviAssure `12/12 = 100.0%`. `scripts/run_comparative_eval.py:20-34` contains local field predicates and invokes no OPA, Kyverno, Sigstore, or Cosign.
- Stored 100K overhead: `180.859 ms / (100000 * 1.5 ms) * 100 = 0.1205727%`, which rounds to `0.1206%`, not `0.1221%`. The denominator is assigned at `scripts/run_release_benchmark.py:42`, not measured execution duration.
- Stored throughput: `1000 / 0.1712 s = 5841.1215 ops/s`, close to the producer's pre-rounding `5841.27`, not `5883.86`. Stored speedup is `5841.27 / 1476.14 = 3.9571x`, not linear 8x scaling.
- Fresh non-writing producer calls returned 100K packaging `178.078 ms`, Merkle construction `41.160 ms`, synthetic ratio `0.1187%`, and 8-worker throughput `5872.13 ops/s`. The producer retains no repeated samples, warm-up data, seeds, CPU/load state, timeouts, exclusions, percentiles, or standard errors.
- Raw corpus count: declared profiles `50`; actual `5`; anomalies `2`; trace rows `10`; architectures `{CodeSynthesisAgent, DatabaseAdminAgent, MultiStepRAGAgent}`. The benchmark uses generated bundles and does not read this corpus.
- Direct falsifiers: a new Ed25519 key signed a bundle that was approved; a signed bundle with `traces=[]` and `execution_traces_count=3` was approved; the same fresh bundle was approved twice without a caller-supplied nonce store; and a default HMAC bundle was approved. These results independently follow from evidence-controlled public-key verification (`assurance/policy.py:130-140`), truthy-only Merkle validation (`151-161`), caller-owned non-persistent nonce state (`195-221`; `assurance/verifier.py:13-33`), and the HMAC policy allowance (`governance/release_policy.yaml:8-10`).
- A SHA-256 root has `64` hexadecimal characters but `32` decoded bytes. A 10,000-trace proof for one audited index had `14` siblings and compact JSON size `1,435` bytes; this does not establish an unspecified aggregate `<5 KB` transmission bound.

## Findings

- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-135 — the gate still accepts a valid Ed25519 signature under an attacker-selected public key because policy contains no trusted public-key, issuer, or KMS-identity binding.
  evidence: a newly generated key signed a fresh evidence bundle and `ReleasePolicyEngine.evaluate()` returned `(True, [])`; `governance/release_policy.yaml:6-21` provides only algorithm selection and a revoked-key denylist. This round-1 through round-5 bypass persists in current source and execution.
  remedy: bind accepted key IDs, public keys, and KMS identities to policy-controlled trust roots, reject unknown keys, and add the attacker-key bundle as a negative regression vector.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:151-161 — the gate still approves an empty trace list with a signed declared count of three, so trace omission is not completely mediated.
  evidence: a fresh signed default bundle altered only to `traces=[]` returned `(True, [])`; Merkle verification is skipped for an empty list and no code compares `execution_traces_count` with actual traces. The remedy identified in rounds 1-5 is absent.
  remedy: require exact count equality, define and validate the empty-tree root, and add empty, shortened, and count-mismatch adversarial tests.
- [BLOCKER] (science.replay_protection) assurance/verifier.py:13-33 — the deployable invocation accepts no durable nonce store and never records an approved nonce, permitting replay.
  evidence: evaluating the identical fresh bundle twice with `ReleasePolicyEngine.evaluate()` returned `(True, [])` both times; V4 only blocks because `benchmark/tamper_vectors.py:129-131` pre-populates a copied set. This round-4/5 finding persists.
  remedy: atomically commit approved nonces to a durable shared store with expiry, fail closed on store failure, and test first and second production-path submissions.
- [BLOCKER] (science.key_management) governance/release_policy.yaml:8-10 — HMAC-SHA256 with a source-embedded secret is accepted, contradicting the claimed Ed25519/HSM/KMS-rooted asymmetric assurance.
  evidence: `create_evidence_pack(use_ed25519=False)` evaluated as `(True, [])`; `DEFAULT_SECRET_KEY` is a source literal at `assurance/evidence.py:27`, and policy neither pins trusted keys/KMS ARNs nor requires a default threshold above one. This round-4/5 finding persists.
  remedy: remove HMAC demonstration mode from production policy and require policy-pinned asymmetric keys with independently verified KMS identity, or obtain human approval to narrow the claim.
- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 — released data contain five profiles and two anomalies, not the manuscript's 50 profiles, five represented architectures, 15 anomalies, or reproducible 15/15 block result.
  evidence: direct parsing found 5 profiles, 2 non-`CLEAN` labels, 10 trace rows, and 3 architectures; `scripts/run_release_benchmark.py:99-141` reads no corpus input and cannot produce 15/15. The missing corpus/evaluator reported in rounds 1-5 was not added.
  remedy: provide the claimed versioned corpus and a per-profile result producer, or obtain human approval to revise every corpus and 15/15 claim to audited data.
- [MAJOR] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59 — all three exact abstract performance figures remain stale against the current result artifact and fresh independent execution.
  evidence: `results/benchmark_summary.json:37-42` records 39.081 ms and 0.1206%, while lines 67-72 record 5841.27 ops/s; the manuscript states 39.59 ms, 0.1221%, and 5883.86 ops/s. A fresh in-memory producer call returned 41.160 ms, 0.1187%, and 5872.13 ops/s.
  remedy: retain authoritative raw timing runs, resolve the experiment revision and methodology, then submit a human-reviewed proposal for corrected claims.
- [MAJOR] (science.methods_statistics) scripts/run_release_benchmark.py:31-141 — the stated 1,000-run means and standard-error bounds are not implemented, and the claimed linear scaling is false for reproduced data.
  evidence: each trace count has one timing, each worker count has one aggregate 1,000-request batch, and each vector runs once; no repetition, warm-up, sample persistence, standard-error/percentile calculation, seed, load state, timeout, or exclusion record exists. Stored one-to-eight-worker speedup is 3.96x.
  remedy: collect versioned repeated samples with a predeclared warm-up, exclusion, and aggregation protocol plus environment/load metadata; report justified intervals and measured speedup.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 — claimed comparisons to OPA/Kyverno and Sigstore/Cosign are local predicates rather than executions of named systems.
  evidence: `eval_opa_schema_gate` checks two fields and `eval_sigstore_cosign_gate` checks signature presence and pass rate; the producer imports or invokes no baseline implementation, version, policy, or decision log. Its 0/3/3/12 counts are only counts for stand-ins.
  remedy: evaluate version-pinned external baselines with archived configurations, commands, inputs, and per-vector decisions, or obtain human approval to relabel the comparison as local predicate ablations.
- [MAJOR] (science.attack_construct_validity) benchmark/tamper_vectors.py:167-184 — V10 and V12 do not reach the JSON-canonicalization or sparse-proof mechanisms attributed to them.
  evidence: V10 only sets `test_pass_pct=99.9`; V12 shortens `traces`; `assurance/policy.py:149-161` consumes neither serialized JSON bytes nor `sparse_proofs`. Rerun V10 reported signature and pass-rate violations, and V12 reported only a root mismatch.
  remedy: use parser-boundary alternate/duplicate-key and proof-verifier malformed-path inputs with isolated success criteria and vector-specific rejection reasons.
- [MINOR] (repro.claim_provenance) docs/usenix_paper_manuscript.tex:125-134 — the manuscript calls a SHA-256 root 64 bytes and asserts a sub-5-KB proof-transmission bound without a result artifact specifying audit-set size or serialization.
  evidence: `assurance/crypto.py:16-20` emits 64 hex characters, which decode to 32 bytes; an independently generated one-index 10,000-trace proof is 1,435 compact-JSON bytes, while no benchmark emits an aggregate proof-size measurement.
  remedy: correct bytes-versus-encoded-character terminology and emit a versioned size artifact keyed by trace count, audited indices, encoding, and regeneration command.

## Data required

- `DATA_REQUIRED`: versioned raw corpus with exactly 50 profile rows, 15 anomaly rows, stable IDs, all five architecture labels, trace inputs, labels, schema, and a per-profile gate-result artifact; this permits audit of the corpus and 15/15 claims.
- `DATA_REQUIRED`: repeated raw timing records for every trace-count and worker-count configuration, including run ID, monotonic timings, warm-up flag, hardware/OS/Python/dependency versions, load state, failures/timeouts, exclusions, and script revision; this permits valid centers, intervals, scaling, and precision.
- `DATA_REQUIRED`: version-pinned OPA/Kyverno and Sigstore/Cosign configurations, inputs, commands, versions, and per-vector decision logs; this permits a named-baseline comparison.
- `DATA_REQUIRED`: paired representative trace-execution and packaging duration observations from a documented workload; this permits an operational end-to-end overhead calculation.

## Commands run

- `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/ -v` — exit 0, 0.04 s; 14 passed. The suite does not test the four approved bypasses.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_release_gate.py --format json` — exit 0; generated default evidence was `APPROVED`.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... stored artifact arithmetic and Wilson interval ...'` — exit 0; observed 0.1205727% stored ratio, 5841.1215 ops/s from displayed elapsed time, 3.9571x stored speedup, 12/12 tamper blocks, comparison 0/3/3/12, and Wilson lower bound 75.7506%.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... raw corpus parse ...'` — exit 0; observed declared 50 versus actual 5 profiles, 2 anomalies, 10 traces, and 3 architectures.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... attacker key, empty traces, replay, HMAC ...'` — exit 0; attacker key, trace omission/count mismatch, replay, and HMAC bundles all approved.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c 'from scripts.run_release_benchmark import ...'` — exit 0; non-writing in-memory producer call observed 178.078-ms packaging, 41.160-ms Merkle construction, 0.1187% synthetic ratio, 5872.13 ops/s, and 12/12 curated denials.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... in-memory comparative predicates ...'` — exit 0; recomputed 0/3/3/12 blocked outcomes without writing result artifacts.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... V10/V12 mechanism recheck ...'` — exit 0; V10 was rejected for signature/pass-rate violations and V12 for a Merkle-root mismatch.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... 10,000-trace sparse proof serialization ...'` — exit 0; observed 64 hex characters / 32 root bytes, 14 proof steps, and 1,435 compact-JSON bytes.

The standalone documented benchmark and comparison commands were not invoked because they overwrite the tracked result artifacts. Their raw JSON was independently recomputed and their producers were exercised in memory; no manuscript, source, corpus, governance, test, or result value was manually edited by this audit.

### from analysis-round-5.md

# Analytical audit — round 5

## Executive decision
NOT YET SUPPORTED. The unit suite, documented benchmark, comparison script, and default gate invocation reproduce, but four independently constructed adversarial bundles are approved despite violating the paper's stated release-assurance boundary. The corpus, named-baseline, and performance claims remain contradicted by released evidence or unsupported by raw repeated measurements; the freshly regenerated result artifact also disagrees with the abstract's exact values.

## Claim ledger

| Claim | Source, artifact key, producer/input/command | Recomputation | Result | Status |
|---|---|---|---|---|
| "100.0% (12/12)" block rate | `docs/usenix_paper_manuscript.tex:59,283`; `results/benchmark_summary.json:75-216`, `tamper_resilience`; `scripts/run_release_benchmark.py:evaluate_tamper_resilience`; 12 generated payloads from `benchmark/tamper_vectors.py`; `python3 scripts/run_release_benchmark.py` | Count `vector_details[*].blocked` | 12/12 deterministic curated payloads denied | VERIFIED only for this suite |
| CI 0/12, OPA/Sigstore 3/12, EviAssure 12/12 | `docs/usenix_paper_manuscript.tex:59,300`; `results/comparative_evaluation.json:3-106`; `scripts/run_comparative_eval.py:main`; same 12 generated payloads; `python3 scripts/run_comparative_eval.py` | Sum the four Boolean columns | 0, 3, 3, and 12 blocks | VERIFIED for local predicates, not named systems |
| 5,883.86 ops/s at 8 cores, "linear" scaling | `docs/usenix_paper_manuscript.tex:59,244`; `results/benchmark_summary.json:67-72`; `measure_parallel_throughput`; one 1,000-task process-pool batch; `python3 scripts/run_release_benchmark.py` | `1000 / elapsed_seconds`; 8-worker/1-worker rate | Fresh artifact: 5,841.27 displayed ops/s; displayed time gives 5,841.12; speedup is 3.96x | CONTRADICTED; no repeated-run evidence |
| 100,000 traces in 39.59 ms, 0.1221% overhead | `docs/usenix_paper_manuscript.tex:59,234`; `results/benchmark_summary.json:37-42`; `measure_merkle_scaling`; synthetic 1.5-ms traces; `python3 scripts/run_release_benchmark.py` | `180.859/(100000*1.5)*100` | Fresh artifact: 39.081 ms build and 0.1206% synthetic ratio | CONTRADICTED / DRIFTED |
| 50 profiles, 15 anomalies, 15/15 blocked | `docs/usenix_paper_manuscript.tex:225-226`; `corpus/agent_trace_corpus.json:4-58`; no corpus-result artifact or producer; direct JSON parse | Count raw profiles, labels, traces, architectures | 5 profiles, 2 anomalies, 10 traces, 3 architectures; no 15/15 output | CONTRADICTED |
| Gate rejects unauthenticated or modified evidence | `docs/usenix_paper_manuscript.tex:111,200-218`; `assurance/policy.py:77-228`, `assurance/verifier.py:13-33`; policy YAML; adversarial construction command below | Evaluate attacker-key, trace-omission, replay, and HMAC bundles | All four bundles approved | CONTRADICTED |
| Ed25519/KMS-rooted threshold assurance | `docs/usenix_paper_manuscript.tex:59,67,73,76,85-86`; `governance/release_policy.yaml:6-21`; `assurance/evidence.py:27,107-121`; default gate command | Inspect accepted algorithms/key policy and evaluate HMAC bundle | HMAC with source-embedded secret is accepted; no trusted public-key/KMS binding; default threshold is one | CONTRADICTED |
| 64-byte root, `<5 KB` sparse proof transmission, and `O(log N)` paths | `docs/usenix_paper_manuscript.tex:125-134`; `assurance/crypto.py:16-20,55-85`; `EvidenceBundle.generate_sparse_proofs`; command below | Decode root and serialize one 10,000-trace proof | 64 hex characters = 32 bytes; 14 steps, 1,437-byte compact JSON proof; no aggregate-size artifact | Root unit CONTRADICTED; asymptotic path VERIFIED; bound UNSOURCED |

## Independent calculations

- Tamper rate: `12 / 12 * 100 = 100.0%`. Wilson 95% confidence interval for `x=12, n=12` is `75.75%` to `100.0%`; the harness constructs one deterministic payload per vector, so it is not a sampled attack population or 1,000 repetitions.
- Fresh comparative rows give `CI=0/12`, local OPA-schema predicate `3/12`, local Sigstore/Cosign predicate `3/12`, and EviAssure `12/12`. `scripts/run_comparative_eval.py:20-34` implements those named baselines as local field predicates and executes no OPA, Kyverno, Sigstore, or Cosign binary/configuration.
- Fresh 100,000-trace synthetic overhead: `180.859 ms / (100000 * 1.5 ms) * 100 = 0.1205727%`, rounding to the persisted `0.1206%`. The 1.5-ms denominator is assigned in `scripts/run_release_benchmark.py:42`, not measured trace execution time.
- Fresh displayed throughput arithmetic: `1000 / 0.1712 s = 5841.1215 ops/s`, close to the producer's pre-rounding `5841.27`; measured 1-to-8-worker speedup is `5841.27 / 1476.14 = 3.9571x`, not 8x linear scaling.
- Corpus denominator: raw JSON gives `declared_profiles=50`, `actual_profiles=5`, `anomalies=2`, `traces=10`, and three observed architectures. The benchmark consumes generated bundles rather than this corpus, so no released command calculates 15/15.
- Direct falsifiers: a newly generated Ed25519 key signed a bundle accepted by `ReleasePolicyEngine.evaluate()`; a normally signed bundle with `traces=[]` and signed `execution_traces_count=3` was accepted; evaluating one fresh bundle twice without supplied state approved both submissions; and `create_evidence_pack(use_ed25519=False)` was accepted. These results follow independently from evidence-controlled public-key verification (`assurance/policy.py:130-140`), truthy-only Merkle verification (`151-161`), non-persistent caller-owned replay state (`195-221`), and policy-allowed HMAC (`governance/release_policy.yaml:8-10`).
- SHA-256 output is 64 hexadecimal characters, decoding to 32 bytes. A compact JSON sparse proof for index 0 among 10,000 synthetic traces has 14 siblings and is 1,437 bytes; this does not establish the manuscript's unspecified total transmission claim.

## Findings

- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-135 — the gate still accepts a valid Ed25519 signature under an attacker-selected public key because policy contains no trusted public-key, issuer, or KMS-identity binding.
  evidence: a fresh generated key signed a fresh evidence bundle and `ReleasePolicyEngine.evaluate()` returned `(True, [])`; `governance/release_policy.yaml:6-21` provides only algorithm selection and a revoked-key denylist. This round-1 through round-4 bypass persists in current source and execution.
  remedy: bind accepted key IDs, public keys, and KMS identities to policy-controlled trust roots, reject unknown keys, and add the attacker-key bundle as a negative regression vector.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:151-161 — the gate still approves an empty trace list with a signed declared count of three, so trace omission is not completely mediated.
  evidence: a fresh signed default bundle altered only to `traces=[]` returned `(True, [])`; Merkle verification is skipped for an empty list and no code compares `execution_traces_count` with actual traces. This is the previously reported bypass and its remedy is absent.
  remedy: require exact count equality, define and validate the empty-tree root, and add empty, shortened, and count-mismatch adversarial tests.
- [BLOCKER] (science.replay_protection) assurance/verifier.py:13-33 — the deployable invocation accepts no durable nonce store and never records an approved nonce, permitting replay.
  evidence: evaluating the identical fresh bundle twice with `ReleasePolicyEngine.evaluate()` returned `(True, [])` both times; V4 only blocks because `benchmark/tamper_vectors.py:129-131` manually pre-populates a copied nonce set. This round-4 finding persists.
  remedy: atomically commit approved nonces to a durable shared store with expiry, fail closed on store failure, and test first and second production-path submissions.
- [BLOCKER] (science.key_management) governance/release_policy.yaml:8-10 — HMAC-SHA256 with a source-embedded secret is accepted, contradicting the claimed Ed25519/HSM/KMS-rooted asymmetric assurance.
  evidence: `create_evidence_pack(use_ed25519=False)` evaluated as `(True, [])`; `DEFAULT_SECRET_KEY` is literal source at `assurance/evidence.py:27`, and policy neither pins trusted keys/KMS ARNs nor requires a default threshold above one. This round-4 finding persists.
  remedy: remove HMAC demonstration mode from production policy and require policy-pinned asymmetric keys with independently verified KMS identity, or human-approve a narrower symmetric demonstration claim.
- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 — released data contain five profiles and two anomalies, not the claimed 50 profiles, five represented architectures, 15 anomalies, or reproducible 15/15 block result.
  evidence: direct JSON parsing found 5 profiles, 2 non-`CLEAN` labels, 10 trace rows, and 3 architectures; `scripts/run_release_benchmark.py:99-141` reads no corpus input and therefore cannot produce 15/15. The missing corpus/evaluator identified in rounds 1-4 was not added.
  remedy: provide the claimed versioned corpus and a per-profile result artifact/producer, or obtain human approval to revise all corpus and 15/15 claims to audited data.
- [MAJOR] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59 — all three exact abstract performance figures remain stale after the documented benchmark regenerated its result artifact.
  evidence: fresh `results/benchmark_summary.json:37-42` records 39.081 ms and 0.1206%, while lines 67-72 record 5,841.27 ops/s; the manuscript states 39.59 ms, 0.1221%, and 5,883.86 ops/s. Independent arithmetic from persisted displayed times confirms the mismatch.
  remedy: retain authoritative raw timing runs, resolve the methodology and experiment revision, then submit a human-reviewed proposal for revised scientific claims.
- [MAJOR] (science.methods_statistics) scripts/run_release_benchmark.py:31-141 — the manuscript's claim of 1,000-run means and standard-error bounds is not implemented, and its scaling statement is false for the reproduced data.
  evidence: each trace count has one timing, each worker count has one aggregate 1,000-request batch, and vectors run once; there is no repetition, warm-up, sample persistence, standard-error/percentile calculation, seed, load state, timeout, or exclusion record. Fresh 1-to-8-worker scaling is 3.96x, not linear 8x.
  remedy: collect versioned repeated samples under a predeclared warm-up/exclusion protocol with environment/load metadata, report intervals and justified precision, and report measured rather than linear scaling.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 — claimed comparisons to OPA/Kyverno and Sigstore/Cosign are local predicates rather than executions of named systems.
  evidence: `eval_opa_schema_gate` checks two fields and `eval_sigstore_cosign_gate` checks signature presence and pass rate; the producer imports or invokes no baseline implementation, version, policy, or decision log. Its 0/3/3/12 raw counts are thus only counts for these stand-ins.
  remedy: evaluate version-pinned external baselines with archived configurations, commands, inputs, and per-vector decisions, or human-approve relabeling as local predicate ablations.
- [MAJOR] (science.attack_construct_validity) benchmark/tamper_vectors.py:167-184 — V10 and V12 do not reach the JSON-canonicalization or sparse-proof mechanisms attributed to them.
  evidence: V10 only sets `test_pass_pct=99.9`; V12 shortens `traces`; `assurance/policy.py:149-161` consumes neither serialized JSON bytes nor `sparse_proofs`. Fresh V10 output reports signature and pass-rate violations, not canonicalization.
  remedy: use parser-boundary alternate/duplicate-key and proof-verifier malformed-path inputs with isolated success criteria and vector-specific rejection reasons.
- [MINOR] (repro.claim_provenance) docs/usenix_paper_manuscript.tex:125-134 — the manuscript calls a SHA-256 root 64 bytes and asserts a sub-5-KB proof transmission bound without a result artifact specifying audit-set size or serialization.
  evidence: `assurance/crypto.py:16-20` emits 64 hex characters, which decode to 32 bytes; an independently generated one-index, 10,000-trace proof is 1,437 compact-JSON bytes, while no benchmark emits an aggregate proof-size measurement.
  remedy: correct bytes versus encoded-character terminology and emit a versioned proof-size artifact keyed by trace count, audited indices, encoding, and regeneration command.

## Data required

- `DATA_REQUIRED`: versioned raw corpus with exactly 50 profile rows, 15 anomaly rows, stable IDs, all five architecture labels, trace inputs, labels, schema, and a per-profile gate-result artifact; this permits audit of the corpus and 15/15 claims.
- `DATA_REQUIRED`: repeated raw timing records for every trace-count and worker-count configuration, including run ID, monotonic timings, warm-up flag, hardware/OS/Python/dependency versions, load state, failures/timeouts, exclusions, and script revision; this permits valid centers, intervals, scaling, and precision.
- `DATA_REQUIRED`: version-pinned OPA/Kyverno and Sigstore/Cosign configurations, inputs, commands, versions, and per-vector decision logs; this permits a named-baseline comparison.
- `DATA_REQUIRED`: paired representative trace-execution and packaging duration observations from a documented workload; this permits an operational end-to-end overhead calculation.

## Commands run

- `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/ -v` — exit 0, 0.04 s; 14 passed. The suite does not test the four approved bypasses.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_release_gate.py --format json` — exit 0; generated default evidence was `APPROVED`.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py` — exit 0; regenerated 39.081-ms 100K Merkle build, 0.1206% synthetic ratio, 5,841.27 ops/s at eight workers, and 12/12 curated denials.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_comparative_eval.py` — exit 0; regenerated 0/12 CI, 3/12 local OPA predicate, 3/12 local Sigstore predicate, and 12/12 EviAssure denials.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... corpus parse ...'` — exit 0; observed declared 50 versus actual 5 profiles, 2 anomalies, 10 traces, and 3 architectures.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... attacker key, empty traces, replay, HMAC ...'` — exit 0; all four adversarial bundles were approved.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... artifact arithmetic and Wilson interval ...'` — exit 0; observed 0.1205727% ratio, 5,841.1215 ops/s from displayed time, 3.9571x speedup, raw counts 12/12 and 0/3/3/12, and 75.75% Wilson lower bound.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... 10,000-trace sparse proof serialization ...'` — exit 0; observed 64 hex characters / 32 root bytes, 14 proof steps, and 1,437 compact-JSON bytes.

The documented benchmark and comparison commands overwrite their generated result JSONs; this was required for the end-to-end reproduction pass. No manuscript, source, corpus, governance, test, or result value was manually edited by this audit.

### from analysis-round-4.md

# Analytical audit — round 4

## Executive decision
NOT YET SUPPORTED. The narrow deterministic 12-vector suite, unit tests, and default gate invocation reproduce, but four direct counterexamples still receive approval: attacker-selected Ed25519 keys, empty trace lists with a claimed nonzero count, replay through the deployable stateless path, and HMAC signatures using an embedded secret. The corpus, named-baseline, and performance claims remain contradicted by the released data or unsupported by retained repeated measurements; current result artifacts also disagree with the exact abstract values.

## Claim ledger

| Claim | Source | Recomputation | Result | Status |
|---|---|---|---|---|
| 100.0% (12/12) fail-closed block rate | manuscript:59,294; `results/benchmark_summary.json:75-216` | Count `vector_details[*].blocked`; producer `scripts/run_release_benchmark.py:evaluate_tamper_resilience`; command below | 12/12 curated deterministic specimens denied; fresh in-memory run also 12/12. Wilson 95% CI is 75.8%-100.0%. | VERIFIED only for this suite |
| CI 0/12; OPA/Sigstore 3/12; EviAssure 12/12 | manuscript:59,311; `results/comparative_evaluation.json:3-106` | Sum raw booleans; producer `scripts/run_comparative_eval.py:main`; command below | 0, 3, 3, 12 blocks. | VERIFIED for local predicates, not named systems |
| 5,883.86 ops/s on 8 cores; linear scaling | manuscript:59,255; `results/benchmark_summary.json:67-72` | `1000 / elapsed_seconds`; producer `measure_parallel_throughput`; in-memory command below | Stored displayed elapsed time gives 5,878.8948 ops/s; stored speedup is 4.1995x from one to eight workers. Fresh batch: 5,984.8 ops/s. | CONTRADICTED / unsupported precision |
| 100,000 traces in 39.59 ms and 0.1221% overhead | manuscript:59,245; `results/benchmark_summary.json:37-42` | `packaging_latency_ms / (trace_count * 1.5) * 100`; producer `measure_merkle_scaling`; command below | Stored: 186.411 ms packaging, 40.525 ms Merkle, 0.124274% derived overhead. Fresh: 177.873 ms packaging, 40.507 ms Merkle, 0.1186%. | CONTRADICTED / unsupported precision |
| 50 profiles, five architectures, 15 anomalies, 15/15 blocked | manuscript:232-238; `corpus/agent_trace_corpus.json:4-58` | Parse raw profile rows; no producer maps corpus profiles to decisions. | 5 profiles, 3 observed architectures, 2 anomalies, 10 traces. | CONTRADICTED |
| Gate rejects unauthenticated or modified evidence | manuscript:111,211-228; `assurance/policy.py:77-228`; `assurance/verifier.py:13-33` | Construct and evaluate four permitted adversarial bundles; command below. | Attacker key, empty traces/count 3, replay without durable state, and HMAC bundle all approve. | CONTRADICTED |
| Ed25519/KMS-rooted, threshold assurance | manuscript:59,67,73,76,85-86; `governance/release_policy.yaml:6-21` | Inspect policy and exercise accepted HMAC path. | HMAC-SHA256 is allowed; secret is source-embedded; policy pins neither trusted public keys nor KMS ARN and requires one signature by default. | CONTRADICTED |
| 64-byte root, sub-5-KB sparse proof transmission, O(log N) proofs | manuscript:125-134; `assurance/crypto.py:16-20,55-85`; `assurance/evidence.py:185-206` | Decode root and serialize a 10,000-trace one-index proof; command below. | Root is 64 hex characters = 32 bytes; generated proof has 14 steps and is 1,435 bytes for one proof. O(log N) implementation is present, but no artifact supports the stated transmission bound. | Root unit CONTRADICTED; size bound UNSOURCED |

## Independent calculations

- Tamper block rate: `12 blocked / 12 vectors * 100 = 100.0%`. Wilson 95% interval for `x=12, n=12` is 75.8%-100.0%; one constructed vector per case is neither 1,000 repetitions nor a sampled attack population. `evaluate_tamper_resilience()` reproduced `12/12` in memory.
- Comparative counts from every raw detail row: CI `0/12 = 0.0%`; local OPA-schema predicate `3/12 = 25.0%`; local Sigstore/Cosign predicate `3/12 = 25.0%`; EviAssure `12/12 = 100.0%`. The producer's functions at `scripts/run_comparative_eval.py:20-34` invoke no OPA, Kyverno, Sigstore, or Cosign; an in-memory recomputation produced `(0, 3, 3, 12)`.
- Current stored overhead: `186.411 ms / (100000 * 1.5 ms) * 100 = 0.124274%`, which rounds to `0.1243%`, not `0.1221%`. The denominator is the assigned synthetic trace duration at `scripts/run_release_benchmark.py:42`, not an execution-workload duration. The stored eight-worker rate is `1000 / 0.1701 s = 5878.8948 ops/s`, not `5883.86`; stored one-to-eight speedup is `5878.56 / 1399.81 = 4.1995x`, not linear 8x.
- Fresh non-writing in-memory benchmark calls yielded 100K `packaging_ms=177.873`, `merkle_ms=40.507`, synthetic ratio `0.1186%`, and eight-worker `5984.8 ops/s`. The script records no repetitions, warm-up, seed, CPU/load state, timeout, exclusion, percentile, or standard-error samples, so neither stored nor fresh values establish a mean or uncertainty bound.
- Raw corpus denominator: declared profiles `50`; actual `len(profiles)=5`; anomaly labels `2`; trace rows `10`; represented architectures `3`. The benchmark generator uses synthetic default bundles and never reads this corpus, so no released artifact can calculate `15/15`.
- Direct falsifiers, independently rerun: `ReleasePolicyEngine.evaluate()` approved a bundle signed by a newly generated Ed25519 key because it verifies the evidence-supplied public key (`assurance/policy.py:130-135`); approved a normally signed bundle altered only to `traces=[]` while retaining `execution_traces_count=3` because validation is conditional on truthiness and no count check exists (`151-161`); approved the same fresh bundle twice through `evaluate()` without a caller-managed nonce set because neither the verifier nor engine stores accepted nonces (`assurance/verifier.py:13-33`, `assurance/policy.py:195-221`); and approved an HMAC bundle because HMAC is policy-allowed (`governance/release_policy.yaml:8-10`) with `DEFAULT_SECRET_KEY` embedded at `assurance/evidence.py:27`.
- SHA-256 output has `64` hexadecimal characters and `32` decoded bytes. A generated 10,000-trace proof contains `14` siblings and its compact JSON serialization is `1,435` bytes for one audited index. This demonstrates logarithmic path length but does not substantiate the manuscript's unspecified aggregate `<5 KB` transmission claim.

## Findings

- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-135 — the gate still accepts a valid Ed25519 signature under an attacker-selected public key because no trusted key, issuer, or KMS binding is policy-controlled.
  evidence: a newly generated key signed a fresh bundle and `ReleasePolicyEngine.evaluate()` returned `True, []`; `governance/release_policy.yaml:6-21` has only an algorithm allowlist and revoked-key denylist. This is the round-1 through round-3 bypass, and the current source still has no prior remedy.
  remedy: bind each accepted key ID, public key, and KMS identity to trusted governance data; reject unknown keys; add the attacker-key bundle as a regression vector.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:151-161 — the gate still approves an empty submitted trace list when the signed declared trace count is three, so trace omission is not completely mediated.
  evidence: a fresh signed default bundle changed only to `traces=[]` returned `True, []`; Merkle recomputation is skipped for an empty list and the declared count is never compared. This is the round-1 through round-3 bypass, and no count-validation remedy appears in current source.
  remedy: require declared count to equal submitted traces, define and validate the zero-trace root, and add empty, shortened, and count-mismatch vectors.
- [BLOCKER] (science.replay_protection) assurance/verifier.py:13-33 — the deployable invocation path does not maintain or atomically commit a durable nonce store, so a fresh bundle can be replayed.
  evidence: two consecutive `ReleasePolicyEngine.evaluate(bundle)` calls returned `True` then `True` with no violations; `evaluate_release_gate` defaults `seen_nonces` to `None`, and policy checks only a caller-supplied set without adding an accepted nonce. V4 instead pre-populates a copied set in `benchmark/tamper_vectors.py:129-131`.
  remedy: use an atomic durable nonce store shared across invocations, commit only approved nonces with expiry, and benchmark the first and second production-path submissions.
- [BLOCKER] (science.key_management) governance/release_policy.yaml:8-10 — the accepted implementation permits HMAC-SHA256 using a source-embedded secret, contradicting the paper's asymmetric Ed25519, HSM/KMS-rooted assurance claims.
  evidence: `create_evidence_pack(use_ed25519=False, signed=True)` was approved; `DEFAULT_SECRET_KEY` is literal source at `assurance/evidence.py:27`, policy accepts `hmac-sha256`, and it specifies no trusted key, KMS ARN, or default threshold greater than one.
  remedy: remove demonstration HMAC from production policy and pin trusted Ed25519/KMS identities, or obtain human approval to scope the paper to symmetric demonstration mode.
- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 — released raw data contain 5 profiles and 2 anomalies, not the manuscript's 50 profiles, five represented architectures, 15 anomalies, or reproducible 15/15 block result.
  evidence: direct parse found `declared:50, actual:5, anomalies:2, traces:10, architectures:3`; `scripts/run_release_benchmark.py:99-141` does not read this corpus. This round-1 through round-3 finding persists because neither data nor a corpus-to-gate producer was added.
  remedy: provide the claimed immutable corpus and per-profile decision producer, or obtain human approval to revise every corpus and 15/15 claim to audited data.
- [MAJOR] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59 — headline performance and overhead values remain stale against the current result artifact.
  evidence: `results/benchmark_summary.json:37-42` records 40.525 ms Merkle time and 0.1243% overhead, while lines 67-72 record 5878.56 ops/s; independent arithmetic from displayed elapsed time gives 5878.8948 ops/s. Fresh in-memory values also differ.
  remedy: retain authoritative raw runs and submit a human-reviewed proposal for revised claims; do not copy artifact values into the paper without resolving methodology.
- [MAJOR] (science.methods_statistics) scripts/run_release_benchmark.py:31-141 — the claimed 1,000-run means and standard-error bounds are not produced: each Merkle size is timed once, each worker count is one 1,000-request batch, and each attack vector is evaluated once.
  evidence: the producer has no repetition/warm-up loop, raw-sample persistence, standard-error calculation, percentile calculation, seed control, or timeout/exclusion record; fresh 100K and eight-worker values differ from the printed values.
  remedy: retain repeated timing samples with a predeclared warm-up, exclusion, and aggregation protocol plus environment/load metadata; report appropriately rounded intervals and measured speedup.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 — the named OPA/Kyverno and Sigstore/Cosign comparisons are hand-written local predicates, not executions of those systems.
  evidence: recomputed artifact counts are 0/3/3/12, but the script imports and invokes no external baseline, policy, binary, version, or decision log. This prior finding remains unresolved.
  remedy: evaluate version-pinned external baselines on equivalent inputs and archive configurations and decisions, or obtain human approval to relabel the results as toy predicate ablations.
- [MAJOR] (science.attack_construct_validity) benchmark/tamper_vectors.py:167-184 — V10 and V12 do not exercise the canonical-JSON or sparse-proof mechanisms attributed in the manuscript.
  evidence: V10 only sets `test_pass_pct=99.9`; V12 shortens `traces`; `assurance/policy.py:149-161` parses neither serialized JSON bytes nor `sparse_proofs`. The V10 artifact attributes rejection to invalid signature and pass-rate checks.
  remedy: construct parser-boundary duplicate/alternate-key and proof-verifier malformed-path inputs with isolated success criteria and record vector-specific rejection reasons.
- [MINOR] (repro.claim_provenance) docs/usenix_paper_manuscript.tex:125-134 — the manuscript calls a SHA-256 root 64 bytes and asserts a sub-5-KB proof transmission bound without a result artifact or specified audit set.
  evidence: `hash_sha256` emits 64 hexadecimal characters, decoding to 32 bytes; a one-index 10K proof serialized to 1,435 bytes, while no producer records a total proof transmission size for a stated number of audited traces.
  remedy: correct byte-versus-hex terminology and emit a versioned size artifact with trace count, audited-index count, encoding, and regeneration command.

## Data required

- `DATA_REQUIRED`: a versioned corpus file with exactly 50 profile rows and 15 anomaly rows, stable IDs, all five architecture labels, trace inputs, labels, schema, and a per-profile gate-result artifact mapping every anomaly ID to a decision; this unlocks the corpus and 15/15 claims.
- `DATA_REQUIRED`: raw repeated performance records for every trace-count and worker-count configuration, with run ID, monotonic timings, warm-up flag, CPU/OS/Python/dependency versions, load state, failures/timeouts, exclusions, and script revision; this unlocks valid centers, intervals, scaling, and precision.
- `DATA_REQUIRED`: version-pinned OPA/Kyverno and Sigstore/Cosign configurations, input artifacts, commands, versions, and per-vector decision logs; this unlocks the named baseline comparison.
- `DATA_REQUIRED`: paired representative trace-execution and packaging-duration observations for a documented workload; this unlocks a meaningful end-to-end packaging-overhead measure.

## Commands run

- `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/ -v` — exit 0, 0.04 s; 14 passed. The suite does not test the four approved bypasses.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_release_gate.py --format json` — exit 0; generated default evidence was `APPROVED`.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... raw benchmark/comparison/corpus arithmetic ...'` — exit 0; observed 0.124274% stored ratio, 5878.8948 ops/s from displayed elapsed time, 4.1995x stored speedup, 12/12 tamper blocks, comparison 0/3/3/12, corpus 50 declared versus 5 actual, and 32 decoded root bytes.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... attacker key, empty traces, replay, HMAC ...'` — exit 0; attacker key `True []`, empty traces/count 3 `True []`, replay without store `True True []`, and HMAC `True`.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c 'from scripts.run_release_benchmark import ...'` — exit 0; non-writing in-memory run observed 177.873 ms packaging, 40.507 ms Merkle, 0.1186% synthetic ratio, 5984.8 ops/s, and 12/12 blocks.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... 10000 trace proof serialization ...'` — exit 0; 64 root hex characters / 32 bytes, 14 proof steps, 1,435-byte compact JSON single proof.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c '... in-memory comparative predicates ...'` — exit 0; recomputed `(0, 3, 3, 12)` blocks without writing tracked result artifacts.

The documented `python3 scripts/run_release_benchmark.py` and `python3 scripts/run_comparative_eval.py` commands were not invoked as standalone programs because both overwrite tracked result artifacts. Their producers were exercised in memory and their persisted raw JSON was independently recomputed; this is a reproduction limitation for file-emission behavior, not evidence against the observed deterministic calculations.
