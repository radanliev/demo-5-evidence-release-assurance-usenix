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

## Gated findings (2 of them)

For each, write `.paperloop/state/proposals/<id>.md` containing: the finding,
what you believe the correct value or claim is, the exact diff you would apply,
and the evidence you would need to be sure. Then stop on those. A human decides.

## When you are done

Re-run `python3 .paperloop/run_gates.py --build` yourself and confirm the count
dropped. Then write a two-line summary of what you changed to
`.paperloop/state/round-3-writer.md`.

---

## AUTO-FIX MANDATE


- [MINOR] (venue.template) 
  could not measure PDF geometry: No module named 'pdfplumber'
  id: 66c5c40df5025c62


## GATED — PROPOSE ONLY, DO NOT EDIT THE PAPER


- [BLOCKER] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59
  manuscript says 0.1221% but the nearest recorded result is 0.1243 — likely a stale number from an earlier run
  found: …ion for   execution traces in   (representing a packaging overhead of 0.1221\%) with   sparse proof compression.…
  expected: 0.1243  (source: results/benchmark_summary.json::merkle_scaling[4].packaging_overhead_pct)
  remedy: Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
  id: 617c011523287e73

- [MAJOR] (science.stale_artifact) 
  2 result artifact(s) changed after the manuscript was last edited
  found: results/benchmark_summary.json; results/comparative_evaluation.json
  expected: manuscript newer than the data it reports
  remedy: Re-read those artifacts and confirm every dependent number, table and figure in the paper still matches.
  id: 1399079e29b05206


## REVIEWER FINDINGS (from the evaluator agents this round)


These come from an agent that read the paper rather than measured it. Apply the same split: `science.*` are gated and you may only propose; everything else is yours to fix.


### from review-round-3-paper-evaluator.md

- [BLOCKER] (science.complete_mediation) docs/usenix_paper_manuscript.tex:111, 211-228 — The stated fail-closed guarantee and theorem remain false for the implemented trust boundary: the verifier accepts a valid signature under an attacker-chosen Ed25519 public key and accepts an empty trace list while its signed declared trace count is nonzero.
  evidence: This was reported in round 2 and remains unfixed because the only writer action was a gate-dependency note (`.paperloop/state/round-2-writer.md:1-2`). `assurance/policy.py:130-135` verifies the evidence-supplied public key without a trusted-key/issuer binding, and lines 151-161 skip Merkle validation for `traces=[]` without checking `execution_traces_count`; the prior audit constructed both approved malicious bundles. The theorem's reduction therefore assumes away attacks admitted by the actual verifier.
  remedy: Human-gated proposal: bind accepted keys, key IDs, and KMS identities to policy-controlled trust roots; require the declared trace count and submitted trace list to agree and verify a defined empty-tree root; add attacker-key, omitted-trace, and count-mismatch attacks to the evaluation; then narrow or re-prove the theorem against the implemented, explicitly stated boundary.
- [BLOCKER] (science.replay_protection) docs/usenix_paper_manuscript.tex:111, 294-300, 310-317 — The manuscript claims replayed evidence is rejected and attributes a 12/12 result to nonce protection, but the deployable verifier accepts no durable nonce store and never records a nonce after approval, so repeated invocations with the same otherwise fresh bundle are approved.
  evidence: `assurance/verifier.py:13-33` defaults `seen_nonces` to `None` and passes it unchanged; `assurance/policy.py:195-221` only checks a caller-supplied set and does not add a newly accepted nonce. V4 is made to fail only because its benchmark manually pre-populates a copied set (`benchmark/tamper_vectors.py:129-131`; `tests/test_tamper_resilience.py:17-26`), not by exercising the production invocation path. This issue was not covered by the prior 12-vector construct-validity finding.
  remedy: Human-gated proposal: implement an atomic, durable nonce-replay store shared by gate invocations, commit a nonce only on accepted evidence, define expiry and failure behavior, and evaluate first submission plus a second submission through `evaluate_release_gate` without benchmark-supplied state; otherwise remove replay-protection claims and V4 attribution.
- [BLOCKER] (science.key_management) docs/usenix_paper_manuscript.tex:59, 67, 76, 85-86 — Claims of Ed25519/KMS-rooted, multi-signature assurance conflict with the accepted policy: it permits HMAC-SHA256 and verification with a source-embedded default symmetric secret, with no KMS ARN or trusted-key requirement.
  evidence: `governance/release_policy.yaml:7-16` allows `hmac-sha256` and has no trusted key, KMS ARN, or required signature threshold; `assurance/evidence.py:27` embeds `DEFAULT_SECRET_KEY`; `assurance/policy.py:79, 138-140` accepts a matching HMAC as a valid signature. `tests/test_release_gate_policy.py:61-77` demonstrates that a second HMAC signature is accepted. Thus the implementation does not provide the asymmetric, HSM/KMS-enforced authority assumed by the claimed architecture and proof.
  remedy: Human-gated proposal: either remove HMAC and require policy-pinned Ed25519 public keys with independently verified KMS identity, or explicitly scope the system to a demonstration symmetric-key mode and remove KMS/asymmetric-security claims; evaluate key compromise, unknown-key, and KMS-binding failures under the chosen design.
- [BLOCKER] (science.corpus_provenance) docs/usenix_paper_manuscript.tex:232-237 — The claimed 50-profile, five-architecture corpus with 15 planted anomalies and a 15/15 block result remains contradicted by the released corpus and has no producing evaluator.
  evidence: This is the round-2 blocker still present because no corpus or evaluator was added. `corpus/agent_trace_corpus.json` contains five profiles, two non-`CLEAN` labels, ten traces, and three represented architectures, while `benchmark/tamper_vectors.py:101-186` generates a separate synthetic 12-vector suite without reading the corpus.
  remedy: Human-gated proposal: release a versioned corpus containing the claimed profiles and anomaly IDs plus a corpus-to-gate evaluator that preserves one decision per profile, or revise all corpus size, architecture, anomaly, and 15/15 claims to the audited data.
- [MAJOR] (science.baseline_validity) docs/usenix_paper_manuscript.tex:59, 310-317 — The named CI, OPA/Sigstore, and Cosign comparison remains a comparison against hand-written local predicates, not the named systems, so its 0%, 25%, and claimed causal advantage are not meaningful deployment-baseline results.
  evidence: This round-2 finding remains unfixed. `scripts/run_comparative_eval.py:20-34` defines in-process CI, OPA-schema, and Sigstore/Cosign predicate functions and invokes none of OPA, Kyverno, Sigstore, or Cosign; `results/comparative_evaluation.json:3-106` consequently records outcomes only for those stand-ins.
  remedy: Human-gated proposal: run version-pinned OPA/Kyverno and Sigstore/Cosign with archived policies, commands, inputs, and per-vector logs under equivalent threat assumptions; otherwise relabel this as a local ablation and remove claims about the named systems.
- [MAJOR] (science.methods_statistics) docs/usenix_paper_manuscript.tex:242-255 — The performance methodology remains internally inconsistent: it calls values means across 1,000 runs with standard-error bounds, while each scaling point is one timing and each throughput point is one 1,000-request aggregate batch with no retained samples; the current artifact also disagrees with the exact printed headline numbers.
  evidence: The unresolved round-2 finding is reinforced by the current stale-artifact gate: `results/benchmark_summary.json:37-42` reports 40.525 ms and 0.1243% at 100K, and lines 67-72 report 5,878.56 ops/s, versus 39.59 ms, 0.1221%, and 5,883.86 in the manuscript. The producer has no repeated-run, warm-up, or standard-error calculation, and the 1-to-8 worker data are about 4.20x rather than the claimed linear scaling.
  remedy: Human-gated proposal: retain repeated raw samples with a preregistered warm-up/exclusion protocol and full environment metadata; report an appropriately rounded center and interval plus measured speedup, and either measure an end-to-end workload denominator or report packaging time without the synthetic-overhead claim.
- [MAJOR] (science.attack_construct_validity) docs/usenix_paper_manuscript.tex:294-307 — The 12/12 result is a curated denial count, not evidence that all named defenses work: V10 changes `test_pass_pct` rather than presenting a JSON malleability payload, V12 truncates traces rather than submitting a sparse proof, and the verifier never consumes `sparse_proofs`.
  evidence: This is the unresolved round-2 mechanism-coverage finding. `benchmark/tamper_vectors.py:167-184` implements V10 as `test_pass_pct=99.9` and V12 as a shortened trace list; `assurance/policy.py:149-161` parses neither JSON bytes nor sparse proofs. The stored V10 result reports an invalid signature and sub-threshold test rate, not canonicalization.
  remedy: Human-gated proposal: define executable adversarial inputs at the parser and proof-verifier boundaries, ensure each attack reaches the claimed defense, record vector-specific rejection reasons, and separate mechanism coverage from aggregate denial rate.
- [MAJOR] (science.technical_accuracy) docs/usenix_paper_manuscript.tex:125-134 — The paper still calls a SHA-256 digest root 64 bytes and states a sub-5-KB sparse-proof transmission bound without a size-producing artifact, undermining the claimed efficiency contribution.
  evidence: This prior finding remains unfixed. `assurance/crypto.py` returns a 64-character hexadecimal SHA-256 string, representing 32 bytes, and neither result JSON nor `scripts/run_release_benchmark.py` serializes sparse proofs or records their size; `EvidenceBundle.generate_sparse_proofs()` is not called by the benchmark.
  remedy: Human-gated proposal: correct bytes versus hexadecimal characters and add a reproducible serialized-proof-size measurement keyed by trace count, audit-set size, trace schema, and encoding before retaining a concrete transmission bound.

### from review-round-2-science-auditor.md

- [BLOCKER] (science.corpus_provenance) docs/usenix_paper_manuscript.tex:232-237 — The claimed 50-profile, five-architecture corpus with 15 anomalies and a 15/15 block result has no supporting data: the raw corpus holds five profiles, two anomalies, ten traces, and three represented architectures; no script evaluates those profiles.
  evidence: Claim ledger: the sentence at `docs/usenix_paper_manuscript.tex:232-237` reports 50/15/15; `corpus/agent_trace_corpus.json:4-58` declares `total_profiles=50` but `len(profiles)=5`, with two non-`CLEAN` labels and three distinct `architecture` values. The only tamper producer is `benchmark/tamper_vectors.py:101-186`, which does not read the corpus; `PYTHONDONTWRITEBYTECODE=1 python3 -c 'import json; c=json.load(open("corpus/agent_trace_corpus.json")); print(len(c["profiles"]), sum(p["label"] != "CLEAN" for p in c["profiles"]), sum(len(p["traces"]) for p in c["profiles"]))'` yields `5 2 10`. This is the round-1 blocker still present because the supplied corpus and per-profile producing script were not added.
  remedy: Human-gated proposal: either supply a versioned 50-profile corpus with 15 anomaly IDs plus a producer that emits one gate outcome per profile, or revise every 50/15/15 claim to audited counts; preserve the per-profile result artifact and a regeneration command before asserting a corpus block rate.
- [BLOCKER] (science.complete_mediation) docs/usenix_paper_manuscript.tex:111,211-228 — The fail-closed guarantee and security theorem claim that modified trace histories and unauthenticated evidence are rejected, but the gate accepts an attacker-chosen Ed25519 key and accepts an empty submitted trace list with a claimed nonzero count.
  evidence: Claim ledger: the guarantee is stated at `docs/usenix_paper_manuscript.tex:111` and theorem at lines 211-228; producer/implementation is `assurance/policy.py:77-228`, regenerable with `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests -v` plus an adversarial-bundle regression. At `assurance/policy.py:130-137`, verification trusts `public_key` supplied in the evidence and `governance/release_policy.yaml:19-21` supplies only a revoke list, not trusted issuers; at lines 150-161, Merkle validation is skipped for `traces=[]` and never checks `execution_traces_count`. These are the round-1 falsifiers still untested by `benchmark/tamper_vectors.py:101-186`; the 12/12 artifact does not include either attack.
  remedy: Human-gated proposal: bind verification to a policy-controlled trusted key/issuer set and independently validate the KMS identity; require declared trace count to equal submitted traces and verify the empty-tree root for zero traces. Add attacker-key, trace-omission, and count-mismatch vectors to the benchmark and only then scope the guarantee to the tested trust boundary.
- [MAJOR] (science.baseline_validity) docs/usenix_paper_manuscript.tex:59,310-317 — The 0.0% CI and 25.0% OPA/Sigstore comparison is arithmetically reproducible only for local toy predicates, not for standard CI, OPA/Kyverno, Sigstore, or Cosign, so it does not isolate EviAssure's claimed cause or establish a strongest-available baseline.
  evidence: Claim ledger: `results/comparative_evaluation.json:3-106` stores 0/12, 3/12, 3/12, and 12/12; recomputing `sum(row[key] for row in details)` yields those counts. Its producer `scripts/run_comparative_eval.py:20-34` defines `eval_ci_exit_code_gate`, `eval_opa_schema_gate`, and `eval_sigstore_cosign_gate` as in-process field predicates and imports neither OPA/Kyverno nor Sigstore/Cosign; regenerate with `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_comparative_eval.py`. The round-1 finding is not fixed because no version-pinned baseline configurations, inputs, or decision logs exist.
  remedy: Human-gated proposal: execute version-pinned OPA/Kyverno and Sigstore/Cosign configurations on the same signed inputs, archive policies, commands, versions, and per-vector decisions, and add a paired analysis; otherwise relabel the values as illustrative predicate behavior and remove claims about the named systems.
- [MAJOR] (science.methods_statistics) docs/usenix_paper_manuscript.tex:242-255 — The paper reports means across 1,000 runs with standard-error bounds and "linear" scaling, but the result producer takes one timing per trace count and one 1,000-request batch per worker count, retains no samples, and the stored data show only 4.24x speedup at eight workers.
  evidence: Claim ledger: `results/benchmark_summary.json:37-42` records 39.587 ms and 0.1221%; `results/benchmark_summary.json:67-72` records 5,883.86 ops/s. `scripts/run_release_benchmark.py:31-96` has no repeat/warm-up/sample/SE calculation; `183.225 / (100000 * 1.5) * 100 = 0.12215%` verifies the stored overhead but it uses code-assigned synthetic 1.5-ms durations (`scripts/run_release_benchmark.py:36-63`), not measured trace execution. `5883.86 / 1387.49 = 4.24065`, contradicting linear 8x scaling. Regenerate with `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py`; the prior round noted fresh values differ, and raw repetitions remain unavailable.
  remedy: Human-gated proposal: predefine repeated-run methodology, warm-up/exclusion rules, hardware/load metadata, and measured workload denominator; retain raw samples, report a rounded central estimate with appropriate intervals and actual speedup, and remove the unsubstantiated standard-error and linear-scaling language until that artifact exists.
- [MAJOR] (science.attack_construct_validity) docs/usenix_paper_manuscript.tex:305-307 — V10 and V12 do not test the mechanisms the paper attributes to them, so 12/12 is a curated denial count rather than evidence that canonicalization and sparse-proof-path validation resist the stated attacks.
  evidence: Claim ledger: Table 1/lines 305-307 claim canonical JSON sorting and path-height verification; `results/benchmark_summary.json:182-214` records both as blocked. Their producer `benchmark/tamper_vectors.py:167-184` changes only `test_pass_pct` to 99.9 for V10 and truncates the full `traces` list for V12; it creates neither duplicate/alternate JSON keys at the signed-byte parsing boundary nor a sparse proof/path supplied to the verifier. The recorded V10 violations are invalid signature and sub-threshold pass rate, while `assurance/policy.py:149-161` never reads `sparse_proofs`. Regenerate with `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_release_benchmark.py`.
  remedy: Human-gated proposal: replace each vector with an executable adversarial serialization/proof input and a success criterion that reaches the actual parser and proof verifier, record the specific rejection reason, and do not attribute the aggregate rate to defenses those vectors do not exercise.
- [MAJOR] (science.technical_accuracy) docs/usenix_paper_manuscript.tex:125-134 — The manuscript calls the SHA-256 root "64-byte" and claims proof transmission under 5 KB without a measurement artifact; the root is 32 bytes encoded as 64 hexadecimal characters, and no producer emits proof-size results.
  evidence: Claim ledger: the sentence and values are at `docs/usenix_paper_manuscript.tex:125-134`; `assurance/crypto.py:16-20` returns a 64-character SHA-256 hex string, i.e., 32 digest bytes, and `scripts/run_release_benchmark.py:31-66` emits no sparse-proof byte count. `EvidenceBundle.generate_sparse_proofs()` at `assurance/evidence.py:185-206` is not invoked by the benchmark. This round-1 finding remains unresolved because no proof-size artifact or command was added.
  remedy: Human-gated proposal: correct the byte/hex distinction and add a reproducible measurement that serializes proof bundles for named trace counts and audit-set sizes; retain those measurements as an artifact before making any size bound.

### from review-round-1-venue-compliance-auditor.md

- [BLOCKER] (venue.open_science) docs/usenix_paper_manuscript.tex:350 — The submission lacks the mandatory Open Science Appendix required by the live USENIX Security '27 CFP; the only Open Science text is a numbered main-body section and gives no anonymous artifact URL or access instructions.
  evidence: The official CFP requires an ``Open Science Appendix'' on submission that describes artifacts and how to access them (or explicitly explains why they cannot be provided), with anonymous, non-tracking links during review. Lines 350--351 use ``\section{Ethics and Open Science Availability}`` before the conclusion and bibliography, merely state that material is on GitHub and Zenodo, and provide neither URL nor access procedure.
  remedy: Add a distinct `\appendix` Open Science section after the self-contained main paper that inventories the code, corpus, harnesses, and result-generation scripts; provide a tested anonymous non-tracking artifact URL and reproduction/access steps, or explicitly state the reason and scope of every unavailable artifact. Keep it separate from the optional Ethics appendix.
- [MAJOR] (venue.config) .paperloop/venue.yaml:55 — The venue configuration does not encode the live CFP's mandatory Open Science Appendix or its anonymity/access requirements, so the deterministic gate cannot enforce them.
  evidence: The CFP checked at `https://www.usenix.org/conference/usenixsecurity27/call-for-papers` requires every submission to include an Open Science Appendix and requires anonymous, non-tracking artifact links. `venue.yaml` lists `Open Science` as a required section but has no appendix requirement or anonymous-artifact rule.
  remedy: Extend the venue rules to require an Open Science Appendix and an anonymous, non-tracking artifact access description, rather than accepting a main-body section named `Open Science`.
- [MAJOR] (figure.labels) docs/figures/comparative_block_rate.png:1 — Figure 3 labels the evaluated system ``Demo 5 Assurance,'' while the manuscript consistently names the system EviAssure.
  evidence: The rightmost bar in the rendered figure reads ``Demo 5 Assurance'' whereas the caption at line 316 and the surrounding text at lines 310--311 identify it as EviAssure. This makes the comparison figure non-standalone and appears to compare a different system.
  remedy: Regenerate `comparative_block_rate.png` with the rightmost category labeled `EviAssure` and rebuild the PDF.
- [MAJOR] (science.claim) docs/usenix_paper_manuscript.tex:255 — The text characterizes Figure 2 as ``linear throughput scaling,'' but the rendered bars show materially sublinear scaling from 1 to 8 workers (1,387 to 5,883 ops/s, about 4.24x for 8x workers).
  evidence: The labels on the rendered Figure 2 are 1,387, 2,628, 4,185, and 5,883 ops/s for 1, 2, 4, and 8 workers; the caption does not qualify the claim. The visible data therefore contradicts a literal linear-scaling statement.
  remedy: Submit a science proposal to replace the linear-scaling characterization with a quantitatively accurate one, or provide the justified scaling analysis; do not alter the plotted values without human approval.


## ANALYTICAL AUDIT (independent recomputation)


These findings come from the read-only analytical agent. Treat every `science.*` item as gated: do not change numbers, statistics, datasets, or experimental claims. You may repair only `repro.*`, `figure.*`, and other non-scientific presentation/documentation items.


### from analysis-round-3.md

# Analytical audit — round 3

## Executive decision
NOT YET SUPPORTED. The checked-in 12-vector harness and unit tests reproduce their narrow denial result, but the current gate still approves both an attacker-selected signing key and a signed trace omission, directly contradicting the release-soundness and complete-mediation claims. The headline corpus and performance claims also remain inconsistent with delivered evidence or lack the repeated raw measurements needed to support their stated precision.

## Claim ledger

| Claim | Source | Recomputation | Result | Status |
|---|---|---|---|---|
| "100.0% (12/12) block rate" | manuscript:59,294; `results/benchmark_summary.json:75-216` | Count `vector_details[*].blocked`; producer `scripts/run_release_benchmark.py:evaluate_tamper_resilience`; command `python3 scripts/run_release_benchmark.py` | Stored raw rows contain 12 blocked of 12; the harness constructs one deterministic specimen per vector. | VERIFIED for the curated suite only |
| CI 0/12; OPA/Sigstore 3/12; EviAssure 12/12 | manuscript:59,311; `results/comparative_evaluation.json:3-106` | Sum each raw detail boolean; producer `scripts/run_comparative_eval.py:main`; command `python3 scripts/run_comparative_eval.py` | 0, 3, 3, and 12 blocked of 12. | VERIFIED for local predicates, not named external systems |
| 5,883.86 ops/s on 8 cores | manuscript:59,255; `results/benchmark_summary.json:67-72` | `1000 / 0.1701`; producer `measure_parallel_throughput`; command `python3 scripts/run_release_benchmark.py` | 5,878.89 ops/s from the persisted rounded elapsed value, not 5,883.86. | DRIFTED; single batch, no raw repetitions |
| 100,000 traces in 39.59 ms and 0.1221% overhead | manuscript:59,245; `results/benchmark_summary.json:37-42` | `186.411 / (100000 * 1.5) * 100`; producer `measure_merkle_scaling`; command `python3 scripts/run_release_benchmark.py` | Persisted values are 40.525 ms Merkle build and 0.124274%, rounding to 0.1243%. | CONTRADICTED / DRIFTED |
| 50 profiles, 15 anomalies, 15/15 blocked | manuscript:232-238; `corpus/agent_trace_corpus.json:4-58` | Parse `profiles`, labels, and architectures; no corpus-evaluation producer exists. | 5 profiles, 2 anomalies, 10 traces, 3 observed architectures. | CONTRADICTED |
| Gate rejects unauthenticated or modified evidence | manuscript:111,211-228,294-307; `assurance/policy.py:77-228` | Generate attacker key and signed empty-trace/count-mismatch bundles; command recorded below. | Both bundles are approved with no violations. | CONTRADICTED |
| SHA-256 root is 64 bytes and sparse proofs are under 5 KB | manuscript:125-134; `assurance/crypto.py:16-20,55-85`; `assurance/evidence.py:185-206` | Inspect digest encoding and serialize a generated proof; no result producer measures the stated N=10,000 bound. | Root is 64 hex characters = 32 bytes; default 3-trace proof serializes to 295 bytes. | Root unit CONTRADICTED; size bound UNSOURCED |

## Independent calculations

- Persisted tamper result: `12 / 12 * 100 = 100.0%`. A Wilson 95% interval for 12 successes in 12 trials is 75.8% to 100.0%; the observations are deterministic curated test cases, not independent draws or 1,000 repetitions.
- Persisted comparison counts from all 12 `details` records are `CI=0`, `OPA predicate=3`, `Sigstore predicate=3`, and `EviAssure=12`. The alleged baselines are local functions at `scripts/run_comparative_eval.py:20-34`, with no OPA, Kyverno, Sigstore, or Cosign invocation.
- Persisted overhead: `186.411 ms / (100000 * 1.5 ms) * 100 = 0.124274%`, which rounds to 0.1243%, not the manuscript's 0.1221%. The denominator is assigned synthetic trace duration at `scripts/run_release_benchmark.py:42`, so it is not an end-to-end workload overhead measurement.
- Persisted throughput: `1000 / 0.1701 s = 5878.8948 ops/s`; the artifact prints 5878.56 because it computed before rounding elapsed time. Neither value supports the manuscript's 5883.86 figure. The stored speedup is `5878.56 / 1399.81 = 4.20x` with eight workers, not linear 8x scaling.
- Corpus parse observed `declared_profiles=50`, `actual_profiles=5`, `anomalies=2`, `traces=10`, and architectures `{CodeSynthesisAgent, DatabaseAdminAgent, MultiStepRAGAgent}`. `run_release_benchmark.py` does not read this file, so no delivered calculation can yield 15/15.
- Direct mechanism re-check: an attacker-generated Ed25519 public key and a signed default bundle altered only to `traces=[]` (while retaining `execution_traces_count=3`) each returned `(True, [])`. The first follows the evidence-controlled public key at `assurance/policy.py:130-135`; the second follows the truthy-only Merkle check at lines 151-161 and absent count comparison.

## Findings

- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-135 - the gate accepts a valid signature under an attacker-selected Ed25519 public key; the round-1/2 remedy was not applied and no trusted-key, issuer, or KMS-identity binding exists in the policy.
  evidence: a newly generated Ed25519 key signed a fresh bundle and `ReleasePolicyEngine.evaluate()` returned `(True, [])`; `governance/release_policy.yaml:6-20` only specifies allowed algorithms and a revoked-key denylist.
  remedy: bind accepted key IDs and public keys to trusted governance data, verify the binding independently of bundle fields, and add this attacker-key case as a negative regression test.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:151-161 - the gate approves a signed evidence bundle with no traces and a declared trace count of three; the round-1/2 remedy was not applied.
  evidence: `create_evidence_pack().to_dict()` with `traces=[]` returned `(True, [])`; Merkle validation executes only for a truthy trace list and never compares `execution_traces_count` to submitted traces.
  remedy: reject absent/empty traces when the declared count is nonzero, validate exact count equality and the defined empty-tree representation, and test empty, shortened, and count-mismatched bundles.
- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 - the released corpus has five profiles and two anomalies, not the claimed 50 profiles, 15 anomalies, five observed architectures, or a reproducible 15/15 result.
  evidence: direct raw JSON parse found 5 profile objects, 2 non-`CLEAN` labels, 10 trace records, and 3 architectures; `scripts/run_release_benchmark.py:99-141` evaluates synthetic tamper bundles rather than corpus profiles.
  remedy: provide an immutable 50-profile corpus and a per-profile evaluator that records every anomaly ID, input, gate verdict, and denominator, or obtain human approval to narrow the manuscript to the released data.
- [MAJOR] (science.number_mismatch) docs/usenix_paper_manuscript.tex:59 - the headline 39.59 ms, 0.1221%, and 5,883.86 ops/s values do not match the current result artifacts.
  evidence: `results/benchmark_summary.json:37-42` records 40.525 ms and 0.1243%; lines 67-72 record 5878.56 ops/s, while independent arithmetic gives 5878.89 ops/s from its displayed elapsed time.
  remedy: retain the current artifact and raw run samples, determine the authoritative experiment revision, then submit a human-reviewed proposal for any scientific claim correction.
- [MAJOR] (science.methods_statistics) scripts/run_release_benchmark.py:35-141 - the paper's assertion of means across 1,000 runs with standard-error bounds is not implemented: each Merkle size has one timing, each worker count has one 1,000-request aggregate batch, and each attack vector has one evaluation.
  evidence: the producer contains no repetition/warm-up loop, raw-sample persistence, standard-error calculation, seed recording, percentile calculation, or timeout/exclusion accounting; `statistics` is imported but unused.
  remedy: collect versioned per-run samples with warm-up, environment/load metadata, failures, and predeclared aggregation; report central estimates and dispersion at justified precision.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 - claimed OPA/Kyverno and Sigstore/Cosign comparative rates are calculated by simplified in-process predicates rather than the named systems.
  evidence: `eval_opa_schema_gate` examines only pass percentage and drift, and `eval_sigstore_cosign_gate` examines signature presence and pass percentage; the script imports or invokes no external baseline.
  remedy: evaluate pinned real baseline configurations against equivalent artifacts and archive configs, commands, and per-vector decisions, or human-approve a relabeling as toy predicate ablations.
- [MAJOR] (science.attack_construct_validity) benchmark/tamper_vectors.py:167-170 - V10 is labelled JSON key malleability but changes only `test_pass_pct` to 99.9 and does not exercise an alternate or duplicate JSON-key serialization at the signed-byte parser boundary.
  evidence: the persisted V10 result lists invalid signature and sub-threshold pass rate as blockers (`results/benchmark_summary.json:182-192`); no injected key exists in the vector code.
  remedy: define a concrete serialization-malleability adversary, success criterion, and parser boundary, then add a vector that isolates that mechanism.
- [MINOR] (repro.claim_provenance) docs/usenix_paper_manuscript.tex:125-134 - the manuscript states a 64-byte SHA-256 root and a sub-5-KB sparse-proof bound without a corresponding measurement artifact.
  evidence: `hash_sha256` emits a 64-character hex digest, which independently decodes to 32 bytes; no result JSON or producer measures proof size for N=10,000 and a specified audit count/serialization.
  remedy: correct the byte-versus-hex terminology and emit a versioned proof-size measurement with trace schema, audited indices, serialization, and command.

## Data required

- A versioned corpus containing exactly 50 profile rows and 15 anomaly rows, with stable IDs, all five architecture labels, input traces, expected labels, schema documentation, and per-profile gate results. This unlocks the corpus and 15/15 claims.
- Raw repeated timing records for every trace count and worker count: run ID, warm-up flag, monotonic timings, environment/CPU/load metadata, failures/timeouts, exclusions, and script revision. This unlocks valid latency, throughput, scaling, and uncertainty reporting.
- Version-pinned OPA/Kyverno and Sigstore/Cosign configurations, inputs, commands, versions, and per-vector outputs. This unlocks the comparative baseline claim.
- Paired representative trace-execution durations and packaging times for a documented workload. This unlocks an operational packaging-overhead estimate.

## Commands run

- `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests/ -v` - exit 0, 0.04 s; 14 passed.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_release_gate.py --format json` - exit 0; generated default evidence was approved.
- `python3 -c "... raw benchmark/comparison arithmetic ..."` - exit 0; recomputed 0.124274% overhead, 5878.8948 ops/s from displayed elapsed time, 12/12 blocks, and comparative counts 0/3/3/12.
- `python3 -c "... parse corpus ..."` - exit 0; observed declared 50 versus actual 5 profiles, 2 anomalies, 10 traces, and 3 architectures.
- `python3 -c "... root/proof representation ..."` - exit 0; observed a 64-hex-character / 32-byte root and a 295-byte serialized default proof.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c "... attacker key and empty traces ..."` - exit 0; attacker-selected-key and empty-trace/count-mismatch bundles each returned `(True, [])`.
- Documented `python3 scripts/run_release_benchmark.py` and `python3 scripts/run_comparative_eval.py` were not re-executed in this round because each overwrites a tracked result artifact; their raw JSON, source producers, and independent arithmetic were audited instead. This is a reproduction limitation, not evidence that their stored deterministic outputs differ from the calculations above.

### from analysis-round-2.md

# Analytical audit — round 2

## Executive decision
NOT YET SUPPORTED. The documented tests and synthetic 12-vector harness reproduce their stated 12/12 denial outcome, but the gate approves both an attacker-selected Ed25519 signing key and a signed bundle with no traces despite a claimed trace count, contradicting the claimed trust boundary and complete-mediation result. The corpus claim is contradicted by the checked-in data, and the performance claims remain unsupported because the producer takes one timing sample rather than the stated 1,000 runs with standard errors.

## Claim ledger

| Claim | Source | Recalculation / evidence path | Result | Status |
|---|---|---|---|---|
| EviAssure blocks 100.0% (12/12) vectors | manuscript:59,294; `results/benchmark_summary.json:75-216` | `scripts/run_release_benchmark.py:evaluate_tamper_resilience`; count `blocked` in 12 generated payloads | Fresh run: 12/12 blocked, 100.0%; Wilson 95% CI 75.8%-100.0% | VERIFIED for the curated deterministic suite; inadequate for the broad security claim |
| CI 0/12, OPA/Sigstore 3/12, EviAssure 12/12 | manuscript:59,311; `results/comparative_evaluation.json:3-106` | `python3 scripts/run_comparative_eval.py`; sum raw detail booleans | 0, 3, 3, and 12 blocked of 12 | VERIFIED only for local toy predicate functions, not OPA, Kyverno, Sigstore, or Cosign |
| 5,883.86 ops/s at 8 workers | manuscript:59,255; `results/benchmark_summary.json:67-72` | `scripts/run_release_benchmark.py:measure_parallel_throughput`; `1000 / elapsed_seconds` | Fresh independent batches: 5,878.56 and 5,988.01 ops/s; each is one 1,000-request batch | DRIFTED and statistical method unsupported |
| 100,000 traces in 39.59 ms; 0.1221% overhead | manuscript:59,245; `results/benchmark_summary.json:37-42` | `scripts/run_release_benchmark.py:measure_merkle_scaling`; overhead = `packaging_ms/(N*1.5 ms)*100` | Fresh independent runs: 40.52 ms / 0.1243% and 41.863 ms / 0.1179%; denominator is code-assigned synthetic duration | DRIFTED latency; DERIVED overhead, but not an operational overhead measurement |
| 50 profiles, 15 anomalies, and 15/15 blocked | manuscript:232-238; `corpus/agent_trace_corpus.json:4-58` | Parse `profiles`, labels, and architecture fields directly | 5 profiles, 2 anomalies, 10 traces, and 3 observed architectures; no corpus-to-gate evaluation producer | CONTRADICTED |
| Fail-closed gate rejects unauthenticated or modified evidence | manuscript:111,212,294-307; `assurance/policy.py:77-228` | Construct bypass payloads and call `ReleasePolicyEngine.evaluate` | Attacker-generated Ed25519 key and signed empty-trace bundle each returned `(True, [])` | CONTRADICTED |
| Sparse proofs are O(log N) | manuscript:59,125,134; `assurance/crypto.py:55-85`, `assurance/evidence.py:185-206` | `generate_merkle_proof` emits one sibling per tree level | Algorithmic implementation has proof length equal to tree depth; no artifact substantiates the printed `<5 KB` transmission claim | VERIFIED asymptotic mechanism; UNSOURCED size bound |

## Independent calculations

- Tamper rate: `12 blocked / 12 vectors * 100 = 100.0%`. Wilson 95% interval with `n=12`, `x=12` is 75.8%-100.0%. The code creates one deterministic payload per vector, so these are neither 1,000 runs nor independent draws from an attack population.
- Comparative rates, recomputed from the 12 raw `details` rows: CI `0/12 = 0.0%`; local OPA-schema predicate `3/12 = 25.0%`; local Sigstore/Cosign predicate `3/12 = 25.0%`; EviAssure `12/12 = 100.0%`. `scripts/run_comparative_eval.py:20-34` defines the latter two baselines in-process and invokes no external baseline implementation.
- Stored eight-worker rate is internally consistent before rounded display: `1000 / 0.1700 s = 5882.35 ops/s`, close to the stored `5883.86` calculated before elapsed-time rounding. Fresh batches produced 5,878.56 and 5,988.01 ops/s. Eight-worker scaling in the first fresh batch was `5878.56 / 1399.81 = 4.20x` for 8x workers, not linear 8x scaling.
- Stored packaging overhead is arithmetically correct: `183.225 ms / (100000 * 1.5 ms) * 100 = 0.12215%`, rounded to 0.1221%. The `1.5 ms` denominator is assigned to every synthetic trace at `scripts/run_release_benchmark.py:42`, not measured trace execution time.
- Corpus parse: declared profiles `50`; actual `len(profiles)=5`; declared architectures `5`; observed architectures `3`; anomaly labels `2`. Therefore neither `15/15` nor any anomaly block rate can be recomputed from the delivered corpus.
- Robustness falsifiers: (1) a bundle signed using a newly generated attacker Ed25519 key was approved because `assurance/policy.py:130-135` verifies any supplied public key without an allowlist or trusted key-to-KMS binding; (2) a normally signed bundle changed to `traces=[]` while retaining `execution_traces_count=3` was approved because `assurance/policy.py:151` skips Merkle validation for an empty list and never checks the declared count. These are evidence against the scoped release-soundness claim, not merely missing controls.

## Findings

- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-135 — the gate accepts a valid Ed25519 signature under an attacker-selected public key because the policy has no trusted-key allowlist or binding between key ID, KMS ARN, and public key.
  evidence: `generate_ed25519_keypair()` followed by `bundle.sign_ed25519(private, public)` and `ReleasePolicyEngine.from_yaml(...).evaluate(bundle)` returned `(True, [])`; the same bypass was recorded in the prior analytical work order and persists in the current source.
  remedy: require each accepted signing key to be pinned in trusted policy/governance data, verify its claimed identity and KMS binding, and add a negative regression test using an attacker-generated key.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:151-161 — the gate approves a signed evidence bundle with `traces=[]` and a retained declared count of three, so it does not completely mediate the attested trace set.
  evidence: a fresh `create_evidence_pack().to_dict()` with only `traces=[]` changed returned `(True, [])`; the prior analytical report identified the same bypass, and current code still executes Merkle validation only when `traces` is truthy and never compares `execution_traces_count` with `len(traces)`.
  remedy: reject an absent or empty trace list when the declared count is nonzero, compare declared and actual counts before computing the Merkle root, and add adversarial tests for empty, shortened, and count-mismatched trace lists.
- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 — the repository data contradicts the manuscript's 50-profile, five-architecture, 15-anomaly corpus and has no evaluator producing the claimed 15/15 block rate.
  evidence: direct JSON parse found five profile objects, two non-`CLEAN` labels, ten trace rows, and three observed architecture values; `scripts/run_release_benchmark.py` instead evaluates synthetic default bundles from `benchmark/tamper_vectors.py` and never reads this corpus.
  remedy: provide the immutable 50-profile corpus plus a script that records each anomaly profile ID, input, gate verdict, and denominator, or obtain human approval to revise the claims to the released data.
- [MAJOR] (science.methods_statistics) docs/usenix_paper_manuscript.tex:242-255 — the stated 1,000-run means and standard-error bounds are not produced by the benchmark: each Merkle size is timed once, each worker configuration is one 1,000-request aggregate batch, and each tamper vector is evaluated once.
  evidence: `scripts/run_release_benchmark.py:48-64`, `78-94`, and `109-139` contain no repetition, warm-up, seed/control recording, sample persistence, percentile calculation, or standard-error calculation; two fresh 100K runs yielded 40.52 and 41.863 ms, and fresh eight-worker batches yielded 5,878.56 and 5,988.01 ops/s.
  remedy: collect and preserve per-run timing samples after a documented warm-up under recorded hardware/load conditions; report appropriate dispersion or confidence intervals and change the manuscript only after human review of regenerated data.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 — the comparison labels OPA/Kyverno and Sigstore/Cosign, but evaluates simplified local predicates rather than those systems, so the reported comparative rates do not measure the named baselines.
  evidence: `eval_opa_schema_gate` checks only pass percentage and drift; `eval_sigstore_cosign_gate` checks only signature presence and pass percentage; neither imports, invokes, configures, nor records outputs from OPA, Kyverno, Sigstore, or Cosign.
  remedy: evaluate pinned external baseline implementations under equivalent policies and inputs, or relabel the results as toy predicate ablations and narrow the comparative claim with human approval.
- [MAJOR] (science.claim_scope) docs/usenix_paper_manuscript.tex:294-311 — the reported 100.0% tamper and comparative block rates overstate what 12 curated deterministic vectors establish and omit the limited uncertainty and attack selection scope.
  evidence: the harness constructs one known-bad payload per vector (`benchmark/tamper_vectors.py:101-184`), each is denied, and the 12/12 Wilson 95% interval is 75.8%-100.0%; several vectors are rejected by unrelated checks, for example V10 changes `test_pass_pct` to 99.9 in addition to relying on a stale signature.
  remedy: define attack success and vector-specific mechanism coverage, report the curated-suite denominator and interval, add adaptive/held-out attacks targeting trusted-key and trace-count boundaries, and obtain human approval before changing scientific claims.
- [MAJOR] (science.performance_precision) docs/usenix_paper_manuscript.tex:245-255 — the headline latency and throughput values are single-sample, environment-sensitive measurements reported with unjustified precision, and the described scaling is sublinear rather than linear.
  evidence: fresh 100K Merkle times ranged from 40.52 to 41.863 ms versus 39.59 ms printed; fresh 8-worker throughput ranged from 5,878.56 to 5,988.01 ops/s versus 5,883.86 printed; first fresh 1-to-8 worker scaling was 4.20x, not 8x.
  remedy: retain repeated raw timings, report median and spread at precision supported by the samples, and describe the observed scaling quantitatively rather than as linear after human approval.
- [MAJOR] (science.metric_validity) docs/usenix_paper_manuscript.tex:245 — the stated 0.1221% packaging overhead is a ratio to a hard-coded 1.5 ms synthetic per-trace duration, not a measured execution-workload overhead.
  evidence: `scripts/run_release_benchmark.py:42` assigns every generated trace `duration_ms=1.5`, and line 63 divides packaging time by `count * 1.5`; the fresh ratio calculation is correct but has no real workload denominator.
  remedy: measure trace execution duration for a documented workload and report packaging cost separately from end-to-end overhead, with human approval for any manuscript correction.
- [MINOR] (repro.claim_provenance) docs/usenix_paper_manuscript.tex:125,134 — the manuscript's raw-log size and `<5 KB` sparse-proof transmission statements have no result artifact, generating command, selected audit-count parameter, or reproducible calculation.
  evidence: the two JSON result files contain scaling, throughput, tamper, and comparison values only; `generate_sparse_proofs` creates paths but no benchmark measures serialized proof sizes or raw-log size for the stated N=10,000 scenario.
  remedy: emit a versioned proof-size result with exact trace schema, audited-index count, serialization format, and regeneration command.

## Data required

- A versioned corpus file containing exactly 50 profile records and 15 anomaly records, with stable profile IDs, all five architecture labels, full trace inputs, labels, and schema documentation; plus a per-profile evaluation output mapping every anomaly ID to its gate verdict. This unlocks verification of the corpus and 15/15 claims.
- Repeated raw benchmark samples for every trace count and worker count, including warm-up protocol, seed/environment metadata, CPU model, load conditions, timestamps, per-request or per-batch timing values, exclusions/timeouts, and the script version/commit. This unlocks valid means, uncertainty, scaling, and precision claims.
- External baseline configurations, versions, policy files, commands, and per-vector outputs for OPA/Kyverno and Sigstore/Cosign. This unlocks the comparative deployment-gate claim.
- A measured production or representative execution-workload duration dataset paired with trace counts. This unlocks an operational packaging-overhead calculation.

## Commands run

- `pytest tests/ -v` — exit 0, 0.05 s; 14 passed. This verifies current unit tests but they do not include either discovered bypass.
- `python3 scripts/run_release_benchmark.py` — exit 0; fresh output included 40.52 ms Merkle build and 0.1243% derived overhead at N=100,000, 5,878.56 ops/s at eight workers, and 12/12 blocked.
- `python3 -c "from scripts.run_release_benchmark import measure_merkle_scaling, measure_parallel_throughput, evaluate_tamper_resilience; ..."` — exit 0; independent second samples: 41.863 ms and 0.1179% at N=100,000, 5,988.01 ops/s at eight workers, and 12/12 blocked.
- `python3 scripts/run_comparative_eval.py` — exit 0; 0/12 CI, 3/12 local OPA predicate, 3/12 local Sigstore predicate, and 12/12 EviAssure blocks.
- `python3 scripts/verify_release_gate.py --format json` — exit 0; generated default evidence was approved. No external services or credentials were needed.
- `python3 -c "import json; ..."` parsing `corpus/agent_trace_corpus.json` — exit 0; declared 50 profiles versus 5 actual profiles, 2 anomalies, and 3 observed architectures.
- `python3 -c "... generate_ed25519_keypair(); ... sign_ed25519(private, public); ... evaluate(bundle)"` — exit 0; attacker-created key bundle returned `(True, [])`.
- `python3 -c "... b=create_evidence_pack().to_dict(); b['traces']=[]; ... evaluate(b)"` — exit 0; empty-trace, count-mismatched bundle returned `(True, [])`.
- `python3 -c "... Wilson interval and arithmetic ..."` — exit 0; Wilson interval 75.8%-100.0%, 4.20x fresh 1-to-8-worker scaling, and 0.1243% fresh synthetic-duration ratio.

Environment limitation: the documented reproduction scripts overwrite `results/benchmark_summary.json` and `results/comparative_evaluation.json`; execution was necessary to satisfy the requested end-to-end reproduction pass, and these generated-file modifications are outside this report's authored scope. No manuscript, source, test, corpus, governance, or result values were manually edited.

### from analysis-round-1.md

# Analytical audit — round 1

## Executive decision
NOT YET SUPPORTED. The documented synthetic suite and test suite reproduce their 12/12 denial result, but two independently constructed bundles that violate the stated trust boundary are approved: one signed by an attacker-created Ed25519 key and one with no traces despite a claimed trace count of three. The corpus also contains only five profiles and two anomalies, not the claimed 50 and 15; performance claims lack repeated-run evidence and uncertainty.

## Claim ledger

| Claim | Source | Recomputation | Result | Status |
|---|---|---|---|---|
| "100.0% (12/12) block rate" | manuscript:59,294; `results/benchmark_summary.json:75-216` | `evaluate_tamper_resilience()`; count `blocked` | 12/12 curated vectors denied | VERIFIED, but mechanism contradicted by bypasses below |
| CI 0/12; OPA/Sigstore 3/12; EviAssure 12/12 | manuscript:59,311; `results/comparative_evaluation.json:3-106` | `python3 scripts/run_comparative_eval.py`; sum each `*_blocked` key | 0, 3, 3, 12 of 12 | VERIFIED for the toy baseline functions, not external OPA/Sigstore |
| 5,883.86 ops/s on 8 cores | manuscript:59,255; `results/benchmark_summary.json:67-72` | `1000 / 0.1700 = 5882.35`; fresh `measure_parallel_throughput()` | fresh 5,864.18 ops/s; one 1,000-request batch | DRIFTED / no repeated-run evidence |
| 100,000 traces in 39.59 ms and 0.1221% overhead | manuscript:59,245; `results/benchmark_summary.json:37-42` | `183.225 / (100000 * 1.5) * 100` | stored value yields 0.1221%; fresh build was 41.424 ms and 0.1246% | DERIVED overhead; latency DRIFTED / no repeated-run evidence |
| Corpus has 50 profiles, 15 anomalies; 15/15 blocked | manuscript:232-238; `corpus/agent_trace_corpus.json:4-58` | count `profiles` and labels | 5 profiles, 2 anomalies, 10 traces; 3 populated architectures | CONTRADICTED |
| Gate rejects modified trace history / unauthenticated evidence | manuscript:111,211-228; `assurance/policy.py:77-228` | sign arbitrary key and evaluate; sign empty trace bundle with count 3 and evaluate | both malicious bundles approved | CONTRADICTED |
| Sparse proofs are `<5 KB` and root is 64 bytes | manuscript:125-134; `assurance/crypto.py:16-20,30-85` | inspect digest/proof representation | SHA-256 root is 32 bytes (64 hex characters); no size artifact or producer measurement | UNSOURCED / technically incorrect unit |

## Independent calculations

- Tamper rate: `12 blocked / 12 vectors * 100 = 100.0%`. Wilson 95% CI for the observed block proportion is 75.8% to 100.0%; it is not evidence of a population-wide 100% block rate. The suite is a single deterministic construction per vector, not 1,000 runs.
- Comparative counts from raw detail rows: CI `0/12`; toy OPA schema function `3/12`; toy Sigstore function `3/12`; EviAssure `12/12`. The producing script defines these stand-ins locally in `scripts/run_comparative_eval.py:20-34`; it invokes neither OPA, Kyverno, Sigstore, nor Cosign.
- Stored overhead: `183.225 ms / (100000 synthetic traces * 1.5 ms synthetic duration per trace) * 100 = 0.12215%`, rounded to 0.1221%. This is a ratio to code-assigned synthetic durations, not a measured workload execution duration.
- Stored eight-worker throughput: `1000 / 0.1700 s = 5882.35 ops/s`, close to the stored unrounded-clock-derived 5,883.86. Fresh execution gave 5,864.18 ops/s; fresh 100K Merkle construction gave 41.424 ms rather than 39.587 ms. Neither script repeats a configuration, warms up, fixes CPU state, records samples, reports percentiles, or computes a standard error.
- Corpus count command observed `declared_profiles=50`, `actual_profiles=5`, label counts `CLEAN=3`, `ANOMALY_UNSAFE_CMD=1`, `ANOMALY_PROMPT_INJECTION=1`, and `trace_count=10`.
- Direct falsifier 1: an independently generated Ed25519 key signed the required canonical payload; `ReleasePolicyEngine.evaluate()` returned `attacker_generated_key_approved=True, violations=[]`. The verifier uses the public key supplied by the evidence (`assurance/policy.py:130-137`) and has no trusted-key allowlist or KMS ARN verification.
- Direct falsifier 2: an Ed25519-signed bundle with `traces=[]` and `execution_traces_count=3` returned `empty_traces_claimed_count_approved=True, violations=[]`. Merkle recomputation is skipped when `traces` is empty (`assurance/policy.py:150-161`) and the count is never checked.

## Findings

- [BLOCKER] (science.corpus_provenance) corpus/agent_trace_corpus.json:4-58 — the source corpus contains 5 profiles and 2 anomaly profiles, contradicting the manuscript's 50 profiles, 15 planted anomalies, and 15/15 block result.
  evidence: independent JSON count found 5 profile objects, 10 traces, 3 clean labels, and 2 anomaly labels; only 3 of the 5 named architectures occur.
  remedy: provide the immutable 50-profile corpus and an evaluation script that maps every one of the 15 anomaly IDs to its gate result, or obtain human approval to revise the claims to the actual data.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:130-137 — the gate accepts an evidence-controlled Ed25519 public key, so an attacker can create a key, sign a malicious bundle, and receive APPROVED.
  evidence: a fresh attacker key and signature produced `attacker_generated_key_approved=True` with no violations; the policy contains only a revoked-key denylist, not a trusted issuer/key allowlist or KMS verification.
  remedy: add a trusted-key/issuer binding and verify it independently of evidence-controlled fields; then add this attack to the benchmark and obtain human approval before changing security claims.
- [BLOCKER] (science.complete_mediation) assurance/policy.py:150-161 — a signed bundle with no submitted traces but `execution_traces_count=3` is approved, so modified or omitted trace histories are not necessarily rejected.
  evidence: independently created and correctly signed empty-trace bundle returned `empty_traces_claimed_count_approved=True, violations=[]`; Merkle validation only runs when `traces` is non-empty and never compares the declared count.
  remedy: require and validate count equality and an empty-tree root for zero traces; add omission and count-mismatch vectors, then obtain human approval before changing security claims.
- [MAJOR] (science.methods_statistics) docs/usenix_paper_manuscript.tex:242-255 — the paper states means across 1,000 runs with standard-error bounds, but the benchmark performs one timing per Merkle size, one 1,000-request batch per worker count, and one pass through each tamper vector.
  evidence: `scripts/run_release_benchmark.py:35-96,99-141` contains no repetition loop, warm-up, seed control, sample retention, standard-error calculation, percentile calculation, timeout accounting, or confidence interval; fresh values differ from stored values.
  remedy: collect and preserve per-run timing samples with environment/load metadata, predeclare aggregation and exclusions, report appropriate dispersion/intervals, and obtain human approval for corrected performance claims.
- [MAJOR] (science.baseline_validity) scripts/run_comparative_eval.py:20-34 — the reported OPA/Sigstore comparison is implemented as two local predicate functions rather than the named systems, so the baseline rates do not support claims about OPA, Kyverno, Sigstore, or Cosign.
  evidence: the script imports no baseline implementation and defines `eval_opa_schema_gate` and `eval_sigstore_cosign_gate` inline; its 3/12 counts reproduce only those predicates.
  remedy: run version-pinned real baseline configurations against equivalent inputs, archive configs and outputs, or explicitly relabel the comparison as illustrative toy predicates with human approval.
- [MAJOR] (science.claim_precision) docs/usenix_paper_manuscript.tex:59 — exact performance values are stale or non-reproducible at the stated precision, and the claimed linear scaling is not established.
  evidence: fresh run measured 41.424 ms at 100K versus 39.587 ms stored, and 5,864.18 versus 5,883.86 ops/s; stored 1-to-8 worker scaling is only `5883.86 / 1387.49 = 4.24x`, not linear 8x.
  remedy: preserve raw repetitions and report rounded central estimates with intervals and measured speedup; obtain human approval for any revised quantitative claim.
- [MAJOR] (science.attack_construct_validity) benchmark/tamper_vectors.py:167-170 — V10 is described as an uncanonicalized-key injection but only changes `test_pass_pct` to 99.9; the result cannot test the stated JSON-malleability mechanism.
  evidence: V10 adds no key or duplicate/alternate serialization and is blocked by signature/pass-rate checks reported in `results/benchmark_summary.json:187-190`.
  remedy: specify an executable serialization-malleability adversary and success criterion, test it against the signed-byte parser boundary, and obtain human approval before asserting the mechanism.
- [MAJOR] (science.technical_accuracy) docs/usenix_paper_manuscript.tex:125-134 — the paper calls a SHA-256 Merkle root 64 bytes and asserts sparse proof size under 5 KB without an artifact.
  evidence: `hash_sha256` returns a 64-character hexadecimal digest (`assurance/crypto.py:16-20`), representing 32 digest bytes; no benchmark key records proof byte lengths or a producing command.
  remedy: correct the byte/hex distinction and emit proof-size measurements for stated trace counts, subject to human approval.

## Data required

- A versioned raw corpus with exactly 50 profile rows and 15 anomaly rows, including schema documentation, profile IDs, architecture labels, trace inputs, expected outcomes, and per-profile gate outputs; this would permit the corpus claim and 15/15 calculation to be audited.
- Per-run raw performance samples for every trace count and worker configuration: at least run ID, start/end monotonic timestamps, warm-up indicator, trace count, worker count, hardware/OS/Python/dependency versions, CPU/load conditions, failures/timeouts, and random seed where applicable; this would permit means, uncertainty, percentiles, exclusions, and scaling analysis.
- Version-pinned OPA/Kyverno and Sigstore/Cosign configurations, input artifacts, invocation logs, and per-vector decisions; this would permit a fair baseline comparison.

## Commands run

- `PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider tests -v` — exit 0, 0.05 s; 14 passed.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_release_gate.py --format json` — exit 0; generated evidence was APPROVED.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c "... corpus count ..."` — exit 0; observed 5 actual profiles, 2 anomalies, 10 traces.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c "from scripts.run_release_benchmark import ..."` — exit 0; fresh 100K Merkle build 41.424 ms, eight-worker throughput 5,864.18 ops/s, tamper suite 12/12 blocked.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_comparative_eval.py` — exit 0; reproduced 0/12, 3/12, 3/12, and 12/12 predicate outcomes.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c "... attacker-generated key ..."` — exit 0; attacker-generated Ed25519 key bundle approved with no violations.
- `PYTHONDONTWRITEBYTECODE=1 python3 -c "... empty traces, claimed count 3 ..."` — exit 0; bundle approved with no violations.
