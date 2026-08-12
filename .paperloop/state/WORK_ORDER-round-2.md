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

## Gated findings (0 of them)

For each, write `.paperloop/state/proposals/<id>.md` containing: the finding,
what you believe the correct value or claim is, the exact diff you would apply,
and the evidence you would need to be sure. Then stop on those. A human decides.

## When you are done

Re-run `python3 .paperloop/run_gates.py --build` yourself and confirm the count
dropped. Then write a two-line summary of what you changed to
`.paperloop/state/round-2-writer.md`.

---

## AUTO-FIX MANDATE


- [MINOR] (venue.template) 
  could not measure PDF geometry: No module named 'pdfplumber'
  id: 66c5c40df5025c62


## REVIEWER FINDINGS (from the evaluator agents this round)


These come from an agent that read the paper rather than measured it. Apply the same split: `science.*` are gated and you may only propose; everything else is yours to fix.


### from review-round-3-paper-evaluator.md

- [MAJOR] (prose.style) docs/x.tex:1 — reviewer paper-evaluator round finding
  evidence: simulated
  remedy: simulated

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
