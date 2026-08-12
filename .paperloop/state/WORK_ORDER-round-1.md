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
`.paperloop/state/round-1-writer.md`.

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

- [MAJOR] (prose.style) docs/x.tex:1 — reviewer science-auditor round finding
  evidence: simulated
  remedy: simulated

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
