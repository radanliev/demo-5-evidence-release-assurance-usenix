---
name: security-eval-statistics
description: Apply and audit statistical rigor in security and ML evaluation — significance tests, confidence intervals, multiple comparisons, effect sizes, power, and attack success rates. Use this skill whenever a paper reports detection rates, attack success rates, benchmark scores, or comparisons against baselines; whenever someone says "significant", "outperforms", or "improves"; and proactively when reviewing any experimental evaluation section in a security or machine learning paper.
---

# Statistics for security and ML evaluation

Security papers report rates: detection rate, attack success rate, false positive
rate, bypass rate. These are proportions, usually from small n, often compared
across many configurations. That combination breaks most naive statistics.

## The reporting floor

No comparative claim ships without all five:

1. **n** — and what one unit *is*. Trials? Prompts? Repositories? Independent
   samples or repeated measures on the same targets?
2. **Dispersion** — SD, IQR, or a CI. A bare mean is uninterpretable.
3. **The test** — named, with its assumptions stated and one- versus two-sided
   declared before you saw the data.
4. **Effect size** — the magnitude, not just the p-value. With large n, trivial
   differences reach significance; with small n, large differences do not.
5. **Multiple-comparison handling** — or an explicit statement that this is a
   single pre-registered comparison.

Missing any one of these turns a result into an anecdote with a decimal point.

## Choosing the test

**Proportions, independent groups** (detection rate of A vs B on disjoint sets):
two-proportion z-test if both groups have ≥10 successes and ≥10 failures;
Fisher's exact test otherwise. Security evaluations frequently violate the
normal approximation and nobody notices.

**Proportions, paired** (both defenses on the *same* attack corpus): McNemar's
test. This is the common case and using an unpaired test here is wrong — it
throws away the pairing and inflates the variance.

**Continuous, non-normal** (latency, overhead — almost always right-skewed):
Wilcoxon signed-rank for paired, Mann–Whitney U for independent. Do not assume
normality of latency. Ever.

**More than two configurations**: do not run all pairwise tests and report the
winners. Either a single omnibus test followed by planned comparisons, or
correct the family.

**Small n, complex statistic**: bootstrap the CI (≥10,000 resamples) and report
the interval. Honest and assumption-light.

## Confidence intervals for rates

Never use the Wald interval (p̂ ± 1.96·√(p̂(1−p̂)/n)). At the rates security
papers care about — near 0% and near 100% — it produces intervals extending
past 0 or 1, and its coverage is badly wrong.

Use **Wilson** or **Clopper–Pearson**. For the perfect-score case that comes up
constantly (0 successes in n trials), the rule of three gives the 95% upper
bound as **3/n**: zero bypasses in 100 attempts means the true rate could still
be up to 3%. State it that way. "100% prevention" from n=100 is not a finding
about the true rate, and a reviewer will say so.

## Multiple comparisons

An attack matrix of 8 attacks × 5 defenses is 40 comparisons. At α=0.05 you
expect 2 false positives from noise alone.

- **Bonferroni** — α/m. Simple, conservative, fine when m is small.
- **Holm–Bonferroni** — uniformly more powerful than Bonferroni, no extra
  assumptions. Prefer it.
- **Benjamini–Hochberg** — controls false discovery rate. Appropriate for
  exploratory sweeps where some false positives are tolerable.

Say which you used and what m was. If you ran an exploratory sweep and then
tested the winner, that is not a confirmatory result — either say so, or
validate the winner on held-out data.

## Traps specific to this field

**Attack success rate on the design set.** If the attacks were used to build the
defense, ASR on them measures memorization. Only held-out ASR is
robustness-relevant. Report both, labelled, and never headline the design-set
number.

**The adaptive attacker.** A defense evaluated only against attacks that predate
it is untested. A static ASR of 0% against a fixed corpus is a weak claim; the
reviewer's question is what an adversary who reads your paper achieves.

**Deterministic components reported with statistics.** If a mediator denies by
construction, that is a proof obligation, not an experiment. Say "by
construction, under assumptions X" rather than "0% in 1000 trials", which
implies uncertainty that does not exist and invites the reviewer to ask about
trial 1001.

**Nondeterministic models, single run.** LLM-in-the-loop evaluations vary across
seeds, temperature, and provider-side model updates. One run is one sample.
Report seeds, the number of repetitions, the date, and the exact model version —
model identifiers silently change behaviour under a stable name.

**Base rate neglect.** A detector with 99% TPR and 1% FPR looks strong until the
positive class is 0.1% of traffic, at which point most alerts are false. Report
precision at the deployment base rate, or state the base rate you assume.

**Overhead measured without contention.** Single-tenant benchmark numbers do not
transfer. State the load conditions.

## Auditing someone else's numbers

- Recompute the headline statistic from the raw artifacts.
- Check whether the CI crosses the decision boundary. If it does, the result is
  negative regardless of the p-value.
- Check whether n supports the reported precision. 87.34% from n=50 does not.
- Check whether the same n is used consistently across a table — differing
  denominators between rows, unlabelled, is a common and serious error.
- Look for the experiment that would have falsified the claim, and whether it
  was run.

## Phrasing

Match the strength of the claim to the evidence:

- No test → "we observed", not "significantly".
- CI crossing zero → "we did not detect a difference", never "no difference".
- Deterministic guarantee → "by construction, under assumptions X".
- Held-out result → say "held-out" in the sentence, every time.
