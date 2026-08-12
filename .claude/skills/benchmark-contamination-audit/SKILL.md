---
name: benchmark-contamination-audit
description: Audit a benchmark or evaluation dataset for leakage, contamination, saturation, construct validity, and difficulty calibration. Use this skill whenever building or reviewing a benchmark, evaluation suite, or dataset paper; whenever checking train/test separation or whether scores are inflated by memorization; and proactively whenever someone mentions eval design, benchmark scores, held-out sets, IRT, item difficulty, or dataset documentation.
---

# Benchmark contamination and validity audit

A benchmark's job is to make model quality legible. It fails silently: the
numbers keep going up while measuring less and less. These are the failure modes
in the order reviewers check them.

## Contamination

**Pretraining contamination.** If items are drawn from public sources, assume
frontier models have seen them. Check: were items scraped from the web, GitHub,
Stack Overflow, or an existing public benchmark? Give the canary string, the
collection date, and any decontamination procedure. "We assume no contamination"
is not a method.

Detection signals, none conclusive alone but jointly informative:
- Anomalously low perplexity on item text versus paraphrase.
- Performance collapsing under semantically neutral paraphrase — the model
  matched a surface form, not the task.
- Exact-substring or high n-gram overlap against known corpora.
- A model that solves items requiring information published after its cutoff.

**Train/test leakage inside your own pipeline.** The failures are boring and
common: near-duplicates across the split; the same underlying source document
in both; templated items sharing structure; splitting after augmentation rather
than before; and calibration data reused as evaluation data. Check by near-dup
detection (embedding or MinHash), not exact match.

**Label leakage.** A feature that encodes the answer. In security corpora this
shows up as a filename, a path, or a commit message that gives away the label.

## Saturation

A benchmark where the best model scores 97% has stopped measuring. Report the
score distribution, not just the max. Ceiling effects mean your headline
comparison rests on a handful of items.

Track and report: score distribution across models; the fraction of items every
model solves (these carry no signal — consider retiring them); the fraction no
model solves (check these are actually solvable and not mislabelled); and
headroom to a human or expert baseline.

Mislabelled items are the quiet killer. Items nothing solves are usually either
genuinely hard or wrong, and the ratio matters. Hand-check a sample.

## Difficulty and discrimination

Item response theory is the right frame if you are calibrating difficulty:

- **Difficulty (b)** — the ability level at which P(correct) = 0.5.
- **Discrimination (a)** — how sharply the item separates ability levels. Items
  with low discrimination add noise and should be cut, no matter how elegant
  they look.
- **Fisher information** — where on the ability scale the item is informative. A
  benchmark whose information mass sits far from the ability range of the models
  under test is measuring precision you do not need.

Report the ability range over which the benchmark is informative. A benchmark
calibrated for weak models says little about strong ones, and vice versa.

If you fit IRT: state the model (1PL/2PL/3PL), the estimation method, the sample
size, and convergence diagnostics. Report parameter uncertainty. IRT parameters
from small samples are unstable, and a plot without error bars overstates
confidence.

## Construct validity

The question the reviewer asks that most benchmark papers do not answer: does
this measure what its name says?

- What is the construct, stated in one sentence?
- Why do these items measure it rather than something correlated with it?
- What would a model that scored well *without* having the capability look like?
  Shortcut features, format exploitation, and answer-position bias all produce
  high scores with no capability.
- Is the metric appropriate? Exact match punishes correct-but-differently-worded
  answers. Model-graded evaluation inherits the grader's biases — report
  grader–human agreement if you use one.
- Does performance track anything external? A benchmark correlating with nothing
  else is hard to defend.

## Documentation, which venues now require

Dataset track reviewers check for these specifically:

- **Provenance** — where each item came from, collected when, by what method.
- **Licensing** — per source, with redistribution rights stated. This is a
  frequent reject: aggregating permissively-licensed sources does not always
  yield a redistributable dataset.
- **Consent and PII** — for anything involving people or scraped content.
- **Annotation** — who annotated, their expertise, the guidelines, and
  inter-annotator agreement. Report the agreement statistic, not "high
  agreement".
- **Known limitations and biases** — stated by you, not discovered by a reviewer.
- **Maintenance** — who fixes errors, how items get retired, versioning.
- **Structured metadata** — a datasheet, data card, or Croissant record.

## Reproducibility of the evaluation itself

- Pinned model versions with dates. Provider-side updates change behaviour
  under a stable model name; a benchmark run without a date is unrepeatable.
- Decoding parameters: temperature, top-p, max tokens, seed.
- The exact prompt template, including system prompt and few-shot examples.
- Number of repetitions and the variance across them. A single run of a
  nondeterministic model is one sample.
- The grading code, not a description of it.

## Audit output

For each finding: the failure mode, the evidence, the effect on reported scores
and its direction, and the remedy. Rank by how much a reviewer would discount
the paper.

State plainly whether the benchmark's headline claim survives. If contamination
plausibly explains the top scores, that belongs in the abstract's framing, not
buried in limitations.
