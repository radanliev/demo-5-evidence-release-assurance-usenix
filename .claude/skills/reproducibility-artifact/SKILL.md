---
name: reproducibility-artifact
description: Prepare and audit a research artifact for reproducibility and artifact evaluation — environment pinning, one-command reproduction, anonymous release, and the claim-to-script mapping AE committees check. Use this skill whenever preparing code or data for release alongside a paper, submitting to an artifact evaluation committee, writing an availability statement, or checking whether results can actually be regenerated from the repository.
---

# Reproducibility and artifact evaluation

Artifact evaluation asks one question: can someone who is not you, on a machine
that is not yours, regenerate the numbers in the paper? Most artifacts fail on
environment and entry point, not on science.

## The three badges

Terminology differs slightly by venue but the tiers are consistent:

- **Available** — the artifact is publicly and permanently archived. A DOI, not
  a GitHub URL. Nearly free to obtain; get it.
- **Functional / Evaluated** — it builds, runs, and does what the paper says.
  Documented, complete, exercisable.
- **Reproduced / Results Reproduced** — an independent party regenerated the
  paper's key results. This is the one that requires real preparation.

## The entry point

One command. Not a README of twelve steps.

```bash
./reproduce.sh          # regenerates every number, table and figure in the paper
./reproduce.sh --quick  # a representative subset, minutes not days
```

Both matter. An evaluator on a deadline runs `--quick` first; if that fails, the
artifact is marked down before the full run is ever attempted.

Print progress. State expected runtime up front. An evaluator who cannot tell
whether your script is working or hung will kill it.

## Environment

Pin everything, in descending order of preference:

1. **Container image** with a digest, not a tag. `python:3.11` moves; a sha256
   does not.
2. **Lockfile** — `requirements.lock` from `pip freeze`, `poetry.lock`,
   `uv.lock`. Not a loose `requirements.txt` with `>=` constraints.
3. **Documented external dependencies** — TeX distribution and packages, system
   libraries, CUDA version, GPU model and memory, and the exact CLI tools your
   scripts shell out to.

State the hardware the results were produced on. Timing and overhead numbers are
meaningless without it. If a GPU is required, say which and how much memory —
an evaluator without one needs to know before they start.

## Nondeterminism

Most artifacts are not bit-reproducible, and that is acceptable if you say so.

- Set and record seeds for every RNG: Python, NumPy, framework, and any
  sampling in your own code.
- For anything calling a hosted model: record the model identifier, the date,
  decoding parameters, and the number of repetitions. Model behaviour changes
  under a stable name — this is the single biggest reproducibility hazard in
  current work.
- Ship cached responses for API-dependent experiments so the artifact can be
  exercised without credentials or spend, *and* provide the live path. Say which
  the paper's numbers came from.
- State a tolerance: "accuracy within ±0.5% across seeds" tells an evaluator
  what counts as a successful reproduction. Without it, any difference looks
  like a failure.

## The mapping table

The highest-value artifact document, and the most often missing. One row per
paper claim:

| Paper location | Claim | Script | Command | Output artifact | Runtime |
|---|---|---|---|---|---|
| Table 3, row 2 | 87.3% detection | `eval/run_detect.py` | `./reproduce.sh --detect` | `results/detect.json` | ~12 min |

Evaluators work through this table. Without it they guess, and guessing produces
"could not verify".

## Anonymous release for double-blind venues

Double-blind submission and artifact availability conflict, and the conflict has
a standard resolution:

- Anonymous GitHub proxy, or a Zenodo deposit with anonymous authorship and
  restricted access.
- **Strip metadata before uploading.** Git history with author names and emails,
  `LICENSE` with a copyright holder, `CITATION.cff`, `.git/config` remotes,
  container labels, notebook execution metadata, PDF producer fields, and
  absolute paths containing your username. Every one of these has broken
  anonymity in a real submission.
- Check the artifact yourself as an outsider would: `git log`, `grep -ri` for
  your surname, institution, and username across the whole tree.
- The paper cites the anonymous location; the camera-ready swaps in the
  permanent DOI.

## Data and licensing

- Per-source licensing, with redistribution rights confirmed. Aggregating
  permissively licensed sources does not always produce a redistributable set.
- If data cannot be released, say so, say why, and release everything that lets
  someone reproduce the pipeline on their own data: schemas, generation code,
  and a small synthetic sample.
- Large files belong in an archive with a DOI, not in git. Include checksums.

## Self-audit before submitting

Do this in a fresh container, from a fresh clone, with no credentials in the
environment:

1. Clone. Do not reuse your working tree — it has state you forgot about.
2. Follow your own README exactly, doing nothing it does not say.
3. Run `--quick`. Time it.
4. Run the full path.
5. Compare against the paper, number by number, using the mapping table.
6. Grep the whole tree for anything identifying, if the venue is double-blind.

Every step you had to improvise is a step an evaluator will fail on. Fix the
document, not your memory of it.

## Availability statement

State: where the artifact is, what it contains, what it omits and why, what
hardware and runtime are needed, and which results it regenerates. Venues
increasingly require this as a named section — and for some tracks, data and
code must be final at submission time, not added later.
