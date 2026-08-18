# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-18 14:59

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 0 |
| MINOR | 5 |
| INFO | 4 |

Gated (human sign-off required): **0**

<details><summary>Build output (tail)</summary>

```
=== USENIX Security Paper PDF Builder & Figure Generator ===
[+] High-resolution 600 DPI benchmark figures saved to: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/figures
[*] Froze headline metrics -> frozen_metrics.tex (throughput=7,025, overhead=0.000%)
[*] Compiling LaTeX manuscript: usenix_paper_manuscript.tex using pdflatex...
[SUCCESS] Compiled USENIX Security paper PDF: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf

[+] PDF generation complete: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf
findfont: Failed to find font weight semibold, now using 700.
findfont: Failed to find font weight semibold, now using 700.
findfont: Failed to find font weight semibold, now using 700.
findfont: Failed to find font weight semibold, now using 700.
```
</details>

## Auto-fix mandate

The writer agent applies these directly. Formatting, layout, figures, references, venue compliance — no interpretation of results required.

### [MINOR] refs.bibfield `docs/references.bib`:273

notarized2026agents is cited as arXiv — check for a peer-reviewed version

- **remedy:** If it appeared at a venue, cite the published version. Reviewers notice arXiv-only bibliographies.
- **id:** `b6711b95d51ab6d4`

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:113

percentage without an explicit denominator

- **found:** `We implement the protocol in \textsc{EviAssure}, an evidence-bundle format that rides inside in-toto/SLSA envelopes with a domain-separated, depth-bound Merkle trace commitment, an`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `fbe242416462876d`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:515

percentage without an explicit denominator

- **found:** `EviAssure blocks \eviBlocked{} of \eviTotal{} scored vectors (\eviPct\%, 95\% CI [\eviCIlo, \eviCIhi]), and falsely blocks \falseBlockK{} of \falseBlockN{} clean negative controls.`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `45d5d35f673e4061`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:523

percentage without an explicit denominator

- **found:** `\textbf{Differential wire fuzzing.} A fuzzing campaign whose every mutation perturbs a field inside the signed payload cannot fail --- a verifying bundle is unreachable and no clea`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `6322cc329a98e00d`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:564

percentage without an explicit denominator

- **found:** `\caption{Executed baselines against the \scoredVectors{}-vector suite, with Wilson 95\%`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `6e4c635ca9ecd10e`

## Measurements

Recorded for the round log; no action implied.

### [INFO] refs.unverified

33 citation(s) verified against Crossref/OpenAlex/SemanticScholar

- **id:** `99fa5a895f354914`

### [INFO] science.artifact_missing

indexed 205 distinct values from 7 artifacts

- **id:** `c36d4129c343f2f8`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `13 body pages / 18 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

