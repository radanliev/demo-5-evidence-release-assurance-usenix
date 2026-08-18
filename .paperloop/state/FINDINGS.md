# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-18 12:56

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 1 |
| MINOR | 7 |
| INFO | 4 |

Gated (human sign-off required): **1**

## Auto-fix mandate

The writer agent applies these directly. Formatting, layout, figures, references, venue compliance — no interpretation of results required.

### [MINOR] refs.bibfield

only 16 of 33 cited works carry a DOI

- **found:** `16/33`
- **expected:** a DOI on every reference that has one
- **remedy:** Add DOIs from the publisher's page or Crossref. They let a reviewer check a reference in one click, and let this gate verify it exactly rather than by fuzzy title match.
- **id:** `6c1bb8fd5103f189`

### [MINOR] refs.bibfield `docs/references.bib`:280

notarized2026agents is cited as arXiv — check for a peer-reviewed version

- **remedy:** If it appeared at a venue, cite the published version. Reviewers notice arXiv-only bibliographies.
- **id:** `580aa57ffcdfca8e`

### [MINOR] refs.unused

1 bibliography entries are never cited

- **found:** `krawczyk1997hmac`
- **remedy:** Harmless with bibtex, but a long unused tail usually means the related-work section drifted from the .bib.
- **id:** `74de020e5478c32c`

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [MAJOR] science.stale_artifact

2 result artifact(s) changed after the manuscript was last edited

- **found:** `results/benchmark_summary.json; results/security_evaluation.json`
- **expected:** manuscript newer than the data it reports
- **remedy:** Re-read those artifacts and confirm every dependent number, table and figure in the paper still matches.
- **id:** `1399079e29b05206`

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

indexed 199 distinct values from 7 artifacts

- **id:** `6916a3eb632d1cfe`

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

