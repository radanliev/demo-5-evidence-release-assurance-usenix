# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-19 00:34

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 0 |
| MINOR | 4 |
| INFO | 4 |

Gated (human sign-off required): **0**

## Auto-fix mandate

The writer agent applies these directly. Formatting, layout, figures, references, venue compliance — no interpretation of results required.

### [MINOR] refs.bibfield `docs/references.bib`:268

notarized2026agents is cited as arXiv — check for a peer-reviewed version

- **remedy:** If it appeared at a venue, cite the published version. Reviewers notice arXiv-only bibliographies.
- **id:** `0773e9972633d214`

### [MINOR] refs.bibfield `docs/references.bib`:340

shi2025progent is cited as arXiv — check for a peer-reviewed version

- **remedy:** If it appeared at a venue, cite the published version. Reviewers notice arXiv-only bibliographies.
- **id:** `79316e3ed4543120`

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:518

percentage without an explicit denominator

- **found:** `EviAssure blocks \eviBlocked{} of \eviTotal{} scored vectors (\eviPct\%, 95\% CI [\eviCIlo, \eviCIhi]), and falsely blocks \falseBlockK{} of \falseBlockN{} clean negative controls.`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `48dd7d0fe41d5226`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:526

percentage without an explicit denominator

- **found:** `\textbf{Differential wire fuzzing.} A campaign whose every mutation perturbs a field inside the signed payload cannot fail (a verifying bundle is unreachable), so it carries no inf`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `4cf2748735cd4fe5`

## Measurements

Recorded for the round log; no action implied.

### [INFO] refs.unverified

45 citation(s) verified against Crossref/OpenAlex/SemanticScholar

- **id:** `30abfb8ca6869b49`

### [INFO] science.artifact_missing

indexed 235 distinct values from 8 artifacts

- **id:** `e91d590adae99747`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `13 body pages / 19 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

