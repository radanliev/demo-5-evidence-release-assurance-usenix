# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-12 20:38

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 1 |
| MINOR | 0 |
| INFO | 3 |

Gated (human sign-off required): **0**

## Auto-fix mandate

The writer agent applies these directly. Formatting, layout, figures, references, venue compliance — no interpretation of results required.

### [MAJOR] venue.pagecount

paper is well under the 13-page budget

- **found:** `8 body pages`
- **expected:** competitive submissions use 11-13 pages
- **remedy:** Expand evaluation, threat model, or related work; reviewers read a short paper as an underdeveloped one.
- **id:** `6cfb9be7880c8171`

## Measurements

Recorded for the round log; no action implied.

### [INFO] refs.unverified

Crossref and OpenAlex are unreachable — citations not verified

- **expected:** network access to api.crossref.org and api.openalex.org
- **remedy:** Add both to the network allowlist, then re-run. Offline, citation existence cannot be checked at all.
- **id:** `7b862c54c1971489`

### [INFO] science.artifact_missing

indexed 66 distinct values from 5 artifacts

- **id:** `2df7050383de2842`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

