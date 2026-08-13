# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-13 12:06

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 0 |
| MINOR | 0 |
| INFO | 5 |

Gated (human sign-off required): **0**

<details><summary>Build output (tail)</summary>

```
=== USENIX Security Paper PDF Builder & Figure Generator ===
[+] Benchmark figures saved to: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/figures
[*] Froze headline metrics -> frozen_metrics.tex (throughput=5,919, overhead=0.116%)
[*] Compiling LaTeX manuscript: usenix_paper_manuscript.tex using pdflatex...
[SUCCESS] Compiled USENIX Security paper PDF: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf

[+] PDF generation complete: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf
```
</details>

## Measurements

Recorded for the round log; no action implied.

### [INFO] figure.clipping

rendered 0 page images for visual QA

- **found:** `/Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/.paperloop/state/pages`
- **id:** `9cf707a2e8e178df`

### [INFO] refs.unverified

Crossref and OpenAlex are unreachable — citations not verified

- **expected:** network access to api.crossref.org and api.openalex.org
- **remedy:** Add both to the network allowlist, then re-run. Offline, citation existence cannot be checked at all.
- **id:** `7b862c54c1971489`

### [INFO] science.artifact_missing

indexed 101 distinct values from 5 artifacts

- **id:** `24182eedce03f588`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `11 body pages / 11 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

