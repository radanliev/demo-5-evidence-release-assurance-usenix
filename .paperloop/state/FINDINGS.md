# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-16 22:50

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 0 |
| MINOR | 1 |
| INFO | 6 |

Gated (human sign-off required): **0**

<details><summary>Build output (tail)</summary>

```
=== USENIX Security Paper PDF Builder & Figure Generator ===
[!] Warning: Figure generation error (No module named 'matplotlib')
[*] Froze headline metrics -> frozen_metrics.tex (throughput=7,321, overhead=0.000%)
[*] Compiling LaTeX manuscript: usenix_paper_manuscript.tex using pdflatex...
[SUCCESS] Compiled USENIX Security paper PDF: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf

[+] PDF generation complete: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf
```
</details>

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [MINOR] refs.unverified

no OPENALEX_API_KEY or S2_API_KEY set — APIs require keys for all requests since 2026-02-13, so only Crossref is being queried

- **expected:** OPENALEX_API_KEY or S2_API_KEY set
- **remedy:** Free key at https://openalex.org/settings/api, then ./set-key.sh OPENALEX_API_KEY or S2_API_KEY. Crossref alone misses preprints and some CS venues, so coverage is reduced.
- **id:** `ebace01cc8334e81`

## Measurements

Recorded for the round log; no action implied.

### [INFO] figure.clipping

rendered 20 page images for visual QA

- **found:** `/Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/.paperloop/state/pages`
- **id:** `3e8705bea43410a2`

### [INFO] refs.unverified

Crossref, OpenAlex, and Semantic Scholar are unreachable — citations not verified

- **expected:** network access to citation APIs
- **remedy:** Add both to the network allowlist, then re-run. Offline, citation existence cannot be checked at all.
- **id:** `ef13d2045d43d08a`

### [INFO] refs.unverified

21 citation(s) verified against Crossref/OpenAlex/SemanticScholar, 13 unresolved

- **id:** `f99023751abf748d`

### [INFO] science.artifact_missing

indexed 146 distinct values from 6 artifacts

- **id:** `9395f41b027fa0a9`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `13 body pages / 20 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

