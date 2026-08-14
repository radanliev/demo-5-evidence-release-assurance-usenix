# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-14 21:11

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 7 |
| MINOR | 0 |
| INFO | 5 |

Gated (human sign-off required): **7**

<details><summary>Build output (tail)</summary>

```
=== USENIX Security Paper PDF Builder & Figure Generator ===
[+] Benchmark figures saved to: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/figures
[*] Froze headline metrics -> frozen_metrics.tex (throughput=5,129, overhead=0.122%)
[*] Compiling LaTeX manuscript: usenix_paper_manuscript.tex using pdflatex...
[SUCCESS] Compiled USENIX Security paper PDF: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf

[+] PDF generation complete: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/usenix_paper_manuscript.pdf
```
</details>

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [MAJOR] refs.unverified `docs/references.bib`:9

citation 'slsa2023supply' does not resolve in Crossref or OpenAlex

- **found:** `"Supply-chain Levels for Software Artifacts (SLSA) Framework Specification"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `206b73cd20dd823a`

### [MAJOR] refs.unverified `docs/references.bib`:35

citation 'yang2024swebench' does not resolve in Crossref or OpenAlex

- **found:** `"SWE-bench: Can Language Models Resolve Real-World GitHub Issues?"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `86e7d1290795c829`

### [MAJOR] refs.unverified `docs/references.bib`:82

citation 'spiffe2020spire' does not resolve in Crossref or OpenAlex

- **found:** `"SPIFFE and SPIRE: Universal Workload Identity for Cloud Native Infrastructure"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `9d9d61941dbbebd7`

### [MAJOR] refs.unverified `docs/references.bib`:90

citation 'opa2021openpolicy' does not resolve in Crossref or OpenAlex

- **found:** `"Open Policy Agent (OPA): Declarative Fine-Grained Policy Engine for Cloud Native Environments"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `b2fe3701521ddbae`

### [MAJOR] refs.unverified `docs/references.bib`:98

citation 'kyverno2022policy' does not resolve in Crossref or OpenAlex

- **found:** `"Kyverno: Kubernetes Native Policy Management Engine"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `29a92d20793d66f4`

### [MAJOR] refs.unverified `docs/references.bib`:115

citation 'papernot2016cleverhans' does not resolve in Crossref or OpenAlex

- **found:** `"Technical Report on the CleverHans v1.0.0 Adversarial Examples Library"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `d8eeeb1a1846e886`

### [MAJOR] refs.unverified `docs/references.bib`:198

citation 'yao2023react' does not resolve in Crossref or OpenAlex

- **found:** `"ReAct: Synergizing Reasoning and Acting in Language Models"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `4d3e85e71bd7e905`

## Measurements

Recorded for the round log; no action implied.

### [INFO] figure.clipping

rendered 0 page images for visual QA

- **found:** `/Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/.paperloop/state/pages`
- **id:** `9cf707a2e8e178df`

### [INFO] refs.unverified

23 citation(s) verified against Crossref/OpenAlex, 7 unresolved

- **id:** `baa069333e2380e4`

### [INFO] science.artifact_missing

indexed 112 distinct values from 5 artifacts

- **id:** `0c0304182337223c`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `12 body pages / 12 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

