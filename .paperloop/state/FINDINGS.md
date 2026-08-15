# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-15 23:39

| Severity | Count |
|---|---|
| BLOCKER | 0 |
| MAJOR | 9 |
| MINOR | 0 |
| INFO | 5 |

Gated (human sign-off required): **9**

<details><summary>Build output (tail)</summary>

```
=== USENIX Security Paper PDF Builder & Figure Generator ===
[+] Benchmark figures saved to: /Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/docs/figures
[*] Froze headline metrics -> frozen_metrics.tex (throughput=4,863, overhead=0.125%)
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

### [MAJOR] refs.unverified `docs/references.bib`:81

citation 'spiffe2020spire' does not resolve in Crossref or OpenAlex

- **found:** `"SPIFFE and SPIRE: Universal Workload Identity for Cloud Native Infrastructure"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `d8d883428a22e7da`

### [MAJOR] refs.unverified `docs/references.bib`:89

citation 'opa2021openpolicy' does not resolve in Crossref or OpenAlex

- **found:** `"Open Policy Agent (OPA): Declarative Fine-Grained Policy Engine for Cloud Native Environments"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `0d698a857bcccd1f`

### [MAJOR] refs.unverified `docs/references.bib`:97

citation 'kyverno2022policy' does not resolve in Crossref or OpenAlex

- **found:** `"Kyverno: Kubernetes Native Policy Management Engine"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `9b5c8f226e8321a8`

### [MAJOR] refs.unverified `docs/references.bib`:114

citation 'papernot2016cleverhans' does not resolve in Crossref or OpenAlex

- **found:** `"Technical Report on the CleverHans v1.0.0 Adversarial Examples Library"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `0945889a9254fbb2`

### [MAJOR] refs.unverified `docs/references.bib`:197

citation 'yao2023react' does not resolve in Crossref or OpenAlex

- **found:** `"ReAct: Synergizing Reasoning and Acting in Language Models"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `2986620a7350d575`

### [MAJOR] refs.unverified `docs/references.bib`:256

citation 'intoto2026agent-decision' does not resolve in Crossref or OpenAlex

- **found:** `"RFC: agent-decision/v0.1 Predicate for AI Agent Policy Decisions"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `dbfd33d0536c8b4c`

### [MAJOR] refs.unverified `docs/references.bib`:265

citation 'apas2026agent-provenance' does not resolve in Crossref or OpenAlex

- **found:** `"Agent Provenance Attestation Standard (APAS)"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `0b53e123b4c53b11`

### [MAJOR] refs.unverified `docs/references.bib`:274

citation 'aas12026agent-audit' does not resolve in Crossref or OpenAlex

- **found:** `"Agent Auditability Standard (AAS-1), Working Paper v0.1"`
- **expected:** a work that exists in at least one bibliographic database
- **remedy:** Verify this reference by hand. A title that matches nothing is usually a hallucinated or misremembered citation — check the authors, year and venue against the publisher's page, or remove it.
- **id:** `a88da2424995aaf6`

## Measurements

Recorded for the round log; no action implied.

### [INFO] figure.clipping

rendered 16 page images for visual QA

- **found:** `/Users/skywalker/Projects/demo-5-evidence-release-assurance-usenix/.paperloop/state/pages`
- **id:** `519c5e2395cf3450`

### [INFO] refs.unverified

24 citation(s) verified against Crossref/OpenAlex, 9 unresolved

- **id:** `2c70f11a8673530e`

### [INFO] science.artifact_missing

indexed 129 distinct values from 6 artifacts

- **id:** `9a27c7de6b999178`

### [INFO] venue.font

body font size correct

- **found:** `9.96pt`
- **expected:** 10.0pt
- **id:** `4c59ff54d5e8d91e`

### [INFO] venue.pagecount

page count within limit

- **found:** `11 body pages / 16 total`
- **expected:** <= 13
- **id:** `1f0cf72111de700b`

