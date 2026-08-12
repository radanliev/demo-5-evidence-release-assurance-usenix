# Gate report — demo-5-evidence-release-assurance-usenix

**Venue:** USENIX Security 2027  
**Manuscript:** `docs/usenix_paper_manuscript.tex`  
**Run:** 2026-08-12 17:45

| Severity | Count |
|---|---|
| BLOCKER | 6 |
| MAJOR | 8 |
| MINOR | 5 |
| INFO | 3 |

Gated (human sign-off required): **4**

## Auto-fix mandate

The writer agent applies these directly. Formatting, layout, figures, references, venue compliance — no interpretation of results required.

### [BLOCKER] layout.overfull `docs/usenix_paper_manuscript.tex`:113

content sticks 20.8pt past the column/text width (0.289in into the margin)

- **found:** `Overfull \hbox 20.8pt`
- **expected:** no overfull hbox above 1.0pt
- **remedy:** Usually an unbreakable token: a long URL (use \url or \sloppy), a wide table (use \resizebox or \small on the tabular only), code/identifier (add \allowbreak), or a figure wider than \columnwidth (set width=\columnwidth).
- **id:** `17d50fc73aceffe4`

### [BLOCKER] venue.margins p.1

bottom margin violated on p.1

- **found:** `0.720in`
- **expected:** >= 0.9in (tolerance 0.02in)
- **remedy:** Content intrudes into the bottom margin on p.1. Usually a wide table, figure, algorithm block, or unbroken URL. Wrap it, scale it to \columnwidth, or rebreak the line — do not move the margin.
- **id:** `6000516d72902832`

### [BLOCKER] venue.margins p.2

right margin violated on p.2

- **found:** `0.462in`
- **expected:** >= 0.7in (tolerance 0.02in)
- **remedy:** Content intrudes into the right margin on p.2. Usually a wide table, figure, algorithm block, or unbroken URL. Wrap it, scale it to \columnwidth, or rebreak the line — do not move the margin.
- **id:** `7122301b5e6fad3f`

### [BLOCKER] venue.margins p.4

top margin violated on p.4

- **found:** `0.731in`
- **expected:** >= 0.9in (tolerance 0.02in)
- **remedy:** Content intrudes into the top margin on p.4. Usually a wide table, figure, algorithm block, or unbroken URL. Wrap it, scale it to \columnwidth, or rebreak the line — do not move the margin.
- **id:** `2a4189e5b25dbf93`

### [MAJOR] refs.bibfield

only 16 distinct works cited

- **found:** `16`
- **expected:** >= 30
- **remedy:** A thin bibliography reads as an unfamiliarity with the literature. Expand related work.
- **id:** `960ac10b0c300757`

### [MAJOR] refs.bibfield `docs/references.bib`:118

@inproceedings{bernstein2012high} missing required field(s): booktitle

- **remedy:** Complete the entry from the publisher's page. Incomplete references read as carelessness.
- **id:** `cd5f7b8f62f672cc`

### [MAJOR] refs.bibfield `docs/references.bib`:173

@inproceedings{shostack2014threat} missing required field(s): booktitle

- **remedy:** Complete the entry from the publisher's page. Incomplete references read as carelessness.
- **id:** `807caaf3e909fc11`

### [MAJOR] refs.bibfield `docs/usenix_paper_manuscript.blg`

bibtex: Warning--empty booktitle in bernstein2012high

- **remedy:** Fill the missing bibliography field.
- **id:** `503c7bdb8248479e`

### [MAJOR] refs.bibfield `docs/usenix_paper_manuscript.blg`

bibtex: Warning--empty booktitle in shostack2014threat

- **remedy:** Fill the missing bibliography field.
- **id:** `c60d0e8bf5dd0f74`

### [MAJOR] venue.pagecount

paper is well under the 13-page budget

- **found:** `6 body pages`
- **expected:** competitive submissions use 11-13 pages
- **remedy:** Expand evaluation, threat model, or related work; reviewers read a short paper as an underdeveloped one.
- **id:** `6cfb9be7880c8171`

### [MINOR] refs.bibfield

only 0 of 16 cited works carry a DOI

- **found:** `0/16`
- **expected:** a DOI on every reference that has one
- **remedy:** Add DOIs from the publisher's page or Crossref. They let a reviewer check a reference in one click, and let this gate verify it exactly rather than by fuzzy title match.
- **id:** `8f7321233eb2d505`

### [MINOR] refs.bibfield `docs/usenix_paper_manuscript.blg`

bibtex: Warning--can't use both volume and number fields in bernstein2012high

- **remedy:** Fill the missing bibliography field.
- **id:** `6feff32bc8f1a91f`

### [MINOR] refs.unused

11 bibliography entries are never cited

- **found:** `bellare1993random, birgisson2014macaroons, boneh2001short, cappos2008look, krawczyk1997hmac, laurie2014certificate, mowery2012welcome, papernot2016cleverhans, spiffe2020spire, taly2011definitive, tramer2022adversarial`
- **remedy:** Harmless with bibtex, but a long unused tail usually means the related-work section drifted from the .bib.
- **id:** `26d1b84b58958766`

## Gated — requires your decision

**The writer agent must not touch these.** Changing a number to make a gate pass converts a data error into a published claim. Each one gets a proposed diff in `.paperloop/state/proposals/`, and the loop halts.

### [BLOCKER] science.number_mismatch `docs/usenix_paper_manuscript.tex`:54

manuscript says 5,981 but the nearest recorded result is 5850.09 — likely a stale number from an earlier run

- **found:** `…A/Sigstore) while processing policy gate evaluations at up to \textbf{5,981 operations/second} across 8 parallel cores, scaling Merkle tree const…`
- **expected:** 5850.09  (source: results/benchmark_summary.json::parallel_throughput.workers_8.throughput_ops_sec)
- **remedy:** Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
- **id:** `61a2fc7bbac40f52`

### [BLOCKER] science.number_mismatch `docs/usenix_paper_manuscript.tex`:54

manuscript says 0.123 but the nearest recorded result is 0.1217 — likely a stale number from an earlier run

- **found:** `…traces in under   (representing a negligible packaging overhead of **0.123…`
- **expected:** 0.1217  (source: results/benchmark_summary.json::merkle_scaling[3].packaging_overhead_pct)
- **remedy:** Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
- **id:** `32e53341de974461`

### [MAJOR] science.number_mismatch `docs/usenix_paper_manuscript.tex`:48

manuscript says 227 but the nearest recorded result is 222.6 — likely a stale number from an earlier run

- **found:** `…Submission ID: 227…`
- **expected:** 222.6  (source: results/benchmark_summary.json::merkle_scaling[2].bundle_size_kb)
- **remedy:** Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
- **id:** `c5f92562f9e22192`

### [MAJOR] science.number_mismatch `docs/usenix_paper_manuscript.tex`:115

manuscript says 22.0 but the nearest recorded result is 22.4 — likely a stale number from an earlier run

- **found:** `…For   traces, transmitting raw trace logs requires ~22.0 MB of storage. Demo 5 provides sparse Merkle proof compression, trans…`
- **expected:** 22.4  (source: corpus/agent_trace_corpus.json::profiles[3].traces[1].duration_ms)
- **remedy:** Do NOT edit the paper to match blindly. Re-run the producing script, confirm which value is current, then update the manuscript AND state in the round log which artifact it came from.
- **id:** `7eee4a0d870591c0`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:288

percentage without an explicit denominator

- **found:** `\item \textbf{V7 (Sub-threshold Pass Rate)}: Rejects releases with unit test thresholds below 100\%.`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `5e53cebf7ba2135b`

### [MINOR] science.stat_reporting `docs/usenix_paper_manuscript.tex`:297

percentage without an explicit denominator

- **found:** `Figure~\ref{fig:comparative} compares Demo 5 against standard CI exit code gates, OPA schema validators, and Sigstore/Cosign container gates. Demo 5 achieves 100.0\% detection, whe`
- **expected:** rule: rate_without_denominator
- **remedy:** Give the numerator/denominator (e.g. '62% (31/50)').
- **id:** `6b592df853780a61`

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

