---
name: bibtex-forensics
description: Verifying .bib entries against Crossref, OpenAlex, and DBLP — API quirks, fabrication tells, and the fixes for each failure mode
---

# BibTeX Forensics

Use when citations must be verified as real (gate finding, audit, or cleanup).
Worked example: the demo-5 audit found 6 fabricated references, 7 wrong DOIs,
and 3 mangled entries in one pass.

## Pipeline per entry

1. **DOI present?** Resolve `https://api.crossref.org/works/<doi>` and compare
   the title (fuzzy ≥0.75). Wrong-DOI entries are common — fix with the DOI of
   the *right* work found by title search.
2. **Title search** — Crossref `query.bibliographic` first, then OpenAlex
   `filter=title.search:`, then DBLP as author-level ground truth
   (`https://dblp.org/search/publ/api?q=<name>&format=json`).
3. **Still nothing?** Web-search the exact title + authors against the
   publisher (USENIX/NDSS pages, ACM DL, IEEE). If nothing anywhere: fabricated
   — remove the entry *and* every in-text `\cite` of it.

## API quirks (learned by experiment — don't rediscover)

- **Crossref splits subtitles**: `title` holds the main title, `subtitle` the
  rest. Compare against `title: subtitle` joined, or full titles with
  subtitles get false mismatches (hit both "A look in the mirror" and
  "Random oracles are practical").
- **OpenAlex `title.search` ANDs tokens**: one word missing from its
  (sometimes truncated) record title → 0 results. Retry with the leading ~8
  words; still guard the result with a ≥0.87 similarity check so truncation
  can't false-verify.
- **OpenAlex rejects punctuation**: double spaces (after stripping a colon)
  and `?` cause HTTP 400. Strip punctuation, collapse whitespace, and append
  `&mailto=` for the polite pool.
- **OpenAlex key**: required since 2026-02 and stored in
  `~/Projects/.paperloop-env`; a stale key 401s *silently per-query* and
  degrades everything to "unverified". Keyless+mailto worked from this
  network as a fallback. Crossref needs no key.
- **DOI schemes that Crossref can't resolve**: DataCite DOIs (arXiv
  `10.48550/...`, Zenodo `10.5281/...`) — title search must carry these.

## Fabrication tells

- Fake `10.5555/...` DOIs (a made-up ACM DL scheme — no such prefix).
- Author lists like "X Project Team" or "X Working Group" on systems papers
  that actually have named authors.
- Plausible-generic titles that match nothing anywhere ("Considerations for
  Adversarial Robustness Benchmarks") — often *near-misses* of a real author's
  actual paper; check DBLP by author to be sure.
- Real author, wrong title ("Automated Security Analysis of Financial
  Workflows" — those authors' real paper was "Automated Analysis of
  Security-Critical JavaScript APIs").
- Venue confusion (Diplomat is NSDI'16, not USENIX Security'16; the real
  in-toto paper is "in-toto: Providing Farm-to-Table Guarantees...", USENIX
  Security '19, with different co-authors).

## House rules

- Removing a fabricated citation = edit the `.bib` *and* every `\cite` in the
  manuscript, including comparison-table rows that cite it.
- Prefer the published version over arXiv when both exist (gates flag
  arXiv-only).
- After edits: delete `.paperloop/state/citation_cache.json` before re-running
  gates, or stale verdicts resurface.
- Python clients `habanero` (Crossref) and `pyalex` (OpenAlex) are installed —
  use them instead of raw curl where convenient.
