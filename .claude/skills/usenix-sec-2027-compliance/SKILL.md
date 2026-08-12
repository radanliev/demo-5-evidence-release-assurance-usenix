---
name: usenix-sec-2027-compliance
description: USENIX Security 2027 submission compliance — page limits, template rules, anonymity, ethics requirements, and the reasons papers get desk-rejected there. Use this skill whenever working on a manuscript for USENIX Security, Usenix Sec 27, or a manuscript targeting the USENIX Security Symposium; whenever checking whether a paper meets submission requirements; and proactively before any USENIX Security 2027 submission or when someone mentions page limits, formatting, anonymity, or the call for papers.
---

# USENIX Security 2027 compliance

Requirements below were read from the official call for papers on 2026-08-12.
Source: https://www.usenix.org/conference/usenixsecurity27/call-for-papers

Conference requirements change between years. Re-check the CFP before relying on
any number here, and update this file and `.paperloop/venue.yaml` when it moves.

## Hard limits

**13 pages** for the main body, excluding References and any appendices.

## Grayscale legibility — USENIX states this explicitly

"Please ensure your submission is intelligible when printed/rendered in
grayscale." Reviewers print. This is a real requirement, not advice.

Practical consequence: no figure may encode meaning in hue alone. Every series
needs a distinguishing marker, line style, or hatch pattern. Check by converting
the PDF to grayscale and reading it:

```bash
gs -sDEVICE=pdfwrite -sColorConversionStrategy=Gray \
   -dProcessColorModel=/DeviceGray -o gray.pdf paper.pdf
```

If two lines become indistinguishable, the figure fails.

## Submission mechanics that catch people out

- **Mandatory registration one week before the deadline**, with the *fixed*
  title, the *fixed* full author list including ORCIDs, a tentative abstract,
  and fixed topics. Title and author list cannot change afterwards. Cycle 1 for
  2027: registration 18 August 2026, submission 25 August 2026.
- **At most seven papers per author per cycle.**
- Standard PDF, no unusual fonts or embedding tricks.

## Ethics

The ethics appendix is **no longer mandatory but is strongly encouraged**.
Include one for anything touching human subjects, live systems, disclosure, or
dual use. USENIX reviewers treat its absence on a paper that needed it as a
substantive problem, not a formatting one.

## What USENIX reviewers reward and punish

USENIX Security is a systems-security venue. Reviewers want a real system, a
real adversary, and a real measurement.

Rewarded: end-to-end implementations; evaluation on real workloads or real
corpora; honest negative results; deployment experience; artifacts that work.

Punished: security claims resting on an unmediated path; overhead measured only
in a single-tenant microbenchmark; a threat model that excludes exactly the
attacks that would break the system; "we assume the adversary cannot X" where X
is the crux and no mechanism enforces it.

A short paper reads as underdeveloped here. If the body is well under 13 pages,
the usual diagnosis is a thin evaluation or a threat model that has not been
worked through.

## Verifying against the deterministic gate

The repository measures most of this automatically:

```bash
python3 .paperloop/run_gates.py --build --render
```

That covers page count, margins, fonts, figure resolution, overfull boxes,
citations, and anonymity string-matching. Read `.paperloop/state/FINDINGS.md`.

What it cannot check, and you must: whether figures are legible and correct,
whether captions stand alone, whether the ethics discussion is adequate rather
than merely present, whether the threat model actually scopes the claims, and
whether this year's CFP still says what `venue.yaml` believes.
