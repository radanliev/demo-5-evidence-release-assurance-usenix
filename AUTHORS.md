# Authors

**Do not add any of this to the submission build.** USENIX Security '27 is
double-blind and the CFP states that papers which are not properly anonymised
"may be rejected without review". This file exists so the information is
recorded once, in one place, and is *deliberately excluded* from the anonymous
review artifact — `scripts/prepare_anonymous_artifact.py` uses an allowlist of
paths, and this file is not on it. If you ever switch that script to an
exclude-list, add `AUTHORS.md` to the exclusions first.

The manuscript carries an anonymity switch (`docs/usenix_paper_manuscript.tex`):

| Setting | Build | Use for |
|---|---|---|
| `\anonymoustrue` **(default)** | "Anonymous Submission" | HotCRP submission |
| `\anonymousfalse` | full author block + acknowledgements | camera-ready, arXiv, internal |

Only the title page and the acknowledgements section change. Flip the one line;
do not hand-edit the author block for a build.

---

## Petar Radanliev

- Professor of Secure Autonomous Intelligence, The Open University
- Researcher, The Alan Turing Institute
- Also associated with the University of Oxford and Newcastle University
- Email: radanliev@gmail.com

*Decide before camera-ready which affiliations appear on the title page.
Listing five is unusual and dilutes the primary one; two or three is typical.
Whatever you choose, ALL of them are conflict-of-interest declarations in
HotCRP regardless of whether they appear on the paper.*

*Consider substituting an institutional address before camera-ready; reviewers
and readers generally expect one, and it survives changes of personal provider.*

## Omar Santos

- Senior Director / Distinguished Engineer, Cisco Systems
- Cisco Product Security Incident Response Team (PSIRT), Security & Trust —
  Cisco Security Research and Operations
- Co-chair, Coalition for Secure AI (CoSAI)
- Board member, OASIS Open standards organization
- Address: 7025 Kit Creek Rd, Research Triangle Park, Durham, NC 27709, USA
- Email: osantos@cisco.com / os@cisco.com
- Tel: +1 919 927-2468 · Mobile: +1 919 412-8568
- PGP/GPG: https://cs.co/gpg

## Carsten Maple

- Deputy Pro Vice Chancellor; Professor of Cyber Systems Engineering,
  University of Warwick, Cyber Security Centre
- Researcher, The Alan Turing Institute
- Co-director, National Centre for Cyberstalking Research
- Trustee, Protection Against Stalking
- Fellow, British Computer Society
- Vice-chair, Council of Professors and Heads of Computing
- Address: Coventry, CV4 7AL, United Kingdom
- Phone: +44 (0)24 7657 4606
- Email: carsten.maple@warwick.ac.uk

---

## Notes for submission

1. **Author order** is as given above and is not encoded anywhere else; change
   it here and in the `\else` branch of the manuscript together.
2. **Roles and honours** (CoSAI co-chair, OASIS board, DPVC, BCS Fellow, and so
   on) are recorded here but deliberately kept off the paper's title page —
   USENIX title pages carry name, affiliation and email. They belong in author
   bios if a venue asks for them.
3. **Phone numbers, postal addresses and PGP keys** are contact metadata, not
   publication metadata. They are not in the manuscript and should not be.
4. **Conflicts of interest** must be declared in HotCRP at submission: anyone
   sharing an institutional affiliation with an author now or in the past two
   years (The Open University, Cisco, University of Warwick, **and The Alan
   Turing Institute** — shared by two authors and easy to overlook, plus
   **the University of Oxford** and **Newcastle University**), advisors and
   advisees, recent collaborators, co-PIs, and funders. See the CFP's
   Conflicts of Interest section. Five institutions across three authors is a
   wide conflict surface; work through it deliberately rather than from memory.
5. **All three authors must be registered in HotCRP** by the registration
   deadline. The CFP: papers for which at least one author fails to comply
   "will not be considered for review".


---

## Anonymising the artifact repository — read before uploading

The CFP: *"Authors are solely responsible for ensuring no identifying
information is exposed (e.g., usernames, organization names, **commit
history**)."*

Three concrete traps in this specific repository:

1. **`AUTHORS.md` is this file.** If the anonymous mirror is pointed at the
   GitHub repository, this file is served verbatim and names all three authors.
2. **Commit history.** Commits are authored by a named identity, and the
   repository lives under a personal GitHub account whose username is the
   surname of the first author. Anything that exposes history or the origin URL
   deanonymises the paper.
3. **`PR_BODY.md`** and any `COMMIT_MSG.txt` left in the tree.

**Recommended: do not mirror the GitHub repository.** Upload the contents of
`eviassure_usenix27_artifact.zip` instead. That archive is built from an
explicit allowlist, carries no git history, and has been scanned end-to-end for
identifying strings with a clean result. It also excludes the manuscript source,
which contains the camera-ready author block.

Create the anonymous repository with conference ID **`SEC27`** so the expiry
matches this cycle, then confirm the URL in the paper resolves and stays live
through the shepherd approval deadline.
