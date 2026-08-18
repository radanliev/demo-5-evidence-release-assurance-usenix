# Author

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
| `\anonymousfalse` | author block + acknowledgements | camera-ready, arXiv, internal |

Only the title page and the acknowledgements section change. Flip the one line;
do not hand-edit the author block for a build.

---

## Petar Radanliev — sole author

- Professor of Secure Autonomous Intelligence, The Open University
- Researcher, The Alan Turing Institute
- Also associated with the University of Oxford and Newcastle University
- Email: radanliev@gmail.com

*Decide before camera-ready which affiliations appear on the title page.
Listing four is unusual and dilutes the primary one; two is typical. Whatever
appears on the paper, ALL of them are conflict-of-interest declarations in
HotCRP regardless.*

*Consider substituting an institutional address before camera-ready; reviewers
and readers generally expect one, and it survives changes of personal provider.*

---

## Note on authorship

This was submitted as a single-author paper. Two colleagues were considered as
co-authors during drafting and were not approached before the deadline:

- Omar Santos (Cisco Systems)
- Carsten Maple (University of Warwick)

Neither appears on the submission, and neither should be added to the
camera-ready without their agreement — a person cannot be made an author of a
paper they have not seen and approved. USENIX treats an incorrect author list as
academic misconduct, and that cuts both ways: naming someone who did not consent
is as much a problem as omitting someone who contributed.

If either contributed materially before the deadline, the correct remedy is an
acknowledgement with their permission, not a silent addition at camera-ready.

**Practical consequence:** the HotCRP conflict surface is now narrower. Only the
author's own affiliations create conflicts. Cisco and the University of Warwick
are no longer conflicted institutions, which means people there — including both
colleagues above — are now eligible to be assigned as reviewers.

---

## Notes for submission

1. **Conflicts of interest** must be declared in HotCRP: anyone sharing an
   institutional affiliation with the author now or in the past two years
   (The Open University, The Alan Turing Institute, the University of Oxford,
   Newcastle University), advisors and advisees, recent collaborators, co-PIs,
   and funders. See the CFP's Conflicts of Interest section.
2. **Roles and honours** are recorded here but deliberately kept off the paper's
   title page — USENIX title pages carry name, affiliation and email.
3. **Phone numbers, postal addresses and PGP keys** are contact metadata, not
   publication metadata. They are not in the manuscript and should not be.

---

## Anonymising the artifact repository — read before uploading

The CFP: *"Authors are solely responsible for ensuring no identifying
information is exposed (e.g., usernames, organization names, **commit
history**)."*

Three traps in this specific repository:

1. **`AUTHORS.md` is this file.** If the anonymous mirror is pointed at the
   GitHub working repository, this file is served verbatim.
2. **Commit history.** The repository lives under a personal GitHub account
   whose username is the author's surname. Anything exposing history or the
   origin URL deanonymises the paper.
3. **`.anonymity-terms`** lists the terms the packager scans for, which is
   itself a list of identifying strings.

The published anonymous artifact is a separate repository built from
`scripts/prepare_anonymous_artifact.py`, with a single commit authored by
`Anonymous <anonymous@example.invalid>` and no shared history.
