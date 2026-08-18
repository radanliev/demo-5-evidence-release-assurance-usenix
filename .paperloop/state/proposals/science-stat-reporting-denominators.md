# science.stat_reporting: percentages without an explicit denominator

## Finding

The gate reports four MINOR `science.stat_reporting` findings against
`docs/usenix_paper_manuscript.tex` at lines 113, 515, 523 and 564, each
"percentage without an explicit denominator".

I read all four sites. **None of them is a rate missing its denominator.**
Three are confidence *levels*, which have no denominator by definition, and
the fourth states its denominator in a macro the checker cannot expand.

The rule (`.paperloop/checks/check_science.py:252`) triggers on a literal
digit followed by `%`:

```
trigger = r"\d+(\.\d+)?\s*\\?%"
require = r"(n\s*=|N\s*=|of\s+\d|out of|\bacross\s+\d|\bover\s+\d|/\s*\d)"
```

Every clause of `require` demands a literal digit. Where this manuscript
supplies its denominator through a generated macro — `\eviTotal{}`,
`\fuzzCases{}` — the requirement cannot match, however explicit the sentence
is to a reader.

| Line | Percentage that fired | What it actually is | Verdict |
|---|---|---|---|
| 113 | `95\%` in `(95\% CI [\eviCIlo, \eviCIhi])` | Wilson confidence level | False positive |
| 515 | `95\%` in `(\eviPct\%, 95\% CI [...])` | Confidence level; the rate beside it already reads `\eviBlocked{} of \eviTotal{}` | False positive |
| 523 | `20\%` in `Over \fuzzCases{} cases (20\% clean controls)` | Real proportion; denominator is `\fuzzCases{}` = 1000 | Denominator present, but macro-hidden |
| 564 | `95\%` in `with Wilson 95\% intervals` | Confidence level in a figure caption | False positive |

Line 113 additionally already carries `\eviBlocked/\eviTotal{}` — a
slash-denominator that `/\s*\d` would have accepted had it been literal.

## Correct value or claim

No number in the manuscript is wrong, and no claim is unsupported. Rendered,
the three confidence-level sites read "95% CI [73.0, 99.0]" and "Wilson 95%
intervals", which is the standard way to report an interval estimate; adding
a denominator to a confidence level would be meaningless. Line 523 renders as
"Over 1000 cases (20% clean controls)", where 20% of 1000 is stated one
clause earlier.

Rewording these four sites to satisfy the regex would make the paper worse,
not better, and would be editing prose to turn a check green. I have applied
nothing.

## Exact proposed diff

**Option A — no manuscript change (recommended).** Accept the four findings
as known false positives and leave the text as written. Nothing to apply.

**Option B — refine the rule so it stops firing on confidence levels and
macro denominators.** This changes the checker, not the science, and it
narrows the rule rather than disabling it: a genuine bare rate still fires.

```diff
--- a/.paperloop/checks/check_science.py
+++ b/.paperloop/checks/check_science.py
@@
     dict(name="rate_without_denominator",
-         trigger=r"\d+(\.\d+)?\s*\\?%",
-         require=r"(n\s*=|N\s*=|of\s+\d|out of|\bacross\s+\d|\bover\s+\d|/\s*\d)",
+         # A confidence *level* has no denominator: "95% CI", "Wilson 95%
+         # intervals". Excluding it stops the rule flagging correct interval
+         # reporting as if it were an unsupported rate.
+         trigger=r"(?<!Wilson )\d+(\.\d+)?\s*\\?%(?!\s*(CI|confidence|interval))",
+         # Denominators in this manuscript arrive through generated macros
+         # (\eviTotal{}, \fuzzCases{}), so a literal-digit requirement cannot
+         # see them. \\\w+ accepts a macro in the same positions only.
+         require=r"(n\s*=|N\s*=|of\s+(\d|\\\w+)|out of|\bacross\s+(\d|\\\w+)|"
+                 r"\bover\s+(\d|\\\w+)|/\s*(\d|\\\w+))",
          severity="MINOR",
          msg="percentage without an explicit denominator",
          remedy="Give the numerator/denominator (e.g. '62% (31/50)')."),
```

**Option C — reword the manuscript to satisfy the current rule.** Recorded
for completeness; I do not recommend it. It would require, at line 523,
`Over \fuzzCases{} cases (200 of 1000 clean controls)` — hardcoding a
denominator that is currently generated, which is exactly the drift the
macro system exists to prevent — and at lines 113, 515 and 564 there is no
honest rewording at all, because a confidence level has no denominator to
give.

## Evidence needed

A human decision on Option A versus Option B. Option B is a change to a gate,
so it needs the same scrutiny as a manuscript change: confirm that the
narrowed `trigger` still fires on a genuine bare rate (e.g. "detection
improved to 94%" with no denominator anywhere) before accepting it. I have
not applied Option B, because narrowing a rule that is currently flagging
your own paper is precisely the kind of change that should not be made by
the agent that wants the gate quiet.

If neither option is taken, the four MINORs are expected to persist
indefinitely. They are not blocking: current gate state is BLOCKER 0.
