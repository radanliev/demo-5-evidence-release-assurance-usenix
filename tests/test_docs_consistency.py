"""
Meta-test: the manuscript's claims about the repository must match reality.

The test-count claim drifted three times while tests were being added -- the
manuscript claimed 44 while the suite collected 29 at the time of the
2026-08-17 review, and REPRODUCE.md/README.md claimed "44/44 PASS". The number
is now *generated* into docs/security_metrics.tex rather than typed, and this
test asserts the generator is in sync with the collected suite, so prose and
code cannot disagree.
"""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
TESTS = Path(__file__).parent


def _collected() -> int:
    total = 0
    for f in sorted(TESTS.glob("test_*.py")):
        if f.name == "test_docs_consistency.py":
            continue          # this guard is not part of the suite the paper describes
        total += len(re.findall(r"^def (test_\w+)", f.read_text(), re.M))
    return total


def test_generated_test_count_matches_collection():
    macros = (ROOT / "docs" / "security_metrics.tex").read_text()
    m = re.search(r"\\newcommand\{\\testCount\}\{(\d+)\}", macros)
    assert m, ("docs/security_metrics.tex has no \\testCount macro; "
               "run scripts/write_security_macros.py")
    assert int(m.group(1)) == _collected(), (
        f"macro claims {m.group(1)} tests, suite collects {_collected()}; "
        "re-run scripts/write_security_macros.py"
    )


def test_manuscript_uses_the_macro_not_a_literal():
    tex = (ROOT / "docs" / "usenix_paper_manuscript.tex").read_text()
    assert "\\testCount{} tests" in tex, "appendix must cite the generated macro"
    assert not re.search(r"execute all \d+ unit", tex), \
        "a hard-coded test count was reintroduced into the manuscript"


def test_headline_numbers_come_from_macros_not_literals():
    """The block-rate and corpus figures must be macro-bound too, so a re-run
    cannot leave a stale number in the abstract (the E1/E7 drift class)."""
    tex = (ROOT / "docs" / "usenix_paper_manuscript.tex").read_text()
    abstract = tex[tex.index("\\begin{abstract}"):tex.index("\\end{abstract}")]
    for macro in ("\\eviBlocked", "\\eviTotal", "\\compBlocked", "\\corpusProfiles"):
        assert macro in abstract, f"{macro} must be macro-bound in the abstract"
    assert "100.0\\%" not in abstract, \
        "the abstract must not carry a hard-coded headline percentage"
