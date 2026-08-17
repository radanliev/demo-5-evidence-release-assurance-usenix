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

import pytest

ROOT = Path(__file__).parent.parent
TESTS = Path(__file__).parent


def _collected() -> int:
    total = 0
    # Every test file, this one included. The manuscript quotes this number
    # beside the literal command `pytest tests/`, so the two must agree; an
    # earlier version excluded this guard and the paper under-reported by 3.
    for f in sorted(TESTS.glob("test_*.py")):
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
    tex_path = ROOT / "docs" / "usenix_paper_manuscript.tex"
    if not tex_path.exists():
        pytest.skip("manuscript source is not shipped in the anonymous artifact "
                    "(it contains the camera-ready author block)")
    tex = tex_path.read_text()
    assert "\\testCount{} tests" in tex, "appendix must cite the generated macro"
    assert not re.search(r"execute all \d+ unit", tex), \
        "a hard-coded test count was reintroduced into the manuscript"


def test_headline_numbers_come_from_macros_not_literals():
    """The block-rate and corpus figures must be macro-bound too, so a re-run
    cannot leave a stale number in the abstract (the E1/E7 drift class)."""
    tex_path = ROOT / "docs" / "usenix_paper_manuscript.tex"
    if not tex_path.exists():
        pytest.skip("manuscript source is not shipped in the anonymous artifact")
    tex = tex_path.read_text()
    abstract = tex[tex.index("\\begin{abstract}"):tex.index("\\end{abstract}")]
    for macro in ("\\eviBlocked", "\\eviTotal", "\\compBlocked", "\\corpusProfiles"):
        assert macro in abstract, f"{macro} must be macro-bound in the abstract"
    assert "100.0\\%" not in abstract, \
        "the abstract must not carry a hard-coded headline percentage"


def test_markdown_docs_do_not_state_a_stale_test_count():
    """README.md and REPRODUCE.md are the first two files an artifact evaluator
    opens, and both once claimed "44/44 PASS" while the suite collected far
    more. Those files are plain Markdown, so they cannot \\input a generated
    macro the way the manuscript does -- which is exactly why the claim rotted
    unnoticed through several revisions. This test is the substitute binding:
    any test-count assertion in either file must equal the collected count.

    If this fails, update the prose. Do not relax the pattern.
    """
    expected = _collected()
    patterns = [
        re.compile(r"(\d+)\s+[Tt]ests\b"),      # "83 tests", "83 Tests"
        re.compile(r"\b(\d+)\s*/\s*(\d+)\s+PASS"),  # "83/83 PASS"
    ]
    problems = []
    for name in ("README.md", "REPRODUCE.md"):
        path = ROOT / name
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for rx in patterns:
                for m in rx.finditer(line):
                    for value in m.groups():
                        if int(value) != expected:
                            problems.append(
                                f"{name}:{lineno} claims {value}, suite collects "
                                f"{expected}: {line.strip()}"
                            )
    assert not problems, "stale test counts in documentation:\n" + "\n".join(problems)
