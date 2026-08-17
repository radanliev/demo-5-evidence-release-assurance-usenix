"""The anonymity scan in scripts/prepare_anonymous_artifact.py is a submission
control, not a convenience. USENIX Security's CFP puts the burden entirely on
authors -- "Authors are solely responsible for ensuring no identifying
information is exposed (e.g., usernames, organization names, commit history)" --
and states that papers which are not properly anonymised may be rejected without
review. A control that can silently pass when it should fail is worse than none,
because it manufactures confidence.

This suite therefore tests that the scanner FAILS on things it must catch. An
earlier build of this artifact shipped a hard-coded macOS site-packages path
containing a username; every test here descends from that miss.

Note on construction: several literals below are assembled at runtime from
fragments. tests/ is itself packaged into the anonymous artifact, so spelling
the forbidden patterns out here would make this file trip the very scan it
exercises -- a self-referential failure that would block every future build.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGER = REPO_ROOT / "scripts" / "prepare_anonymous_artifact.py"


def _load_packager():
    if not PACKAGER.exists():
        pytest.skip("packager script not present in this tree")
    spec = importlib.util.spec_from_file_location("_packager", PACKAGER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def packager():
    return _load_packager()


def _scan_text(packager, tmp_path, text, terms=("acme-university",)):
    """Write `text` to a scannable file and return the scanner's findings."""
    target = tmp_path / "sample.py"
    target.write_text(text, encoding="utf-8")
    return packager.scan_for_identifying_strings(
        [(target, Path("sample.py"))], list(terms)
    )


# --- the regression that motivated the scanner --------------------------------

def test_absolute_macos_home_path_is_rejected(packager, tmp_path):
    """The exact defect that shipped: a hard-coded per-user site-packages path.
    It is both a portability bug and an author fingerprint."""
    leak = "/" + "Users" + "/jdoe/Library/Python/3.14/lib/python/site-packages"
    findings = _scan_text(packager, tmp_path, f'EXTRA = ["{leak}"]\n')
    assert findings, "a hard-coded macOS home path must be reported"
    assert any("home path" in f[2] for f in findings)


def test_absolute_linux_home_path_is_rejected(packager, tmp_path):
    leak = "/" + "home" + "/jdoe/project/venv"
    findings = _scan_text(packager, tmp_path, f'PREFIX = "{leak}"\n')
    assert any("home path" in f[2] for f in findings)


def test_ci_runner_home_path_is_allowed(packager, tmp_path):
    """/home/runner is GitHub Actions' fixed working directory. It names no
    person, and flagging it would train the author to ignore the scanner."""
    benign = "/" + "home" + "/runner/work/repo/repo"
    findings = _scan_text(packager, tmp_path, f'CI_DIR = "{benign}"\n')
    assert not findings, f"CI paths must not be flagged, got {findings}"


# --- contact details ----------------------------------------------------------

def test_email_address_is_rejected(packager, tmp_path):
    addr = "a.researcher" + "@" + "some-university.edu"
    findings = _scan_text(packager, tmp_path, f'CONTACT = "{addr}"\n')
    assert any("email" in f[2] for f in findings)


def test_documentation_domains_are_allowed(packager, tmp_path):
    """RFC 2606 reserves example.com/.invalid precisely for this. The anonymous
    commit identity uses one, so flagging them would fail every clean build."""
    text = 'AUTHOR = "anonymous@example.invalid"\nCONTACT = "user@example.com"\n'
    findings = _scan_text(packager, tmp_path, text)
    assert not findings, f"documentation domains must not be flagged, got {findings}"


def test_orcid_is_rejected(packager, tmp_path):
    """An ORCID resolves directly to a named researcher, so one left in a
    metadata field or a docstring deanonymises the paper outright.

    Assembled from fragments for the reason given in the module docstring: a
    literal ORCID here would trip the scan on this very file. The value is
    ORCID's own documentation example, which belongs to a fictional person."""
    orcid = "0000-" + "0002-" + "1825-" + "0097"
    findings = _scan_text(packager, tmp_path, f'ORCID = "{orcid}"\n')
    assert any("ORCID" in f[2] for f in findings)


# --- the term list ------------------------------------------------------------

def test_forbidden_terms_match_case_insensitively(packager, tmp_path):
    """Author names appear capitalised in prose and lowercase in usernames and
    email addresses. A case-sensitive scan would catch one and miss the other.

    One finding per line per term is the intended granularity -- the author
    needs the line, not every column -- so each casing goes on its own line."""
    findings = _scan_text(
        packager, tmp_path, "# Acme-University\n# ACME-UNIVERSITY\n# acme-university\n"
    )
    assert {f[1] for f in findings} == {1, 2, 3}, f"every casing must match, got {findings}"


def test_clean_content_produces_no_findings(packager, tmp_path):
    """Without this the suite could not distinguish a working scanner from one
    that rejects everything -- the same control that OC1 provides for the
    omission suite."""
    text = (
        "import hashlib\n"
        "def digest(b: bytes) -> str:\n"
        "    return hashlib.sha256(b).hexdigest()\n"
    )
    assert _scan_text(packager, tmp_path, text) == []


def test_terms_file_is_not_shipped_in_the_artifact(packager):
    """.anonymity-terms lists the author surnames. scripts/ is packaged, so if
    the term list were inside the packager -- or added to INCLUDED_PATHS -- it
    would hand reviewers the author list. This is the trap that keeping the
    terms in a separate, unshipped file exists to avoid."""
    included = set(packager.INCLUDED_PATHS)
    assert ".anonymity-terms" not in included
    assert not any(str(p).startswith(".anonymity") for p in included)


def test_packager_fails_closed_without_a_term_list(packager, monkeypatch, tmp_path):
    """No term list must mean no artifact. Degrading to "scan nothing, ship
    anyway" would produce a green run that checked nothing at all."""
    monkeypatch.setattr(packager, "TERMS_FILE", tmp_path / "does-not-exist")
    with pytest.raises(SystemExit) as exc:
        packager.load_terms()
    assert exc.value.code != 0


def test_real_term_list_is_populated(packager):
    """A term list that exists but is empty passes every scan vacuously."""
    if not packager.TERMS_FILE.exists():
        pytest.skip(".anonymity-terms is not present in this tree (expected in "
                    "the packaged artifact, which deliberately omits it)")
    terms = packager.load_terms()
    assert len(terms) >= 5
    assert all(t == t.lower() for t in terms), "terms are lowercased for matching"


# --- archive determinism ------------------------------------------------------

def test_digest_bearing_file_is_not_inside_the_archive(packager):
    """docs/artifact_digest.tex holds the SHA-256 of the archive. Shipping it
    inside the archive makes the digest self-referential: each build embeds the
    previous build's hash, so the value printed in the paper is correct for
    exactly one build and drifts on any rebuild. In a paper about verifiable
    evidence, a quoted digest that does not reproduce is the worst possible
    detail to get wrong."""
    assert "docs/artifact_digest.tex" not in set(packager.INCLUDED_PATHS)


def test_collect_files_is_deterministically_ordered(packager):
    """Member order changes the zip bytes, so an unsorted os.walk would make the
    digest depend on filesystem enumeration order rather than on content."""
    first, _ = packager.collect_files()
    second, _ = packager.collect_files()
    names = [str(rel) for _, rel in first]
    assert names == [str(rel) for _, rel in second]
    assert names == sorted(names)
