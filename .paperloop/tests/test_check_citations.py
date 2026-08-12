"""Tests for the citation verifier, with the network mocked.

The live path cannot be exercised where api.crossref.org is blocked, so the
matching and classification logic is tested against recorded-shape responses.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from checks import check_citations as cc  # noqa: E402
from lib.common import Config  # noqa: E402


def _cfg(tmp_path: Path, bib: str, tex: str) -> Config:
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "refs.bib").write_text(bib)
    (tmp_path / "docs" / "p.tex").write_text(tex)
    (tmp_path / ".paperloop").mkdir(exist_ok=True)
    return Config(
        root=tmp_path,
        raw={"paths": {"manuscript_tex": "docs/p.tex",
                       "manuscript_pdf": "docs/p.pdf",
                       "bibliography": ["docs/refs.bib"]}},
        venue={"contact_email": "test@example.org"})


REAL_BIB = """@inproceedings{good2020,
  author = {Alice Smith},
  title = {Attention Is All You Need},
  booktitle = {NeurIPS},
  year = {2017},
  doi = {10.1000/real}
}
"""
TEX = r"\begin{document}\cite{good2020}\end{document}"


def test_similarity_is_robust_to_latex_braces():
    assert cc._similar("{Attention} Is All You Need", "Attention Is All You Need") > 0.95
    assert cc._similar("Attention Is All You Need", "A Totally Different Paper") < 0.6


def test_verified_citation_produces_no_complaint(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, REAL_BIB, TEX)
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: {
        "source": "crossref", "doi": d, "title": "Attention Is All You Need",
        "year": 2017, "container": "NeurIPS", "type": "proceedings-article"})
    out = cc.check(cfg)
    assert not [f for f in out if f.severity in ("BLOCKER", "MAJOR")]


def test_nonexistent_citation_is_flagged(tmp_path, monkeypatch):
    """The case that matters: a plausible title matching nothing real."""
    cfg = _cfg(tmp_path, REAL_BIB.replace("10.1000/real", ""), TEX)
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: None)
    monkeypatch.setattr(cc, "_lookup_title", lambda t, m: None)
    monkeypatch.setattr(cc, "_get", lambda u, m: {"message": {"items": []}})  # API is up
    out = cc.check(cfg)
    bad = [f for f in out if f.category == "refs.unverified" and f.severity == "MAJOR"]
    assert bad, "a citation resolving nowhere must be reported"
    assert "does not resolve" in bad[0].message


def test_doi_pointing_at_a_different_work_is_a_blocker(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, REAL_BIB, TEX)
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: {
        "source": "crossref", "doi": d, "title": "An Entirely Unrelated Paper",
        "year": 2017, "container": "NeurIPS", "type": "proceedings-article"})
    out = cc.check(cfg)
    bad = [f for f in out if f.category == "refs.doi_mismatch"]
    assert bad and bad[0].severity == "BLOCKER"


def test_year_drift_is_reported(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, REAL_BIB, TEX)
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: {
        "source": "crossref", "doi": "10.1000/real",
        "title": "Attention Is All You Need",
        "year": 2023, "container": "NeurIPS", "type": "proceedings-article"})
    out = cc.check(cfg)
    assert [f for f in out if "year disagrees" in f.message]


def test_arxiv_only_with_published_version(tmp_path, monkeypatch):
    bib = REAL_BIB.replace("booktitle = {NeurIPS}", "journal = {arXiv preprint}")
    cfg = _cfg(tmp_path, bib, TEX)
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: {
        "source": "crossref", "doi": d, "title": "Attention Is All You Need",
        "year": 2017, "container": "Advances in Neural Information Processing Systems",
        "type": "proceedings-article"})
    out = cc.check(cfg)
    assert [f for f in out if "cited as arXiv but appeared at a venue" in f.message]


def test_offline_never_produces_false_failures(tmp_path, monkeypatch):
    """A network outage must not look like a bad bibliography."""
    cfg = _cfg(tmp_path, REAL_BIB, TEX)
    monkeypatch.setattr(cc, "_get", lambda u, m: None)     # everything unreachable
    out = cc.check(cfg)
    assert not [f for f in out if f.severity in ("BLOCKER", "MAJOR")], \
        "offline must degrade to INFO, never to a citation complaint"
    assert [f for f in out if f.severity == "INFO" and "unreachable" in f.message]


def test_uncited_bib_entries_are_not_queried(tmp_path, monkeypatch):
    """Only what the manuscript cites is verified — no wasted API calls."""
    bib = REAL_BIB + """@article{never_cited,
  author = {Bob},
  title = {Unused Work},
  journal = {J},
  year = {2020}
}
"""
    cfg = _cfg(tmp_path, bib, TEX)
    seen = []
    monkeypatch.setattr(cc, "_lookup_doi", lambda d, m: (seen.append(d), {
        "source": "crossref", "doi": d, "title": "Attention Is All You Need",
        "year": 2017, "container": "NeurIPS", "type": "proceedings-article"})[1])
    cc.check(cfg)
    assert seen == ["10.1000/real"]


def test_cache_prevents_repeat_queries(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, REAL_BIB, TEX)
    calls = {"n": 0}

    def counting(d, m):
        calls["n"] += 1
        return {"source": "crossref", "doi": d, "title": "Attention Is All You Need",
                "year": 2017, "container": "NeurIPS", "type": "proceedings-article"}

    monkeypatch.setattr(cc, "_lookup_doi", counting)
    cc.check(cfg)
    cc.check(cfg)
    assert calls["n"] == 1, "second run must be served from the cache"
