"""Verify every citation actually exists, against Crossref and OpenAlex.

`check_refs.py` catches undefined keys and missing BibTeX fields — it cannot
tell a real paper from a plausible-looking one. That distinction matters: a
fabricated or misremembered reference is the failure mode reviewers punish
hardest, and LLM-assisted writing produces them readily.

Crossref needs no key — a contact email in the User-Agent puts you in its polite
pool. OpenAlex is different: since 2026-02-13 it requires an API key on EVERY
request. The key is free from https://openalex.org/settings/api and is passed as
the `api_key` query parameter. Without it only Crossref is queried, which misses
preprints and some CS venues.

Offline behaviour is deliberate: unreachable APIs produce INFO ("unverified"),
never MAJOR. A network failure must not look like a bad citation.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import Config, Finding  # noqa: E402
from checks.check_refs import parse_bib  # noqa: E402

CROSSREF = "https://api.crossref.org/works"
OPENALEX = "https://api.openalex.org/works"
TIMEOUT = 20
PAUSE = 0.15          # be polite; both APIs are free and unmetered
CACHE_VERSION = 1


# ---------------------------------------------------------------------------
def _cache_path(cfg: Config) -> Path:
    return cfg.state_dir / "citation_cache.json"


def _load_cache(cfg: Config) -> dict:
    p = _cache_path(cfg)
    if p.exists():
        try:
            d = json.loads(p.read_text())
            if d.get("_version") == CACHE_VERSION:
                return d
        except Exception:
            pass
    return {"_version": CACHE_VERSION}


def _save_cache(cfg: Config, cache: dict) -> None:
    try:
        _cache_path(cfg).write_text(json.dumps(cache, indent=2))
    except Exception:
        pass


def _openalex_key() -> str | None:
    """OpenAlex has required an API key for ALL requests since 2026-02-13.

    Free from https://openalex.org/settings/api. Passed as the `api_key` query
    parameter; no header is used. Read from the environment so it never has to
    live in a repository.
    """
    for var in ("OPENALEX_API_KEY", "OPENALEX_KEY"):
        v = os.environ.get(var, "").strip()
        if v:
            return v
    # fall back to the shared key file, which sits outside every repo
    for cand in (Path.home() / "Projects" / ".paperloop-env",
                 Path.cwd() / ".paperloop-env",
                 Path.cwd().parent / ".paperloop-env"):
        try:
            if cand.exists():
                m = re.search(r'^export\s+OPENALEX_API_KEY="?([^"\n]+)"?',
                              cand.read_text(), re.MULTILINE)
                if m:
                    return m.group(1).strip()
        except Exception:
            pass
    return None


def _get(url: str, mailto: str) -> dict | None:
    """Return parsed JSON, or None if the API is unreachable or rejects us."""
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}mailto={urllib.parse.quote(mailto)}"
    if "openalex.org" in url:
        key = _openalex_key()
        if key:
            full += f"&api_key={urllib.parse.quote(key)}"
    req = urllib.request.Request(
        full, headers={"User-Agent": f"paperloop/1.0 (mailto:{mailto})",
                       "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _norm(s: str) -> str:
    s = re.sub(r"\{|\}|\\[a-zA-Z]+", "", s or "")
    return re.sub(r"[^a-z0-9 ]+", " ", s.lower()).strip()


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def _field(blob: str, name: str) -> str | None:
    """Extract a BibTeX field value, brace-aware.

    Two things a naive regex gets wrong and this does not: titles routinely
    contain nested braces (`title = {{BERT}: Pre-training...}`), and the LAST
    field in an entry has no trailing comma or newline inside the captured
    blob — which silently lost the DOI on almost every entry.
    """
    m = re.search(rf"\b{name}\s*=\s*", blob, re.IGNORECASE)
    if not m:
        return None
    i = m.end()
    if i >= len(blob):
        return None
    opener = blob[i]
    if opener == "{":
        depth, j = 0, i
        while j < len(blob):
            if blob[j] == "{":
                depth += 1
            elif blob[j] == "}":
                depth -= 1
                if depth == 0:
                    return blob[i + 1:j].strip()
            j += 1
        return None
    if opener == '"':
        j = blob.find('"', i + 1)
        return blob[i + 1:j].strip() if j != -1 else None
    # bare value, e.g. year = 2017
    m2 = re.match(r"([^,\n}]+)", blob[i:])
    return m2.group(1).strip() if m2 else None


# ---------------------------------------------------------------------------
def _crossref_title(m: dict) -> str:
    """Crossref stores subtitles separately; a bib title that includes the
    subtitle is the paper's full registered title, so join them."""
    title = (m.get("title") or [""])[0]
    sub = (m.get("subtitle") or [""])[0]
    return f"{title}: {sub}" if sub else title


def _lookup_doi(doi: str, mailto: str) -> dict | None:
    d = _get(f"{CROSSREF}/{urllib.parse.quote(doi)}", mailto)
    if d and d.get("message"):
        m = d["message"]
        return {"source": "crossref", "doi": doi,
                "title": _crossref_title(m),
                "year": (m.get("issued", {}).get("date-parts") or [[None]])[0][0],
                "container": (m.get("container-title") or [""])[0],
                "type": m.get("type", "")}
    return None


def _lookup_title(title: str, mailto: str) -> dict | None:
    q = urllib.parse.quote(title[:250])
    d = _get(f"{CROSSREF}?query.bibliographic={q}&rows=3", mailto)
    if d:
        for it in d.get("message", {}).get("items", []):
            cand = _crossref_title(it)
            if cand and _similar(cand, title) >= 0.87:
                return {"source": "crossref", "doi": it.get("DOI", ""),
                        "title": cand,
                        "year": (it.get("issued", {}).get("date-parts") or [[None]])[0][0],
                        "container": (it.get("container-title") or [""])[0],
                        "type": it.get("type", "")}
    # OpenAlex covers preprints and CS venues Crossref sometimes misses.
    # Its search endpoint rejects some punctuation with HTTP 400, so strip it.
    d = _get(f"{OPENALEX}?filter=title.search:"
             f"{urllib.parse.quote(re.sub(r'[^\\w\\s-]', ' ', title[:250]))}&per-page=3",
             mailto)
    if d:
        for it in d.get("results", []):
            cand = it.get("title") or it.get("display_name") or ""
            if cand and _similar(cand, title) >= 0.87:
                loc = (it.get("primary_location") or {}).get("source") or {}
                return {"source": "openalex",
                        "doi": (it.get("doi") or "").replace("https://doi.org/", ""),
                        "title": cand, "year": it.get("publication_year"),
                        "container": loc.get("display_name", ""),
                        "type": it.get("type", "")}
    return None


# ---------------------------------------------------------------------------
def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    mailto = (cfg.venue.get("contact_email")
              or cfg.raw.get("contact_email")
              or "paperloop@example.org")

    entries: dict[str, dict] = {}
    for b in cfg.bib:
        if b.exists():
            entries.update(parse_bib(b))
    if not entries:
        return out

    # only verify what the manuscript actually cites
    from lib.common import read_tex
    cited = set()
    for _, _, t in read_tex(cfg.manuscript):
        for m in re.finditer(r"\\cite[a-zA-Z]*\*?(?:\[[^\]]*\])*\{([^}]+)\}", t):
            cited.update(k.strip() for k in m.group(1).split(",") if k.strip())

    if not _openalex_key():
        out.append(Finding(
            "citations", "refs.unverified", "MINOR",
            "no OPENALEX_API_KEY — OpenAlex has required a key for all requests "
            "since 2026-02-13, so only Crossref is being queried",
            expected="OPENALEX_API_KEY set",
            remedy="Free key at https://openalex.org/settings/api, then "
                   "./set-key.sh OPENALEX_API_KEY. Crossref alone misses "
                   "preprints and some CS venues, so coverage is reduced."))

    cache = _load_cache(cfg)
    reachable = None
    verified = unverified = 0
    rel = lambda p: str(Path(p).relative_to(cfg.root))

    # DOI coverage. Not cosmetic: without a DOI a reference can only be matched
    # by title, which is fuzzy for both this checker and a human reviewer.
    with_doi = sum(1 for k in cited
                   if entries.get(k) and _field(entries[k]["blob"], "doi"))
    if cited and with_doi / len(cited) < 0.5:
        out.append(Finding(
            "citations", "refs.bibfield", "MINOR",
            f"only {with_doi} of {len(cited)} cited works carry a DOI",
            evidence=f"{with_doi}/{len(cited)}",
            expected="a DOI on every reference that has one",
            remedy="Add DOIs from the publisher's page or Crossref. They let a "
                   "reviewer check a reference in one click, and let this gate "
                   "verify it exactly rather than by fuzzy title match."))

    for key in sorted(cited):
        e = entries.get(key)
        if not e:
            continue        # check_refs.py already reports missing entries
        blob = e["blob"]
        title = _field(blob, "title")
        doi = _field(blob, "doi")
        year = _field(blob, "year")
        if not title:
            continue

        ck = f"{key}|{doi or ''}|{_norm(title)[:80]}"
        if ck in cache:
            rec = cache[ck]
        else:
            if reachable is False:
                rec = None
            else:
                rec = _lookup_doi(doi, mailto) if doi else None
                if rec is None:
                    rec = _lookup_title(title, mailto)
                if rec is None and reachable is None:
                    # distinguish "not found" from "API down" with one probe
                    reachable = _get(f"{CROSSREF}?rows=1", mailto) is not None
                    if reachable is False:
                        out.append(Finding(
                            "citations", "refs.unverified", "INFO",
                            "Crossref and OpenAlex are unreachable — citations not verified",
                            expected="network access to api.crossref.org and api.openalex.org",
                            remedy="Add both to the network allowlist, then re-run. "
                                   "Offline, citation existence cannot be checked at all."))
                else:
                    reachable = True
                time.sleep(PAUSE)
            if reachable:
                cache[ck] = rec
        if reachable is False:
            unverified += 1
            continue

        loc = dict(file=rel(e["file"]), line=e["line"])
        if rec is None:
            unverified += 1
            out.append(Finding(
                "citations", "refs.unverified", "MAJOR",
                f"citation '{key}' does not resolve in Crossref or OpenAlex",
                evidence=f'"{title[:110]}"', **loc,
                expected="a work that exists in at least one bibliographic database",
                remedy="Verify this reference by hand. A title that matches nothing is "
                       "usually a hallucinated or misremembered citation — check the "
                       "authors, year and venue against the publisher's page, or remove it."))
            continue

        verified += 1
        # DOI present but pointing somewhere else
        if doi and rec.get("title") and _similar(rec["title"], title) < 0.75:
            out.append(Finding(
                "citations", "refs.doi_mismatch", "BLOCKER",
                f"citation '{key}': the DOI resolves to a different work",
                evidence=f'bib: "{title[:80]}"', **loc,
                expected=f'DOI {doi} is "{rec["title"][:80]}"',
                remedy="The DOI and the title disagree. One of them is wrong; fix "
                       "whichever, and check the rest of the entry while you are there."))
        # year drift
        if year and rec.get("year"):
            try:
                if abs(int(year) - int(rec["year"])) > 1:
                    out.append(Finding(
                        "citations", "refs.bibfield", "MAJOR",
                        f"citation '{key}': year disagrees with the record",
                        evidence=f"bib says {year}", **loc,
                        expected=f'{rec["source"]} says {rec["year"]}',
                        remedy="Usually a preprint year cited for a paper published later. "
                               "Use the version you actually read."))
            except ValueError:
                pass
        # arXiv-only where a published version exists
        looks_arxiv = bool(re.search(r"arxiv", blob, re.IGNORECASE))
        published = rec.get("container", "") and "arxiv" not in rec["container"].lower()
        if looks_arxiv and published and rec.get("type") not in ("posted-content",):
            out.append(Finding(
                "citations", "refs.bibfield", "MINOR",
                f"citation '{key}' is cited as arXiv but appeared at a venue",
                evidence=f'published in "{rec["container"][:80]}"', **loc,
                expected="cite the peer-reviewed version",
                remedy=f"Update to the published version"
                       + (f" (DOI {rec['doi']})" if rec.get("doi") else "")
                       + ". Reviewers notice arXiv-only bibliographies."))

    _save_cache(cfg, cache)
    if verified:
        out.append(Finding("citations", "refs.unverified", "INFO",
                           f"{verified} citation(s) verified against Crossref/OpenAlex"
                           + (f", {unverified} unresolved" if unverified else "")))
    return out


if __name__ == "__main__":
    from lib.common import load_config, find_repo_root, sort_findings
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else find_repo_root())
    for f in sort_findings(check(cfg)):
        print(f.render())
