"""Citation and bibliography gate."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import Config, Finding, read_tex  # noqa: E402

REQUIRED_FIELDS = {
    "article": ["author", "title", "journal", "year"],
    "inproceedings": ["author", "title", "booktitle", "year"],
    "conference": ["author", "title", "booktitle", "year"],
    "book": ["author|editor", "title", "publisher", "year"],
    "incollection": ["author", "title", "booktitle", "publisher", "year"],
    "techreport": ["author", "title", "institution", "year"],
    "phdthesis": ["author", "title", "school", "year"],
    "mastersthesis": ["author", "title", "school", "year"],
    "misc": ["title"],
}

ENTRY_RE = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\}", re.DOTALL)
FIELD_RE = re.compile(r"(\w+)\s*=\s*[{\"]", re.IGNORECASE)


def parse_bib(path: Path):
    text = path.read_text(errors="replace")
    entries = {}
    for m in ENTRY_RE.finditer(text):
        etype, key, blob = m.group(1).lower(), m.group(2).strip(), m.group(3)
        line = text[:m.start()].count("\n") + 1
        fields = {f.lower() for f in FIELD_RE.findall(blob)}
        entries[key] = {"type": etype, "fields": fields, "line": line,
                        "blob": blob, "file": path}
    return entries


def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    rel = lambda p: str(Path(p).relative_to(cfg.root))

    lines = read_tex(cfg.manuscript)
    bibitem_keys: set[str] = set()
    for _f, _n, _t in lines:
        for _m in re.finditer(r"\\bibitem\s*(?:\[[^\]]*\])?\s*\{([^}]+)\}", _t):
            bibitem_keys.add(_m.group(1).strip())

    # ---- build log signals ------------------------------------------------
    for logp, label in ((cfg.log, "log"), (cfg.log.with_suffix(".blg"), "blg")):
        if not logp.exists():
            continue
        text = logp.read_text(errors="replace")
        for m in re.finditer(r"(?:LaTeX )?Warning: Citation ['`\"]?([^'\"` ]+)['`\"]? "
                             r"(?:on page \d+ )?undefined", text):
            if m.group(1) in bibitem_keys:
                continue
            out.append(Finding("refs", "refs.undefined", "BLOCKER",
                               f"undefined citation \\cite{{{m.group(1)}}} — renders as [?]",
                               file=rel(logp), evidence=m.group(1),
                               remedy=f"Add {m.group(1)} to the .bib, or fix the key. "
                                      f"Re-run bibtex/biber then latex twice."))
        for m in re.finditer(r"Warning: Reference ['`\"]?([^'\"` ]+)['`\"]? "
                             r"(?:on page \d+ )?undefined", text):
            out.append(Finding("refs", "refs.undefined", "BLOCKER",
                               f"undefined reference \\ref{{{m.group(1)}}} — renders as ??",
                               file=rel(logp), evidence=m.group(1),
                               remedy=f"Add \\label{{{m.group(1)}}} to the target float/section."))
        for m in re.finditer(r"Warning: (?:There were )?multiply[- ]defined labels?", text):
            out.append(Finding("refs", "refs.undefined", "MAJOR",
                               "multiply-defined labels — \\ref may point at the wrong object",
                               file=rel(logp),
                               remedy="Find duplicate \\label keys and make them unique."))
            break
        if label == "blg":
            for m in re.finditer(r"^(Warning--.*)$", text, re.MULTILINE):
                msg = m.group(1).strip()
                sev = "MAJOR" if "empty" in msg.lower() else "MINOR"
                out.append(Finding("refs", "refs.bibfield", sev,
                                   f"bibtex: {msg[:160]}", file=rel(logp),
                                   remedy="Fill the missing bibliography field."))

    # ---- cite keys vs bib -------------------------------------------------
    cited: dict[str, tuple[str, int]] = {}
    for f, n, t in lines:
        for m in re.finditer(r"\\cite[a-zA-Z]*\*?(?:\[[^\]]*\])*\{([^}]+)\}", t):
            for key in m.group(1).split(","):
                key = key.strip()
                if key:
                    cited.setdefault(key, (f, n))

    entries: dict[str, dict] = {}
    for b in cfg.bib:
        if b.exists():
            entries.update(parse_bib(b))

    # A manual \begin{thebibliography} with \bibitem entries is a complete
    # bibliography. Treating those keys as undefined because there is no .bib
    # file reports a correct paper as broken.
    if bibitem_keys and not entries:
        out.append(Finding("refs", "refs.bibfield", "INFO",
                           f"manuscript uses a manual thebibliography with "
                           f"{len(bibitem_keys)} \\bibitem entries",
                           remedy="Field-level checks are skipped for manual "
                                  "bibliographies; verify entries by eye or move "
                                  "to BibTeX."))

    if entries:
        for key, (f, n) in sorted(cited.items()):
            if key not in entries and key not in bibitem_keys:
                out.append(Finding("refs", "refs.undefined", "BLOCKER",
                                   f"\\cite{{{key}}} has no entry in the bibliography",
                                   file=rel(f), line=n, evidence=key,
                                   remedy=f"Add a complete @entry for {key}, or remove the cite."))
        unused = sorted(set(entries) - set(cited))
        if unused:
            out.append(Finding("refs", "refs.unused", "MINOR",
                               f"{len(unused)} bibliography entries are never cited",
                               evidence=", ".join(unused[:12]),
                               remedy="Harmless with bibtex, but a long unused tail usually "
                                      "means the related-work section drifted from the .bib."))

        for key, e in sorted(entries.items()):
            if key not in cited:
                continue
            req = REQUIRED_FIELDS.get(e["type"], [])
            missing = []
            for spec in req:
                if not any(alt in e["fields"] for alt in spec.split("|")):
                    missing.append(spec)
            if missing:
                out.append(Finding("refs", "refs.bibfield", "MAJOR",
                                   f"@{e['type']}{{{key}}} missing required field(s): "
                                   f"{', '.join(missing)}",
                                   file=rel(e["file"]), line=e["line"],
                                   remedy="Complete the entry from the publisher's page. "
                                          "Incomplete references read as carelessness."))
            blob = e["blob"]
            if re.search(r"arxiv", blob, re.IGNORECASE) and e["type"] in ("misc", "article"):
                out.append(Finding("refs", "refs.bibfield", "MINOR",
                                   f"{key} is cited as arXiv — check for a peer-reviewed version",
                                   file=rel(e["file"]), line=e["line"],
                                   remedy="If it appeared at a venue, cite the published version. "
                                          "Reviewers notice arXiv-only bibliographies."))
            if e["type"] in ("inproceedings", "conference"):
                bt = re.search(r"booktitle\s*=\s*[{\"](.*?)[}\"]", blob, re.DOTALL)
                if bt and len(bt.group(1).strip()) < 8:
                    out.append(Finding("refs", "refs.bibfield", "MINOR",
                                       f"{key} has a suspiciously short booktitle",
                                       file=rel(e["file"]), line=e["line"],
                                       evidence=bt.group(1)[:60],
                                       remedy="Use the full proceedings name."))
        # duplicate DOIs => same work cited twice under two keys
        dois: dict[str, list[str]] = {}
        for key, e in entries.items():
            m = re.search(r"doi\s*=\s*[{\"]([^}\"]+)", e["blob"], re.IGNORECASE)
            if m:
                dois.setdefault(m.group(1).strip().lower(), []).append(key)
        for doi, keys in dois.items():
            if len(keys) > 1:
                out.append(Finding("refs", "refs.bibfield", "MAJOR",
                                   f"duplicate bibliography entries share DOI {doi}",
                                   evidence=", ".join(keys),
                                   remedy="Merge to one key and update all \\cite calls."))
    else:
        out.append(Finding("refs", "refs.bibfield", "MINOR",
                           "no .bib file configured or parseable",
                           remedy="Set paths.bibliography in .paperloop/config.yaml if the "
                                  "paper uses BibTeX."))

    # citation density sanity
    if cfg.venue.get("limits", {}).get("min_references"):
        want = int(cfg.venue["limits"]["min_references"])
        if entries and len(cited) < want:
            out.append(Finding("refs", "refs.bibfield", "MAJOR",
                               f"only {len(cited)} distinct works cited",
                               evidence=str(len(cited)), expected=f">= {want}",
                               remedy="A thin bibliography reads as an unfamiliarity with the "
                                      "literature. Expand related work."))
    return out


if __name__ == "__main__":
    from lib.common import load_config, find_repo_root, sort_findings
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else find_repo_root())
    for f in sort_findings(check(cfg)):
        print(f.render())
