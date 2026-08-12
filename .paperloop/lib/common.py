"""Shared primitives for the paperloop self-correcting review system.

Everything a checker emits is a Finding. Findings are the contract between the
deterministic gates and the LLM agents: gates emit them, the writer agent
consumes them, the orchestrator decides whether the loop continues.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    raise

# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------
# BLOCKER  - submission would be desk-rejected, or the science is wrong.
#            Science BLOCKERs halt the loop for human review.
# MAJOR    - reviewer would hold this against the paper; must be fixed.
# MINOR    - polish.
# INFO     - measurement, no action implied.
SEVERITIES = ("BLOCKER", "MAJOR", "MINOR", "INFO")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Findings in these categories may be edited by the writer agent without
# human sign-off. Anything else is gated.
AUTOFIX_CATEGORIES = {
    "venue.pagecount",
    "venue.margins",
    "venue.font",
    "venue.template",
    "venue.anonymity",
    "venue.structure",
    "figure.overflow",
    "figure.resolution",
    "figure.fontsize",
    "figure.clipping",
    "refs.undefined",
    "refs.bibfield",
    "refs.unused",
    "layout.overfull",
    "layout.underfull",
    "prose.style",
}

# Findings in these categories require human sign-off before the paper changes.
GATED_CATEGORIES = {
    "science.number_mismatch",
    "science.unsourced_number",
    "science.stat_reporting",
    "science.claim_unsupported",
    "science.artifact_missing",
    "science.stale_artifact",
    "refs.unverified",
    "refs.doi_mismatch",
}


@dataclass
class Finding:
    check: str           # which checker produced it
    category: str        # dotted category, drives autofix vs gate routing
    severity: str        # BLOCKER | MAJOR | MINOR | INFO
    message: str         # human/agent readable statement of the problem
    file: str | None = None
    line: int | None = None
    page: int | None = None
    evidence: str | None = None      # measured value / quoted text
    expected: str | None = None      # what the venue or the data requires
    remedy: str | None = None        # concrete instruction for the writer agent
    fingerprint: str | None = None   # stable id for dedupe across rounds

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.fingerprint is None:
            # Must be stable ACROSS PROCESSES. Python's built-in hash() is salted
            # per interpreter, which would give every round a fresh set of ids and
            # silently break stall detection and proposal filenames.
            base = f"{self.check}|{self.category}|{self.file}|{self.line}|{self.message[:120]}"
            self.fingerprint = hashlib.blake2b(base.encode(), digest_size=8).hexdigest()

    @property
    def gated(self) -> bool:
        """True if a human must approve before this is acted on."""
        return self.category in GATED_CATEGORIES

    @property
    def autofixable(self) -> bool:
        return self.category in AUTOFIX_CATEGORIES

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["gated"] = self.gated
        d["autofixable"] = self.autofixable
        return d

    def render(self) -> str:
        loc = ""
        if self.file:
            loc = f" {self.file}"
            if self.line:
                loc += f":{self.line}"
        elif self.page:
            loc = f" p.{self.page}"
        out = [f"[{self.severity}] {self.category}{loc} — {self.message}"]
        if self.evidence:
            out.append(f"    found:    {self.evidence}")
        if self.expected:
            out.append(f"    expected: {self.expected}")
        if self.remedy:
            out.append(f"    remedy:   {self.remedy}")
        return "\n".join(out)


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
@dataclass
class Config:
    root: Path
    raw: dict[str, Any]
    venue: dict[str, Any]

    @property
    def manuscript(self) -> Path:
        return self.root / self.raw["paths"]["manuscript_tex"]

    @property
    def pdf(self) -> Path:
        return self.root / self.raw["paths"]["manuscript_pdf"]

    @property
    def log(self) -> Path:
        return self.pdf.with_suffix(".log")

    @property
    def bib(self) -> list[Path]:
        return [self.root / p for p in self.raw["paths"].get("bibliography", [])]

    @property
    def figure_dirs(self) -> list[Path]:
        return [self.root / p for p in self.raw["paths"].get("figure_dirs", [])]

    @property
    def result_globs(self) -> list[str]:
        return self.raw["paths"].get("result_globs", [])

    @property
    def build_command(self) -> str | None:
        return self.raw.get("build", {}).get("command")

    @property
    def state_dir(self) -> Path:
        d = self.root / ".paperloop" / "state"
        d.mkdir(parents=True, exist_ok=True)
        return d


def load_config(root: Path | str) -> Config:
    root = Path(root).resolve()
    cfg_path = root / ".paperloop" / "config.yaml"
    venue_path = root / ".paperloop" / "venue.yaml"
    if not cfg_path.exists():
        raise SystemExit(f"no paperloop config at {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text())
    venue = yaml.safe_load(venue_path.read_text()) if venue_path.exists() else {}
    return Config(root=root, raw=raw, venue=venue)


def find_repo_root(start: Path | None = None) -> Path:
    """Walk upward looking for .paperloop/config.yaml."""
    p = (start or Path.cwd()).resolve()
    for cand in [p, *p.parents]:
        if (cand / ".paperloop" / "config.yaml").exists():
            return cand
    raise SystemExit("could not locate .paperloop/config.yaml above " + str(p))


# --------------------------------------------------------------------------
# LaTeX source handling
# --------------------------------------------------------------------------
COMMENT_RE = re.compile(r"(?<!\\)%.*$")


def strip_comments(line: str) -> str:
    return COMMENT_RE.sub("", line)


def read_tex(path: Path, follow_inputs: bool = True, _seen: set | None = None
             ) -> list[tuple[str, int, str]]:
    """Return [(file, lineno, text)] with comments stripped, following \\input."""
    _seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in _seen or not path.exists():
        return []
    _seen.add(path)
    out: list[tuple[str, int, str]] = []
    for i, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        text = strip_comments(raw)
        out.append((str(path), i, text))
        if follow_inputs:
            m = re.search(r"\\(?:input|include)\{([^}]+)\}", text)
            if m:
                child = m.group(1)
                for ext in ("", ".tex"):
                    cp = (path.parent / (child + ext))
                    if cp.exists() and cp.is_file():
                        out.extend(read_tex(cp, follow_inputs, _seen))
                        break
    return out


def tex_body_lines(lines: Iterable[tuple[str, int, str]]) -> list[tuple[str, int, str]]:
    """Lines between \\begin{document} and \\end{document}."""
    out, inside = [], False
    for f, n, t in lines:
        if "\\begin{document}" in t:
            inside = True
            continue
        if "\\end{document}" in t:
            inside = False
        if inside:
            out.append((f, n, t))
    return out


def section_of(lines: list[tuple[str, int, str]], target_line: int, target_file: str) -> str:
    """Best-effort: name of the nearest preceding \\section for a given line."""
    current = "preamble"
    for f, n, t in lines:
        if f != target_file:
            continue
        if n > target_line:
            break
        m = re.search(r"\\(?:sub)*section\*?\{([^}]*)\}", t)
        if m:
            current = m.group(1)
        elif "\\begin{abstract}" in t:
            current = "Abstract"
    return current


# --------------------------------------------------------------------------
# PDF handling
# --------------------------------------------------------------------------
def pdf_page_count(pdf: Path) -> int | None:
    try:
        from pypdf import PdfReader
        return len(PdfReader(str(pdf)).pages)
    except Exception:
        return None


def run(cmd: str, cwd: Path | None = None, timeout: int = 900) -> tuple[int, str, str]:
    p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


# --------------------------------------------------------------------------
# Findings IO
# --------------------------------------------------------------------------
def write_findings(findings: list[Finding], path: Path, meta: dict | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": meta or {},
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2))


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_sev: dict[str, int] = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_sev[f.severity] += 1
    gated = [f for f in findings if f.gated and f.severity in ("BLOCKER", "MAJOR")]
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "actionable": sum(by_sev[s] for s in ("BLOCKER", "MAJOR", "MINOR")),
        "gated_actionable": len(gated),
        "clean": by_sev["BLOCKER"] == 0 and by_sev["MAJOR"] == 0,
    }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.category,
                                           f.file or "", f.line or 0))
