"""Bind manuscript numerals to benchmark artifacts.

The 2026-08 audits found three copies of the truth for one throughput number,
a tree depth from the wrong row, and timings that were never measured. Root
cause: humans (and writer agents) type numbers into prose, and the next
benchmark run strands them. `frozen_metrics.tex` removes the temptation for
the hot numbers; this check catches everything else.

Method: harvest decimal numerals from the manuscript, drop the known
structural constants (policy values, counts, spec sizes, years, section
numbers), then try to match each survivor against every numeric leaf in the
artifact JSONs. A numeral that matches nothing AND looks benchmark-ish
(carries a unit context: ms, KB, ops, %, x) is reported; a numeral that
matches an artifact value it shouldn't (e.g. a stale build time still equal
to an old run) is invisible to this check by design — macros are the fix for
those, this gate is the tripwire for the rest.

Offline behaviour: if the artifacts are missing entirely the check is silent
(nothing to compare against); a half-written artifact fails loudly.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import Config, Finding, read_tex  # noqa: E402

# Numerals that are definitions, not measurements. Keep tight; anything added
# here is invisible to the check.
WHITELIST = {
    # protocol / policy constants
    "32", "64", "256", "3600", "30", "100.0", "100", "0", "1", "3", "12",
    "16", "8", "10", "2", "5", "4", "6", "7", "9", "11", "13", "15", "20",
    "50", "85.5", "99.9", "9999",
    # counts that are corpus/protocol facts, re-verified by tests
    "1050", "1000", "10000", "100000", "1000000",
    # version numbers
    "0.2", "1.0", "0.1", "2.0", "3.0", "1.1",
    # years
    "1989", "1993", "1997", "2010", "2011", "2012", "2013", "2014", "2015",
    "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024",
    "2026", "2027", "27", "19", "25", "22",
    # math constants appearing in equations/proofs
    "0.5", "2", "0", "1", "negl",
}
WHITELIST = {w for w in WHITELIST}

UNIT_HINTS = re.compile(
    r"(\\text\{\s*ms\}|\\text\{\s*s\}|\\text\{\s*K?B\}|ops|/s|/sec|%|\\%|"
    r"\bKB\b|\bMB\b|\bGB\b|\bms\b|\bbytes?\b|speedup|rate|latency|throughput|"
    r"workers?|cores?|proof size|bandwidth|reduction|overhead)", re.I)


def _artifact_numbers(cfg: Config) -> list[float]:
    vals: list[float] = []
    for pat in cfg.result_globs:
        for f in cfg.root.glob(pat):
            try:
                blob = json.loads(f.read_text())
            except Exception:
                continue
            _walk(blob, vals)
    return vals


def _walk(node, vals: list[float]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                if k in ("timestamp",):
                    continue
                vals.append(float(v))
            else:
                _walk(v, vals)
    elif isinstance(node, list):
        for v in node:
            _walk(v, vals)


def _matches(num: float, arts: list[float], rel_tol=0.02) -> bool:
    for a in arts:
        if a == 0:
            continue
        if abs(num - a) / max(abs(a), 1e-12) <= rel_tol:
            return True
        # rounded forms: prose says 403.7 for 403.714, 1.93 for 1.927
        for div in (10.0, 100.0, 1000.0):
            if abs(round(a * div) / div - num) / max(abs(a), 1e-12) <= rel_tol:
                return True
    return False


def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    arts = _artifact_numbers(cfg)
    if not arts:
        return out  # nothing to compare against; other gates flag artifacts

    text = "\n".join(t for _, _, t in read_tex(cfg.manuscript))

    # strip comments, macro definitions we generated, citations, labels
    text = re.sub(r"(?m)^%.*$", "", text)
    text = re.sub(r"\\cite[a-zA-Z]*\{[^}]*\}", "", text)
    text = re.sub(r"\\(label|ref|input|include|url)\{[^}]*\}", "", text)

    seen: dict[str, int] = {}
    for m in re.finditer(r"(?<![\w.])(\d+(?:[.,]\d+)+|\d+\.\d+)(?![\w}])", text):
        raw = m.group(1).replace(",", "")
        if raw in WHITELIST:
            continue
        try:
            num = float(raw)
        except ValueError:
            continue
        if num > 5_000_000:
            continue
        # only judge numerals with a measurement-ish context
        ctx = text[max(0, m.start() - 90):m.end() + 90]
        if not UNIT_HINTS.search(ctx):
            continue
        if _matches(num, arts):
            continue
        seen.setdefault(raw, m.start())

    for raw in sorted(seen, key=lambda r: seen[r]):
        out.append(Finding(
            "numerals", "science.numeral_unbound", "MAJOR",
            f"measurement-shaped numeral '{raw}' matches no artifact value",
            evidence="appears with unit/latency/throughput context but no "
                     "value within 2% exists in results/*.json",
            file=str(cfg.manuscript),
            remedy="Either regenerate the artifact, cite the number via a "
                   "frozen_metrics macro, or — if it is a constant, not a "
                   "measurement — add it to the whitelist with a comment "
                   "saying why. Never edit the number to silence this check."))
    return out
