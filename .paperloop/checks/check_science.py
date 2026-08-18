"""Scientific-integrity gate: does the paper say what the data says?

Three families of check:
  1. Provenance  — every empirical number in the manuscript must trace to a
                   value that actually exists in results/ artifacts.
  2. Drift       — a number that is *close but not equal* to an artifact value
                   is a stale figure left behind by a re-run. This is the single
                   most common way a correct experiment becomes a wrong paper.
  3. Reporting   — statistical claims must carry the machinery that makes them
                   interpretable: n, dispersion, test, correction, effect size.

Everything this file emits is GATED. The writer agent may not silently "fix" a
number to make a check pass — that would launder an error into the paper. It
proposes; a human decides.
"""
from __future__ import annotations

import csv
import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import (Config, Finding, read_tex, tex_body_lines,  # noqa: E402
                        section_of)

try:
    import yaml
except ImportError:
    yaml = None

# ---------------------------------------------------------------------------
# 1. Build an index of every number the experiments actually produced
# ---------------------------------------------------------------------------
MAX_ARTIFACT_BYTES = 40 * 1024 * 1024


def _walk_json(obj, path, sink):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_json(v, f"{path}.{k}" if path else str(k), sink)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2000]):
            _walk_json(v, f"{path}[{i}]", sink)
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, (int, float)):
        if math.isfinite(obj):
            sink.append((float(obj), path))
    elif isinstance(obj, str):
        m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*%?\s*", obj)
        if m:
            sink.append((float(m.group(1)), path))


def build_artifact_index(cfg: Config) -> tuple[dict[float, list[str]], list[Path]]:
    index: dict[float, list[str]] = {}
    files: list[Path] = []
    for pattern in cfg.result_globs:
        for p in sorted(cfg.root.glob(pattern)):
            if not p.is_file() or p.stat().st_size > MAX_ARTIFACT_BYTES:
                continue
            if any(part in {"__pycache__", ".git", "venv", "node_modules", "llm_cache"}
                   for part in p.parts):
                continue
            sink: list[tuple[float, str]] = []
            try:
                if p.suffix.lower() == ".json":
                    _walk_json(json.loads(p.read_text(errors="replace")), "", sink)
                elif p.suffix.lower() in (".yaml", ".yml") and yaml:
                    _walk_json(yaml.safe_load(p.read_text(errors="replace")) or {}, "", sink)
                elif p.suffix.lower() in (".csv", ".tsv"):
                    delim = "\t" if p.suffix.lower() == ".tsv" else ","
                    with p.open(newline="", errors="replace") as fh:
                        for r, row in enumerate(csv.reader(fh, delimiter=delim)):
                            if r > 20000:
                                break
                            for c, cell in enumerate(row):
                                m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*%?\s*", cell or "")
                                if m:
                                    sink.append((float(m.group(1)), f"row{r}col{c}"))
                elif p.suffix.lower() == ".tex":
                    # frozen-metric .tex files (\newcommand{\foo}{12.3})
                    for m in re.finditer(r"\\(?:newcommand|def)\s*\{?\\(\w+)\}?\s*\{([^}]*)\}",
                                         p.read_text(errors="replace")):
                        mm = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*\\?%?\s*", m.group(2))
                        if mm:
                            sink.append((float(mm.group(1)), f"\\{m.group(1)}"))
            except Exception:
                continue
            if sink:
                files.append(p)
                rp = str(p.relative_to(cfg.root))
                for val, jpath in sink:
                    index.setdefault(round(val, 6), []).append(f"{rp}::{jpath}")
    return index, files


# ---------------------------------------------------------------------------
# 2. Extract empirical numeric claims from the manuscript
# ---------------------------------------------------------------------------
# Skip anything that is structurally not a result.
SKIP_LINE = re.compile(
    r"\\(usepackage|documentclass|label|ref|eqref|cite|bibliography|includegraphics|"
    r"newcommand|renewcommand|def|setlength|addtolength|hspace|vspace|columnwidth|"
    r"textwidth|linewidth|scalebox|resizebox|url|href|input|include)\b")

NUM_RE = re.compile(
    r"(?<![\w.])(-?\d{1,3}(?:,\d{3})*(?:\.\d+)?|-?\d+(?:\.\d+)?)\s*(\\?%|percent)?(?![\w])")

YEARISH = re.compile(r"^(19|20)\d{2}$")

# Contexts where a bare integer is structural, not empirical.
STRUCTURAL_CTX = re.compile(
    r"(section|sec\.|figure|fig\.|table|tab\.|algorithm|alg\.|equation|eq\.|"
    r"appendix|listing|line|step|phase|stage|rq|threat |tier |level |version|v\d)\s*$",
    re.IGNORECASE)

# Standards and vulnerability identifiers are names that happen to be numerals.
# "RFC 6962" was being matched against a throughput measurement of 7151.66 and
# reported as a stale result; a domain-separation standard does not track the
# benchmark.
IDENTIFIER_CTX = re.compile(
    r"\b(rfc|cve|cwe|capec|iso|iec|nist|sp|fips|ietf|draft|pep|ansi|ieee|"
    r"cvss|owasp|bcp|std)\b[\s.-]*$", re.IGNORECASE)

# A confidence LEVEL is a parameter of the analysis, not a result of it.
# "95% CI [73.0, 99.0]" was being matched against the nearest recorded value
# (94.1) and reported as a stale number, which is the opposite of true: 95 is
# the one number in that sentence that must NOT track the data.
CONFIDENCE_LEVEL_AFTER = re.compile(
    r"^\s*\\?%?\s*(CI\b|confidence|interval|credible)", re.IGNORECASE)
CONFIDENCE_LEVEL_BEFORE = re.compile(
    r"(wilson|clopper|agresti|bootstrap|binomial|confidence|CI)\W*$", re.IGNORECASE)


def _is_empirical(num_text: str, pct: bool, before: str, after: str) -> bool:
    raw = num_text.replace(",", "")
    try:
        val = float(raw)
    except ValueError:
        return False
    if pct:
        # 90/95/99 immediately adjacent to CI/confidence wording is the
        # confidence level, not a measurement.
        if val in (90.0, 95.0, 99.0) and (CONFIDENCE_LEVEL_AFTER.match(after or "")
                                          or CONFIDENCE_LEVEL_BEFORE.search(before or "")):
            return False
        return True
    if YEARISH.match(raw):
        return False
    if STRUCTURAL_CTX.search(before):
        return False
    if IDENTIFIER_CTX.search(before):
        return False
    # decimals and large counts are almost always measurements
    if "." in raw:
        return True
    if abs(val) >= 100:
        return True
    # small bare integers: only empirical if the sentence is quantitative
    quant = re.search(r"\b(n\s*=|N\s*=|participants|samples|runs|trials|seeds|repositories|"
                      r"models|instances|tasks|cases|attacks|variants|queries|examples|"
                      r"mean|median|average|total of|out of)\b", before + " " + after,
                      re.IGNORECASE)
    return bool(quant)


# Verbatim-ish contexts: model names, package versions, filenames, CLI flags.
# "gemini-3.1-flash" is not a measurement.
LITERAL_ENV = re.compile(
    r"\\(?:texttt|verb|lstinline|path|url|href|texorpdfstring|mintinline)\b\s*"
    r"(?:\{[^{}]*\}|\[[^\]]*\]\{[^{}]*\}|.\S*?.)")

VERSIONISH = re.compile(r"[\w./-]$")          # char immediately before the number
VERSIONISH_AFTER = re.compile(r"^(?:[-_./]?[A-Za-z]|\.\d)")   # "3.1-flash", "3.13.5"
VERSION_CTX = re.compile(
    r"\b(python|cuda|pytorch|tensorflow|numpy|scipy|java|node|gcc|clang|llvm|"
    r"ubuntu|debian|macos|windows|kernel|docker|git|openssl|version|v|rev|"
    r"release|gpt|gpt-|claude|gemini|llama|mistral|qwen|api)\s*[-v]?\s*$",
    re.IGNORECASE)


def extract_claims(cfg: Config):
    lines = read_tex(cfg.manuscript)
    body = tex_body_lines(lines)
    claims = []
    for f, n, t in body:
        if not t.strip() or SKIP_LINE.search(t):
            continue
        # drop inline math — constants there are rarely results
        clean = re.sub(r"\$[^$]*\$", " ", t)
        clean = LITERAL_ENV.sub(" ", clean)
        clean = re.sub(r"\\cite[tp]?\*?(\[[^\]]*\])*\{[^}]*\}", " ", clean)
        clean = re.sub(r"\\(?:ref|eqref|label|autoref|cref|Cref)\{[^}]*\}", " ", clean)
        for m in NUM_RE.finditer(clean):
            raw, pct = m.group(1), bool(m.group(2))
            before, after = clean[:m.start()][-90:], clean[m.end():][:90]
            # identifier/version fragment, not a measurement
            if not pct and (VERSIONISH.search(before[-1:] or " ")
                            or VERSIONISH_AFTER.match(after[:2] or " ")
                            or VERSION_CTX.search(before)):
                continue
            if not _is_empirical(raw, pct, before, after):
                continue
            claims.append({
                "file": f, "line": n, "raw": raw, "pct": pct,
                "value": float(raw.replace(",", "")),
                "context": (before[-70:] + m.group(0) + after[:70]).strip(),
                "section": section_of(lines, n, f),
            })
    return claims, lines


# ---------------------------------------------------------------------------
# 3. Statistical reporting hygiene
# ---------------------------------------------------------------------------
STAT_RULES = [
    dict(name="significance_without_p",
         trigger=r"\b(significant(ly)?|outperform(s|ed)?|improv(es|ed|ement))\b",
         require=r"(p\s*[<=>]\s*0?\.\d+|p\s*[<=]\s*\\?10|\bCI\b|confidence interval|"
                 r"bootstrap|permutation|Wilcoxon|Mann[- ]Whitney|t-test|chi|McNemar|"
                 r"Fisher|effect size|Cohen)",
         severity="MAJOR",
         msg="claims significance/improvement without a test statistic, p-value, or CI",
         remedy="Attach the test, its statistic, n, and either a p-value or a CI — "
                "or downgrade the wording to a descriptive comparison."),
    dict(name="p_without_test",
         trigger=r"p\s*[<=]\s*0?\.\d+",
         require=r"(t-test|Wilcoxon|Mann[- ]Whitney|chi|McNemar|Fisher|permutation|"
                 r"bootstrap|ANOVA|binomial|Kolmogorov|likelihood[- ]ratio|z-test)",
         severity="MAJOR",
         msg="p-value reported without naming the statistical test",
         remedy="Name the test and state whether it is one- or two-sided."),
    dict(name="p_without_correction",
         trigger=r"p\s*[<=]\s*0?\.\d+",
         require=r"(Bonferroni|Holm|Benjamini|FDR|family[- ]wise|corrected for multiple|"
                 r"multiple comparisons|single pre-?registered)",
         severity="MINOR",
         msg="p-value with no multiple-comparison correction stated",
         remedy="State the correction, or state explicitly that this is a single "
                "pre-registered comparison."),
    dict(name="mean_without_dispersion",
         trigger=r"\b(mean|average)\b",
         require=r"(\\pm|±|std|s\.d\.|SD|standard deviation|IQR|CI|variance|"
                 r"interquartile|\\sigma)",
         severity="MINOR",
         msg="mean reported without dispersion",
         remedy="Report SD, IQR, or a CI alongside the mean."),
    dict(name="rate_without_denominator",
         trigger=r"\d+(\.\d+)?\s*\\?%",
         require=r"(n\s*=|N\s*=|of\s+\d|out of|\bacross\s+\d|\bover\s+\d|/\s*\d)",
         severity="MINOR",
         msg="percentage without an explicit denominator",
         remedy="Give the numerator/denominator (e.g. '62% (31/50)')."),
    # Only fires on the authors' own asserted properties, and only in the
    # affirmative — "X is not guaranteed" is a limitation, not an overclaim.
    dict(name="absolute_claim",
         trigger=r"(?<!not )(?<!never )\b(we (?:guarantee|prove|ensure|eliminate)|"
                 r"(?:our|the proposed|this) \w+ (?:guarantees|proves|ensures|"
                 r"eliminates|prevents all|blocks all)|"
                 r"provably (?:secure|sound|complete)|"
                 r"(?:is|are) (?:guaranteed|provably) \w+|"
                 r"the first (?:system|framework|approach|work|tool|method) (?:to|that)|"
                 r"complete(?:ly)? (?:secure|sound|eliminat))\b",
         require=r"(theorem|lemma|proof|under the assumption|assum(e|ing|ption)|"
                 r"threat model|we define|by construction|formal|to our knowledge|"
                 r"to the best of our)",
         severity="MAJOR",
         msg="absolute or priority claim with no proof, assumption set, or scoping",
         remedy="Scope the claim to your threat model and assumptions, supply the "
                "proof, or soften it to an empirical statement. Unqualified "
                "'first' and 'guarantees' claims draw a rejection on sight."),
]

# Rules that make no sense inside a table: the denominator lives in the caption
# or column header, and every cell would fire.
TABULAR_EXEMPT = {"rate_without_denominator", "mean_without_dispersion"}
ENV_OPEN = re.compile(r"\\begin\{(tabular\*?|tabularx|longtable|array|"
                      r"lstlisting|verbatim|algorithmic|algorithm)\*?\}")
ENV_CLOSE = re.compile(r"\\end\{(tabular\*?|tabularx|longtable|array|"
                       r"lstlisting|verbatim|algorithmic|algorithm)\*?\}")


def check_stats(cfg: Config, lines) -> list[Finding]:
    out: list[Finding] = []
    body = tex_body_lines(lines)
    text_by_line = {(f, n): t for f, n, t in body}
    ordered = [(f, n, t) for f, n, t in body if t.strip()]
    rel = lambda p: str(Path(p).relative_to(cfg.root))

    depth = 0
    for idx, (f, n, t) in enumerate(ordered):
        opened = len(ENV_OPEN.findall(t))
        closed = len(ENV_CLOSE.findall(t))
        in_tabular = depth > 0 or opened > 0
        depth = max(0, depth + opened - closed)

        # look at a small window so requirements can be satisfied nearby;
        # inside a table the caption is usually a few lines further out
        span = 6 if in_tabular else 2
        window = " ".join(x[2] for x in ordered[max(0, idx - span): idx + span + 1])
        for rule in STAT_RULES:
            if in_tabular and rule["name"] in TABULAR_EXEMPT:
                continue
            if not re.search(rule["trigger"], t, re.IGNORECASE):
                continue
            if re.search(rule["require"], window, re.IGNORECASE):
                continue
            out.append(Finding(
                "science", "science.stat_reporting", rule["severity"],
                rule["msg"], file=rel(f), line=n,
                evidence=t.strip()[:180],
                expected=f"rule: {rule['name']}",
                remedy=rule["remedy"]))
    return out


# ---------------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------------
def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    rel = lambda p: str(Path(p).relative_to(cfg.root))

    if not cfg.manuscript.exists():
        return [Finding("science", "science.artifact_missing", "BLOCKER",
                        "manuscript not found", file=str(cfg.manuscript))]

    index, art_files = build_artifact_index(cfg)
    sci = cfg.venue.get("science", {})

    if not art_files:
        out.append(Finding("science", "science.artifact_missing", "BLOCKER",
                           "no machine-readable result artifacts found — every number "
                           "in this paper is currently unverifiable",
                           expected=f"files matching {cfg.result_globs}",
                           remedy="Emit results as JSON/CSV from the eval scripts and point "
                                  "paths.result_globs at them. Until then no gate can tell "
                                  "a correct number from a typo."))
        return out

    out.append(Finding("science", "science.artifact_missing", "INFO",
                       f"indexed {len(index)} distinct values from {len(art_files)} artifacts"))

    claims, lines = extract_claims(cfg)
    tol_rel = float(sci.get("match_relative_tolerance", 0.005))
    drift_rel = float(sci.get("drift_relative_tolerance", 0.10))
    hot = [s.lower() for s in sci.get("provenance_required_sections",
                                      ["abstract", "result", "evaluation", "experiment",
                                       "finding", "measurement", "introduction"])]

    sorted_vals = sorted(index)

    def nearest(v: float):
        best, bestd = None, None
        for cand in sorted_vals:
            d = abs(cand - v)
            if bestd is None or d < bestd:
                best, bestd = cand, d
        return best, bestd

    def displayed_decimals(raw: str) -> int:
        return len(raw.split(".")[1]) if "." in raw else 0

    def rounds_to(artifact_val: float, claim_val: float, decimals: int) -> bool:
        """A paper printing 0.021 for a stored 0.0213 is correct, not stale."""
        try:
            return round(artifact_val, decimals) == round(claim_val, decimals)
        except (ValueError, OverflowError):
            return False

    unsourced = 0
    emitted: set[tuple] = set()
    for c in claims:
        v = c["value"]
        dec = displayed_decimals(c["raw"])
        key = (c["file"], c["line"], c["raw"])
        if key in emitted:
            continue

        exact = [k for k in (round(v, 6), round(v / 100.0, 6), round(v * 100.0, 6))
                 if k in index]
        if exact:
            continue
        scale = max(abs(v), 1e-9)
        near, dist = nearest(v)
        near_pct, dist_pct = nearest(v / 100.0) if c["pct"] else (None, None)

        matched = (dist is not None and dist / scale <= tol_rel) or \
                  (dist_pct is not None and dist_pct / max(abs(v / 100.0), 1e-9) <= tol_rel)
        # rounding-aware: does ANY artifact value display as this number?
        if not matched:
            for cand in (near, near_pct):
                if cand is not None and rounds_to(cand, v, dec):
                    matched = True
                    break
        if not matched and c["pct"]:
            for cand in (near, near_pct):
                if cand is not None and rounds_to(cand * 100.0, v, dec):
                    matched = True
                    break
        if matched:
            continue

        in_hot = any(h in c["section"].lower() for h in hot)
        emitted.add(key)

        # Drift: an artifact value sits suspiciously close but not equal, and
        # not explainable by display rounding. Kept tight on purpose — a loose
        # threshold turns every coincidental neighbour into a false alarm.
        if dist is not None and 0 < dist / scale <= drift_rel:
            out.append(Finding(
                "science", "science.number_mismatch",
                "BLOCKER" if in_hot else "MAJOR",
                f"manuscript says {c['raw']}{'%' if c['pct'] else ''} but the nearest "
                f"recorded result is {near:g} — likely a stale number from an earlier run",
                file=rel(c["file"]), line=c["line"],
                evidence=f"…{c['context']}…",
                expected=f"{near:g}  (source: {index[near][0]})",
                remedy="Do NOT edit the paper to match blindly. Re-run the producing script, "
                       "confirm which value is current, then update the manuscript AND state "
                       "in the round log which artifact it came from."))
            continue

        if in_hot:
            unsourced += 1
            out.append(Finding(
                "science", "science.unsourced_number", "MAJOR",
                f"empirical number {c['raw']}{'%' if c['pct'] else ''} in '{c['section']}' "
                f"does not appear in any result artifact",
                file=rel(c["file"]), line=c["line"],
                evidence=f"…{c['context']}…",
                expected="a value present in results/ artifacts",
                remedy="Either point this number at the script and artifact that produced it, "
                       "or remove it. A number no artifact contains is either hand-typed, "
                       "hand-rounded, or wrong."))

    if unsourced:
        out.append(Finding(
            "science", "science.claim_unsupported", "INFO",
            f"{unsourced} unsourced empirical number(s) in result-bearing sections",
            remedy="Consider emitting a single frozen-metrics file that the manuscript "
                   "\\input{}s, so numbers cannot drift from the data by construction."))

    # ---- \input'd metric files exist -------------------------------------
    for f, n, t in lines:
        for m in re.finditer(r"\\(?:input|include)\{([^}]+)\}", t):
            target = m.group(1)
            base = Path(f).parent
            if not any((base / (target + ext)).exists() for ext in ("", ".tex")):
                out.append(Finding("science", "science.artifact_missing", "BLOCKER",
                                   f"\\input{{{target}}} does not resolve — the paper is "
                                   f"missing content it claims to include",
                                   file=rel(f), line=n,
                                   remedy=f"Generate {target} or remove the \\input."))

    # ---- staleness --------------------------------------------------------
    try:
        man_mtime = cfg.manuscript.stat().st_mtime
        newer = [p for p in art_files if p.stat().st_mtime > man_mtime + 60]
        if newer:
            out.append(Finding(
                "science", "science.stale_artifact", "MAJOR",
                f"{len(newer)} result artifact(s) changed after the manuscript was last edited",
                evidence="; ".join(rel(p) for p in newer[:5]),
                expected="manuscript newer than the data it reports",
                remedy="Re-read those artifacts and confirm every dependent number, table "
                       "and figure in the paper still matches."))
    except OSError:
        pass

    out.extend(check_stats(cfg, lines))
    return out


if __name__ == "__main__":
    from lib.common import load_config, find_repo_root, sort_findings
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else find_repo_root())
    for f in sort_findings(check(cfg)):
        print(f.render())
