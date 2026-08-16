"""Deterministic venue-compliance gate.

Measures the compiled PDF and inspects the LaTeX source against venue.yaml.
Nothing here is a judgement call — every finding is a measurement with a
number attached, which is exactly what makes it safe to auto-fix.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import (Config, Finding, read_tex, tex_body_lines,  # noqa: E402
                        pdf_page_count)

PT_PER_IN = 72.0

# Commands that steal margin/space from the template. Venues treat these as
# format violations because they defeat the page limit.
MARGIN_HACKS = [
    (r"\\addtolength\s*\{\s*\\(textheight|textwidth|topmargin|oddsidemargin|"
     r"evensidemargin|voffset|hoffset|columnsep|footskip|headsep)\s*\}", "margin length altered"),
    (r"\\setlength\s*\{\s*\\(textheight|textwidth|topmargin|oddsidemargin|"
     r"evensidemargin|voffset|hoffset|paperheight|paperwidth)\s*\}", "page geometry overridden"),
    (r"\\usepackage(\[[^\]]*\])?\{geometry\}", "geometry package overrides template margins"),
    (r"\\geometry\s*\{", "explicit \\geometry{} call"),
    (r"\\enlargethispage", "page enlarged past template height"),
    (r"\\vspace\*?\s*\{\s*-\s*[0-9.]+\s*(in|cm|mm|pt|em|ex|baselineskip)", "negative vspace used to claw back space"),
    (r"\\setlength\s*\{\s*\\(abovedisplayskip|belowdisplayskip|floatsep|"
     r"textfloatsep|intextsep|dbltextfloatsep)\s*\}", "float/display spacing compressed"),
    (r"\\renewcommand\s*\{\s*\\baselinestretch\s*\}", "line spacing altered"),
    (r"\\linespread\s*\{\s*0?\.", "line spacing compressed"),
]

# Reducing font size is normal inside a table, listing or caption and a
# violation in running text. Track the environment before judging.
FONT_SHRINK = re.compile(r"\\(small|footnotesize|scriptsize|tiny)\b")
FLOAT_OPEN = re.compile(r"\\begin\{(table|figure|tabular|tabularx|longtable|"
                        r"lstlisting|verbatim|algorithm|algorithmic|minipage|"
                        r"threeparttable|array)\*?\}")
FLOAT_CLOSE = re.compile(r"\\end\{(table|figure|tabular|tabularx|longtable|"
                         r"lstlisting|verbatim|algorithm|algorithmic|minipage|"
                         r"threeparttable|array)\*?\}")

# Strings that break double-blind review.
IDENTITY_PATTERNS = [
    (r"\\author\s*\{(?![^}]*[Aa]nonymous)(?![^}]*\\IEEEauthorblockN\{\s*\})[^}]{3,}",
     "author block contains a name"),
    (r"\\thanks\s*\{", "\\thanks block (usually funding/affiliation)"),
    (r"\\(acknowledgment|acknowledgments|acknowledgement|acknowledgements)\b",
     "acknowledgements section present"),
    (r"github\.com/(?!\s*ANONYM)[A-Za-z0-9._-]+", "de-anonymising GitHub URL"),
    (r"\b(?:doi\.org/10\.5281/zenodo\.\d+)", "Zenodo DOI may de-anonymise"),
    (r"\\orcid\{", "ORCID identifier"),
    # Deliberately anonymous placeholders are the CORRECT state for a
    # double-blind submission, so they must not be reported as leaks.
    # Not every user@host.tld is an email. LaTeX internals are full of
    # things like \csname ver@hyperxmp.sty\endcsname, and reporting those
    # as anonymity leaks trains people to ignore the check.
    (r"(?<![\\\w])(?!anonymous@|anon@|noreply@|ver@|Gin@|c@|g@)[A-Za-z0-9._%+-]+@(?!example\.(?:org|com)\b|anonymous\b)[A-Za-z0-9.-]+\.(?!sty\b|cls\b|tex\b|def\b|cfg\b|clo\b|fd\b)[A-Za-z]{2,}",
     "email address"),
    (r"\\(?:institution|affiliation|acmAffiliation)\s*\{(?![^}]*[Aa]nonymous)[^}]{3,}",
     "institution/affiliation named"),
    (r"\b(?:our (?:previous|prior|earlier) (?:work|paper|study)) \\cite",
     "self-citation phrased non-anonymously"),
]


FURNITURE_RE = re.compile(r"^[\divxlcIVXLC.\-–—]{1,6}$")


def _is_furniture(word: dict, page_w: float, page_h: float) -> bool:
    """Page numbers, running heads, and acmart review-mode line numbers live in
    the margin by design. Counting them as content makes every margin check
    fire on every page, so they are excluded before measuring."""
    text = (word.get("text") or "").strip()
    x0, x1 = float(word["x0"]), float(word["x1"])
    top, bottom = float(word["top"]), float(word["bottom"])
    outer = (x0 < 0.62 * PT_PER_IN or x1 > page_w - 0.62 * PT_PER_IN
             or top < 0.55 * PT_PER_IN or bottom > page_h - 0.62 * PT_PER_IN)
    if not outer:
        return False
    # short numeric/roman tokens in the outer strip: line or page numbers
    if FURNITURE_RE.match(text):
        return True
    # narrow vertical strip on the far left with only digits => line numbers
    if x1 < 0.62 * PT_PER_IN and text.isdigit():
        return True
    return False


def _repeated_bands(doc, tol: float = 2.0, min_share: float = 0.5):
    """Find y-positions where text repeats across most pages.

    Running heads and footers are the same height on every page by construction.
    Detecting them by repetition is reliable in a way that guessing a margin
    strip is not: a NeurIPS running head sits well inside the nominal top
    margin, and treating it as body content reports every page as violating.
    """
    from collections import Counter
    n = len(doc.pages)
    if n < 3:
        return []
    band = Counter()
    for page in doc.pages:
        seen = set()
        try:
            words = page.extract_words()
        except Exception:
            continue
        for w in words:
            key = round(float(w["top"]) / tol)
            if key not in seen:
                seen.add(key)
                band[key] += 1
    return [k * tol for k, c in band.items() if c >= n * min_share]


def _page_geometry(pdf: Path):
    """Return per-page (width, height, content bbox) in points using pdfplumber."""
    import pdfplumber
    pages = []
    with pdfplumber.open(str(pdf)) as doc:
        repeated = _repeated_bands(doc)
        top_furniture = [y for y in repeated if y < 1.2 * PT_PER_IN]
        bot_furniture = [y for y in repeated
                         if y > (doc.pages[0].height - 1.2 * PT_PER_IN)] if doc.pages else []
        for pno, page in enumerate(doc.pages, 1):
            xs0, xs1, ys0, ys1 = [], [], [], []
            try:
                words = page.extract_words(use_text_flow=False)
            except Exception:
                words = []
            for w in words:
                if _is_furniture(w, page.width, page.height):
                    continue
                wtop = float(w["top"])
                if any(abs(wtop - y) <= 2.5 for y in top_furniture + bot_furniture):
                    continue        # running head / footer, not body content
                xs0.append(float(w["x0"])); xs1.append(float(w["x1"]))
                ys0.append(float(w["top"])); ys1.append(float(w["bottom"]))
            for obj in list(page.images) + list(page.rects) + list(page.curves):
                # hairline rules used as page furniture (e.g. header separators)
                if abs(float(obj["x1"]) - float(obj["x0"])) < 1 and \
                        abs(float(obj["bottom"]) - float(obj["top"])) < 1:
                    continue
                xs0.append(float(obj["x0"])); xs1.append(float(obj["x1"]))
                ys0.append(float(obj["top"])); ys1.append(float(obj["bottom"]))
            sizes = [round(ch["size"], 2) for ch in page.chars]
            bbox = (min(xs0), min(ys0), max(xs1), max(ys1)) if xs0 else None
            pages.append({
                "page": pno, "width": page.width, "height": page.height,
                "bbox": bbox, "sizes": sizes,
                "text": page.extract_text() or "",
            })
    return pages


def _modal_font_size(all_sizes: list[float]) -> float | None:
    if not all_sizes:
        return None
    counts: dict[float, int] = {}
    for s in all_sizes:
        counts[s] = counts.get(s, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    v = cfg.venue
    tex = cfg.manuscript
    pdf = cfg.pdf

    # ---------------------------------------------------------------- source
    if not tex.exists():
        return [Finding("venue", "venue.template", "BLOCKER",
                        f"manuscript source not found at {tex}",
                        remedy="Fix paths.manuscript_tex in .paperloop/config.yaml")]

    lines = read_tex(tex)
    body = tex_body_lines(lines)
    rel = lambda p: str(Path(p).relative_to(cfg.root)) if str(p).startswith(str(cfg.root)) else str(p)

    # documentclass
    want_class = v.get("template", {}).get("documentclass")
    want_opts = set(v.get("template", {}).get("required_options", []) or [])
    forbid_opts = set(v.get("template", {}).get("forbidden_options", []) or [])
    dc = None
    for f, n, t in lines:
        m = re.search(r"\\documentclass\s*(\[([^\]]*)\])?\s*\{([^}]+)\}", t)
        if m:
            dc = (f, n, m.group(2) or "", m.group(3))
            break
    if dc and want_class:
        f, n, opts, cls = dc
        got = {o.strip() for o in opts.split(",") if o.strip()}
        if cls != want_class:
            out.append(Finding("venue", "venue.template", "BLOCKER",
                               f"wrong document class for {v.get('name')}",
                               file=rel(f), line=n, evidence=f"\\documentclass{{{cls}}}",
                               expected=f"\\documentclass{{{want_class}}}",
                               remedy=f"Switch to the official {v.get('name')} class {want_class}."))
        missing = want_opts - got
        if missing:
            out.append(Finding("venue", "venue.template", "BLOCKER",
                               f"missing required class options: {', '.join(sorted(missing))}",
                               file=rel(f), line=n, evidence=f"[{opts}]",
                               expected=f"options must include {sorted(want_opts)}",
                               remedy=f"Add {', '.join(sorted(missing))} to \\documentclass options."))
        bad = forbid_opts & got
        if bad:
            out.append(Finding("venue", "venue.template", "MAJOR",
                               f"forbidden class options present: {', '.join(sorted(bad))}",
                               file=rel(f), line=n, evidence=f"[{opts}]",
                               remedy=f"Remove {', '.join(sorted(bad))} from \\documentclass."))

    # margin / spacing hacks
    if v.get("format", {}).get("forbid_margin_hacks", True):
        float_depth = 0
        for f, n, t in lines:
            for pat, why in MARGIN_HACKS:
                if re.search(pat, t):
                    out.append(Finding("venue", "venue.margins", "MAJOR",
                                       f"{why} — defeats the template's page budget",
                                       file=rel(f), line=n, evidence=t.strip()[:160],
                                       expected="unmodified template geometry",
                                       remedy="Delete this command and shorten the prose instead."))
            opened = len(FLOAT_OPEN.findall(t))
            inside = float_depth > 0 or opened > 0
            float_depth = max(0, float_depth + opened - len(FLOAT_CLOSE.findall(t)))
            style_def = re.search(r"(basicstyle|lstset|lstdefinestyle|numberstyle|"
                                  r"keywordstyle|commentstyle|stringstyle|"
                                  r"\\newcommand|\\renewcommand|\\DeclareRobustCommand)", t)
            if not inside and not style_def and FONT_SHRINK.search(t) \
                    and "\\caption" not in t:
                out.append(Finding("venue", "venue.margins", "MAJOR",
                                   "body text size reduced in running text — defeats the "
                                   "template's page budget",
                                   file=rel(f), line=n, evidence=t.strip()[:160],
                                   expected="body text at the template's size",
                                   remedy="Remove the size command and shorten the prose. "
                                          "Reviewers notice, and it is a format violation "
                                          "on its own."))

    # anonymity
    if v.get("review", {}).get("double_blind", False):
        allow = v.get("review", {}).get("anonymity_allowlist", []) or []
        for f, n, t in lines:
            if any(a in t for a in allow):
                continue
            for pat, why in IDENTITY_PATTERNS:
                if re.search(pat, t, re.IGNORECASE):
                    out.append(Finding("venue", "venue.anonymity", "BLOCKER",
                                       f"double-blind violation: {why}",
                                       file=rel(f), line=n, evidence=t.strip()[:160],
                                       expected="no author-identifying content in the submission",
                                       remedy="Anonymise or remove; move to camera-ready only."))

    # required sections
    for sec in v.get("structure", {}).get("required_sections", []) or []:
        pat = re.compile(r"\\(?:sub)*section\*?\{[^}]*" + re.escape(sec) + r"[^}]*\}"
                         r"|\\begin\{" + re.escape(sec.lower()) + r"\}", re.IGNORECASE)
        if not any(pat.search(t) for _, _, t in lines):
            out.append(Finding("venue", "venue.structure", "MAJOR",
                               f"required section missing: {sec}",
                               file=rel(tex),
                               expected=f"{v.get('name')} requires a '{sec}' section",
                               remedy=f"Add a \\section{{{sec}}}."))

    # ------------------------------------------------------------------- pdf
    if not pdf.exists():
        out.append(Finding("venue", "venue.template", "MAJOR",
                           f"compiled PDF not found at {rel(pdf)}",
                           remedy=f"Build it: {cfg.build_command or 'see .paperloop/config.yaml'}"))
        return out

    try:
        pages = _page_geometry(pdf)
    except Exception as e:                                   # pragma: no cover
        out.append(Finding("venue", "venue.template", "MINOR",
                           f"could not measure PDF geometry: {e}"))
        return out

    npages = pdf_page_count(pdf) or len(pages)

    # page size
    want_size = v.get("format", {}).get("page_size")  # "letter" | "a4"
    if want_size and pages:
        w, h = round(pages[0]["width"]), round(pages[0]["height"])
        expect = {"letter": (612, 792), "a4": (595, 842)}.get(want_size.lower())
        if expect and (abs(w - expect[0]) > 2 or abs(h - expect[1]) > 2):
            out.append(Finding("venue", "venue.template", "BLOCKER",
                               f"wrong paper size ({w}x{h}pt)",
                               page=1, evidence=f"{w}x{h}pt",
                               expected=f"{want_size} = {expect[0]}x{expect[1]}pt",
                               remedy=f"Compile with {want_size}paper."))

    # ---- page limit -------------------------------------------------------
    limits = v.get("limits", {})
    limit = limits.get("body_pages")
    excl_refs = limits.get("excludes_references", True)
    excl_appendix = limits.get("excludes_appendix", True)

    if limit:
        ref_page = None
        appendix_page = None
        # Two-column extraction merges columns per line, so a heading often
        # shares its line with the other column's body text.
        ref_head = re.compile(r"^[ \t]*References\b|References[ \t]*$",
                              re.MULTILINE)
        app_head = re.compile(r"^[ \t]*[A-Z](?:[ \t]+Open[ \t]+Science)?[ \t]+Appendix\b|"
                              r"Appendix[ \t]*$|"
                              r"^[ \t]*Appendices\b|"
                              r"^[ \t]*[A-Z]\s+[A-Za-z\s]+Appendix", re.MULTILINE)
        for p in pages:
            # headings can sit mid-column in two-column layouts, so scan the whole page
            if ref_page is None and ref_head.search(p["text"]):
                ref_page = p["page"]
            if appendix_page is None and app_head.search(p["text"]):
                appendix_page = p["page"]
        cut = npages
        basis = "whole document"
        cands = [x for x in (ref_page if excl_refs else None,
                             appendix_page if excl_appendix else None) if x]
        if cands:
            cut = min(cands) - 1
            basis = f"body ends p.{cut} (references/appendix start p.{min(cands)})"
        if cut > limit:
            out.append(Finding("venue", "venue.pagecount", "BLOCKER",
                               f"over the {v.get('name')} page limit by {cut - limit} page(s)",
                               page=limit + 1, evidence=f"{cut} body pages ({basis}); {npages} total",
                               expected=f"<= {limit} body pages"
                                        + (" excluding references" if excl_refs else ""),
                               remedy=f"Cut {cut - limit} page(s) of body content. Do NOT shrink margins, "
                                      f"fonts, or float spacing — those are separate violations."))
        elif limits.get("warn_under") and cut < limits["warn_under"]:
            out.append(Finding("venue", "venue.pagecount", "MAJOR",
                               f"paper is well under the {limit}-page budget",
                               evidence=f"{cut} body pages",
                               expected=f"competitive submissions use {limits['warn_under']}-{limit} pages",
                               remedy="Expand evaluation, threat model, or related work; "
                                      "reviewers read a short paper as an underdeveloped one."))
        else:
            out.append(Finding("venue", "venue.pagecount", "INFO",
                               f"page count within limit",
                               evidence=f"{cut} body pages / {npages} total",
                               expected=f"<= {limit}"))

    # ---- margins ----------------------------------------------------------
    mspec = v.get("format", {}).get("min_margins_in")
    if mspec and pages:
        tol = float(v.get("format", {}).get("margin_tolerance_in", 0.02))
        worst = {}
        for p in pages:
            if not p["bbox"]:
                continue
            x0, y0, x1, y1 = p["bbox"]
            m = {"left": x0 / PT_PER_IN,
                 "right": (p["width"] - x1) / PT_PER_IN,
                 "top": y0 / PT_PER_IN,
                 "bottom": (p["height"] - y1) / PT_PER_IN}
            for k, val in m.items():
                if k not in mspec:
                    continue
                if val < mspec[k] - tol and (k not in worst or val < worst[k][0]):
                    worst[k] = (val, p["page"])
        for k, (val, pg) in sorted(worst.items()):
            out.append(Finding("venue", "venue.margins", "BLOCKER",
                               f"{k} margin violated on p.{pg}",
                               page=pg, evidence=f'{val:.3f}in',
                               expected=f'>= {mspec[k]}in (tolerance {tol}in)',
                               remedy=f"Content intrudes into the {k} margin on p.{pg}. Usually a wide "
                                      f"table, figure, algorithm block, or unbroken URL. Wrap it, scale "
                                      f"it to \\columnwidth, or rebreak the line — do not move the margin."))

    # ---- body font size ---------------------------------------------------
    fspec = v.get("format", {}).get("body_font_pt")
    if fspec and pages:
        all_sizes = [s for p in pages for s in p["sizes"]]
        modal = _modal_font_size(all_sizes)
        if modal is not None:
            if abs(modal - float(fspec)) > 0.35:
                out.append(Finding("venue", "venue.font", "BLOCKER",
                                   f"body font is {modal}pt, not the mandated {fspec}pt",
                                   evidence=f"{modal}pt (modal over {len(all_sizes)} glyphs)",
                                   expected=f"{fspec}pt",
                                   remedy="Restore the template's body size; remove any global "
                                          "\\small/\\footnotesize or font-size redefinition."))
            else:
                out.append(Finding("venue", "venue.font", "INFO", "body font size correct",
                                   evidence=f"{modal}pt", expected=f"{fspec}pt"))
        # caption/figure text floor
        floor = v.get("format", {}).get("min_any_font_pt")
        if floor:
            tiny = sorted({s for s in all_sizes if 0 < s < float(floor) - 0.2})
            if tiny:
                pgs = sorted({p["page"] for p in pages
                              if any(0 < s < float(floor) - 0.2 for s in p["sizes"])})
                out.append(Finding("venue", "venue.font", "MAJOR",
                                   "text below the minimum legible size (usually figure labels)",
                                   page=pgs[0],
                                   evidence=f"sizes {tiny[:6]} on pages {pgs[:8]}",
                                   expected=f">= {floor}pt everywhere",
                                   remedy="Regenerate the affected figures with a larger base font "
                                          "rather than scaling the image down."))

    # embedded fonts (camera-ready blocker at IEEE/ACM)
    if v.get("format", {}).get("require_embedded_fonts", True):
        try:
            from lib.common import run
            rc, so, _ = run(f'pdffonts "{pdf}"')
            if rc == 0:
                bad = [ln for ln in so.splitlines()[2:]
                       if ln.strip() and len(ln.split()) > 3 and ln.split()[-4] == "no"]
                if bad:
                    out.append(Finding("venue", "venue.font", "MAJOR",
                                       f"{len(bad)} font(s) not embedded",
                                       evidence="; ".join(b.split()[0] for b in bad[:5]),
                                       expected="all fonts embedded (Type 1 / TrueType subset)",
                                       remedy="Rebuild with -dPDFSETTINGS=/prepress or "
                                              "\\pdfmapfile settings that embed fonts."))
        except Exception:
            pass

    return out


if __name__ == "__main__":
    from lib.common import load_config, find_repo_root, sort_findings
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else find_repo_root())
    for f in sort_findings(check(cfg)):
        print(f.render())
