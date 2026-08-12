"""Figure, diagram and layout gate.

The LaTeX .log already knows about every box that does not fit — most people
never read it. This reads it, plus measures the rendered images in the PDF so
that "the diagram is blurry" and "the figure runs into the margin" become
numbers instead of opinions.

Also exports page renders so a multimodal agent can *look* at the layout.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.common import Config, Finding, read_tex, tex_body_lines, run  # noqa: E402

OVERFULL_RE = re.compile(
    r"^(Overfull|Underfull)\s+\\([hv])box\s+\(([\d.]+)pt too (wide|high|short|little)\).*?"
    r"(?:at lines? (\d+)(?:--(\d+))?|has occurred while \\output is active)",
    re.MULTILINE)

RASTER = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif"}
VECTOR = {".pdf", ".eps", ".ps", ".svg"}


def _log_boxes(cfg: Config, out: list[Finding]) -> None:
    log = cfg.log
    if not log.exists():
        return
    text = log.read_text(errors="replace")
    rel = str(log.relative_to(cfg.root))
    src = str(cfg.manuscript.relative_to(cfg.root))

    hb_thresh = float(cfg.venue.get("format", {}).get("overfull_hbox_pt_threshold", 1.0))
    seen = set()
    for m in OVERFULL_RE.finditer(text):
        kind, box, amount, _, l1, l2 = m.group(1), m.group(2), float(m.group(3)), \
            m.group(4), m.group(5), m.group(6)
        line = int(l1) if l1 else None
        key = (kind, box, round(amount, 1), line)
        if key in seen:
            continue
        seen.add(key)

        if kind == "Overfull" and box == "h":
            if amount < hb_thresh:
                continue
            sev = "BLOCKER" if amount >= 10 else ("MAJOR" if amount >= 3 else "MINOR")
            out.append(Finding(
                "figures", "layout.overfull", sev,
                f"content sticks {amount:.1f}pt past the column/text width "
                f"({amount / 72:.3f}in into the margin)",
                file=src, line=line, evidence=f"Overfull \\hbox {amount:.1f}pt",
                expected="no overfull hbox above %.1fpt" % hb_thresh,
                remedy="Usually an unbreakable token: a long URL (use \\url or \\sloppy), "
                       "a wide table (use \\resizebox or \\small on the tabular only), "
                       "code/identifier (add \\allowbreak), or a figure wider than "
                       "\\columnwidth (set width=\\columnwidth)."))
        elif kind == "Overfull" and box == "v":
            out.append(Finding(
                "figures", "layout.overfull", "MAJOR",
                f"content overruns the text height by {amount:.1f}pt",
                file=src, line=line, evidence=f"Overfull \\vbox {amount:.1f}pt",
                remedy="A float or block is taller than the page body. Shrink or move it."))
        elif kind == "Underfull" and amount >= 5000:
            out.append(Finding(
                "figures", "layout.underfull", "MINOR",
                f"badly stretched line (badness {amount:.0f})",
                file=src, line=line,
                remedy="Rephrase the sentence or add \\sloppy locally."))
    if log.exists():
        for pat, msg, sev in [
            (r"LaTeX Warning: Float too large", "a float is too large for the page", "MAJOR"),
            (r"pdfTeX warning.*?fail(?:ed)? to (?:find|load)", "a resource failed to load", "MAJOR"),
            (r"Missing character:", "glyph missing from the chosen font", "MAJOR"),
        ]:
            hits = len(re.findall(pat, text))
            if hits:
                out.append(Finding("figures", "layout.overfull", sev,
                                   f"{msg} ({hits} occurrence(s) in the build log)",
                                   file=rel, remedy="Read the log around this warning and fix "
                                                    "the underlying asset or font."))


def _pdf_images(cfg: Config, out: list[Finding]) -> None:
    pdf = cfg.pdf
    if not pdf.exists():
        return
    fmt = cfg.venue.get("format", {})
    min_dpi = float(fmt.get("min_raster_dpi", 300))
    mspec = fmt.get("min_margins_in", {})
    try:
        import pdfplumber
    except ImportError:
        return

    with pdfplumber.open(str(pdf)) as doc:
        for pno, page in enumerate(doc.pages, 1):
            for im in page.images:
                w_pt = float(im["x1"]) - float(im["x0"])
                h_pt = float(im["bottom"]) - float(im["top"])
                src = im.get("srcsize") or (None, None)
                if src[0] and w_pt > 1:
                    dpi_x = src[0] / (w_pt / 72.0)
                    dpi_y = (src[1] / (h_pt / 72.0)) if src[1] and h_pt > 1 else dpi_x
                    dpi = min(dpi_x, dpi_y)
                    if dpi < min_dpi:
                        sev = "MAJOR" if dpi < min_dpi * 0.6 else "MINOR"
                        out.append(Finding(
                            "figures", "figure.resolution", sev,
                            f"raster figure on p.{pno} renders at {dpi:.0f} DPI",
                            page=pno,
                            evidence=f"{src[0]}x{src[1]}px drawn at "
                                     f"{w_pt / 72:.2f}x{h_pt / 72:.2f}in = {dpi:.0f} DPI",
                            expected=f">= {min_dpi:.0f} DPI",
                            remedy="Regenerate this figure as vector PDF (matplotlib "
                                   "savefig('.pdf'), or export the diagram to PDF/SVG). "
                                   "Upscaling the bitmap will not help."))
                # bleed past the margin
                if mspec:
                    left_in = float(im["x0"]) / 72.0
                    right_in = (page.width - float(im["x1"])) / 72.0
                    top_in = float(im["top"]) / 72.0
                    bot_in = (page.height - float(im["bottom"])) / 72.0
                    for name, val in (("left", left_in), ("right", right_in),
                                      ("top", top_in), ("bottom", bot_in)):
                        if name in mspec and val < mspec[name] - 0.03:
                            out.append(Finding(
                                "figures", "figure.overflow", "BLOCKER",
                                f"figure on p.{pno} bleeds into the {name} margin",
                                page=pno, evidence=f"{val:.3f}in from the {name} edge",
                                expected=f">= {mspec[name]}in",
                                remedy="Set the graphic to width=\\columnwidth "
                                       "(or \\textwidth for a figure*) and re-export at "
                                       "the correct aspect ratio; do not \\hspace it back."))


def _source_hygiene(cfg: Config, out: list[Finding]) -> None:
    lines = read_tex(cfg.manuscript)
    body = tex_body_lines(lines)
    rel = lambda p: str(Path(p).relative_to(cfg.root))
    joined = "\n".join(t for _, _, t in body)

    # every float should have a caption and a label, and be referenced
    for env in ("figure", "table", "algorithm"):
        blocks = re.finditer(rf"\\begin\{{{env}\*?\}}(.*?)\\end\{{{env}\*?\}}",
                             joined, re.DOTALL)
        for i, b in enumerate(blocks, 1):
            inner = b.group(1)
            if "\\caption" not in inner and env != "algorithm":
                out.append(Finding("figures", "figure.clipping", "MAJOR",
                                   f"{env} #{i} has no \\caption",
                                   file=rel(cfg.manuscript),
                                   remedy=f"Add a \\caption to {env} #{i}. Reviewers read "
                                          f"captions before body text."))
            lm = re.search(r"\\label\{([^}]+)\}", inner)
            if not lm:
                out.append(Finding("figures", "figure.clipping", "MINOR",
                                   f"{env} #{i} has no \\label, so it cannot be referenced",
                                   file=rel(cfg.manuscript),
                                   remedy=f"Add \\label{{{env[:3]}:...}} and \\ref it in the text."))
            elif f"\\ref{{{lm.group(1)}}}" not in joined and \
                 f"\\autoref{{{lm.group(1)}}}" not in joined and \
                 f"\\Cref{{{lm.group(1)}}}" not in joined and \
                 f"\\cref{{{lm.group(1)}}}" not in joined:
                out.append(Finding("figures", "figure.clipping", "MAJOR",
                                   f"{env} '{lm.group(1)}' is never referenced in the text",
                                   file=rel(cfg.manuscript),
                                   evidence=lm.group(1),
                                   remedy="Every float must be discussed in the prose. Add a "
                                          "\\ref at the point where the reader needs it, or "
                                          "cut the float."))

    # figures pinned to a raster source when a vector one is available
    for f, n, t in body:
        m = re.search(r"\\includegraphics\s*(\[[^\]]*\])?\s*\{([^}]+)\}", t)
        if not m:
            continue
        opts, target = (m.group(1) or ""), m.group(2)
        if "width" not in opts and "scale" not in opts and "height" not in opts:
            out.append(Finding("figures", "figure.overflow", "MAJOR",
                               f"\\includegraphics{{{target}}} has no width — it will render "
                               f"at native size and can overflow the column",
                               file=rel(f), line=n, evidence=t.strip()[:150],
                               expected="width=\\columnwidth (or \\linewidth)",
                               remedy="Add [width=\\columnwidth]."))
        found = None
        for d in cfg.figure_dirs + [cfg.manuscript.parent]:
            for ext in ("", ".pdf", ".png", ".jpg", ".eps", ".svg"):
                cand = d / (target + ext)
                if cand.exists() and cand.is_file():
                    found = cand
                    break
            if found:
                break
        if not found:
            out.append(Finding("figures", "figure.clipping", "BLOCKER",
                               f"figure source not found: {target}",
                               file=rel(f), line=n,
                               remedy="Regenerate the figure or fix the path; the PDF is "
                                      "currently built from a stale cached image."))
        elif found.suffix.lower() in RASTER:
            sibling = found.with_suffix(".pdf")
            if sibling.exists():
                out.append(Finding("figures", "figure.resolution", "MINOR",
                                   f"{target} uses the raster version although "
                                   f"{sibling.name} exists",
                                   file=rel(f), line=n,
                                   remedy=f"Point \\includegraphics at {sibling.stem} to get "
                                          f"vector output."))


def render_pages(cfg: Config, dpi: int = 130) -> list[Path]:
    """Export page PNGs so a multimodal agent can visually inspect layout."""
    outdir = cfg.state_dir / "pages"
    outdir.mkdir(parents=True, exist_ok=True)
    for old in outdir.glob("page-*.png"):
        old.unlink()
    rc, _, err = run(f'pdftoppm -r {dpi} -png "{cfg.pdf}" "{outdir}/page"')
    if rc != 0:
        run(f'gs -dNOPAUSE -dBATCH -sDEVICE=png16m -r{dpi} '
            f'-sOutputFile="{outdir}/page-%02d.png" "{cfg.pdf}"')
    return sorted(outdir.glob("page*.png"))


def check(cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    _log_boxes(cfg, out)
    _pdf_images(cfg, out)
    _source_hygiene(cfg, out)
    return out


if __name__ == "__main__":
    from lib.common import load_config, find_repo_root, sort_findings
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else find_repo_root())
    if "--render" in sys.argv:
        pages = render_pages(cfg)
        print(f"rendered {len(pages)} pages to {cfg.state_dir / 'pages'}")
    for f in sort_findings(check(cfg)):
        print(f.render())
