#!/usr/bin/env python3
"""Run every deterministic gate and emit the machine-readable work order.

    python3 .paperloop/run_gates.py [repo_root] [--build] [--render] [--json]

Exit codes (the orchestrator and CI both depend on these):
    0  clean            - no BLOCKER, no MAJOR
    1  fixable          - actionable findings, all inside the writer's mandate
    2  gated            - at least one science BLOCKER/MAJOR: needs a human
    3  broken           - the paper does not build / gates could not run
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.common import (Finding, load_config, find_repo_root, run,  # noqa: E402
                        sort_findings, summarize, write_findings)
from checks import (check_venue, check_science, check_figures, check_refs,  # noqa: E402
                    check_citations)

CHECKS = [
    ("venue", check_venue.check),
    ("figures", check_figures.check),
    ("refs", check_refs.check),
    ("citations", check_citations.check),
    ("science", check_science.check),
]


def build(cfg) -> tuple[bool, str]:
    cmd = cfg.build_command
    if not cmd:
        return True, "no build command configured; using the existing PDF"
    rc, so, se = run(cmd, cwd=cfg.root)
    tail = (so + se).strip().splitlines()[-25:]
    return rc == 0, "\n".join(tail)


def render_markdown(cfg, findings: list[Finding], summary: dict, built: str | None) -> str:
    venue = cfg.venue.get("name", "unknown venue")
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# Gate report — {cfg.root.name}",
        "",
        f"**Venue:** {venue}  ",
        f"**Manuscript:** `{cfg.raw['paths']['manuscript_tex']}`  ",
        f"**Run:** {now}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, n in summary["by_severity"].items():
        lines.append(f"| {sev} | {n} |")
    lines += ["", f"Gated (human sign-off required): **{summary['gated_actionable']}**", ""]
    if built:
        lines += ["<details><summary>Build output (tail)</summary>", "", "```",
                  built, "```", "</details>", ""]

    auto = [f for f in findings if f.severity != "INFO" and not f.gated]
    gated = [f for f in findings if f.severity != "INFO" and f.gated]
    info = [f for f in findings if f.severity == "INFO"]

    def block(title, items, note):
        if not items:
            return []
        out = [f"## {title}", "", note, ""]
        for f in items:
            loc = f" `{f.file}`" + (f":{f.line}" if f.line else "") if f.file else \
                  (f" p.{f.page}" if f.page else "")
            out.append(f"### [{f.severity}] {f.category}{loc}")
            out.append("")
            out.append(f.message)
            out.append("")
            if f.evidence:
                out.append(f"- **found:** `{f.evidence}`")
            if f.expected:
                out.append(f"- **expected:** {f.expected}")
            if f.remedy:
                out.append(f"- **remedy:** {f.remedy}")
            out.append(f"- **id:** `{f.fingerprint}`")
            out.append("")
        return out

    lines += block(
        "Auto-fix mandate", auto,
        "The writer agent applies these directly. Formatting, layout, figures, "
        "references, venue compliance — no interpretation of results required.")
    lines += block(
        "Gated — requires your decision", gated,
        "**The writer agent must not touch these.** Changing a number to make a gate "
        "pass converts a data error into a published claim. Each one gets a proposed "
        "diff in `.paperloop/state/proposals/`, and the loop halts.")
    lines += block("Measurements", info, "Recorded for the round log; no action implied.")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=None)
    ap.add_argument("--build", action="store_true", help="compile the PDF first")
    ap.add_argument("--render", action="store_true", help="export page PNGs for visual QA")
    ap.add_argument("--json", action="store_true", help="print findings JSON to stdout")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--fail-on", choices=("blocker", "major", "any", "never"),
                    default="major",
                    help="which severity makes the exit code non-zero. CI uses "
                         "'blocker' so a known backlog of MAJORs does not paint "
                         "every run red; the loop uses the default.")
    args = ap.parse_args()

    cfg = load_config(args.root or find_repo_root())
    built_tail = None
    if args.build:
        ok, built_tail = build(cfg)
        if not ok:
            f = Finding("build", "venue.template", "BLOCKER",
                        "the manuscript does not compile",
                        evidence=built_tail[-800:],
                        remedy="Fix the LaTeX error before anything else; every other "
                               "gate is measuring a stale PDF until this passes.")
            write_findings([f], cfg.state_dir / "findings.json",
                           {"build_failed": True})
            (cfg.state_dir / "FINDINGS.md").write_text(
                render_markdown(cfg, [f], summarize([f]), built_tail))
            print(f.render())
            return 3

    findings: list[Finding] = []
    for name, fn in CHECKS:
        try:
            findings.extend(fn(cfg))
        except Exception as e:                                    # pragma: no cover
            findings.append(Finding(name, "venue.template", "MINOR",
                                    f"check '{name}' crashed: {type(e).__name__}: {e}",
                                    remedy="Fix or disable this checker."))
    if args.render:
        try:
            pages = check_figures.render_pages(cfg)
            findings.append(Finding("figures", "figure.clipping", "INFO",
                                    f"rendered {len(pages)} page images for visual QA",
                                    evidence=str(cfg.state_dir / "pages")))
        except Exception:
            pass

    findings = sort_findings(findings)
    summary = summarize(findings)

    write_findings(findings, cfg.state_dir / "findings.json",
                   {"venue": cfg.venue.get("name"),
                    "manuscript": cfg.raw["paths"]["manuscript_tex"],
                    "generated": dt.datetime.now().isoformat(timespec="seconds")})
    md = render_markdown(cfg, findings, summary, built_tail)
    (cfg.state_dir / "FINDINGS.md").write_text(md)

    if args.json:
        print(json.dumps(json.loads((cfg.state_dir / "findings.json").read_text()), indent=2))
    elif not args.quiet:
        for f in findings:
            if f.severity != "INFO":
                print(f.render())
        s = summary["by_severity"]
        print(f"\n{'-' * 68}")
        print(f"BLOCKER {s['BLOCKER']}  MAJOR {s['MAJOR']}  MINOR {s['MINOR']}  "
              f"INFO {s['INFO']}   gated: {summary['gated_actionable']}")
        print(f"report: {cfg.state_dir / 'FINDINGS.md'}")

    s = summary["by_severity"]
    if args.fail_on == "never":
        return 0
    if args.fail_on == "blocker":
        return 3 if s["BLOCKER"] else 0

    gated_bad = [f for f in findings if f.gated and f.severity in ("BLOCKER", "MAJOR")]
    if gated_bad:
        return 2
    if summary["clean"]:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
