#!/usr/bin/env python3
"""The self-correcting loop: measure -> evaluate -> write, repeat.

    python3 .paperloop/loop.py --forever --push --pr     # never stops
    python3 .paperloop/loop.py --rounds 6 --push --pr    # bounded

Each round has three phases:

    measure    deterministic gates gate the compiled PDF and the source
    evaluate   an LLM reviewer reads the paper and reports what a script cannot
    write      the writer agent applies everything it is allowed to apply

The reviewer rotates every round — venue compliance, science, adversarial peer
review, literature — so no single agent's blind spot survives, and a stall jumps
the rotation to get genuinely different eyes on whatever is stuck.

The loop does not stop when it gets stuck and it does not stop when a science
finding appears. A stall re-frames the work order with a new reviewer. A science
finding is parked as a proposal for the human and the loop carries on fixing
everything else. It only ends on: --rounds spent, --max-hours reached, a build it
cannot compile with no writer available, or two consecutive rounds where the gate
is clean AND the reviewer reports nothing new (and with --forever it sleeps and
re-checks rather than exiting even then).

The writer is whatever agent CLI is on PATH — Claude Code, Cursor, Codex, Gemini,
OpenCode, Crush, Aider, Kimi — auto-detected and launched headless.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.common import load_config, find_repo_root, run  # noqa: E402
from lib import fixers  # noqa: E402

GATES = str(HERE / "run_gates.py")


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------
def git(cfg, *args, check=True) -> str:
    p = subprocess.run(["git", *args], cwd=cfg.root, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


def ensure_branch(cfg, branch: str) -> str:
    current = git(cfg, "rev-parse", "--abbrev-ref", "HEAD")
    if current == branch:
        return branch
    existing = git(cfg, "branch", "--list", branch)
    if existing.strip():
        git(cfg, "checkout", branch)
    else:
        git(cfg, "checkout", "-b", branch)
    return branch


def has_changes(cfg, ignore_state: bool = True) -> bool:
    """Did anything change? Loop bookkeeping under .paperloop/state does not
    count as progress — otherwise a writer that did nothing still looks busy."""
    raw = git(cfg, "status", "--porcelain", check=False).strip()
    if not raw:
        return False
    if not ignore_state:
        return True
    for line in raw.splitlines():
        path = line[3:].strip().strip('"')
        if not path.startswith(".paperloop/state/"):
            return True
    return False


def commit(cfg, message: str) -> str | None:
    if not has_changes(cfg, ignore_state=False):
        return None
    git(cfg, "add", "-A")
    subprocess.run(["git", "commit", "-m", message], cwd=cfg.root,
                   capture_output=True, text=True)
    return git(cfg, "rev-parse", "--short", "HEAD", check=False)


# ---------------------------------------------------------------------------
# work order
# ---------------------------------------------------------------------------
WORK_ORDER = """\
You are the paper-writer agent for `{repo}`, targeting **{venue}**.

A deterministic gate just measured the compiled manuscript. Your job is to make
the findings below go away by editing the paper — not by editing the gate, not
by relaxing the venue spec, and not by touching anything marked GATED.

Manuscript: `{manuscript}`
Full report: `.paperloop/state/FINDINGS.md`
Machine-readable: `.paperloop/state/findings.json`

## Your mandate

Fix every finding in the **Auto-fix mandate** section. For each one:
  1. Read the surrounding source before editing. Never blind-replace.
  2. Apply the smallest change that resolves the measurement.
  3. Preserve meaning. If a page-limit cut would remove a technical
     contribution, cut redundancy and prose bloat instead and say what you cut.

## Hard prohibitions

- Do not shrink margins, fonts, line spacing, or float separation to fit a
  page limit. Those are themselves violations and the gate will catch them.
- Do not change any number, statistic, or empirical claim. If a number is
  wrong, that is a GATED finding: write a proposal, do not edit the paper.
- Do not delete a check, loosen `venue.yaml`, or add a suppression to make a
  gate pass. If you believe a finding is a false positive, write it to
  `.paperloop/state/disputed.md` with your reasoning and leave the paper alone.
- Do not invent citations, results, or artifacts.

## Gated findings ({gated} of them)

For each, write `.paperloop/state/proposals/<id>.md` containing: the finding,
what you believe the correct value or claim is, the exact diff you would apply,
and the evidence you would need to be sure. Then stop on those. A human decides.

## When you are done

Re-run `python3 .paperloop/run_gates.py --build` yourself and confirm the count
dropped. Then write a two-line summary of what you changed to
`.paperloop/state/round-{round}-writer.md`.

---

{findings}
"""


def compose_work_order(cfg, round_no: int, reviews: list[str] | None = None) -> Path:
    data = json.loads((cfg.state_dir / "findings.json").read_text())
    findings = data["findings"]
    auto = [f for f in findings if f["severity"] in ("BLOCKER", "MAJOR", "MINOR")
            and not f["gated"]]
    gated = [f for f in findings if f["severity"] in ("BLOCKER", "MAJOR") and f["gated"]]

    def fmt(f):
        loc = f.get("file") or ""
        if f.get("line"):
            loc += f":{f['line']}"
        if not loc and f.get("page"):
            loc = f"p.{f['page']}"
        parts = [f"- [{f['severity']}] ({f['category']}) {loc}\n  {f['message']}"]
        if f.get("evidence"):
            parts.append(f"  found: {f['evidence']}")
        if f.get("expected"):
            parts.append(f"  expected: {f['expected']}")
        if f.get("remedy"):
            parts.append(f"  remedy: {f['remedy']}")
        parts.append(f"  id: {f['fingerprint']}")
        return "\n".join(parts)

    body = ["## AUTO-FIX MANDATE\n"] + [fmt(f) for f in auto]
    if gated:
        body += ["\n## GATED — PROPOSE ONLY, DO NOT EDIT THE PAPER\n"] + [fmt(f) for f in gated]
    if reviews:
        body += ["\n## REVIEWER FINDINGS (from the evaluator agents this round)\n",
                 "These come from an agent that read the paper rather than measured it. "
                 "Apply the same split: `science.*` are gated and you may only propose; "
                 "everything else is yours to fix.\n"]
        body += reviews

    text = WORK_ORDER.format(
        repo=cfg.root.name,
        venue=cfg.venue.get("name", "unknown"),
        manuscript=cfg.raw["paths"]["manuscript_tex"],
        gated=len(gated),
        round=round_no,
        findings="\n\n".join(body))
    p = cfg.state_dir / f"WORK_ORDER-round-{round_no}.md"
    p.write_text(text)
    (cfg.state_dir / "WORK_ORDER.md").write_text(text)
    return p


# ---------------------------------------------------------------------------
# fixer invocation
# ---------------------------------------------------------------------------
def resolve_fixer(cfg, autonomy: str) -> tuple[str | None, str]:
    return fixers.resolve(cfg.raw.get("fixer", {}).get("command"), autonomy)


def invoke_fixer(cfg, cmd: str, prompt_path: Path, timeout: int) -> tuple[bool, str]:
    takes_file = "{prompt_file}" in cmd
    cmd = cmd.replace("{prompt_file}", shlex.quote(str(prompt_path)))
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=cfg.root,
            # Feed the prompt on stdin unless the CLI wants a file. Either way
            # stdin is never a terminal, so a tool that tries to prompt gets EOF
            # and exits instead of hanging the loop forever.
            input="" if takes_file else prompt_path.read_text(),
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"fixer timed out after {timeout}s"
    tail = ((p.stdout or "") + (p.stderr or "")).strip()[-4000:]
    return p.returncode == 0, tail


def gate(cfg, build: bool, render: bool) -> tuple[int, dict]:
    cmd = [sys.executable, GATES, str(cfg.root), "--quiet"]
    if build:
        cmd.append("--build")
    if render:
        cmd.append("--render")
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads((cfg.state_dir / "findings.json").read_text())
    except Exception:
        data = {"summary": {"by_severity": {}, "clean": False, "gated_actionable": 0},
                "findings": []}
    if p.returncode == 3:
        print(p.stdout[-2000:])
    return p.returncode, data


def actionable_ids(data: dict) -> set[str]:
    return {f["fingerprint"] for f in data["findings"]
            if f["severity"] in ("BLOCKER", "MAJOR", "MINOR")}


# ---------------------------------------------------------------------------
# Evaluator phase
# ---------------------------------------------------------------------------
# The deterministic gate measures what a script can measure. These are the
# reviewers that read the paper. The loop rotates through them so every round
# gets a different pair of eyes, and no single reviewer's blind spot persists.
EVALUATORS = [
    ("venue-compliance-auditor",
     "Audit {venue} submission compliance. The deterministic gate has already "
     "measured page count, margins, fonts, figure DPI, overfull boxes and "
     "citations — do not re-derive those. Your job is what it cannot see: open "
     "the page renders in `.paperloop/state/pages/` and LOOK at every figure and "
     "diagram for overlapping labels, arrows pointing nowhere, legends covering "
     "data, greyscale failure, and diagrams that contradict the text. Read every "
     "caption standalone. Check the live CFP at the venue's site against "
     "`.paperloop/venue.yaml`."),
    ("science-auditor",
     "Audit the science. Rebuild the claim ledger: for every headline claim, the "
     "sentence, the number, the artifact file and key, the producing script, and "
     "the command to regenerate. Re-derive the headline numbers yourself from raw "
     "artifacts — aggregation is where errors hide. Interrogate the design: does "
     "the comparison isolate the claimed cause, is the baseline the strongest "
     "available, are splits disjoint, was the analysis specified before the data "
     "was seen. Check the negative space: which experiment would have falsified "
     "the claim, and was it run."),
    ("paper-evaluator",
     "Review this as the harshest competent reviewer on the {venue} PC. Attack the "
     "contribution: is it novel, is it significant, does the evaluation support the "
     "claims, would you fight for it or against it in the PC meeting. Give the "
     "specific reasons you would reject, ranked. Be concrete about what would "
     "change your mind."),
    ("literature-venue-verifier",
     "Verify the literature and venue fit. Every reference: relevance, authority, "
     "primary-source status, bibliographic correctness, and whether a canonical or "
     "stronger source should replace it. Identify seminal and current work that is "
     "missing — a reviewer who knows this field will notice the gap. Confirm the "
     "{venue} requirements against the official call."),
]

EVAL_PROMPT = """\
You are the **{agent}** for `{repo}`, targeting **{venue}**.

{brief}

## Read-only

You do not edit the manuscript. Another agent does that. If you change the paper
you corrupt the loop's measurement of its own progress.

## Context

- Current measured findings: `.paperloop/state/FINDINGS.md`
- Machine-readable: `.paperloop/state/findings.json`
- Page renders for visual inspection: `.paperloop/state/pages/`
- Manuscript: `{manuscript}`
- Previous rounds of review: `.paperloop/state/review-*.md`

Read the previous rounds first. Do not repeat a finding that is already there and
already fixed. Do flag one that was reported and *not* fixed — that is a signal
the writer could not act on it, and you should say why and propose a different
remedy.

## Output — this is the contract

Write your findings to `{outfile}` as a markdown list. One finding per bullet, in
exactly this shape so the writer can act on it without interpretation:

```
- [SEVERITY] (category) file:line — what is wrong
  evidence: what you observed
  remedy: the specific change to make
```

SEVERITY is BLOCKER, MAJOR or MINOR. category is one of:
`venue.*`, `figure.*`, `layout.*`, `refs.*`, `prose.style` for things the writer
may fix directly; `science.*` for anything touching a number, statistic, claim,
or experimental design — those are gated and the writer may only propose.

Be specific. "Improve the evaluation" is useless. "Table 3 reports accuracy
without a baseline; add the {venue}-standard comparison against X" is actionable.

If you find nothing new, write "no new findings" and say what you checked. An
honest empty round is more useful than invented work.
"""


def run_evaluator(cfg, cmd: str, agent: str, brief: str, rnd: int,
                  timeout: int) -> tuple[bool, Path]:
    outfile = cfg.state_dir / f"review-round-{rnd}-{agent}.md"
    prompt = EVAL_PROMPT.format(
        agent=agent, repo=cfg.root.name, venue=cfg.venue.get("name", "the venue"),
        brief=brief.format(venue=cfg.venue.get("name", "the venue")),
        manuscript=cfg.raw["paths"]["manuscript_tex"],
        outfile=outfile.relative_to(cfg.root))
    ppath = cfg.state_dir / f"eval-prompt-round-{rnd}.md"
    ppath.write_text(prompt)
    ok, tail = invoke_fixer(cfg, cmd, ppath, timeout)
    if not outfile.exists():
        # the agent answered on stdout instead of writing the file
        if tail.strip():
            outfile.write_text(f"# {agent} round {rnd} (captured from stdout)\n\n{tail}")
        else:
            return False, outfile
    return True, outfile


def review_findings(cfg) -> list[str]:
    """Unresolved reviewer findings, most recent round first."""
    out = []
    for p in sorted(cfg.state_dir.glob("review-round-*.md"), reverse=True)[:3]:
        text = p.read_text().strip()
        if text and "no new findings" not in text.lower():
            out.append(f"### from {p.name}\n\n{text}")
    return out


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=None)
    ap.add_argument("--rounds", type=int, default=6,
                    help="0 or negative = keep going indefinitely")
    ap.add_argument("--forever", action="store_true",
                    help="do not stop on convergence; sleep and re-check instead")
    ap.add_argument("--idle", type=int, default=15,
                    help="minutes to sleep between passes when --forever is idle")
    ap.add_argument("--max-hours", type=float, default=0,
                    help="wall-clock ceiling for unlimited runs (0 = none)")
    ap.add_argument("--push-every", action="store_true",
                    help="push after every round, not just at the end")
    ap.add_argument("--branch", default=None, help="default: paperloop/autofix")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--render", action="store_true", help="export page PNGs each round")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--pr", action="store_true", help="open a PR at the end (needs gh)")
    ap.add_argument("--no-git", action="store_true", help="edit files, never touch git")
    ap.add_argument("--timeout", type=int, default=3600, help="per-round fixer timeout")
    ap.add_argument("--gates-only", action="store_true",
                    help="measure and write the work order, then stop")
    ap.add_argument("--autonomy", choices=("edits", "full"), default=None,
                    help="'edits' auto-accepts file edits; 'full' asks for nothing "
                         "(use for unattended overnight runs)")
    ap.add_argument("--fixer", default=None, help="override the writer CLI command")
    ap.add_argument("--list-fixers", action="store_true",
                    help="show which agent CLIs were detected, then exit")
    args = ap.parse_args()

    if args.list_fixers:
        print(fixers.describe())
        return 0

    cfg = load_config(args.root or find_repo_root())
    build = not args.no_build
    branch = args.branch or cfg.raw.get("git", {}).get("branch", "paperloop/autofix")
    use_git = not args.no_git and (cfg.root / ".git").exists()
    log_path = cfg.state_dir / "loop.log"
    started = dt.datetime.now()

    def say(msg: str) -> None:
        line = f"[{dt.datetime.now():%H:%M:%S}] {msg}"
        print(line, flush=True)
        with log_path.open("a") as fh:
            fh.write(line + "\n")

    say(f"=== paperloop {cfg.root.name} -> {cfg.venue.get('name')} ===")

    autonomy = args.autonomy or cfg.raw.get("fixer", {}).get("autonomy", "edits")
    if args.fixer:
        fixer_cmd, how = args.fixer, "--fixer"
    else:
        fixer_cmd, how = resolve_fixer(cfg, autonomy)
    if fixer_cmd:
        say(f"writer: {fixer_cmd}")
        say(f"        via {how}, autonomy={autonomy}")
    else:
        say(f"writer: none — {how}")

    base_branch = None
    if use_git:
        base_branch = git(cfg, "rev-parse", "--abbrev-ref", "HEAD")
        ensure_branch(cfg, branch)
        say(f"working on branch {branch} (base {base_branch})")

    history: list[set[str]] = []
    outcome = "exhausted"
    rounds_done = 0
    stall_streak = 0
    clean_streak = 0
    last_used: dict[str, int] = {}
    if args.forever and args.rounds == 6:      # 6 is the default, not a choice
        args.rounds = 0
    budget = args.rounds if args.rounds > 0 else 10 ** 9   # --rounds 0 = keep going
    unlimited = args.rounds <= 0

    rnd = 0
    while rnd < budget:
        rnd += 1
        rounds_done = rnd
        total = "inf" if unlimited else str(args.rounds)

        # ---------------------------------------------------------- MEASURE
        say(f"--- round {rnd}/{total} · measure")
        rc, data = gate(cfg, build, args.render)
        sev = data["summary"].get("by_severity", {})
        ids = actionable_ids(data)
        n_gated = data["summary"].get("gated_actionable", 0)
        say(f"    BLOCKER {sev.get('BLOCKER', 0)}  MAJOR {sev.get('MAJOR', 0)}  "
            f"MINOR {sev.get('MINOR', 0)}  gated {n_gated}")

        if rc == 3:
            # A broken build is the one thing worth pausing on: every downstream
            # measurement is of a stale PDF, so more rounds would be fiction.
            say("    the manuscript does not compile")
            if not fixer_cmd:
                outcome = "broken"
                break
            say("    sending the build error to the writer and continuing")

        if args.gates_only:
            outcome = "gates-only"
            compose_work_order(cfg, rnd)
            say("    work order written; --gates-only, so stopping here")
            break
        if not fixer_cmd:
            outcome = "no-fixer"
            compose_work_order(cfg, rnd)
            say(f"    no writer CLI available; work order at "
                f"{cfg.state_dir / 'WORK_ORDER.md'}")
            break

        # Track progress, but never terminate on it. A stalled round means the
        # writer could not act on this work order — the answer is a different
        # reviewer and a re-framed order, not giving up.
        if history and ids == history[-1]:
            stall_streak += 1
            say(f"    no change in measured findings ({stall_streak} round(s) running)")
        else:
            stall_streak = 0
        history.append(ids)

        # --------------------------------------------------------- EVALUATE
        # Rotate reviewers so a single agent's blind spot cannot persist. While
        # stalled, pick the least recently used one — the round counter and the
        # stall counter advance together, so naive arithmetic would oscillate
        # between the same two reviewers and never reach the others.
        if stall_streak:
            agent, brief = min(EVALUATORS, key=lambda e: last_used.get(e[0], -1))
        else:
            agent, brief = EVALUATORS[(rnd - 1) % len(EVALUATORS)]
        last_used[agent] = rnd
        say(f"--- round {rnd} · evaluate ({agent})")
        ev_ok, ev_file = run_evaluator(cfg, fixer_cmd, agent, brief, rnd, args.timeout)
        if ev_ok and ev_file.exists():
            head = ev_file.read_text().strip().splitlines()
            n = len([l for l in head if l.strip().startswith("- [")])
            say(f"    {agent}: {n} finding(s) -> {ev_file.name}")
        else:
            say(f"    {agent} produced no report this round")

        # ------------------------------------------------------------ WRITE
        reviews = review_findings(cfg)
        wo = compose_work_order(cfg, rnd, reviews)
        if n_gated:
            say(f"    {n_gated} science finding(s) parked for you — the writer will "
                f"propose, not edit, and the loop continues on everything else")
        say(f"--- round {rnd} · write")
        ok, tail = invoke_fixer(cfg, fixer_cmd, wo, args.timeout)
        (cfg.state_dir / f"round-{rnd}-fixer.log").write_text(tail)
        if not ok:
            say("    writer exited non-zero; re-measuring anyway")

        if use_git:
            touched = has_changes(cfg)
            c = commit(cfg, f"paperloop round {rnd}: {agent} review + writer pass "
                            f"({sev.get('BLOCKER', 0)}B/{sev.get('MAJOR', 0)}M)")
            if not touched:
                say("    writer changed no paper files this round")
            elif c:
                say(f"    committed {c}")
            if args.push and args.push_every and touched:
                p = subprocess.run(["git", "push", "-u", "origin", branch],
                                   cwd=cfg.root, capture_output=True, text=True)
                say("    pushed" if p.returncode == 0 else
                    f"    push failed: {p.stderr.strip()[:160]}")

        # ------------------------------------------------------- CONVERGENCE
        # "Clean" is not a reason to stop on its own: the reviewers may still
        # find something a measurement cannot. Require the gate to be clean AND
        # the reviewer to report nothing new, twice running.
        quiet_review = (not ev_file.exists()
                        or "no new findings" in ev_file.read_text().lower())
        if rc == 0 and quiet_review:
            clean_streak += 1
            say(f"    clean gate + quiet review ({clean_streak}/2)")
            if clean_streak >= 2:
                outcome = "converged"
                say("    two consecutive clean rounds across gate and review")
                if not args.forever:
                    break
                say("    --forever: sleeping, will re-check")
                time.sleep(max(60, args.idle * 60))
                clean_streak = 0
        else:
            clean_streak = 0

        if unlimited and args.max_hours and \
                (dt.datetime.now() - started).total_seconds() > args.max_hours * 3600:
            outcome = "time-limit"
            say(f"    hit the {args.max_hours}h wall clock limit")
            break

    # ------------------------------------------------------------------ wrap
    rc, data = gate(cfg, build, False)
    sev = data["summary"].get("by_severity", {})
    say(f"=== {outcome} after {rounds_done} round(s): "
        f"BLOCKER {sev.get('BLOCKER', 0)} MAJOR {sev.get('MAJOR', 0)} "
        f"MINOR {sev.get('MINOR', 0)} ===")

    summary_md = cfg.state_dir / "LOOP_SUMMARY.md"
    summary_md.write_text(
        f"# paperloop summary — {cfg.root.name}\n\n"
        f"- venue: {cfg.venue.get('name')}\n"
        f"- outcome: **{outcome}**\n"
        f"- rounds: {rounds_done}/{args.rounds}\n"
        f"- started: {started:%Y-%m-%d %H:%M}\n"
        f"- finished: {dt.datetime.now():%Y-%m-%d %H:%M}\n"
        f"- remaining: BLOCKER {sev.get('BLOCKER', 0)}, MAJOR {sev.get('MAJOR', 0)}, "
        f"MINOR {sev.get('MINOR', 0)}\n"
        f"- gated needing your decision: {data['summary'].get('gated_actionable', 0)}\n\n"
        f"See `FINDINGS.md` for the current report and `proposals/` for anything the "
        f"writer was not allowed to change on its own.\n")

    if use_git:
        commit(cfg, f"paperloop: {outcome} after {rounds_done} round(s)")
        if args.push:
            p = subprocess.run(["git", "push", "-u", "origin", branch],
                               cwd=cfg.root, capture_output=True, text=True)
            say("pushed" if p.returncode == 0 else f"push failed: {p.stderr.strip()[:300]}")
            if args.pr and p.returncode == 0:
                title = f"paperloop: {outcome} — {cfg.venue.get('name')} compliance round"
                body = summary_md.read_text()
                pr = subprocess.run(
                    ["gh", "pr", "create", "--title", title, "--body", body,
                     "--base", base_branch or "main", "--head", branch],
                    cwd=cfg.root, capture_output=True, text=True)
                if pr.returncode == 0:
                    say(f"opened PR: {pr.stdout.strip()}")
                else:
                    say(f"PR not opened ({pr.stderr.strip()[:200]}). "
                        f"Run: gh pr create --head {branch}")

    return {"converged": 0, "gates-only": 0, "gated": 2, "stalled": 1,
            "broken": 3, "exhausted": 1, "no-fixer": 1}.get(outcome, 1)


if __name__ == "__main__":
    raise SystemExit(main())
