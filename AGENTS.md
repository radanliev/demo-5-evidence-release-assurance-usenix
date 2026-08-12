# demo-5-evidence-release-assurance-usenix — self-correcting review loop

Target venue: **USENIX Security 2027**
Manuscript: `docs/usenix_paper_manuscript.tex`

## One command

```bash
python3 .paperloop/loop.py --forever --push --pr
```

Each round: **measure → evaluate + analyze → write**. Deterministic gates, then a
read-only reviewer and a separate read-only analytical auditor run in parallel,
then the writer receives both reports. The reviewer rotates every round (venue
compliance, science, adversarial peer review, literature) so no single blind spot
persists. Works on `paperloop/autofix`, commits each round, opens a PR.

It does not stop when it gets stuck. A stall rotates to a different reviewer and
re-frames the work order. A science finding is parked for you while the loop
carries on with everything else. Only a build it cannot compile takes it out of
the rotation. Use `--rounds 6` instead of `--forever` for a bounded run.

**You do not approve each round.** The loop finds an agent CLI on PATH and launches
it in headless mode. Check what it detected:

```bash
python3 .paperloop/loop.py --list-fixers
```

For a run you walk away from, `--autonomy full` stops the writer pausing before
shell commands. All five repos at once, from the folder above them:

```bash
python3 paperloop-all.py --autonomy full --push --pr      # one pass
python3 paperloop-all.py --watch 30 --autonomy full       # forever, every 30 min
```

## Just measure, don't change anything

```bash
python3 .paperloop/run_gates.py --build --render
```

Writes `.paperloop/state/FINDINGS.md` (read this), `findings.json` (for agents), and
page renders in `.paperloop/state/pages/` for visual inspection.

Exit codes: `0` clean · `1` fixable findings · `2` gated, needs a human · `3` build broken.

## Wiring up whichever tool you are in

Auto-detection covers Claude Code, Cursor, Codex, Gemini/Antigravity, OpenCode,
Crush, Aider and Kimi, each launched in its own headless mode. To pin one:

```bash
export PAPERLOOP_FIXER='claude -p --dangerously-skip-permissions'
export PAPERLOOP_FIXER='cursor-agent -p --force --output-format text'
export PAPERLOOP_FIXER='codex exec --dangerously-bypass-approvals-and-sandbox -'
export PAPERLOOP_FIXER='<your cli> --prompt-file {prompt_file}'   # anything else
```

Precedence is `$PAPERLOOP_FIXER` → `fixer.command` → auto-detection.

In a chat UI with no CLI (ChatGPT, Kimi web, Claude desktop), run:

```bash
python3 .paperloop/loop.py --gates-only --render
```

then paste `.paperloop/state/WORK_ORDER.md` into the chat. It is written as a
complete, self-contained instruction — mandate, prohibitions, and findings.

## The agents

| Agent | Access | Job |
|---|---|---|
| `venue-compliance-auditor` | read | USENIX Security 2027 rules the gate can't measure: figure legibility, caption quality, live CFP |
| `science-auditor` | read | claim ledger, re-derives headline numbers, statistics, reproduction |
| `paper-evaluator` | read | adversarial peer review, the reviewer you don't want |
| `analytical-auditor` | read + analytical tools | independently recomputes results, checks statistics, and requests missing data |
| `literature-venue-verifier` | read | citations, novelty, missing seminal work, official venue requirements |
| `paper-writer` | **write** | applies the auto-fix mandate; proposes, never applies, on science |
| `loop-orchestrator` | write | drives rounds, decides when to stop and when to escalate |

Same definitions in `.cursor/agents/`, `.claude/agents/`, and `AGENTS.md`, so Cursor,
Claude Code, Codex, Antigravity, Kimi, Zed and the rest all run the same loop.

Copy/paste prompts and the full handoff contract are in
`docs/AGENT_WORKFLOW.md`.

## Skills

`.claude/skills/` holds the domain knowledge the agents load on demand:

- `claim-evidence-ledger`
- `security-eval-statistics`
- `threat-model-rigor`
- `benchmark-contamination-audit`
- `reproducibility-artifact`
- `usenix-sec-2027-compliance`

The venue skill records what the official CFP said and when it was checked.
Conference rules move between years — when they do, correct the skill and
`venue.yaml` together.

## The one rule that matters

Formatting is fixed automatically. **Science is not.** A wrong number, a stale
result, an unsupported claim — the writer drafts a proposal in
`.paperloop/state/proposals/` for you to decide on, while the loop keeps working on
everything else. Nothing edits a number to make a check go green, because a gate you
can silence that way is not a gate.

## Tuning

`.paperloop/venue.yaml` holds the venue rules — page limit, margins, fonts, required
sections, anonymity, statistical tolerances. Year-specific limits are marked
`verified: false`; `literature-venue-verifier` confirms them against the live CFP and
corrects the file. Correcting `venue.yaml` because it was wrong is fine; relaxing it
to make a failing paper pass is not.
