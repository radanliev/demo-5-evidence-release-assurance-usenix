"""Find an agent CLI on PATH and invoke it non-interactively.

The whole point of the loop is that it runs without someone approving each step.
That means the writer CLI must be launched in a mode where it does not stop to
ask. Every entry below is the documented headless invocation for that tool.

Detection order is preference order. Override with $PAPERLOOP_FIXER or
`fixer.command` in config.yaml, which always win.
"""
from __future__ import annotations

import os
import shutil

# autonomy levels:
#   "edits" - auto-accept file edits, may still ask before shell commands
#   "full"  - ask for nothing (needed for genuinely unattended overnight runs)
FIXERS = [
    dict(name="claude", bin="claude",
         edits='claude -p --permission-mode acceptEdits',
         full='claude -p --dangerously-skip-permissions',
         note="Claude Code"),
    dict(name="cursor", bin="cursor-agent",
         edits='cursor-agent -p --output-format text',
         full='cursor-agent -p --force --output-format text',
         note="Cursor CLI"),
    dict(name="codex", bin="codex",
         edits='codex exec -',
         full='codex exec --dangerously-bypass-approvals-and-sandbox -',
         note="OpenAI Codex CLI"),
    dict(name="gemini", bin="gemini",
         edits='gemini -p',
         full='gemini -p --yolo',
         note="Gemini CLI / Antigravity"),
    dict(name="opencode", bin="opencode",
         edits='opencode run',
         full='opencode run',
         note="OpenCode"),
    dict(name="crush", bin="crush",
         edits='crush run -q',
         full='crush run -q -y',
         note="Charm Crush"),
    dict(name="aider", bin="aider",
         edits='aider --yes --no-auto-commits --message-file {prompt_file}',
         full='aider --yes --no-auto-commits --message-file {prompt_file}',
         note="Aider"),
    dict(name="kimi", bin="kimi",
         edits='kimi -p',
         full='kimi -p --yolo',
         note="Kimi CLI"),
]


def available() -> list[dict]:
    return [f for f in FIXERS if shutil.which(f["bin"])]


def resolve(configured: str | None, autonomy: str = "edits") -> tuple[str | None, str]:
    """Return (command, how_it_was_chosen)."""
    env = os.environ.get("PAPERLOOP_FIXER")
    if env:
        return env, "$PAPERLOOP_FIXER"
    if configured:
        return configured, "fixer.command in config.yaml"
    found = available()
    if not found:
        return None, ("no agent CLI found on PATH — install one, or set "
                      "$PAPERLOOP_FIXER / fixer.command")
    pick = found[0]
    key = "full" if autonomy == "full" else "edits"
    others = ", ".join(f["name"] for f in found[1:])
    how = f"auto-detected {pick['note']} ({pick['name']})"
    if others:
        how += f"; also available: {others}"
    return pick[key], how


def describe() -> str:
    found = available()
    if not found:
        return "no supported agent CLI found on PATH"
    return "detected: " + ", ".join(f"{f['note']} (`{f['bin']}`)" for f in found)


if __name__ == "__main__":
    print(describe())
    cmd, how = resolve(None)
    print(f"\nwould run: {cmd}\n     via: {how}")
