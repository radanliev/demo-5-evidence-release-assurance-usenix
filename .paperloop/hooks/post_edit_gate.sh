#!/usr/bin/env bash
# PostToolUse hook: re-measure the paper the moment it is edited.
#
# Claude Code pipes the tool-call JSON on stdin and feeds whatever this prints
# back to the model. So the writer agent finds out immediately whether an edit
# helped or hurt, instead of at the end of the round.
#
# Deliberately does not rebuild the PDF — a full LaTeX run on every edit would
# make the session unusable. Source-level checks only; the loop rebuilds.

cd "$(dirname "$0")/../.." 2>/dev/null || exit 0
cat > /dev/null   # drain stdin

[ -f .paperloop/run_gates.py ] || exit 0

timeout 90 python3 .paperloop/run_gates.py . --quiet >/dev/null 2>&1
[ -f .paperloop/state/findings.json ] || exit 0

python3 - <<'PY'
import json, pathlib
p = pathlib.Path(".paperloop/state/findings.json")
try:
    d = json.loads(p.read_text())
except Exception:
    raise SystemExit(0)

s = d["summary"]["by_severity"]
gated = d["summary"].get("gated_actionable", 0)
b, m = s.get("BLOCKER", 0), s.get("MAJOR", 0)

prev_p = pathlib.Path(".paperloop/state/.last_counts.json")
prev = {}
if prev_p.exists():
    try:
        prev = json.loads(prev_p.read_text())
    except Exception:
        pass
prev_p.write_text(json.dumps({"BLOCKER": b, "MAJOR": m}))

delta = ""
if prev:
    db = b - prev.get("BLOCKER", b)
    dm = m - prev.get("MAJOR", m)
    if db or dm:
        parts = []
        if db: parts.append(f"BLOCKER {db:+d}")
        if dm: parts.append(f"MAJOR {dm:+d}")
        delta = "  (" + ", ".join(parts) + " since your last edit)"

if b or m:
    print(f"[paperloop] BLOCKER {b}, MAJOR {m}, gated {gated}.{delta} "
          f"Full report: .paperloop/state/FINDINGS.md")
    if gated:
        print("[paperloop] Gated findings touch numbers or claims — propose in "
              ".paperloop/state/proposals/, do not edit them.")
else:
    print(f"[paperloop] source-level gates clean.{delta} "
          f"Rebuild the PDF to confirm layout and page count.")
PY
exit 0
