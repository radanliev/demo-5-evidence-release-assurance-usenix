# demo-5-evidence-release-assurance-usenix

See `AGENTS.md` for the self-correcting review loop — it is the single source of truth and every tool reads the same one.

Sub-agents live in `.claude/agents/`. Start with `loop-orchestrator`.

Quick check before any manuscript edit:

```bash
python3 .paperloop/run_gates.py --build
```

Never edit a number to make a gate pass. Science findings are gated on purpose — see `AGENTS.md`.
