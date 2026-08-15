---
name: local-tex-environment
description: This machine's TeX Live basic + multi-Python setup — silent build failures, PEP 668 pip, user-texmf installs, and the PATH additions that fix them
---

# Local TeX / Python Environment

Load before building LaTeX or installing Python packages on this machine
(macOS, TeX Live 2026 **basic** at `/Library/TeX/texbin`, multiple Pythons).

## Python hazard: three interpreters

| Interpreter | Has |
|---|---|
| `python3` → Homebrew 3.14 (`/opt/homebrew/...`) | matplotlib, pdfplumber, cryptography, **and (installed 2026-08-14)** pytest, hypothesis, mutmut, bandit, mypy, habanero, pyalex |
| Framework 3.13 (`/Library/Frameworks/...`) | its own pytest 9.1.1 |
| CI (`.github/workflows/ci.yml`) | Python 3.11 |

Run tests with `python3 -m pytest tests/ -q` so the interpreter matches the
one the benchmarks ran under. If a paper reports a Python version, make the
benchmark artifact record it (`platform` block) instead of trusting prose.

- pip needs `--user --break-system-packages` (PEP 668).
- User scripts land in `~/Library/Python/3.14/bin` — it's on PATH via
  `~/.zshrc` (added 2026-08-14, along with `~/bin` and `~/.local/bin`).

## TeX Live basic: the silent-build-failure trap

`scripts/generate_paper_pdf.py`-style scripts often swallow pdflatex stderr
and print SUCCESS if any old PDF exists. **A missing .sty fails the compile
but not the script** — gates then measure a weeks-stale PDF. After any build:

```bash
stat -f "%Sm %N" docs/*.pdf    # mtime must have moved
grep -c "^!" docs/*.log        # must be 0
```

### Installing packages (no sudo for tlmgr)

`tlmgr` needs admin for the system tree, and `--usermode` refuses
non-relocatable packages (latexmk, chktex, latexdiff all refused). Workarounds
already in place:

- **Single .sty packages** (e.g. `enumitem`): download from
  `https://mirrors.ctan.org/macros/latex/contrib/<pkg>.zip`, copy the `.sty`
  into `~/Library/texmf/tex/latex/<pkg>/`, run `mktexlsr ~/Library/texmf`.
- **Standalone Perl tools**: `latexmk` and `latexdiff*` are CTAN Perl scripts
  installed to `~/bin` (macOS perl is fine).
- **Compiled tools**: `chktex` built from CTAN source into `~/.local`
  (`./configure --prefix=$HOME/.local && make && make install`).

## Useful extras installed

- `pdftoppm` (poppler) — render pages to PNG for visual inspection (the
  agent can Read images; `.paperloop/state/pages/` already holds renders
  after `--render`).
- `latexdiff` — manuscript revision diffs.
- `chktex` — LaTeX lint before builds.
- `yq` — edit `.paperloop/venue.yaml` / `config.yaml` safely.

## LaTeX error patterns seen here

- Unescaped `&` in `\section`/`\textbf` (14 lines of "Misplaced alignment
  tab") — escape as `\&`.
- `\resizebox{\columnwidth}{!}{tabular}` can shrink text below 5pt —
  gate-flagged; prefer `\footnotesize` + shortened cells.
- in-toto/SLSA papers: check `_type` URI against the actual emitted envelope
  before claiming a spec version.
