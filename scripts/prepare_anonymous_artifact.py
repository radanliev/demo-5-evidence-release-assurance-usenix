#!/usr/bin/env python3
"""
USENIX Security 2027 Anonymous Artifact Packager for EviAssure.

Packages repository artifacts into a clean, metadata-stripped archive
`eviassure_usenix27_artifact.zip` for double-blind peer review.
"""

import sys
import os
import re
import zipfile
import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_ZIP = REPO_ROOT / "eviassure_usenix27_artifact.zip"

# Author-identifying terms live OUTSIDE this file, in `.anonymity-terms`, which
# is not in INCLUDED_PATHS and therefore never ships. scripts/ *is* packaged, so
# a hard-coded list of surnames here would be exactly the leak the scan exists
# to prevent.
TERMS_FILE = REPO_ROOT / ".anonymity-terms"

# Structural patterns that identify a person or machine without naming anyone,
# so they are safe to keep in a shipped file. The home-directory case is not
# hypothetical: a hard-coded macOS site-packages path in
# scripts/generate_paper_pdf.py shipped in an earlier build of this artifact.
# (Written as regexes below rather than spelled out in prose, so this file does
# not trip its own scan.)
STRUCTURAL_PATTERNS = [
    (r"/Users/[A-Za-z0-9._-]+", "absolute macOS home path (contains a username)"),
    (r"/home/(?!runner\b)[A-Za-z0-9._-]+", "absolute Linux home path (contains a username)"),
    (r"[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+", "absolute Windows home path (contains a username)"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email address"),
    (r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b", "ORCID identifier"),
]

# Matches that are known-safe. Kept deliberately short: every entry is a hole in
# the scan, so each one needs a reason.
ALLOWED_SUBSTRINGS = [
    "anonymous@example.invalid",   # the anonymous commit identity itself
    "noreply@",                    # generic no-reply senders
    "@example.com",                # RFC 2606 documentation domain
    "@example.invalid",
    "user@host",                   # placeholder in docs
]

SCANNABLE_EXTS = {".py", ".md", ".txt", ".tex", ".bib", ".json", ".yaml", ".yml",
                  ".toml", ".sh", ".cfg", ".ini", ".rego", ".html", ".csv", ""}


def load_terms():
    """Read the forbidden-term list. Fails closed: no list, no artifact."""
    if not TERMS_FILE.exists():
        print(f"[FATAL] {TERMS_FILE.name} is missing. Refusing to package an "
              f"artifact that cannot be checked for author-identifying strings.\n"
              f"        Recreate it (one term per line) before packaging.")
        sys.exit(2)
    terms = []
    for line in TERMS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            terms.append(line.lower())
    if not terms:
        print(f"[FATAL] {TERMS_FILE.name} contains no terms. Refusing to package.")
        sys.exit(2)
    return terms


def scan_for_identifying_strings(files, terms):
    """Scan every file destined for the archive. Returns a list of findings.

    The CFP places the burden squarely on authors: 'Authors are solely
    responsible for ensuring no identifying information is exposed (e.g.,
    usernames, organization names, commit history).' A packager that cannot
    fail is not a control, so this one aborts the build rather than warning.
    """
    findings = []
    compiled = [(re.compile(p), why) for p, why in STRUCTURAL_PATTERNS]

    for abs_path, rel in files:
        if abs_path.suffix.lower() not in SCANNABLE_EXTS:
            continue
        try:
            text = abs_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue   # binary or unreadable: nothing to match on

        for lineno, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            for term in terms:
                if term in lowered:
                    findings.append((rel, lineno, f"forbidden term {term!r}", line.strip()))
            for rx, why in compiled:
                for m in rx.finditer(line):
                    hit = m.group(0)
                    if any(a.lower() in hit.lower() for a in ALLOWED_SUBSTRINGS):
                        continue
                    findings.append((rel, lineno, f"{why}: {hit!r}", line.strip()))
    return findings

# NOTE (2026-08-17): `benchmark` and `results` were missing, so the packaged
# artifact could not even be collected by pytest -- every test module that
# imports benchmark.* errored at import, and the docs/corpus consistency tests
# had no results/*.json to check against. An Artifact Evaluation Committee
# reviewer unpacking the zip into a fresh virtualenv hit ModuleNotFoundError on
# the first command in REPRODUCE.md. Verified fixed by extracting the zip into
# a clean venv and running the suite.
INCLUDED_PATHS = [
    "assurance",
    "benchmark",
    "governance",
    "corpus",
    "results",
    "specimens",
    "scripts",
    "tests",
    "README.md",
    "REPRODUCE.md",
    "reproduce.sh",
    "pyproject.toml",
    "Makefile",
    "docs/security_metrics.tex",
    "docs/frozen_metrics.tex",
    "docs/references.bib",
    # The GitHub Action the paper describes (Sec. CI/CD Integration) and the
    # workflow that runs the suite. CODEOWNERS and the PR template are NOT
    # shipped: they are repository process files, not artifact, and one of
    # them names accounts.
    ".github/actions/evidence-release-gate/action.yml",
    ".github/workflows/ci.yml",
    # DELIBERATELY NOT SHIPPED: docs/artifact_digest.tex.
    # That file holds the SHA-256 of this very archive. Including it makes the
    # build non-idempotent -- each run embeds the previous run's digest, which
    # changes the archive, which changes the digest, forever. The paper would
    # then quote a digest that only matched for exactly one build, and any AEC
    # reviewer who re-ran the packager and compared hashes would see a mismatch
    # in a paper whose subject is verifiable evidence. Excluding it makes the
    # archive a pure function of the source, so the quoted digest is stable and
    # independently checkable.
    # DELIBERATELY NOT SHIPPED: docs/usenix_paper_manuscript.tex.
    # The manuscript source carries the camera-ready author block inside the
    # \ifanonymous \else branch, so packaging it would hand every reviewer the
    # author list -- the exact deanonymisation the CFP says may cause rejection
    # without review. Only the generated macro files and the bibliography ship;
    # the consistency tests that read the manuscript skip when it is absent.
]

EXCLUDED_EXTS = {".pyc", ".DS_Store", ".pdf", ".png"}
EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".git", ".paperloop"}


def collect_files():
    """Resolve INCLUDED_PATHS into the concrete (absolute, relative) file list
    that will be archived. Separated from writing so the contents can be
    scanned before anything is committed to a zip."""
    collected = []
    missing = []
    for rel_path in INCLUDED_PATHS:
        abs_path = REPO_ROOT / rel_path
        if not abs_path.exists():
            missing.append(rel_path)
            continue

        if abs_path.is_file():
            collected.append((abs_path, Path(rel_path)))
        elif abs_path.is_dir():
            for root, dirs, files in os.walk(abs_path):
                dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
                for f in sorted(files):
                    if os.path.splitext(f)[1] in EXCLUDED_EXTS:
                        continue
                    full_f = Path(root) / f
                    collected.append((full_f, full_f.relative_to(REPO_ROOT)))
    # os.walk does not guarantee a stable directory order across filesystems,
    # and member order changes the zip bytes. Sort so the digest is a function
    # of content alone.
    collected.sort(key=lambda pair: str(pair[1]))
    return collected, missing


def refuse_modeled_baselines(allow_modeled: bool) -> None:
    """The paper's comparison text describes the DSSE and TUF baselines as
    executed and the OPA baseline as executed when the binary is present. The
    results file records what actually ran. Refuse to package a results file in
    which a baseline the paper calls executed recorded itself as modeled --
    that is exactly the silent substitution `run_security_eval.py
    --require-executed` exists to prevent, and packaging is the last place it
    can be caught. Override only for a local dry run, never for the upload."""
    sec = REPO_ROOT / "results" / "security_evaluation.json"
    if not sec.exists():
        print("[FATAL] results/security_evaluation.json is missing; run scripts/run_security_eval.py")
        sys.exit(3)
    import json
    modes = json.loads(sec.read_text()).get("baseline_execution", {})
    bad = {k: v for k, v in modes.items()
           if ("TUF" in k or "DSSE" in k or "OPA" in k or "Composed" in k) and "modeled" in v}
    if bad and not allow_modeled:
        print("[FATAL] results/security_evaluation.json records a modeled baseline that the")
        print("        manuscript describes as executed. Install python-tuf and the opa binary,")
        print("        re-run  python3 scripts/run_security_eval.py --require-executed  and")
        print("        python3 scripts/write_security_macros.py, then package again.")
        for k, v in bad.items():
            print(f"          - {k}: {v}")
        print("        (--allow-modeled packages anyway, for a local dry run only.)")
        sys.exit(4)
    if bad:
        print(f"[!] --allow-modeled: packaging with {len(bad)} modeled baseline label(s); DO NOT upload this zip.")


def create_anonymous_archive(allow_modeled: bool = False):
    print("=== USENIX Security 2027 Anonymous Artifact Packager ===")

    refuse_modeled_baselines(allow_modeled)
    files, missing = collect_files()

    # A silently-missing path is how the previous build shipped an artifact
    # that could not even be collected by pytest. Treat it as fatal, not as a
    # warning nobody reads.
    if missing:
        print("[FATAL] These declared paths do not exist:")
        for m in missing:
            print(f"          - {m}")
        print("        Fix INCLUDED_PATHS or restore the files. No archive written.")
        sys.exit(2)

    print(f"[*] {len(files)} files selected. Scanning for identifying strings...")
    findings = scan_for_identifying_strings(files, load_terms())
    if findings:
        print(f"\n[FATAL] Anonymity scan found {len(findings)} issue(s). "
              f"NO ARCHIVE WAS WRITTEN.\n")
        for rel, lineno, why, line in findings:
            snippet = line if len(line) <= 120 else line[:117] + "..."
            print(f"  {rel}:{lineno}: {why}")
            print(f"      {snippet}")
        print("\n  Fix each finding, or -- only if a match is genuinely benign --")
        print("  add it to ALLOWED_SUBSTRINGS with a comment saying why.")
        sys.exit(1)
    print("[+] Anonymity scan clean.")

    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()

    # Fixed member timestamps and permissions. A zip records each file's mtime,
    # so building from two clean checkouts of identical source would otherwise
    # yield different digests -- which would make the digest printed in the
    # paper unverifiable by anyone but the author who built it.
    FIXED_TIME = (1980, 1, 1, 0, 0, 0)

    with zipfile.ZipFile(OUTPUT_ZIP, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for abs_path, rel in files:
            arcname = os.path.join("eviassure_artifact", str(rel))
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zipf.writestr(info, abs_path.read_bytes())
            print(f" [+] Added file: {rel}")

    # Compute SHA-256 digest of artifact
    hasher = hashlib.sha256()
    with open(OUTPUT_ZIP, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            
    digest = hasher.hexdigest()
    size_kb = OUTPUT_ZIP.stat().st_size / 1024.0
    print(f"\n[SUCCESS] Anonymous review artifact created: {OUTPUT_ZIP.name}")
    print(f"          Size: {size_kb:.2f} KB")
    print(f"          SHA-256 Digest: {digest}")
    
    # Save digest file for LaTeX referencing
    digest_file = REPO_ROOT / "docs" / "artifact_digest.tex"
    digest_file.write_text(
        f"% GENERATED by scripts/prepare_anonymous_artifact.py\n"
        f"\\newcommand{{\\artifactShaTwoFiveSix}}{{{digest}}}\n"
        f"\\newcommand{{\\artifactShaPartOne}}{{{digest[:32]}}}\n"
        f"\\newcommand{{\\artifactShaPartTwo}}{{{digest[32:]}}}\n"
        f"\\newcommand{{\\artifactShaDigest}}{{{digest[:16]}...}}\n"
        f"\\newcommand{{\\artifactSizeKb}}{{{size_kb:.1f}}}\n"
    )
    return digest


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Package the anonymous review artifact.")
    ap.add_argument("--allow-modeled", action="store_true",
                    help="package even if results/ records a modeled DSSE/TUF/OPA baseline "
                         "(local dry run only; never for the upload)")
    args = ap.parse_args()
    create_anonymous_archive(allow_modeled=args.allow_modeled)
