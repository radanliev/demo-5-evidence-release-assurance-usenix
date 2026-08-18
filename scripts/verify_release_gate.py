#!/usr/bin/env python3
"""
USENIX Security Release Gate Verifier CLI
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.verifier import evaluate_release_gate, load_release_request, DEFAULT_NONCE_STORE
from assurance.evidence import DEFAULT_SECRET_KEY


def main():
    parser = argparse.ArgumentParser(description="Evaluate USENIX Security Fail-Closed Release Gate.")
    parser.add_argument(
        "--policy",
        type=str,
        default=str(Path(__file__).parent.parent / "governance" / "release_policy.yaml"),
        help="Path to policy YAML file"
    )
    parser.add_argument("--evidence", type=str, default=None, help="Path to evidence bundle JSON file")
    parser.add_argument(
        "--release-request", type=str, default=None,
        help="Path to the release request JSON written by the orchestrator when it "
             "opened the evaluation session ({\"release_id\", \"session_id\"}). The "
             "gate binds the bundle to THIS session, never to the session the bundle "
             "declares. Required whenever --evidence is given and the policy requires "
             "witnessed completeness (the shipped default); with no --evidence a "
             "witnessed demo pack is created and its own credential is used."
    )
    parser.add_argument("--secret-key", type=str, default=DEFAULT_SECRET_KEY, help="HMAC secret key")
    parser.add_argument("--output-decision", type=str, default=None, help="Output JSON path for release decision")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument(
        "--nonce-store", type=str, default=DEFAULT_NONCE_STORE,
        help="Path to the persistent nonce ledger backing replay protection. "
             "In ephemeral/multi-tenant runners point this at shared storage. "
             "Replay protection is enforced by default; the gate fails closed "
             "if the ledger is unavailable."
    )
    args = parser.parse_args()

    evidence_dict = None
    if args.evidence:
        with open(args.evidence, 'r', encoding='utf-8') as f:
            evidence_dict = json.load(f)

    release_request = None
    if args.release_request:
        release_request = load_release_request(args.release_request)
    elif args.evidence:
        # Convention: package_evidence.py writes <bundle>.release_request.json
        # beside the bundle. Picked up automatically so the common case needs no
        # extra flag, but never inferred from the bundle itself.
        candidate = Path(str(args.evidence) + ".release_request.json")
        if candidate.exists():
            release_request = load_release_request(candidate)

    res = evaluate_release_gate(
        policy_path=args.policy,
        evidence=evidence_dict,
        secret_key=args.secret_key,
        output_decision_file=args.output_decision,
        nonce_store_path=args.nonce_store,
        release_request=release_request,
    )

    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print("=== USENIX Security Release Gate Evaluation ===")
        print(f"Policy:      {res['policy_name']} [{res.get('policy_profile')}]")
        print(f"Evidence ID: {res['evidence_id']} (Signed: {res['signed']})")
        print(f"Replay state: {res.get('replay_state')}")
        print(f"Witnessed completeness required: {res.get('witnessed_completeness_required')}")
        print(f"Session binding: {res.get('session_binding')}")

        if res["violations"]:
            print("\nPolicy Violations Detected:")
            for v in res["violations"]:
                print(f"  - {v}")
            print()

        print("STATUS: RELEASE APPROVED (Fail-Closed Gate Passed)" if res["passed"]
              else "STATUS: RELEASE BLOCKED (Policy Violation)")

    # A1b (2026-08-17 review): the exit code is the gate's contract with the CI
    # pipeline and MUST be set on every output path. Previously `sys.exit(1)`
    # lived only inside the `text` branch, so `--format json` -- the
    # machine-readable mode the GitHub Action uses -- returned 0 on BLOCKED.
    # Any pipeline consuming the exit status was fail-OPEN.
    sys.exit(0 if res["passed"] else 1)


if __name__ == "__main__":
    main()
