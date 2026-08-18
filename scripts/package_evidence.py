#!/usr/bin/env python3
"""
Cryptographic Evidence Packaging Helper for USENIX Security Release Assurance.

Packages a witnessed, signed evidence bundle for one release evaluation and
writes, beside it, the release request the gate reads to learn WHICH session it
is adjudicating. In this demo the packager plays both the collector and the
orchestrator; in a deployment the orchestrator (the trusted CI controller)
issues the session credential before the run and hands the session identifier
to the gate out of band, and the collector never sees the orchestrator key.
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.evidence import create_evidence_pack, DEFAULT_SECRET_KEY
from assurance.witness import issue_session_credential


def main():
    parser = argparse.ArgumentParser(description="Package and sign cryptographic evidence bundle.")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--secret-key", type=str, default=DEFAULT_SECRET_KEY, help="HMAC secret key")
    parser.add_argument("--pass-pct", type=float, default=100.0, help="Test pass percentage")
    parser.add_argument("--drift", type=int, default=0, help="Unresolved drift findings count")
    parser.add_argument("--unsigned", action="store_true", help="Generate unsigned evidence pack")
    parser.add_argument("--unwitnessed", action="store_true",
                        help="Generate a bundle with no witness attestations (the shipped "
                             "policy BLOCKS such bundles; useful only for demonstrating that)")
    parser.add_argument("--release-id", type=str, default="release-demo",
                        help="Release identifier the session credential is bound to")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output display format")
    args = parser.parse_args()

    credential = None if args.unwitnessed else issue_session_credential(args.release_id)

    bundle = create_evidence_pack(
        test_pass_pct=args.pass_pct,
        unresolved_drift=args.drift,
        secret_key=args.secret_key,
        signed=not args.unsigned,
        witnessed=not args.unwitnessed,
        release_id=args.release_id,
        session_credential=credential,
    )

    pack_dict = bundle.to_dict()
    release_request = None
    if credential is not None:
        release_request = {"release_id": args.release_id,
                           "session_id": credential.session_id,
                           "credential": credential.to_dict()}

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, 'w', encoding='utf-8') as f:
            json.dump(pack_dict, f, indent=2)
        print(f"[*] Sealed evidence bundle written to: {args.output}")
        if release_request is not None:
            rr_p = Path(str(out_p) + ".release_request.json")
            with open(rr_p, 'w', encoding='utf-8') as f:
                json.dump(release_request, f, indent=2)
            print(f"[*] Release request (expected session) written to: {rr_p}")

    if args.format == "json":
        print(json.dumps(pack_dict, indent=2))
    else:
        print("=== Cryptographic Evidence Bundle Summary ===")
        print(f"Evidence ID: {bundle.evidence_id}")
        print(f"Timestamp:   {bundle.timestamp}")
        print(f"Merkle Root: {bundle.merkle_root[:16]}...")
        print(f"Traces:      {bundle.execution_traces_count}")
        print(f"Session:     {bundle.session_id}")
        print(f"Receipts:    {len(bundle.witness_receipts)}  Closings: {len(bundle.witness_closings)}")
        print(f"Pass Pct:    {bundle.test_pass_pct}%")
        print(f"Drift Count: {bundle.unresolved_drift}")
        print(f"Signed:      {bundle.signed}")
        if bundle.signature:
            print(f"Signature:   {bundle.signature[:16]}...")


if __name__ == "__main__":
    main()
