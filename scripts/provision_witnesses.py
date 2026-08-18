#!/usr/bin/env python3
"""
Write governance/witness_registry.yaml.

Default: the demo profile -- the three static demo witnesses (auth-gateway,
policy-service, db-gateway) and the demo orchestrator key, whose private halves
are constants in assurance/witness.py so that the packager, the CLI and the
tests agree across processes. This is what the shipped registry contains and
what `python3 scripts/verify_release_gate.py` reconciles against.

--fresh: generate new witness and orchestrator keypairs, write their PUBLIC
halves to the registry and their private halves to a local key file that is
git-ignored (default governance/witness_keys.local.json). This is the shape of
a real deployment: the registry is public and pinned at the gate; the private
keys live with the witnesses and the orchestrator respectively, and never with
the collector.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.crypto import compute_key_id
from assurance.witness import DEMO_WITNESS_SEEDS, demo_witness_registry
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).parent.parent
REGISTRY = ROOT / "governance" / "witness_registry.yaml"

HEADER = """# Witness registry for Witnessed Trace Completeness.
#
# A witness is the component that ACTUALLY SERVES an agent action -- a tool
# endpoint, API gateway, or sandbox syscall broker. It is a separate trust
# domain from the evidence collector: the collector holds a signing key, the
# witnesses do not, and an adversary who owns the collector still cannot forge
# or suppress a witness attestation. `mediates` is the set of action types the
# witness is authoritative for: a trace claiming one of them must carry that
# witness's receipt (fabrication check), and an action outside every witness's
# set is outside the guarantee (the stated boundary).
#
# `orchestrator` is the key under which witnesses verify session credentials.
# Witnesses serve only credentialed requests, so an adversary who owns the
# agent and the collector cannot relabel actions into a session the gate will
# never evaluate (vector O7).
#
# Written by scripts/provision_witnesses.py. The shipped file is the DEMO
# profile (static test-only keys pinned in assurance/witness.py); run
#   python3 scripts/provision_witnesses.py --fresh
# to generate deployment keys.
"""


def fresh_registry(key_file: Path) -> dict:
    orch = ed25519.Ed25519PrivateKey.generate()
    orch_pub = base64.b64encode(orch.public_key().public_bytes_raw()).decode()
    reg = {"orchestrator": {"public_key": orch_pub, "key_id": compute_key_id(orch_pub)},
           "witnesses": {}}
    keys = {"orchestrator_private_key_hex": orch.private_bytes_raw().hex(),
            "witness_private_keys_hex": {}}
    for wid, (_seed, acts) in DEMO_WITNESS_SEEDS.items():
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
        reg["witnesses"][wid] = {"public_key": pub, "key_id": compute_key_id(pub),
                                 "mediates": sorted(acts)}
        keys["witness_private_keys_hex"][wid] = priv.private_bytes_raw().hex()
    key_file.write_text(json.dumps(keys, indent=2))
    print(f"[*] fresh private keys written to {key_file} (keep OUT of the artifact)")
    return reg


def main() -> None:
    ap = argparse.ArgumentParser(description="Provision the witness registry.")
    ap.add_argument("--fresh", action="store_true", help="generate new keypairs instead of the demo profile")
    ap.add_argument("--key-file", type=str, default=str(ROOT / "governance" / "witness_keys.local.json"))
    ap.add_argument("--output", type=str, default=str(REGISTRY))
    args = ap.parse_args()

    reg = fresh_registry(Path(args.key_file)) if args.fresh else demo_witness_registry()
    body = yaml.safe_dump(reg, sort_keys=True, default_flow_style=False)
    Path(args.output).write_text(HEADER + body)
    print(f"[+] {args.output}: {len(reg['witnesses'])} witness(es), "
          f"orchestrator {reg['orchestrator']['key_id']}")


if __name__ == "__main__":
    main()
