"""
Regression tests for the bypasses found by the 2026-08-17 adversarial review
(docs/PEER_REVIEW_2026-08-17.md).

A1 - the shipped verifier CLI never supplied replay state, so the policy
     engine's nonce check was a silent no-op and the same signed bundle was
     APPROVED on every submission.
A2 - `require_trusted_key: False` did not disable Ed25519 verification (as the
     manuscript's ablation narrative claimed); it made the gate verify against
     the public key carried inside the attacker-controlled bundle. Combined
     with a conformant `kms_key_arn` string this was a complete authentication
     bypass, and the 13-vector suite did not detect it.
C2 - `verify_merkle_proof`'s depth bound was optional, so the obvious call
     selected the unsound behaviour.
"""

import json
import subprocess
import sys
from pathlib import Path


from assurance.crypto import generate_ed25519_keypair, sign_payload_ed25519
from assurance.evidence import create_evidence_pack
from assurance.policy import ReleasePolicyEngine, PersistentNonceStore

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "governance" / "release_policy.yaml"

_SIGNED_FIELDS = ("evidence_id", "timestamp", "nonce", "agent_system_version",
                  "test_pass_pct", "unresolved_drift", "execution_traces_count",
                  "merkle_root", "artifact_digests", "session_id", "witness_digest",
                  "sig_alg", "key_id", "kms_key_arn")


def _resign(d, priv):
    d["signature"] = sign_payload_ed25519({k: d.get(k) for k in _SIGNED_FIELDS}, priv)
    return d


# ---------------------------------------------------------------- A1

def test_a1_replay_blocked_through_the_shipped_cli(tmp_path):
    """The exact reproduction from the review: submit one signed bundle three
    times through scripts/verify_release_gate.py. Before the fix all three
    exited 0."""
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    ev = tmp_path / "bundle.json"
    ev.write_text(json.dumps(bundle))
    ledger = tmp_path / "nonces.json"

    codes = []
    for _ in range(3):
        r = subprocess.run(
            [sys.executable, "scripts/verify_release_gate.py",
             "--evidence", str(ev), "--nonce-store", str(ledger), "--format", "json"],
            capture_output=True, text=True, cwd=str(ROOT))
        codes.append(r.returncode)

    assert codes[0] == 0, "first, fresh submission must be APPROVED"
    assert codes[1:] == [1, 1], f"replays must be BLOCKED, got {codes}"


def test_a1_missing_replay_state_fails_closed():
    """Absent replay state is a violation, not a skipped check."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    passed, violations, _ = engine.evaluate(bundle)          # no seen_nonces
    assert passed is False
    assert any("replay protection" in v for v in violations)


def test_a1_replay_state_survives_process_restart(tmp_path):
    """PersistentNonceStore is what makes the CLI's guarantee real in an
    ephemeral runner: a fresh store object over the same file still remembers."""
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    path = tmp_path / "ledger.json"

    ok, _, _ = engine.evaluate(bundle, seen_nonces=PersistentNonceStore(path))
    assert ok is True
    again, violations, _ = engine.evaluate(bundle, seen_nonces=PersistentNonceStore(path))
    assert again is False
    assert any("Replayed evidence nonce" in v for v in violations)


# ---------------------------------------------------------------- A2

def test_a2_attacker_key_rejected_even_with_registry_disabled():
    """The bypass: attacker keypair + a KMS ARN matching the policy regex.
    Before the fix this returned passed=True with zero violations."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    engine.release_conditions.update({"require_trusted_key": False})

    priv, _, pub_b64, _ = generate_ed25519_keypair()
    d = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    d.update({
        "key_id": "KEY-ATTACKER-NOT-IN-REGISTRY",
        "public_key": pub_b64,
        "kms_key_arn": "kms://aws/arn:aws:kms:us-east-1:000000000000:key/attacker-forged",
        "signatures": [],
    })
    _resign(d, priv)

    passed, violations, _ = engine.evaluate(d, seen_nonces=set())
    assert passed is False, "attacker-supplied key must never authenticate"
    assert any("trusted key registry" in v for v in violations)


def test_a2_empty_registry_collapses_the_gate():
    """The manuscript's ablation sentence is now true of the code: with no
    registry the gate rejects ALL Ed25519 evidence rather than weakening
    selectively."""
    engine = ReleasePolicyEngine.from_yaml(POLICY)
    engine.trusted_keys = {}
    honest = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    passed, violations, _ = engine.evaluate(honest, seen_nonces=set())
    assert passed is False
    assert any("No trusted key registry" in v for v in violations)


def test_a2_bundle_supplied_key_is_never_consulted():
    """Structural check: no configuration path reaches verification with a key
    that came out of the bundle."""
    code = "\n".join(
        line.split("#", 1)[0]
        for line in (ROOT / "assurance" / "policy.py").read_text().splitlines()
    )
    assert "pinned_pub or s_pub" not in code, \
        "the bundle-supplied public key fallback must not be reintroduced"


def test_a1b_exit_code_is_set_on_every_output_path(tmp_path):
    """A1b: `--format json` returned 0 on BLOCKED, so any pipeline reading the
    exit status was fail-OPEN in exactly the mode the GitHub Action uses."""
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    bundle["test_pass_pct"] = 12.5                      # guaranteed violation
    ev = tmp_path / "bad.json"
    ev.write_text(json.dumps(bundle))

    for fmt in ("json", "text"):
        r = subprocess.run(
            [sys.executable, "scripts/verify_release_gate.py", "--evidence", str(ev),
             "--nonce-store", str(tmp_path / f"led-{fmt}.json"), "--format", fmt],
            capture_output=True, text=True, cwd=str(ROOT))
        assert r.returncode == 1, f"--format {fmt} must exit 1 on BLOCKED"


def test_duplicate_key_detector_is_per_object():
    """Found by the differential wire-fuzzing campaign: the detector counted
    keys across ALL objects in the document, so sibling objects in the `traces`
    array (each with trace_id, action, ...) registered as duplicates. Any
    operator who actually supplied raw_wire_json -- the only configuration in
    which the V10 defence does anything -- had every multi-trace bundle
    rejected."""
    from assurance.crypto import detect_duplicate_json_keys, canonical_json

    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    assert len(bundle["traces"]) > 1
    wire = canonical_json(bundle)
    assert detect_duplicate_json_keys(wire) == [], \
        "a canonical multi-trace bundle must not be reported as having duplicate keys"

    # and a genuine in-object duplicate is still caught
    assert "test_pass_pct" in detect_duplicate_json_keys(wire[:-1] + ',"test_pass_pct":1.0}')


def test_multi_trace_bundle_with_wire_text_is_approved():
    """The end-to-end consequence of the bug above."""
    from assurance.crypto import canonical_json

    engine = ReleasePolicyEngine.from_yaml(POLICY)
    bundle = create_evidence_pack(use_ed25519=True, signed=True).to_dict()
    bundle["raw_wire_json"] = canonical_json(
        {k: v for k, v in bundle.items() if k != "raw_wire_json"})
    passed, violations, _ = engine.evaluate(bundle, seen_nonces=set())
    assert passed, violations
