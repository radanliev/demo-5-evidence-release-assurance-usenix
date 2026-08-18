"""
Cryptographic primitives, Ed25519 asymmetric signing, Merkle tree engine, and SLSA/in-toto attestation formatters.
"""

import hmac
import hashlib
import json
import base64
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def hash_sha256(data: str | bytes) -> str:
    """Compute SHA-256 digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: Dict[str, Any]) -> str:
    """Produce deterministic, key-sorted JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def detect_duplicate_json_keys(wire_json: str) -> List[str]:
    """Return the list of object keys that occur more than once in a raw JSON
    wire document.

    Duplicate keys are a parser-dependent malleability vector: `json.loads`
    keeps the LAST occurrence while other parsers keep the FIRST, so the same
    signed bytes can evaluate to different values depending on the reader. The
    ingestion boundary rejects such documents outright (2026-08 adversarial
    review, N5)."""
    duplicates: set[str] = set()

    def _pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        # Count occurrences WITHIN THIS OBJECT ONLY.
        #
        # The previous implementation accumulated key counts into one global
        # dict across every object in the document, so any key appearing in two
        # sibling objects -- e.g. "trace_id" in each element of `traces` --
        # registered as a duplicate. The check was latent because
        # `raw_wire_json` is normally absent, but the moment an operator
        # supplied the wire text (the only configuration in which the V10
        # defence does anything at all) every legitimate multi-trace bundle was
        # rejected as non-canonical. Found by the differential wire-fuzzing
        # campaign added on 2026-08-17.
        local: Dict[str, int] = {}
        for key, _value in pairs:
            local[key] = local.get(key, 0) + 1
        duplicates.update(k for k, c in local.items() if c > 1)
        return dict(pairs)

    try:
        json.loads(wire_json, object_pairs_hook=_pairs_hook)
    except json.JSONDecodeError:
        return ["<unparseable-json>"]

    return sorted(duplicates)


# --- Merkle Tree Engine ---

# --- RFC 6962 domain separation -------------------------------------------
# Leaves and internal nodes are hashed under DIFFERENT prefixes so that no
# internal node digest can ever be reinterpreted as a leaf digest, and vice
# versa. The previous construction hashed both as bare SHA-256 over an ASCII
# string ("L:R" for internal nodes) and relied on the two input languages
# happening not to overlap; that is not domain separation, it is luck. See
# RFC 6962 (Laurie et al.) Sec 2.1, and the 2026-08-17 adversarial review, C1.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

MERKLE_DOMAIN_VERSION = "rfc6962-style/v1"


def merkle_leaf_digest(leaf_content: str | bytes) -> str:
    """Digest of a Merkle LEAF: SHA-256(0x00 || content)."""
    if isinstance(leaf_content, str):
        leaf_content = leaf_content.encode("utf-8")
    return hashlib.sha256(LEAF_PREFIX + leaf_content).hexdigest()


def merkle_node_digest(left_hex: str, right_hex: str) -> str:
    """Digest of an INTERNAL node: SHA-256(0x01 || left || right).

    ``left_hex``/``right_hex`` are the 64-character hex digests of the two
    children; they are hashed as raw bytes, so the node preimage has a fixed
    65-byte length and cannot be confused with a leaf preimage.
    """
    if len(left_hex) != 64 or len(right_hex) != 64:
        raise ValueError("Merkle node children must be 64-char hex SHA-256 digests")
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def build_merkle_tree(leaf_digests: List[str]) -> Tuple[str, List[List[str]]]:
    """Build a domain-separated SHA-256 Merkle tree over *leaf digests*.

    Every element of ``leaf_digests`` MUST already be a 64-char hex digest
    produced by :func:`merkle_leaf_digest`. The previous implementation
    accepted arbitrary strings and decided whether to hash them with the
    heuristic ``len(x) != 64``, which meant any 64-character string was
    silently adopted as a leaf digest (2026-08-17 adversarial review, C2).
    Callers now state their intent explicitly.
    """
    if not leaf_digests:
        empty_root = merkle_leaf_digest("EMPTY_TREE")
        return empty_root, [[empty_root]]

    for d in leaf_digests:
        if len(d) != 64 or any(c not in "0123456789abcdefABCDEF" for c in d):
            raise ValueError(
                "build_merkle_tree expects hex SHA-256 leaf digests; "
                "use merkle_leaf_digest() on raw leaf content first"
            )

    current_level = list(leaf_digests)
    levels = [current_level]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(merkle_node_digest(left, right))
        levels.append(next_level)
        current_level = next_level

    return current_level[0], levels


def generate_merkle_proof(index: int, levels: List[List[str]]) -> List[Dict[str, str]]:
    """Generate inclusion proof path for a leaf at index."""
    proof = []
    curr_idx = index
    for level in levels[:-1]:
        is_right = (curr_idx % 2 == 1)
        sibling_idx = curr_idx - 1 if is_right else curr_idx + 1
        if sibling_idx < len(level):
            sibling_hash = level[sibling_idx]
        else:
            sibling_hash = level[curr_idx]

        proof.append({
            "position": "left" if is_right else "right",
            "hash": sibling_hash
        })
        curr_idx //= 2
    return proof


def expected_tree_depth(n_leaves: int) -> int:
    """Proof path length for a tree over n_leaves (the committed geometry).

    Without binding the proof to this length, an internal node digest can be
    presented as a leaf with a shortened path (the inner-node/leaf ambiguity
    of CVE-2017-12842; the odd-node duplication of build_merkle_tree is the
    CVE-2012-2459 pattern, disambiguated by the signed leaf count) - a forgery
    that needs no hash collision.
    Third-party auditors MUST pass expected_depth, derived from the signed
    execution_traces_count, alongside the root.
    """
    if n_leaves < 1:
        return 0
    return (n_leaves - 1).bit_length()


def verify_merkle_proof(leaf_digest: str, proof: List[Dict[str, str]], expected_root: str,
                        expected_depth: int) -> bool:
    """Verify a Merkle inclusion proof against a root of *committed* geometry.

    ``expected_depth`` is REQUIRED (2026-08-17 adversarial review, C2). It was
    previously optional, which meant the obvious call --
    ``verify_merkle_proof(leaf, proof, root)`` -- silently selected the unsound
    behaviour: an internal node digest presented with a shortened path verified
    without any hash collision. Third-party auditors derive the depth from the
    signed ``execution_traces_count`` via :func:`expected_tree_depth`.

    Domain separation (leaf 0x00 / node 0x01) additionally makes internal-node
    substitution impossible even at the correct depth, so the two defences are
    independent.
    """
    if not isinstance(expected_depth, int) or expected_depth < 0:
        return False
    if len(proof) != expected_depth:
        return False
    if len(leaf_digest) != 64:
        return False
    current = leaf_digest
    for step in proof:
        sibling = step["hash"]
        try:
            if step["position"] == "right":
                current = merkle_node_digest(current, sibling)
            elif step["position"] == "left":
                current = merkle_node_digest(sibling, current)
            else:
                return False
        except (ValueError, KeyError, TypeError):
            return False
    return hmac.compare_digest(current, expected_root)


# --- HMAC-SHA256 Cryptography ---

def sign_payload_hmac(payload: Dict[str, Any], secret_key: str) -> str:
    """Sign payload dictionary with HMAC-SHA256."""
    canonical_str = canonical_json(payload)
    return hmac.new(
        secret_key.encode('utf-8'),
        canonical_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_signature_hmac(payload: Dict[str, Any], signature: str, secret_key: str) -> bool:
    """Verify payload signature against HMAC-SHA256 key."""
    expected_sig = sign_payload_hmac(payload, secret_key)
    return hmac.compare_digest(expected_sig, signature)


# --- Asymmetric Ed25519 Cryptography ---

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, str, str]:
    """
    Generate an Ed25519 private/public keypair.
    Returns: (priv_key_obj, pub_key_obj, pub_key_base64, key_id).
    """
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    key_id = f"KEY-{hash_sha256(pub_bytes)[:12]}"
    
    return priv_key, pub_key, pub_b64, key_id


def compute_key_id(pub_key_b64: str) -> str:
    """Compute key ID digest from base64 raw public key."""
    pub_bytes = base64.b64decode(pub_key_b64.encode('utf-8'))
    return f"KEY-{hash_sha256(pub_bytes)[:12]}"


def sign_payload_ed25519(payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign payload dictionary with Ed25519 private key."""
    canonical_str = canonical_json(payload)
    sig_bytes = private_key.sign(canonical_str.encode('utf-8'))
    return base64.b64encode(sig_bytes).decode('utf-8')


def verify_signature_ed25519(payload: Dict[str, Any], signature_b64: str, pub_key_b64: str) -> bool:
    """Verify Ed25519 signature using base64 public key."""
    try:
        pub_bytes = base64.b64decode(pub_key_b64.encode('utf-8'))
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64.encode('utf-8'))
        canonical_str = canonical_json(payload)
        pub_key.verify(sig_bytes, canonical_str.encode('utf-8'))
        return True
    except Exception:
        return False


# --- SLSA v1.0 / in-toto Attestation Formatting ---

def format_intoto_statement(
    subject_name: str,
    subject_sha256: str,
    predicate_type: str,
    predicate_payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Format an in-toto Statement (v0.1) / SLSA Provenance v1.0 envelope."""
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": subject_sha256
                }
            }
        ],
        "predicateType": predicate_type,
        "predicate": predicate_payload
    }


def format_slsa_provenance(
    builder_id: str,
    build_type: str,
    invocation_params: Dict[str, Any],
    materials: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Format SLSA Provenance v1.0 predicate payload."""
    return {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": invocation_params,
            "internalParameters": {
                "builderId": builder_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "resolvedDependencies": materials
        },
        "runDetails": {
            "builder": {
                "id": builder_id
            },
            "metadata": {
                "invocationId": hash_sha256(f"{builder_id}:{build_type}")[:16]
            }
        }
    }
