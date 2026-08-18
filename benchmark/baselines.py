"""
Executed comparison baselines for the release-gate evaluation.

The 2026-08-17 adversarial review (finding B1) rejected the previous baseline
set: the "Sigstore/Cosign-style" gate was a one-line presence check on a JSON
field (`signed and signature is not None`) and the "CI exit-code gate" was
`test_pass_pct > 0`. Against a vector suite derived from EviAssure's own check
list, both scored near zero by construction, and the abstract quoted the
resulting 0.0% / 30.8% as if they characterised the state of the art.

This module replaces them with baselines that **execute real verification
libraries** and that are **configured to win** wherever their design genuinely
covers a vector:

  * ``DSSEInTotoBaseline``   -- DSSE v1 Pre-Authentication Encoding plus
    Ed25519 signature verification (``cryptography``) against a pinned trust
    root, i.e. what an in-toto/Sigstore-style deployment actually does. It
    authenticates the signer, so it blocks unsigned payloads, attacker keys,
    revoked keys, and any mutation of the signed payload -- several vectors the
    old presence model waved through. NOTE (2026-08-18): an earlier docstring
    and label said "securesystemslib"; that library is not imported anywhere
    in this module, so the label was false and has been corrected.
  * ``TUFBaseline``          -- Timestamp-role expiry evaluated with
    ``python-tuf``'s own ``Metadata``/``Timestamp`` objects when python-tuf is
    installed, over the DSSE trust-root check for threshold (=1) and
    revocation. TUF has provided freshness, threshold signing and revocation
    since 2010, so it is the honest strong baseline for exactly the properties
    EviAssure claims as deltas. It is *expected* to block the freshness and
    revocation vectors. NOTE (2026-08-18): the ``execution_mode`` label used
    to be a static string that read "executed (python-tuf)" even when
    python-tuf was absent; it now reports what actually ran, and
    ``--require-executed`` fails when python-tuf is missing.
  * ``OPABaseline``          -- unchanged Rego policy, executed by the real
    ``opa`` binary when present. Falls back to a declared model otherwise, and
    ``--require-executed`` turns that fallback into a hard error so a final
    artifact can never silently ship modeled numbers.
  * ``StatusGateBaseline``   -- the unauthenticated exit-code gate, retained
    explicitly as a **lower bound** rather than a competitor, and labelled as
    such in the artifact and the paper.

Every baseline reports ``execution_mode`` so the artifact records precisely what
was executed versus modeled.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_GOVERNANCE = Path(__file__).parent.parent / "governance"

# MUST stay in sync with EvidenceBundle.payload_for_signing. If it drifts, the
# baselines fail to verify honest signatures and "block" everything -- an
# unfair comparison in the opposite direction, which is the same methodological
# error as a strawman. tests/test_witness_completeness.py asserts the two lists
# agree.
_SIGNED_FIELDS = ("evidence_id", "timestamp", "nonce", "agent_system_version",
                  "test_pass_pct", "unresolved_drift", "execution_traces_count",
                  "merkle_root", "artifact_digests", "session_id",
                  "witness_digest", "sig_alg", "key_id", "kms_key_arn")


def _witness_digest(bundle: Dict[str, Any]) -> str:
    from assurance.crypto import canonical_json, hash_sha256
    items = sorted(canonical_json(r) for r in (bundle.get("witness_receipts") or []))
    items += sorted(canonical_json(c) for c in (bundle.get("witness_closings") or []))
    return hash_sha256("|".join(items)) if items else hash_sha256("NO_WITNESS")


def _payload_view(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """The subset of the bundle that EviAssure's signature covers. Baselines
    are given exactly the same bytes so the comparison is like-for-like."""
    view = {k: bundle.get(k) for k in _SIGNED_FIELDS}
    view["witness_digest"] = _witness_digest(bundle)
    return view


# --------------------------------------------------------------------------
# 1. DSSE / in-toto baseline (executed)
# --------------------------------------------------------------------------

class DSSEInTotoBaseline:
    """DSSE v1 PAE + Ed25519 verification against a pinned trust root.

    This is what a competently configured Sigstore/in-toto deployment gives you:
    the envelope is authenticated against a key the *verifier* trusts, not one
    the payload carries. Modelling that as "is there a signature field?" -- as
    the previous baseline did -- understated it by four vectors.

    The PAE is implemented inline (it is one format string) and the signature
    check uses ``cryptography``'s Ed25519; no third-party DSSE library is
    involved, and the label below says so.
    """

    name = "in-toto/DSSE signature verification"
    execution_mode = "executed (DSSE v1 PAE + Ed25519 via cryptography, pinned trust root)"

    PAYLOAD_TYPE = "application/vnd.in-toto+json"

    def __init__(self, trusted_keys: Dict[str, str], revoked: Optional[set] = None):
        self.trusted_keys = dict(trusted_keys)          # key_id -> base64 raw pk
        self.revoked = set(revoked or ())

    @staticmethod
    def pae(payload_type: str, payload: bytes) -> bytes:
        """DSSE Pre-Authentication Encoding (dsse spec v1)."""
        return b"DSSEv1 %d %s %d %s" % (
            len(payload_type), payload_type.encode(), len(payload), payload)

    def verify(self, bundle: Dict[str, Any]) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        sig_b64 = bundle.get("signature")
        key_id = bundle.get("key_id")
        if not bundle.get("signed") or not sig_b64 or not key_id:
            return False
        if key_id in self.revoked:                       # root-driven revocation
            return False
        pk_b64 = self.trusted_keys.get(key_id)           # trust root, not payload
        if not pk_b64:
            return False

        payload = json.dumps(_payload_view(bundle), sort_keys=True,
                             separators=(",", ":")).encode()
        try:
            pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_b64))
            # EviAssure signs the canonical payload directly; a DSSE verifier
            # accepts either the bare payload or the PAE wrapping, so we accept
            # a signature over either encoding. This is deliberately generous:
            # the baseline should not lose a vector on an encoding technicality.
            for msg in (payload, self.pae(self.PAYLOAD_TYPE, payload)):
                try:
                    pk.verify(base64.b64decode(sig_b64), msg)
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False


# --------------------------------------------------------------------------
# 2. TUF baseline (executed)
# --------------------------------------------------------------------------

class TUFBaseline:
    """Real python-tuf Root/Timestamp metadata: expiry, thresholds, revocation.

    TUF is the correct strong baseline for freshness and key governance, and
    omitting it was the single most damaging gap in the previous comparison --
    Samuel et al. (2010) is *cited by this paper* and provides three of the
    properties the paper claims as novel. This baseline is expected to block the
    expiry and revocation vectors; that is the point.
    """

    name = "TUF metadata verification (expiry + threshold + revocation)"

    def __init__(self, trusted_keys: Dict[str, str], revoked: Optional[set] = None,
                 max_age_seconds: int = 3600, require_executed: bool = False):
        self.dsse = DSSEInTotoBaseline(trusted_keys, revoked)
        self.max_age_seconds = max_age_seconds
        self.root_expires = datetime.now(timezone.utc) + timedelta(days=365)
        self._tuf_available = self._probe_tuf()
        if not self._tuf_available and require_executed:
            raise RuntimeError(
                "TUF baseline requested as executed but python-tuf is not "
                "importable. `pip install tuf` (declared in pyproject.toml) or "
                "drop --require-executed (the artifact will then record this "
                "baseline as modeled)."
            )
        # Report what actually ran. This used to be a static class attribute
        # that read "executed (python-tuf)" whether or not python-tuf was
        # installed -- exactly the silent substitution --require-executed
        # exists to prevent.
        self.execution_mode = (
            "executed (python-tuf Timestamp expiry over a DSSE trust-root check; "
            "threshold=1, root-driven revocation)"
            if self._tuf_available else
            "modeled (python-tuf not installed; expiry compared without python-tuf)")

    @staticmethod
    def _probe_tuf() -> bool:
        try:
            import tuf.api.metadata  # noqa: F401
            return True
        except Exception:
            return False

    def _timestamp_role_accepts(self, ts_iso: str) -> bool:
        """TUF's Timestamp role rejects metadata whose `expires` has passed.
        Modelled here on the evidence timestamp with the same window the release
        policy uses, and evaluated with python-tuf's own expiry comparison."""
        try:
            ev = datetime.fromisoformat(ts_iso)
            if ev.tzinfo is None:
                ev = ev.replace(tzinfo=timezone.utc)
        except Exception:
            return False
        expires = ev + timedelta(seconds=self.max_age_seconds)
        now = datetime.now(timezone.utc)
        if self._tuf_available:
            from tuf.api.metadata import Timestamp, MetaFile, Metadata
            md = Metadata(signed=Timestamp(version=1, spec_version="1.0.31",
                                           expires=expires,
                                           snapshot_meta=MetaFile(version=1)))
            if md.signed.is_expired(now):
                return False
        elif expires <= now:
            return False
        # TUF also rejects metadata dated implausibly far in the future via the
        # client's own clock check.
        return ev <= now + timedelta(seconds=30)

    def verify(self, bundle: Dict[str, Any]) -> bool:
        if not self.dsse.verify(bundle):                 # threshold=1 over root keys
            return False
        return self._timestamp_role_accepts(bundle.get("timestamp", ""))


# --------------------------------------------------------------------------
# 3. OPA baseline (executed when the binary is present)
# --------------------------------------------------------------------------

class OPABaseline:
    name = "OPA Rego schema policy"

    def __init__(self, require_executed: bool = False):
        self.binary = shutil.which("opa")
        if self.binary is None and require_executed:
            raise RuntimeError(
                "OPA baseline requested as executed but no `opa` binary is on "
                "PATH. Install OPA or drop --require-executed (the artifact "
                "will then record this baseline as modeled)."
            )
        self.execution_mode = (f"executed: OPA {self._version()}" if self.binary
                               else "modeled (no opa binary on PATH)")

    def _version(self) -> str:
        try:
            out = subprocess.run([self.binary, "version"], capture_output=True,
                                 text=True, timeout=15).stdout
            for line in out.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return "unknown"

    def verify(self, bundle: Dict[str, Any]) -> bool:
        if self.binary is None:
            return (bundle.get("test_pass_pct", 0.0) >= 100.0
                    and bundle.get("unresolved_drift", 999) <= 0)
        rego = _GOVERNANCE / "baseline_opa.rego"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(bundle, f)
            tmp = f.name
        try:
            out = subprocess.run(
                [self.binary, "eval", "-i", tmp, "-d", str(rego),
                 "data.eviassure.baseline.allow", "--format=raw"],
                capture_output=True, text=True, timeout=30)
            return out.stdout.strip() == "true"
        except Exception:
            return False
        finally:
            Path(tmp).unlink(missing_ok=True)


# --------------------------------------------------------------------------
# 4. Unauthenticated status gate (lower bound, explicitly not a competitor)
# --------------------------------------------------------------------------

class StatusGateBaseline:
    name = "Unauthenticated CI status gate (lower bound)"
    execution_mode = "modeled (exit-code semantics; reported as a floor, not a competitor)"

    def verify(self, bundle: Dict[str, Any]) -> bool:
        return bundle.get("test_pass_pct", 0) > 0 and bundle.get("status") != "HARD_FAILURE"


# --------------------------------------------------------------------------
# 5. Composed pipeline: DSSE + TUF freshness + OPA policy
# --------------------------------------------------------------------------

class ComposedBaseline:
    name = "Composed SOTA pipeline (DSSE/in-toto + TUF freshness + OPA policy)"

    def __init__(self, dsse: DSSEInTotoBaseline, tuf: TUFBaseline, opa: OPABaseline):
        self.dsse, self.tuf, self.opa = dsse, tuf, opa
        self.execution_mode = (
            f"composed execution ({dsse.execution_mode}; {tuf.execution_mode}; "
            f"{opa.execution_mode})")

    def verify(self, bundle: Dict[str, Any]) -> bool:
        return self.dsse.verify(bundle) and self.tuf.verify(bundle) and self.opa.verify(bundle)


def build_baselines(trusted_keys: Dict[str, str], revoked: set,
                    require_executed: bool = False) -> List[Any]:
    dsse = DSSEInTotoBaseline(trusted_keys, revoked)
    tuf = TUFBaseline(trusted_keys, revoked, require_executed=require_executed)
    opa = OPABaseline(require_executed=require_executed)
    return [StatusGateBaseline(), opa, dsse, tuf, ComposedBaseline(dsse, tuf, opa)]


# --------------------------------------------------------------------------
# 6. Completeness baselines -- the axis the tamper baselines cannot reach
# --------------------------------------------------------------------------

class ReceiptsOnlyBaseline:
    """Per-action receipts WITHOUT sequence binding or closing counts.

    Re-implemented from the published designs -- receiver-attested action
    receipts (Notarized Agents / Sello, arXiv:2606.04193; PipeLab Agent Action
    Receipts) -- not their reference code. The verifier checks that every
    recorded action carries a valid receipt from a registered witness for this
    session, and that no receipt is unmatched. It ignores the sequence number,
    the chain link and the closings that EviAssure's receipts additionally
    carry, because the designs it stands for have none of them.

    That is a genuine and useful property. It is also, precisely, not
    completeness: an adversary who drops action a_i drops receipt r_i with it,
    and every remaining pair still matches. This baseline is expected to catch
    fabrication and cross-session splicing and to miss every truncation, which
    is the empirical form of the paper's central argument.
    """

    name = "Per-action receipts (no sequence binding)"
    execution_mode = ("re-implemented from the published designs; executed "
                      "(Ed25519 receipt verification against a pinned witness registry)")

    def __init__(self, witness_registry: Dict[str, str], mediated: Dict[str, Any]):
        self.registry = dict(witness_registry)
        self.mediated = {k: set(v) for k, v in (mediated or {}).items()}

    def verify(self, bundle: Dict[str, Any]) -> bool:
        from assurance.witness import Receipt, action_digest
        from assurance.crypto import verify_signature_ed25519

        session = bundle.get("session_id") or ""
        good = []
        for raw in bundle.get("witness_receipts") or []:
            r = Receipt.from_dict(raw)
            pk = self.registry.get(r.witness_id)
            if not pk or not r.signature:
                return False
            if not verify_signature_ed25519(r.payload(), r.signature, pk):
                return False
            if r.session_id != session:            # catches O5
                return False
            good.append(r)

        digests = {r.action_digest for r in good}
        all_mediated = set().union(*self.mediated.values()) if self.mediated else set()
        for t in bundle.get("traces") or []:
            if t.get("action") in all_mediated and action_digest(t) not in digests:
                return False                        # catches O6
        # NOTE: no check that the receipt set is COMPLETE. Nothing here can be.
        return True


class HashChainBaseline:
    """AAS-1-style per-issuer hash chaining.

    Re-implemented from the AAS-1 working paper's description (per-issuer hash
    chains for omission detection), not from a reference implementation. Each
    receipt carries `prev`, the digest of the same witness's previous receipt
    in the session (GENESIS for the first). The verifier authenticates every
    receipt, then walks each issuer's chain from GENESIS following `prev`
    links; a link that points at a receipt not present breaks the chain. It
    deliberately ignores sequence numbers and closing statements, which the
    design it stands for does not have.

    What that buys and what it does not: an interior omission leaves a receipt
    whose `prev` names a missing one (detected); a spliced foreign receipt
    carries a `prev` from another chain (detected); a contiguous suffix drop
    leaves a chain that verifies end to end, because the end simply moved
    (missed); dropping a whole issuer leaves nothing to check (missed); a
    forged closing is never consulted (missed); a fabricated trace has no
    receipt to chain (missed). Implemented so the paper's comparison of
    chaining against sequence-plus-closing is executed rather than asserted.
    """

    name = "Per-issuer hash chaining (AAS-1 style)"
    execution_mode = ("re-implemented from the AAS-1 description; executed "
                      "(authenticated prev-link chain walk per issuer)")

    def __init__(self, witness_registry: Dict[str, str]):
        self.registry = dict(witness_registry)

    def verify(self, bundle: Dict[str, Any]) -> bool:
        from assurance.witness import Receipt, GENESIS
        from assurance.crypto import verify_signature_ed25519

        per_issuer: Dict[str, list] = {}
        for raw in bundle.get("witness_receipts") or []:
            r = Receipt.from_dict(raw)
            pk = self.registry.get(r.witness_id)
            if not pk or not r.signature:
                return False
            if not verify_signature_ed25519(r.payload(), r.signature, pk):
                return False
            per_issuer.setdefault(r.witness_id, []).append(r)
        for wid, rs in per_issuer.items():
            by_digest = {r.digest(): r for r in rs}
            heads = [r for r in rs if r.prev == GENESIS]
            if len(heads) != 1:
                return False                        # no genesis, or two chains for one issuer
            # every non-genesis receipt must link to a PRESENT receipt of this issuer
            for r in rs:
                if r.prev != GENESIS and r.prev not in by_digest:
                    return False
            # and the walk from genesis must reach every present receipt (no forks)
            seen, cur = {heads[0].digest()}, heads[0]
            nxt = {r.prev: r for r in rs if r.prev != GENESIS}
            while cur.digest() in nxt:
                cur = nxt[cur.digest()]
                if cur.digest() in seen:
                    return False
                seen.add(cur.digest())
            if len(seen) != len(rs):
                return False
        return True


def build_completeness_baselines(witness_registry: Dict[str, str],
                                 mediated: Dict[str, Any]) -> List[Any]:
    return [ReceiptsOnlyBaseline(witness_registry, mediated),
            HashChainBaseline(witness_registry)]
