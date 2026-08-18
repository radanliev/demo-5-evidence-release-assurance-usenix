"""Out-of-process witnesses for the live-agent harness.

Why this module exists
----------------------

`assurance.witness.Witness` documents what a witness is supposed to be: "the
tool endpoint, API gateway, or sandbox syscall broker that *actually serves*
the agent's action -- not a component of the agent runtime." The live harness
did not honour that. It executed the tool itself, built the
`ExecutionTraceRecord`, and then handed that record to a `Witness` object to
sign:

    status, result = _run_tool(action, args, conn)      # collector executes
    trace = ExecutionTraceRecord(..., output_hash=hash_sha256(result))
    receipt = witness.observe(cred, trace)              # witness signs the
                                                        # collector's record

An adversary who owns the collector could therefore doctor the record *before*
the witness saw it, and the witness would faithfully attest the doctored
version. The receipt proved only that the collector's own claim had been
signed twice. It said nothing about what happened, which is the whole point of
having a witness at all.

What changes here
-----------------

The witness runs in a **separate OS process** and is the party that executes
the tool:

  * its Ed25519 signing key is generated inside the child and never crosses
    the process boundary -- the collector cannot mint receipts;
  * it opens its **own** connection to the audit database, so the bytes it
    returns are bytes it produced, not bytes the collector reported;
  * `output_hash` in the attested tuple is computed by the witness over its
    own output, so `action_digest` binds the action the witness actually
    served.

The collector receives the result and builds its own trace record from it. An
honest collector's `output_hash` therefore matches the witness's, and
`reconcile()` check 5 (every receipt binds to a recorded trace) passes. A
collector that alters or omits after the fact no longer matches, and the gate
catches it -- which is exactly the property the in-process harness could not
demonstrate.

This is a single-host approximation of the deployment the paper describes: a
separate process with a private key and its own view of the resource. It is
not a separate container, host, or trust domain, and it does not defend
against an adversary with `ptrace` or root on the box. Section 7.9 and the
Limitations section should say so in those words.

Protocol: newline-delimited JSON over the child's stdin/stdout.

    parent -> child   {"op": "serve", "cred": {...}, "action": "...",
                       "args": {...}, "trace_id": "...", "agent_id": "..."}
    child  -> parent  {"op": "served", "status": "...", "result": "...",
                       "attested": {...}, "receipt": {...}}

    parent -> child   {"op": "close", "cred": {...}}
    child  -> parent  {"op": "closed", "closing": {...}}
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.witness import (                                    # noqa: E402
    CredentialError, Witness, DEMO_ORCHESTRATOR_PUB_B64,
)
from assurance.evidence import hash_sha256                         # noqa: E402


# ---------------------------------------------------------------------------
# Child side: the witness process
# ---------------------------------------------------------------------------

def _serve_forever(witness_id: str, mediates: Set[str], orch_pub: str) -> int:
    """Run one witness. Its private key is created here and stays here."""
    # Deferred import: live_agent_runner imports this module for the client
    # half, so importing it at module scope would be a cycle.
    from specimens.live_agent_runner import _audit_db, _run_tool

    w = Witness(witness_id, mediates=mediates, orchestrator_public_key=orch_pub)
    conn = _audit_db()          # the witness's OWN view of the resource

    def emit(obj: Dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    emit({"op": "hello", "witness_id": witness_id,
          "public_key": w.public_key_b64, "mediates": sorted(mediates),
          "pid": os.getpid()})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            emit({"op": "error", "error": "BadRequest", "detail": str(exc)})
            continue

        op = req.get("op")
        if op == "shutdown":
            break

        if op == "serve":
            action = req.get("action", "")
            if action not in w.mediates:
                # A witness must refuse actions it is not authoritative for;
                # serving them anyway would let the collector pick its witness.
                emit({"op": "error", "error": "NotMediated",
                      "detail": f"{witness_id} does not mediate {action!r}"})
                continue
            t0 = time.perf_counter()
            status, result = _run_tool(action, req.get("args") or {}, conn)
            dt = (time.perf_counter() - t0) * 1000.0
            # The digest the witness signs is over the output the witness
            # itself produced. This line is the entire point of the module.
            attested = {"trace_id": req.get("trace_id", ""),
                        "agent_id": req.get("agent_id", ""),
                        "action": action,
                        "output_hash": hash_sha256(result)}
            try:
                receipt = w.observe(req.get("cred"), attested)
            except CredentialError as exc:
                emit({"op": "error", "error": "CredentialError", "detail": str(exc)})
                continue
            except RuntimeError as exc:            # session already closed
                emit({"op": "error", "error": "RuntimeError", "detail": str(exc)})
                continue
            emit({"op": "served", "status": status, "result": result,
                  "witness_duration_ms": round(dt, 4),
                  "attested": attested, "receipt": asdict(receipt)})
            continue

        if op == "close":
            try:
                closing = w.close(req.get("cred"))
            except CredentialError as exc:
                emit({"op": "error", "error": "CredentialError", "detail": str(exc)})
                continue
            emit({"op": "closed", "closing": asdict(closing)})
            continue

        emit({"op": "error", "error": "UnknownOp", "detail": str(op)})

    conn.close()
    return 0


# ---------------------------------------------------------------------------
# Parent side: the client the collector talks to
# ---------------------------------------------------------------------------

class WitnessProcessError(RuntimeError):
    """The witness process refused a request or died."""


# The image built by specimens/witness.Dockerfile. Overridable so a deployment
# can pin its own digest rather than a floating tag.
WITNESS_IMAGE = os.environ.get("EVIASSURE_WITNESS_IMAGE", "eviassure-witness:latest")


def docker_available() -> bool:
    """True if a Docker daemon is reachable. Used to skip, never to substitute."""
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20).returncode == 0
    except Exception:
        return False


class ProcessWitness:
    """A handle on one out-of-process witness.

    The collector holds this object. It can ask the witness to serve an action
    and to close a session. It cannot sign anything: the key is in the child.

    `isolation` selects how far the witness is separated from the collector:

      "process"    a child process on this host. Separate memory and key,
                   shared filesystem, user, and kernel.
      "container"  a container with its own filesystem, PID and network
                   namespaces, running as a non-root user, with the repository
                   mounted read-only and `--network none`. Still one host and
                   one kernel: it does not stop an adversary who is root on the
                   host or who can reach the Docker socket.

    Neither setting defends against an attacker who can already debug the
    collector's own process; that is a deployment assumption, and the paper
    says so rather than implying the container closes it.
    """

    def __init__(self, witness_id: str, mediates: Set[str],
                 orchestrator_public_key: str = DEMO_ORCHESTRATOR_PUB_B64,
                 python: Optional[str] = None, isolation: str = "process"):
        if isolation not in ("process", "container"):
            raise ValueError(f"unknown isolation {isolation!r}")
        self.witness_id = witness_id
        self.mediates = set(mediates)
        self.isolation = isolation
        args = ["--witness-id", witness_id,
                "--mediates", ",".join(sorted(self.mediates)),
                "--orchestrator-pub", orchestrator_public_key]
        if isolation == "container":
            repo = str(Path(__file__).parent.parent)
            cmd = ["docker", "run", "--rm", "-i",
                   "--network", "none",          # a witness here needs no network
                   "--read-only",                # nothing on disk is writable
                   "--tmpfs", "/tmp",
                   "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges",
                   "--memory", "512m", "--pids-limit", "128",
                   "-v", f"{repo}:/app:ro",
                   WITNESS_IMAGE] + args
        else:
            cmd = [python or sys.executable, os.path.abspath(__file__)] + args
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            cwd=str(Path(__file__).parent.parent))
        hello = self._read()
        if hello.get("op") != "hello":
            raise WitnessProcessError(f"{witness_id}: bad handshake {hello!r}")
        self.public_key_b64: str = hello["public_key"]
        self.pid: int = hello["pid"]

    # -- transport ---------------------------------------------------------
    def _read(self) -> Dict[str, Any]:
        line = self.proc.stdout.readline()
        if not line:
            err = (self.proc.stderr.read() or "").strip()
            raise WitnessProcessError(f"{self.witness_id}: process died. {err[:400]}")
        return json.loads(line)

    def _rpc(self, req: Dict[str, Any]) -> Dict[str, Any]:
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        resp = self._read()
        if resp.get("op") == "error":
            raise WitnessProcessError(
                f"{self.witness_id}: {resp.get('error')}: {resp.get('detail')}")
        return resp

    # -- operations --------------------------------------------------------
    def serve(self, cred: Dict[str, Any], action: str, args: Dict[str, Any],
              trace_id: str, agent_id: str) -> Dict[str, Any]:
        """Have the witness execute the action and attest what it returned."""
        return self._rpc({"op": "serve", "cred": cred, "action": action,
                          "args": args, "trace_id": trace_id, "agent_id": agent_id})

    def close(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc({"op": "close", "cred": cred})["closing"]

    def __del__(self) -> None:                 # net for an aborted session
        try:
            self.shutdown()
        except Exception:
            pass

    def shutdown(self) -> None:
        try:
            if self.proc.poll() is None:
                self.proc.stdin.write(json.dumps({"op": "shutdown"}) + "\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class ProcessWitnessPool:
    """The set of out-of-process witnesses serving one session."""

    def __init__(self, tool_witnesses: Dict[str, Set[str]],
                 orchestrator_public_key: str = DEMO_ORCHESTRATOR_PUB_B64,
                 isolation: str = "process"):
        self.isolation = isolation
        self.witnesses: Dict[str, ProcessWitness] = {}
        try:
            for wid, acts in tool_witnesses.items():
                self.witnesses[wid] = ProcessWitness(
                    wid, set(acts), orchestrator_public_key, isolation=isolation)
        except Exception:
            self.shutdown()
            raise

    def for_action(self, action: str) -> Optional[ProcessWitness]:
        for w in self.witnesses.values():
            if action in w.mediates:
                return w
        return None

    @property
    def registry(self) -> Dict[str, str]:
        return {wid: w.public_key_b64 for wid, w in self.witnesses.items()}

    @property
    def mediated(self) -> Dict[str, Set[str]]:
        return {wid: set(w.mediates) for wid, w in self.witnesses.items()}

    def close_all(self, cred: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [w.close(cred) for w in self.witnesses.values()]

    def shutdown(self) -> None:
        for w in self.witnesses.values():
            w.shutdown()

    def __enter__(self) -> "ProcessWitnessPool":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.shutdown()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--witness-id", required=True)
    ap.add_argument("--mediates", default="",
                    help="comma-separated action names this witness serves")
    ap.add_argument("--orchestrator-pub", default=DEMO_ORCHESTRATOR_PUB_B64)
    a = ap.parse_args()
    mediates = {s for s in a.mediates.split(",") if s}
    return _serve_forever(a.witness_id, mediates, a.orchestrator_pub)


if __name__ == "__main__":
    raise SystemExit(main())
