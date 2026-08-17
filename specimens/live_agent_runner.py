"""
Live LLM agent specimen: a *real*, non-deterministic agent whose tool calls are
mediated by witnesses.

Why this exists
---------------
The paper's most substantial admitted limitation is that no LLM agent is
executed anywhere in the evaluation: the corpus is synthetic and templated, so a
paper arguing that agent releases need new evidence *because agent behaviour is
non-deterministic* was itself evaluated only on deterministic templates. This
module removes that gap for the witness protocol specifically.

An agent here is a real chat-completion loop against an OpenAI-compatible
endpoint (Groq or OpenRouter). The model chooses which tools to call and in what
order; we do not script the sequence. Each tool is fronted by a `Witness`, so a
receipt is issued at the point of service by the component that actually served
the call -- which is the deployment story Definition (WTC) describes, exercised
rather than asserted.

What this does and does not establish
-------------------------------------
It establishes that (a) the witness protocol composes with a real tool-calling
loop, (b) reconciliation holds over genuinely non-deterministic action
sequences, and (c) -- the measurement the paper currently lacks -- what
*fraction* of a real agent's actions are witness-mediated, which is the
deployability question Definition (WTC) leaves abstract.

It does not establish that the model is adversarial, that the sandbox is escape
proof, or that these tools resemble any particular production stack. The tools
are local and side-effect-free by design: a paper about release assurance should
not need to touch a third party to be reproduced.

Determinism note: `temperature=0` is requested but does not make an LLM
deterministic across runs or providers. Sequences vary; that variation is the
point, and every result derived from these runs is reported with the session
count it came from.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from assurance.crypto import hash_sha256
from assurance.evidence import ExecutionTraceRecord
from assurance.witness import Witness

# --------------------------------------------------------------------------
# Providers. Both speak the OpenAI chat-completions shape, so one client works.
# --------------------------------------------------------------------------
PROVIDERS = {
    "groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "env": "GROQ_API_KEY",
        "default_model": "openai/gpt-oss-120b",
    },
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "env": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct",
    },
}


class ProviderError(RuntimeError):
    """Raised when the model endpoint cannot be reached or returns an error.

    Deliberately not swallowed: a run that silently degrades to scripted
    behaviour would reintroduce exactly the synthetic-corpus problem this
    module exists to remove.
    """


# --------------------------------------------------------------------------
# Witness-mediated tools.
#
# `mediates` is the action-type set of Definition (WTC). Every tool below is
# mediated; `emit_summary` deliberately is NOT, so that runs exercise the
# honest boundary -- an action no witness serves -- rather than a world where
# coverage is trivially 100%.
# --------------------------------------------------------------------------
TOOL_WITNESSES: Dict[str, set] = {
    "db-gateway": {"execute_read_only_query", "collect_table_stats"},
    "search-broker": {"vector_search_policy_docs"},
    "identity-provider": {"authenticate_jwt_claims"},
}

UNMEDIATED_ACTIONS = {"emit_summary"}

TOOL_SCHEMA = [
    {"type": "function", "function": {
        "name": "authenticate_jwt_claims",
        "description": "Authenticate the caller and return their role. Call this before anything else.",
        "parameters": {"type": "object", "properties": {
            "user_role": {"type": "string", "description": "Role being claimed, e.g. security-auditor"}},
            "required": ["user_role"]}}},
    {"type": "function", "function": {
        "name": "vector_search_policy_docs",
        "description": "Semantic search over the release-policy document corpus.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "execute_read_only_query",
        "description": "Run a read-only SQL SELECT against the audit database.",
        "parameters": {"type": "object", "properties": {
            "sql": {"type": "string", "description": "A SELECT statement"}}, "required": ["sql"]}}},
    {"type": "function", "function": {
        "name": "collect_table_stats",
        "description": "Return row counts for a table in the audit database.",
        "parameters": {"type": "object", "properties": {
            "table": {"type": "string"}}, "required": ["table"]}}},
    {"type": "function", "function": {
        "name": "emit_summary",
        "description": "Record a final natural-language summary of what you found.",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string"}}, "required": ["summary"]}}},
]

SYSTEM_PROMPT = (
    "You are a release-audit agent. Establish who you are, consult the policy "
    "corpus, then inspect the audit database to determine whether the most "
    "recent release passed its gate. Use the tools; do not guess. When you have "
    "an answer, call emit_summary exactly once and stop."
)


def _audit_db() -> sqlite3.Connection:
    """A small in-memory database. Local and side-effect-free so that a
    reviewer can reproduce every run without provisioning anything."""
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE releases (id INT, version TEXT, gate TEXT, drift INT)")
    c.executemany("INSERT INTO releases VALUES (?,?,?,?)", [
        (1, "v1.4.0", "APPROVED", 0),
        (2, "v1.4.1", "BLOCKED", 3),
        (3, "v1.5.0", "APPROVED", 0),
    ])
    c.execute("CREATE TABLE policy_docs (id INT, title TEXT)")
    c.executemany("INSERT INTO policy_docs VALUES (?,?)", [
        (1, "Release gate thresholds"), (2, "Key revocation procedure")])
    conn.commit()
    return conn


def _run_tool(name: str, args: Dict[str, Any], conn: sqlite3.Connection) -> Tuple[str, str]:
    """Execute a tool. Returns (status, result_text)."""
    try:
        if name == "authenticate_jwt_claims":
            role = args.get("user_role", "unknown")
            return "SUCCESS", json.dumps({"role": role, "authenticated": True})

        if name == "vector_search_policy_docs":
            rows = conn.execute("SELECT id, title FROM policy_docs").fetchall()
            return "SUCCESS", json.dumps({"query": args.get("query", ""), "hits": rows})

        if name == "execute_read_only_query":
            sql = (args.get("sql") or "").strip()
            # Read-only enforcement is the witness's job in a real deployment;
            # here the broker refuses anything that is not a SELECT, and the
            # refusal is itself a witnessed event with status DENIED.
            if not sql.lower().startswith("select"):
                return "DENIED", json.dumps({"error": "read-only path: SELECT only"})
            rows = conn.execute(sql).fetchall()
            return "SUCCESS", json.dumps({"rows": rows[:20]})

        if name == "collect_table_stats":
            table = args.get("table", "")
            if table not in {"releases", "policy_docs"}:
                return "DENIED", json.dumps({"error": f"unknown table {table!r}"})
            n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            return "SUCCESS", json.dumps({"table": table, "rows": n})

        if name == "emit_summary":
            return "SUCCESS", json.dumps({"summary": args.get("summary", "")[:500]})

        return "DENIED", json.dumps({"error": f"no such tool {name!r}"})
    except Exception as exc:                      # a tool that raises is a real outcome
        return "ERROR", json.dumps({"error": type(exc).__name__, "detail": str(exc)[:200]})


def _witness_for(action: str, witnesses: Dict[str, Witness]) -> Optional[Witness]:
    for w in witnesses.values():
        if action in w.mediates:
            return w
    return None


@dataclass
class LiveSession:
    session_id: str
    model: str
    provider: str
    traces: List[ExecutionTraceRecord] = field(default_factory=list)
    receipts: List[Any] = field(default_factory=list)
    closings: List[Any] = field(default_factory=list)
    registry: Dict[str, str] = field(default_factory=dict)
    mediated: Dict[str, set] = field(default_factory=dict)
    turns: int = 0
    unmediated_actions: List[str] = field(default_factory=list)
    stopped_reason: str = ""

    @property
    def mediated_count(self) -> int:
        return len(self.receipts)

    @property
    def coverage(self) -> float:
        """Fraction of executed actions that a witness served. This is the
        number Definition (WTC) leaves abstract and that a deployment must
        actually achieve."""
        return (self.mediated_count / len(self.traces)) if self.traces else 0.0


def _chat(url: str, key: str, model: str, messages: List[Dict[str, Any]],
          timeout: float = 60.0, max_retries: int = 6) -> Dict[str, Any]:
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": TOOL_SCHEMA,
        "tool_choice": "auto",
        "temperature": 0,
    }).encode()
    # An explicit User-Agent is required, not cosmetic: both providers sit
    # behind Cloudflare, which rejects urllib's default "Python-urllib/3.x"
    # with HTTP 403 "error code: 1010" before the request ever reaches the
    # model. Diagnosing that as an auth failure would be easy and wrong.
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": "eviassure-live-agent/1.0"})
    # Free-tier accounts are metered per minute, and a multi-turn tool loop
    # resends the whole conversation each turn, so 429 is the normal case
    # rather than an exceptional one. Retry on the provider's own suggested
    # delay; give up only after exhausting attempts, and never downgrade to
    # scripted behaviour.
    last = ""
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            payload = e.read()[:500].decode("utf-8", "replace")
            last = f"HTTP {e.code}: {payload}"
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = _retry_after(e, payload, attempt)
                time.sleep(wait)
                continue
            raise ProviderError(last) from None
        except Exception as e:                       # transient socket/DNS faults
            last = f"{type(e).__name__}: {e}"
            if attempt < max_retries - 1:
                time.sleep(2.0 * (attempt + 1))
                continue
            raise ProviderError(last) from None
    raise ProviderError(last)


def _retry_after(err, payload: str, attempt: int) -> float:
    """Seconds to wait. Prefer the server's Retry-After, then the delay quoted
    in the error text, then exponential backoff."""
    hdr = None
    try:
        hdr = err.headers.get("retry-after")
    except Exception:
        pass
    if hdr:
        try:
            return min(float(hdr) + 0.5, 65.0)
        except ValueError:
            pass
    m = re.search(r"try again in ([0-9.]+)\s*(ms|s)\b", payload)
    if m:
        v = float(m.group(1))
        if m.group(2) == "ms":
            v /= 1000.0
        return min(v + 1.0, 65.0)
    return min(2.0 ** attempt, 30.0)


def run_live_session(provider: str = "groq", model: Optional[str] = None,
                     max_turns: int = 8, task: Optional[str] = None) -> LiveSession:
    """Run one real agent session with witness-mediated tools."""
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; choose from {sorted(PROVIDERS)}")
    cfg = PROVIDERS[provider]
    key = os.environ.get(cfg["env"], "").strip()
    if not key:
        raise ProviderError(f"{cfg['env']} is not set")
    model = model or cfg["default_model"]

    session_id = f"live-{uuid.uuid4().hex[:12]}"
    witnesses = {wid: Witness(wid, mediates=set(acts)) for wid, acts in TOOL_WITNESSES.items()}
    sess = LiveSession(session_id=session_id, model=model, provider=provider,
                       registry={w: x.public_key_b64 for w, x in witnesses.items()},
                       mediated={w: set(x.mediates) for w, x in witnesses.items()})

    conn = _audit_db()
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task or "Did the most recent release pass its gate?"},
    ]

    step = 0
    for turn in range(max_turns):
        sess.turns = turn + 1
        reply = _chat(cfg["url"], key, model, messages)
        choice = (reply.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        calls = msg.get("tool_calls") or []
        messages.append({k: v for k, v in msg.items()
                         if k in ("role", "content", "tool_calls")} or {"role": "assistant", "content": ""})

        if not calls:
            sess.stopped_reason = "model returned no tool call"
            break

        finished = False
        for call in calls:
            fn = (call.get("function") or {})
            action = fn.get("name") or "unknown"
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            t0 = time.perf_counter()
            status, result = _run_tool(action, args, conn)
            dt = (time.perf_counter() - t0) * 1000.0

            trace = ExecutionTraceRecord(
                trace_id=f"TR-{session_id[5:11]}-{step:03d}",
                agent_id=f"live-agent/{model}",
                action=action,
                status=status,
                duration_ms=round(dt, 4),
                output_hash=hash_sha256(result),
            )
            sess.traces.append(trace)
            step += 1

            w = _witness_for(action, witnesses)
            if w is not None:
                sess.receipts.append(w.observe(session_id, trace))
            else:
                sess.unmediated_actions.append(action)

            messages.append({"role": "tool", "tool_call_id": call.get("id"),
                             "name": action, "content": result[:2000]})
            if action == "emit_summary":
                finished = True
        if finished:
            sess.stopped_reason = "agent emitted summary"
            break
    else:
        sess.stopped_reason = f"hit max_turns={max_turns}"

    conn.close()
    # Every registered witness closes every session, including with n_j = 0 --
    # without that rule, dropping a witness *and* its closing is
    # indistinguishable from never using the tool (vector O3).
    sess.closings = [w.close(session_id) for w in witnesses.values()]
    return sess
