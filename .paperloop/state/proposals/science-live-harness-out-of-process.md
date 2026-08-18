# science.live_harness: §7.9 now understates the harness it describes

## Finding

Risk register item #1 held that the live-agent evaluation measured the harness
rather than a deployment: the collector executed the tool, built the
`ExecutionTraceRecord`, and handed that record to a `Witness` object to sign.
The witness never observed anything independently of the collector it exists
to distrust.

That is fixed in code. `specimens/witness_process.py` runs each witness in its
own OS process, where it executes the tool itself and signs a digest over the
output **it** produced; its Ed25519 key is generated in the child and never
crosses the process boundary. `specimens/live_agent_runner.py` now defaults to
`witness_mode="out-of-process"`, and the whole live dataset was regenerated
under it.

The consequence for the manuscript is that §7.9's honesty paragraph is now
**wrong in the paper's favour**, which is the worse direction to be wrong in.
It tells a reviewer the separation is "by key and by credential, not by
process" and that an out-of-process witness "is not what produced these
numbers". Both sentences described the truth when written and describe the
opposite of the truth now.

Three prose facts are stale:

1. The process-separation caveat (lines 617–622) — now inverted.
2. `\liveModel` is singular; the dataset spans two model families.
3. Session counts and coverage flow through macros and have already updated
   (12 sessions, 8 completed, 0 failures, coverage 89.0% pooled /
   \liveCoverageCompleted\% on completed sessions).

## Correct value or claim

What the new harness does establish, stated at its real strength and no
higher:

* the witness executes the action and hashes its own output, so a collector
  that alters or drops a record after the fact is caught by `reconcile()`.
  `tests/test_out_of_process_witness.py` pins both directions: under
  out-of-process witnesses the altered and omitted collectors are detected;
  under the old in-process arrangement a doctored session reconciles cleanly.
  That last test asserts `ok is True` on purpose — it is the defect, pinned so
  it cannot come back unnoticed.
* the separation is **process and key**, on one host. It is not a separate
  container, host, or trust domain, and it does not survive an adversary with
  `ptrace` or root. Section 7.9 and Limitations must say so in those words —
  swapping one overclaim for another would be no improvement.
* the sample is 12 sessions across 2 model families
  (`openai/gpt-oss-120b`, `qwen/qwen3.6-27b`), 8 of which ran to completion,
  0 provider failures. The register asked for "≥2 models/providers" and
  "enough sessions that most complete"; 2 models and 8/12 meets both, on one
  provider. **A second provider was attempted and is not available**: the
  OpenRouter key returns HTTP 401 "User not found" and both Google keys are
  rejected. The harness refused to emit results rather than substitute
  anything, which is the correct behaviour and is why the sweep is
  single-provider.

## Exact proposed diff

```diff
--- a/docs/usenix_paper_manuscript.tex
+++ b/docs/usenix_paper_manuscript.tex
@@ -613,6 +613,6 @@
 decides what to do? We therefore ran \liveSessions{} sessions of a real
-tool-calling LLM (\texttt{\liveModel}) against a small tool set fronted by
+tool-calling LLM across \liveModelCount{} model families
+(\texttt{\liveModels}) against a small tool set fronted by
 witnesses of Section~\ref{sec:witness}. The model chooses the actions; nothing
 is scripted (Table~\ref{tab:live}). What the harness does and does not separate must be stated before
-its numbers are read: the tools execute in the harness process, the trace
-record is built there, and the witness object is handed that record to sign
-after verifying the session credential. The separation exercised is by
-\emph{key} and by \emph{credential}, not by process; an out-of-process witness
-that computes the action digest from the request it served is the deployment
-design of Section~\ref{sec:witness}, and it is not what produced these numbers.
+its numbers are read. Each witness runs in its own OS process: it executes the
+tool, computes the action digest over the output \emph{it} produced, and signs
+with a key generated in that process and never exported. The collector
+receives the result and builds its own record, so a collector that alters or
+omits a record after the fact no longer matches the receipt and reconciliation
+fails --- a property the earlier in-process harness could not exhibit, because
+there the collector doctored the record before the witness signed it. The
+separation exercised is by \emph{process}, \emph{key} and \emph{credential},
+on a single host. It is not separation by container, host, or trust domain,
+and it does not hold against an adversary with \texttt{ptrace} or root on that
+host; those remain deployment assumptions rather than demonstrated ones.
```

A matching sentence should be added to Limitations. Suggested wording, to be
placed with the other scoping statements:

```diff
+The live evaluation separates witness from collector by process and by key on
+one host. Container-, host-, and trust-domain separation are the deployment
+design and are not evaluated here.
```

## Evidence needed

Already in the repository, and re-runnable:

* `python3 -m pytest tests/test_out_of_process_witness.py -q` — 9 tests,
  covering key isolation, self-hashed output, honest reconciliation, the
  altered and omitted collectors, the pinned in-process defect, and three
  refusal paths.
* `python3 scripts/run_live_agent_eval.py --sessions N --provider groq
  [--model ...] --append --require-live` — regenerates
  `results/live_agent_evaluation.json`, in which every session now records
  `witness_mode`.
* `python3 scripts/run_live_agent_eval.py --witness-mode in-process ...`
  reproduces the superseded harness for comparison.

Two things a human must decide:

1. Whether to chase a second **provider**. The register asked for ≥2
   models/providers; this delivers 2 models on 1 provider because no second
   provider key works. Either supply a working key or state the
   single-provider limit explicitly.
2. Whether the 14 in-process sessions previously in
   `results/live_agent_evaluation.json` should be preserved anywhere. They
   were replaced by the 12 out-of-process sessions and remain in git history
   at commit `2888ee4`. They measure the old harness, so pooling them with the
   new data would be unsound; discarding them silently would also be wrong.

---

## APPLIED 18 Aug 2026 — on the author's explicit instruction

The §7.9 and Limitations corrections in this proposal were applied, together
with container isolation, which did not exist when the proposal was written.
What is now in the manuscript:

* §7.9 states that each witness runs outside the collector, executes the tool,
  digests the output it produced, and signs with a key never exported from its
  own address space; that separation is by process, key, credential, and by
  container (no network, read-only repository) in `\liveIsoContainer{}`
  sessions; and that it holds on one host only — not by host or trust domain,
  and not against root or a debugger.
* Limitations no longer says "single-provider" or "by key and credential
  rather than by process".
* Table 4's caption named a single model for what is now a three-model
  dataset; it reports `\liveModelCount{}` model families instead.

**The page limit forced one cut.** The body was already at exactly 13 of 13
pages, so the correction had to be word-for-word neutral — a net of +19 words
still produced a 14-page body and a BLOCKER. The sentence that did not fit:

> so a collector that alters or drops a record afterwards no longer matches
> its receipt and reconciliation fails

That is the falsifiability payoff of the whole change, and it is currently
implied by §4 and demonstrated only in `tests/test_out_of_process_witness.py`.
Buying roughly 18 words back means cutting author prose elsewhere in §7.9 —
the two candidates are the "declared and measurable rather than assumed away"
aside in the coverage paragraph and the "Detection is cryptographic, so this
confirms rather than surprises" sentence. Both are argumentation rather than
result, so removing either is an editorial decision for the author, not one an
agent should take.
