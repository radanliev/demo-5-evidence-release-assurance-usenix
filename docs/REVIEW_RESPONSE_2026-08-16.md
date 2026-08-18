# Response to Coordinator Review — 2026-08-16

Point-by-point response. Each item cites the section, artifact, or commit that
addresses it. The review was written against the pre-coauthor-round manuscript;
most concerns are addressed by work now on `paperloop/autofix`, and the two
genuinely open items (runtime-trace predicate citation, ablation study) are
closed by this commit.

## 1. Novelty vs in-toto/SLSA (incl. the runtime-trace predicate)

Agreed that this must be explicit, and it now is:

- The Positioning paragraph (§1) and Related Work (§7.1) acknowledge the
  vetted in-toto runtime-trace predicate — now cited specifically
  (`intoto_runtime_trace`, in-toto/attestation `spec/predicates/runtime-trace.md`)
  — and state the delta: those efforts define *record formats*; EviAssure
  defines an *authorization layer* — a gate whose verdict is a deterministic
  function of attested evidence under a pinned policy version, with freshness,
  replay, and revocation integral to the verdict. Four concrete capabilities no
  predicate alone provides are enumerated: (i) completeness-carrying trace
  binding (signed trace count), (ii) freshness/replay as enforced gate
  properties, (iii) reproducible, auditable authorization decisions,
  (iv) the two-layer integrity/inspection model. Composition is explicit:
  the EvidenceBundle is an in-toto Statement, so any predicate (runtime-trace,
  agent-decision, SLSA) can ride the same evidence pack.

## 2. The 2026 landscape (agent-decision RFC, APAS, AAS-1)

Addressed (§1 Positioning, §7.5 `sec:related-2026`): all three are cited and
positioned against — the agent-decision/v0.1 RFC (in-toto/attestation#554),
APAS v0.2.1, and AAS-1 v0.1. All three references were verified against live
sources (titles, authors, and cited details match); the completeness
discussion (§2.4) additionally compares omission-detection approaches
(APAS external witnesses; AAS-1 inter-record hash chains) against
EviAssure's collector boundary.

## 3. Integrity vs completeness

Addressed head-on, including the review's own example: Definition
`def:integrity` vs `def:completeness`, and §2.4 works exactly the
A→B→C→D→E vs A→B→D→E scenario: the Merkle tree attests its leaves, not the
world; completeness is a property of the evidence collector. The collector
assumption is stated as an explicit condition of the system-level theorem
(`thm:authorization`), residual risk is scoped (actions that never reach the
collector are out of scope for any release-attestation system), and mitigations
are given (collect at the outermost observable boundary; inspection layer).

## 4. Evaluation sufficiency

Partially addressed before this round, completed by it:

- *Overhead & scalability*: Merkle scaling to 1M traces, multi-core
  throughput, sparse-proof and blinding costs — now all means over 5 runs
  with σ recorded in the artifact.
- *Baselines*: three separately justified gates (below).
- *Ablations* (new, this commit): a per-check ablation disables each
  enforcement in turn over the 12 vectors and records the escape matrix in
  the artifact (`ablation` block). Result: each check uniquely targets its
  vectors; the trace-count binding independently catches truncation even
  with the Merkle check off (defense in depth); removing the key registry
  fail-closes the gate rather than weakening it. No check is redundant; no
  single check is sufficient.
- *Why properties existing approaches can't provide*: the comparative
  section shows the executed OPA schema gate blocks 3/12 and the signature-
  presence model 1/12 against the same vectors; the positioning section
  states the property delta.

## 5. OPA and Sigstore as one baseline

Addressed: the baselines are three separately configured and separately
justified gates — CI exit-code (modeled), OPA schema policy (executed, OPA
1.19.0, Rego policy in the artifact), Sigstore-style signature presence
(modeled, presence-only semantics with rationale). The artifact records the
execution mode of each (`baseline_execution` block); the paper states which
are executed vs modeled and what each abstraction captures.

## 6. System-level theorem

Addressed: Theorem `thm:authorization` (Evidence-Bound Release Authorization
Soundness) states what an APPROVED verdict means — matching the review's
proposed Release Soundness Theorem nearly verbatim — and reduces to primitive
assumptions (EUF-CMA, collision resistance, depth-bound Merkle soundness)
plus explicitly stated trust boundaries (evidence collector, key registry,
nonce state, KMS/HSM). The primitive-level game proof is retained and scoped
as such (§ "two layers" preamble).

## Summary for the professor

| # | Concern | Status |
|---|---|---|
| 1 | Novelty vs in-toto/SLSA + runtime-trace predicate | Addressed; predicate now cited specifically |
| 2 | 2026 standards positioning | Addressed (§1, §7.5; refs verified live) |
| 3 | Integrity vs completeness | Addressed (defs, reviewer's own example, theorem condition) |
| 4 | Evaluation depth | Ablation added; overheads/scalability/baselines already in |
| 5 | OPA/Sigstore single baseline | Addressed (three baselines, modes disclosed) |
| 6 | System-level theorem | Addressed (`thm:authorization`) |
