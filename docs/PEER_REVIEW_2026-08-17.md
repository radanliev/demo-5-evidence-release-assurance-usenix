# Adversarial Peer Review — 2026-08-17

**Reviewer stance:** hostile PC member, USENIX Security '27 standards.
**Scope:** the science — construction, proofs, evaluation validity, claim/artifact
correspondence. Not typography.
**Method:** every finding below was reproduced against the artifact at
`docs/usenix_paper_manuscript.tex` and the committed `results/*.json`.
Reproduction snippets are given inline; the full harness is
`/tmp/demo_findings.py` (see §Reproduction).

---

## Verdict

**Reject.** Not because the system is uninteresting — the engineering is clean and
the two-layer framing is honest in places most papers would hide. Reject because
**five claims in the paper are contradicted by the authors' own artifact**, and
because the headline empirical result (100% vs. 30.8%) rests on a benchmark that
cannot produce any other outcome.

The paper's central novelty claim — "an *authorization layer*, not a record
format" — is defensible. The problem is that the three properties the paper says
constitute that layer (completeness-carrying trace binding, integral
freshness/replay, reproducible pinned-policy decisions) are each either
unenforced in the shipped verifier, weaker than stated, or measured by an
experiment that is analytically determined.

---

# A. Claims contradicted by the artifact (rejection-grade, individually)

## A1 — Replay protection is **not enforced** by the shipped verifier

The abstract, contribution 1, §4.1, Theorem 2(iii) and §7.1 all assert that
freshness and replay protection are *integral to the gate* and that this is the
delta over in-toto/SLSA. §7.1: "stateful freshness and replay protection enforced
**integrally at the gate**."

In `assurance/policy.py` the nonce check is guarded by
`if seen_nonces is not None and nonce:` — i.e. it is a no-op unless the caller
supplies replay state. The shipped production entry point,
`scripts/verify_release_gate.py` (the one §5.1 names as the GitHub Action's gate
step), calls `evaluate_release_gate(...)` **without** `seen_nonces`, and
`assurance/verifier.py` defaults it to `None`.

Reproduced:

```
$ python3 scripts/verify_release_gate.py --evidence bundle.json --format json
submission #1: exit=0  status=APPROVED
submission #2: exit=0  status=APPROVED
submission #3: exit=0  status=APPROVED
```

The *same signed bundle*, replayed three times through the artifact's own CLI, is
approved every time. V4 ("Replayed Nonce") only blocks because
`scripts/run_release_benchmark.py` and `scripts/run_comparative_eval.py`
hand-seed the nonce into a set they create themselves
(`test_seen_nonces.add(tampered_payload["nonce"])`) and pass it in. The evaluation
harness supplies the state the deployable verifier never maintains.

Consequence: Theorem 2(iii) is false of the artifact as shipped, and the
comparative claim "the composed SOTA baseline ... has no integrated stateful
nonce replay cache (blind to V4)" compares a hand-primed EviAssure against
baselines given no state at all. V4 is not a property of the system under test.

## A2 — The ablation's stated mechanism is false, and it conceals a real bypass

§6.6: *"removing the trusted-key registry does not release any vector — instead
the gate fail-closes, rejecting **all** Ed25519 evidence because signatures can
no longer be authenticated; the registry is the trust anchor whose removal
disables authorization entirely rather than weakening it selectively."*

The `no_key_registry` ablation row sets `require_trusted_key: False`
(`scripts/run_release_benchmark.py:310`). Reading `policy.py:236–251`, that does
not disable Ed25519 verification — it sets `pinned_pub = None` and falls through
to `verify_pub = pinned_pub or s_pub`, i.e. **the gate verifies against the
public key supplied inside the attacker-controlled bundle.**

Reproduced:

```
honest bundle under no_key_registry      -> passed=True   (gate does NOT collapse)
attacker-key bundle, conformant KMS ARN  -> passed=True, violations=[]
```

An adversary who generates their own Ed25519 keypair and sets `kms_key_arn` to
any string matching the policy regex is **APPROVED**. The 13-vector suite does
not catch this because V3 is built from a bundle that was never Ed25519-signed
and therefore carries `kms_key_arn = None` — so V3 is blocked by the *ARN
pattern check*, not by the trusted-key registry. Table 4 attributes V3 to
"Ed25519 over canonical payload; trusted-key registry"; the artifact says
otherwise.

This directly falsifies §6.6's summary sentence: *"Every check is necessary (its
removal releases at least one vector it uniquely targets, or collapses the
gate)."* Two rows of the authors' own ablation matrix
(`no_key_registry`, `no_count_binding`) release **zero** vectors and do **not**
collapse the gate.

## A3 — The 13-vector suite is claimed to be exhaustive over the threat model; it is not

§6.6: *"Because the vectors span the entire formal capability surface of the
threat model, this 1-to-1 mapping empirically **proves** that the implemented
engine successfully covers the **complete** formal domain **without any coverage
gaps, logical bypasses, or missing bindings**."*

Three counterexamples, all in-scope for adversary classes $\mathcal{A}_1$/$\mathcal{A}_2$:

1. The bypass in A2 (attacker key + conformant ARN under a plausible
   misconfiguration) — no vector.
2. The internal-node-as-leaf proof forgery that the authors' own
   `docs/PEER_REVIEW_2026-08-15.md` demonstrated (M1). It was fixed in the
   *verifier signature* but never added to the vector suite. The paper's
   V12 is named "Truncated Merkle Path" and categorised "Integrity", but
   `benchmark/tamper_vectors.py:243–246` implements it as `traces = traces[:1]`
   — a trace-set truncation caught by root recomputation. **No vector exercises
   a malformed proof path at all.**
3. Nothing exercises the collector boundary, which §2.4 identifies as the load-
   bearing assumption.

"Proves ... complete ... without coverage gaps" is not a defensible sentence
about a 13-case suite the authors wrote to match their own 13 checks. Compare
§6.9, which concedes the opposite: *"a 100% block rate demonstrates the checks
fire, not resilience to novel attacks."* Both sentences are in the paper.

## A4 — Reproducibility claim is false: 44 tests vs. 29, and the suite fails

Appendix B.2 and `REPRODUCE.md` instruct reviewers to *"run `pytest tests/ -v` to
execute all **44** ... tests"*; `README.md` claims **44/44 PASS**.

```
$ python3 -m pytest tests/ -q
1 failed, 29 passed
FAILED tests/test_docs_consistency.py::test_manuscript_test_count_matches_collection
AssertionError: Manuscript claims 44 tests but the suite collects 29
```

The repository ships a gate that detects this and the gate is red. An artifact
evaluator runs this command first. This is a five-minute fix and a fatal first
impression.

## A5 — `\sparseProofNodes`/depth: the paper contradicts its own Definition 2

§6.3 states "*For N=1,000,000 traces (**tree depth 21**)*" while reporting a
20-node proof. Definition 2 commits verification to path length
$\lceil\log_2 N\rceil = 20$, and `expected_tree_depth(10^6) = 20`. The artifact's
`"tree_depth": 21` field is `len(levels)` (depth + 1). The paper uses "depth" in
two incompatible senses within the same construction, one of which contradicts
the formal definition the soundness argument rests on.

---

# B. Construct-validity failures in the evaluation

## B1 — The headline comparison is against strawmen the authors wrote

Abstract: "*100.0% ... compared to 0.0% for exit-code gates, 23.1% for schema
gates, and 30.8% for a composed Sigstore+OPA baseline.*"

- The "Standard CI exit-code gate" is
  `payload.get("test_pass_pct",0) > 0 and payload.get("status") != "HARD_FAILURE"`
  (`run_comparative_eval.py:36`). The `status` key does not exist at bundle
  level, so the gate is `test_pass_pct > 0`. Its 0/13 is arithmetic.
- The "Sigstore/Cosign-style" gate is
  `bool(payload.get("signed") and payload.get("signature") is not None)` — a
  *presence* check on a JSON field. Real Sigstore verification (Fulcio identity
  binding, Rekor inclusion + signed entry timestamp, `cosign verify-blob` against
  a trust root) would reject V3 and V9 outright and would supply exactly the
  third-party timestamping the paper claims Sigstore lacks. Calling this "a
  composed **SOTA** baseline" and putting 30.8% in the abstract is not a fair
  characterisation of the state of the art.
- The comparison universe is *EviAssure's own check list*. Any system missing
  check $c_i$ scores low on vector $V_i$ by construction. A reviewer cannot learn
  anything about relative security from a benchmark whose axes are one system's
  feature list.

The paper discloses "modeled" in §6.9. Disclosure does not repair a comparison;
it documents it. **What is missing is a baseline that could win a vector.** There
is no TUF comparison (Samuel et al. 2010 — cited! — gives threshold signatures,
freshness, rollback and revocation, i.e. four of EviAssure's five claimed
deltas), no Rekor/transparency-log comparison, and no in-toto verification with
a real layout despite `governance/intoto_layout.json` existing in the repo.

## B2 — The 1,000-payload fuzzing campaign cannot fail

§6.5 reports "*a 100.0% (1,000/1,000) fail-closed block rate with zero false
approvals*". All ten mutation classes in `generate_fuzzing_mutation_suite`
(`sig_flip`, `root_corrupt`, `leaf_drop`, `leaf_inject`, `timestamp_drift`,
`pass_rate_drop`, `nonce_corrupt`, `key_id_spoof`, `arn_tamper`, `missing_field`)
mutate a field inside the Ed25519-signed payload or inside the Merkle leaf input.
A bundle that verifies is therefore unreachable by construction.

Reproduced (200-payload sample, seed 7): 114 blocked on signature invalidity, 41
on root mismatch, 25 on ARN, 20 on key-ID registry. Zero blocked for a reason
that could have gone either way.

The campaign also contains **no unmutated bundles**, so it cannot measure a false
*block* rate either. The experiment has zero discriminative power in both
directions and should either be removed or redesigned (mutate only fields
*outside* the signed payload, and include clean controls).

## B3 — The corpus anomaly result is analytic, not empirical

`scripts/generate_trace_corpus.py:26` says it outright:

> *"Every action below is on the forensics engine's sensitive-action list, so
> Layer-3 inspection flags exactly these leaves."*

The detector (`assurance/forensics.py:SENSITIVE_ACTIONS`) and the generator
(`ANOMALY_TYPES`) are the same twelve-item list, written by the same authors.
Every planted anomaly *additionally* carries `status != "SUCCESS"`, which is the
detector's first rule. Clean profiles use ten benign action names, none on the
list, all `SUCCESS`.

```
planted subset of detector list?                    True
every anomaly also has status != SUCCESS:           True
```

50/50 recall and 0/1,000 false positives are therefore theorems about the
generator, not measurements of a detector. §6.9 half-concedes this ("measures the
detector against the intended signals") while Table 3, contribution 4, and the
Conclusion present it as an empirical result.

Separately: the "1,050-profile multi-architecture agent trace corpus" is 2,100
records total — **exactly two traces per profile** — produced by ~200 lines of
string templating with two hard-coded action names per "architecture". No LLM, no
agent framework, and no real execution is involved anywhere in this paper. For a
paper whose thesis is that agent releases need a new kind of evidence *because
agent behaviour is non-deterministic*, evaluating entirely on deterministic
synthetic strings is the central external-validity problem.

## B4 — "Real-World Case Study" contains no real-world case

§5 is titled *"Real-World Case Study and Production CI/CD Integration"*. Its two
specimens are described in the same section as "**Simulates** an autonomous
operations agent" and "**Simulates** a web-browser autonomous agent". §3.1 states
the production collector (eBPF/syscall) is not what was evaluated — the
evaluation uses "deterministic Python application-level instrumentation
wrappers". The mechanism on which every security guarantee is conditioned
(complete mediation at the collection boundary) is unimplemented and unmeasured.

## B5 — The performance section measures the wrong things

- **Packaging latency is constant in N.** `measure_merkle_scaling` hoists
  `leaf_hashes` and `trace_dicts` *outside* the timed region and excludes the
  Merkle build and serialization. What remains is dataclass construction plus one
  Ed25519 signature. Measured: 0.168 ms at N=10, 0.102 ms at N=1,000, 0.212 ms at
  N=100,000. Figure 2 plots this as a scaling curve. At N=10⁶ the artifact
  records **0.716 ± 1.207 ms — σ larger than the mean.**
- **"Packaging overhead of 0.0001%"** is that constant divided by
  `1.5 ms × N`. It falls monotonically because the denominator grows. It is not
  an overhead measurement.
- **7,152 ops/s is measured on 3-trace bundles** (`create_evidence_pack` default)
  and is juxtaposed in the abstract and §6.8 with the 10⁶-trace scaling result.
  Since the gate recomputes the whole tree (Protocol 2, step 2), throughput at
  N=10⁶ would be ≈2.6 ops/s. The two headline numbers cannot both describe the
  same workload.
- Peak-at-4-workers with a **1.9× speedup on a 14-core machine**, attributed to
  "memory bandwidth contention" and 16-worker "oversubscription". Neither
  explains the drop at 8 workers. With 1,000 tiny tasks through
  `ProcessPoolExecutor`, the measurement is dominated by pickling/IPC, not by
  verification. The stated explanation is unsupported speculation.

## B6 — No confidence intervals anywhere

"100.0%" on 13 trials is 95% CI **[0.77, 1.00]** (Wilson). The composed baseline's
30.8% is **[0.13, 0.58]**. Those intervals overlap enough that the paper's
qualitative story survives, but reporting 13/13 to one decimal place as "100.0%"
in an abstract, without an interval, is precision the sample cannot support.
Similarly 50/50 recall is [0.93, 1.00] and 0/1000 FP is [0.000, 0.004].

---

# C. Cryptographic and formal errors

## C1 — There is no domain separation, and the paper claims there is

§4.3: *"Because the internal node payload size is rigidly constrained
(64+1+64 = 129 bytes) and structurally separated by the delimiter, it natively
thwarts length-extension and collision/malleability attacks, **guaranteeing
robust domain separation between leaves and internal nodes**."*

`build_merkle_tree` computes leaves as `SHA256(leaf_string)` and internal nodes
as `SHA256(left + ":" + right)`. Both are unprefixed SHA-256 over an ASCII
string. There is **no domain separation**; the two input languages merely happen
not to overlap for the current leaf schema. RFC 6962 §2.1 — Laurie et al., which
this paper cites — exists precisely to fix this, with `0x00`/`0x01` prefixes. The
paper cites Certificate Transparency and omits its central defence, then claims
to have achieved that defence by other means.

The length-extension sentence is a category error. SHA-256 length extension is a
secret-prefix-MAC problem; it does not arise in unkeyed Merkle node hashing, and
a delimiter would not prevent it if it did.

The actual protection here is the depth binding (`expected_depth`) added in the
2026-08-15 round. The prose should say that and nothing more.

## C2 — The unsound proof path is still the default

`verify_merkle_proof(leaf, proof, root, expected_depth=None)`. With
`expected_depth` omitted the M1 attack still succeeds:

```
verify_merkle_proof(internal_node, short_path, root)                 -> True
verify_merkle_proof(internal_node, short_path, root, expected_depth) -> False
```

Soundness is opt-in. Any third-party auditor using the published API the obvious
way gets the unsound behaviour. §7's own use case — "store lightweight inclusion
proofs on-chain or in immutable ledger databases" — is exactly a third-party
verifier. `expected_depth` must be mandatory (positional, no default), or the
proof object must carry the committed depth and the verifier must require it.

A second, unfixed ambiguity in the same function (flagged in the 2026-08-15
review and never addressed): the branch
`hash_sha256(x) if len(x) != 64 else x` passes any 64-character string through
unhashed. `build_merkle_tree(["A"*64])` returns `"A"*64` as the root. Leaf
identity is decided by a length heuristic.

## C3 — Definition 3 (blinding indistinguishability) is false as stated

Definition 3 claims a blinded record is computationally indistinguishable from a
uniform 256-bit string. `blind_payload` is *deterministic*:
`HMAC(S, output_hash)`. Two records with the same payload produce the same
blinded value:

```
blinded(r1) == blinded(r2) for identical payloads:  True
```

An adversary who sees two equal values in a transcript distinguishes it from
uniform random with advantage ≈1. PRF security gives indistinguishability from a
random *function*, which is not the same claim. Either restate Definition 3 as
"indistinguishable from the output of a random function, over distinct inputs",
or make blinding randomised (per-record nonce, stored alongside) — the paper
already gestures at a nonce for low-entropy inputs but does not use it in the
implementation or the definition.

## C4 — Blinding is a non-contribution dressed as a mechanism

Contribution 2 and Security Requirement 4 promise that sensitive parameters
"remain **completely hidden** from public verifiers ... via indistinguishable
salted HMAC blinding". §3.2 then concedes the opposite: bundles never contain raw
payloads, only `output_hash` digests, "so secrecy rests on excluding raw text at
the collector, and blinding does not (and need not) conceal data that is absent
from the bundle. What blinding adds is *domain separation*."

So the mechanism advertised in the abstract as one of four architectural pillars
is, by the authors' own account, an unlinkability tweak applied to values that
were already digests. Either drop it from the contribution list and the abstract,
or give it a real job (e.g. blinding *low-entropy* recoverable digests, with the
recovery attack quantified — `SHA256("TOKEN_VALIDATED")` is brute-forceable in
microseconds, which would be a genuine finding).

## C5 — The proofs are game *labels*, not game hops

Theorem 1's proof asserts
$|\Pr[G_0]-\Pr[G_1]| \le \mathrm{Adv}^{euf\text{-}cma}$ without constructing a
reduction: no simulator, no description of how $\mathcal{A}$'s forgery is
converted into an EUF-CMA forgery, no accounting for signing-oracle queries.
Games 3 and 4 introduce aborts with probability-zero difference, so they are
vacuous hops. A crypto-literate reviewer reads this as notation, not proof.

Two smaller formal defects:

- **Definition 4 (Evidence Integrity)** says no PPT adversary can produce *any*
  $(R'_M,\sigma',N') \ne (R_M,\sigma,N)$ that verifies. That is false for the
  honest signer, who can sign anything. The quantifier must be over tuples not
  previously signed.
- **Theorem 2(ii)** concludes "the recorded evidence therefore corresponds
  exactly to what was submitted" — a tautology. What a reader needs is the
  relation between submitted evidence and the *execution*, which is precisely
  what Definition 5 says cannot be established.
- SHA-256 collision resistance is a fixed-parameter assumption; bounding it by
  $\mathrm{negl}(\lambda)$ is a category error that a CCS/S&P reviewer will
  circle.

## C6 — The KMS ARN check is unauthenticated metadata

$\mathcal{A}_{KMS}$ is presented as a governance control and V13 as an attack
vector. `kms_key_arn` is a self-declared string inside the bundle, covered by the
signature. Against an adversary without a trusted key it adds nothing (they fail
signature verification anyway); against one *with* a trusted key it is a
formatting convention they control. §3.1's "the gate enforces the ARN boundary at
verification time **regardless of where signing occurred**" is exactly the
problem: nothing binds the ARN to where signing actually occurred. A real binding
requires the KMS attestation/CA chain, which the prototype does not implement
(§6.9 admits no real KMS round-trip is measured). V13 should not be counted as an
adversarial vector.

---

# D. Overclaims and internal contradictions

## D1 — The motivating attack is explicitly not blocked, yet the paper says it is

§1 motivates the work with prompt injection and compromised runners. Appendix
A.3 (Responsible Disclosure) claims EviAssure *"prevents compromised runner
environments or **indirect prompt injection vulnerabilities** from bypassing
deployment safety gates."*

§6.7 reports the opposite: all 50 semantically anomalous profiles — including the
`ANOMALY_PROMPT_INJECTION` class — are **APPROVED** by the gate (Table 3, row
"Anomalous APPROVED (disclosed) 50/50 100.0%"). §2.2 additionally places
collector/sandbox compromise out of scope.

A prompt-injected agent produces genuine traces, honestly recorded and honestly
signed. The gate approves them. That is the correct and honest behaviour of this
design — but Appendix A.3 states the reverse, and the Introduction's framing
promises it. One of these has to go.

## D2 — "Completeness-carrying" is an overclaim of the count binding

Contribution 2 says the signed trace count provides "**completeness-carrying**
binding". Definition 5 says completeness is a property of the *collector* and
that "no downstream check can distinguish an action that was never recorded from
one that was honestly absent." The count binding prevents post-signing truncation
only. Rename it (e.g. "truncation-resistant binding") or the abstract and §2.3
are in direct conflict.

## D3 — Self-graded comparison table

Table 5's columns ("Trace Attest.", "Replay Prot.", "Fail-Closed") are EviAssure's
own design axes, filled in by the authors with unsourced ordinal grades
("Baseline", "Partial", "Manual"). SLSA is graded "Partial" on replay protection
with no citation to what that means. This table will be read as advocacy.

## D4 — 14 logical vs. 14 physical cores

§6 says "14 logical cores (10 performance, 4 efficiency)"; §6.2 says 16 workers
"oversubscribe the machine's **14 physical cores**". Pick one.

---

# E. Bibliography and venue compliance

## E1 — `carlini2024poisoning` has a fabricated author list — this is a desk-reject trigger

`docs/references.bib:107–113` lists:

> Carlini, Tramèr, Wallace, Jagielski, Choquette-Choo, Lee, Song, **Thakur,
> Sanjam**, **Mironov, Ilya**, **Nicholas, Zakir**

The actual authors of *Poisoning Web-Scale Training Datasets is Practical*
(arXiv:2302.10149, IEEE S&P 2024) are: Nicholas Carlini, Matthew Jagielski,
Christopher A. Choquette-Choo, Daniel Paleka, Will Pearce, Hyrum Anderson,
Andreas Terzis, Kurt Thomas, Florian Tramèr. The bib entry is a different (and
partly non-existent) author list — "Nicholas, Zakir" appears to be a mangling of
Zakir Durumeric, who is not an author of this paper.

The USENIX Security '27 CFP is explicit:

> *"Any violation to this policy which results in fabrications or hallucinations,
> including non-existing references or **incorrect authors**, invented claims, and
> falsified results is considered **academic misconduct** and might lead to the
> paper being **desk rejected** or other sanctions."*

The paper also carries a "Use of Generative AI" section stating LLM tools were
used for "verifying citation formats". A reviewer who finds E1 will read that
sentence very unkindly. **Fix before anything else, and run the CFP-recommended
`hallucinator` checker over the whole `.bib`.**

## E2 — Miscited cryptographic provenance

- Ed25519 EUF-CMA is cited to `bernstein2012high` + **`boneh2001short`**
  (Boneh–Lynn–Shacham, BLS signatures from the Weil pairing — a different scheme
  entirely) and to **`bellare1993random`** (Random Oracles are Practical) for
  "EUF-CMA secure". EUF-CMA is Goldwasser–Micali–Rivest (1988); the provable
  security of Ed25519 specifically is Brendel, Cremers, Jackson, Zhao,
  *The Provable Security of Ed25519: Theory and Practice*, IEEE S&P 2021. Cite
  that.
- `zheng2023judging` (LLM-as-a-judge) and `papernot2016cleverhans` are cited to
  support *"deterministic checks evaluated once each, so run-to-run dispersion
  there is zero by construction"* (§6, end). Neither paper has anything to do with
  that sentence. Remove.
- `taly2011definitive` (Automated Analysis of Security-Critical JavaScript APIs)
  is used as the "Static Security Analysis" row of Table 5. It does not represent
  that category.

## E3 — Positive verification (credit)

The three 2026 draft standards were checked against live sources and are cited
**accurately**: in-toto/attestation issue #554 ("RFC: agent-decision/v0.1
predicate for AI agent policy decisions", opened 2026-05-19); APAS v0.2.1-draft
at `agentic-research/signet` (including the self-attestation grading the paper
quotes — the doc really does say "at L1-L2, this is the fox guarding the
henhouse"); AAS-1 at aas-1.org. The `runtime-trace` predicate
(`https://in-toto.io/attestation/runtime-trace/v0.1`) also exists as cited. Good
work; this is the part of the bibliography that was done properly.

## E4 — Venue mechanics

- Body is **13 pages**, exactly at the '27 limit (13 pages excluding references
  and appendices). Every addition must be paid for with a deletion.
- Open Science Appendix present ✓; Ethics appendix present ✓ (no longer mandatory
  in '27, still encouraged).
- **Cycle 1 mandatory registration: Tue 18 Aug 2026. Paper: Tue 25 Aug 2026.
  Artifacts: Fri 28 Aug 2026.** (Cycle 2: 19 Jan / 26 Jan 2027.)
- Anonymity: `\author{Anonymous Submission \\ Submission ID: EVI-227}` — the
  fake submission ID is non-standard and serves no purpose; drop it.

---

# F. Minor

- Table 3 label says "L2 Policy gate" / "L3 Inspection" but §6.7 and the paper
  title the model "two-layer". There are three layers in the artifact.
- `benchmark/tamper_vectors.py` docstring still says "12 atomic attack
  scenarios"; `run_release_benchmark.py` docstring says "12-vector"; the
  `evaluate_ablation` docstring says "the 12 vectors". Stale.
- `evaluate_ablation` contains dead code: `if attr == "empty_registry"` is never
  reachable (no variant sets it).
- `_NONCE_TIMESTAMPS` is module-global state shared across engine instances —
  disclosed in Limitations, but it also means the ablation rows are not
  independent.
- V9's key ID `KEY-REVOKED-9999` is pinned in `trusted_keys.yaml` *and* listed in
  the CRL. That is the right way to test revocation, but it should be stated —
  otherwise a reader assumes the registry check fires first.
- §6.7's "note" field in `corpus_evaluation.json` is more honest than the paper's
  prose. Promote it.
- Elapsed-seconds fields in `parallel_throughput` record the *last* run while
  throughput is the *mean* — inconsistent.

---

# G. What survives attack (credit where due)

- The **trusted-key registry** in its default configuration genuinely resists
  attacker-supplied keys and spoofed key IDs.
- **Fail-closed exception handling** — `evaluate()` wraps `_evaluate()` and turns
  any parse error into BLOCKED. Verified with malformed input.
- **Duplicate-key wire detection** (V10) is a real, correctly-implemented
  parser-differential defence, and the vector is honestly constructed.
- **Canonical-JSON signature binding**, including `duration_ms` in the leaf.
- The **integrity-vs-completeness distinction** (Definitions 4–5) is stated more
  carefully than in most attestation papers, and §2.4's worked A→B→C→D→E example
  is genuinely good.
- The **frozen-metrics macro system** — every benchmark numeral in the prose is a
  generated macro bound to the artifact. This is better hygiene than 95% of
  submissions and it is why the numeric errors that remain are *definitional*
  (A5) rather than stale.
- The **2026 standards positioning** (§7.5) is accurate and well-sourced.

---

# Reproduction

```bash
python3 /tmp/demo_findings.py     # A1, A2, C2, C3, B2, A5/B5, B3
python3 -m pytest tests/ -q       # A4
python3 -c "from statsmodels.stats.proportion import proportion_confint as c; print(c(13,13,method='wilson'))"   # B6
```

All findings were reproduced against the working tree as of 2026-08-17.
