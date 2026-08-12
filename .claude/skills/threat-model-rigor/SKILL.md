---
name: threat-model-rigor
description: Write and audit threat models for security papers — adversary capabilities, trust boundaries, assumptions, adaptive attackers, and scoping of security claims. Use this skill whenever a paper claims a defense, mediator, detector, or guarantee; whenever reviewing what an attacker can and cannot do; and proactively whenever someone writes "prevents", "blocks", "guarantees", "secure against", or evaluates a defense against attacks.
---

# Threat model rigor

The fastest way to lose a security paper is a defense whose threat model is
implied rather than stated. Reviewers do not attack the mechanism first; they
attack the boundary of the claim.

## What a threat model must state

**The adversary's goal.** Specific, not "compromise the system". Exfiltrate a
credential. Cause an unauthorized tool invocation. Get a malicious dependency
into the build. The goal determines what counts as a successful attack, and
therefore what your ASR is measuring.

**Capabilities, enumerated.** For each: can the adversary read it, write it,
replay it, reorder it, drop it, or observe timing on it? Be specific about
memory, prompts, tool outputs, network position, and supply-chain access. A
capability you do not list is one a reviewer will assume you overlooked.

**Capabilities explicitly excluded, with justification.** "The adversary cannot
modify the policy file" is legitimate if the policy is signed and you say so.
The same sentence with no justification is where the paper dies. Every exclusion
needs a reason grounded in a mechanism, not convenience.

**Trust boundaries.** Draw them. What is inside the TCB, what is outside, and
what crosses. Then check: does the implementation actually place them where the
figure says? Mismatch between the diagram and the code is a specific, common,
fatal finding.

**Assumptions, itemised and load-bearing.** Cryptographic hardness, correct key
management, complete mediation, non-collusion, honest majority, a trusted
bootstrap. For each, state what breaks if it fails. An assumption whose failure
you have not considered is not an assumption, it is a hole.

**What is out of scope.** Say it in the paper, not in the rebuttal.

## The completeness test

For an enforcement mechanism, the security claim rests entirely on complete
mediation. Every path to the protected operation must pass the check.

- Enumerate the paths. Direct call, SDK wrapper, retry logic, async callback,
  batch endpoint, admin interface, error handler, deserialization path.
- For each, show the check is on it. In the code, not in the design.
- SDK monkey-patching and interposition are famously incomplete. If your
  enforcement depends on wrapping a third-party library, that is a limitation to
  state prominently, not a detail for the appendix.
- One unmediated path collapses the guarantee to zero. Reviewers know this and
  will look.

## Adaptive attackers

A defense tested only against attacks that predate it is untested. This is the
single most common substantive rejection reason for defense papers.

- Assume the adversary read your paper. What do they do?
- Construct the strongest attack *against your specific mechanism* and report
  its result, including when it succeeds.
- Distinguish design-set attacks from held-out attacks everywhere in the paper.
  A defense that scores perfectly on the corpus used to build it has shown you
  nothing about robustness.
- If your mechanism is deterministic and structural — a capability check, a
  type system, an authorization boundary — say that it holds *by construction
  under the stated assumptions*, and then direct the effort at whether the
  assumptions hold. That is a stronger and more honest argument than an
  empirical success rate.
- Text-shaped defenses (keyword filters, instruction hierarchies, wrapper
  prompts) are especially prone to looking strong on a design set and failing
  on paraphrase. Test paraphrase explicitly.

## Scoping the claim

Match the verb to the evidence:

| Verb | Requires |
|---|---|
| "prevents" / "guarantees" | A proof or a construction argument, plus stated assumptions |
| "mitigates" / "reduces" | Measured effect with a CI, against a named baseline |
| "detects" | TPR *and* FPR at a stated threshold and base rate |
| "is secure against" | The threat model it is secure against, named inline |

"The first system to..." requires a literature claim you can defend. Prefer "to
our knowledge, the first" — and then actually search, because a reviewer who
knows one counterexample discards the contribution.

## Ethics, which is now a gate

Security venues increasingly reject on ethical grounds independently of
technical merit. IEEE S&P 2027 has a research ethics committee that can
recommend rejection; ACM CCS requires an Ethical Considerations appendix for any
paper with potential concerns; USENIX strongly encourages one.

Address, where applicable: human subjects and IRB status; vulnerabilities found
in real systems and the disclosure timeline; data collected from live systems
and its legal basis; harm from releasing an attack, and why release is net
positive; dual use. "No ethical concerns" is an acceptable answer only when you
have actually checked each of these.

## Auditing an existing threat model

1. Read the threat model, then read the evaluation. Do the experiments test
   *that* adversary, or a weaker one?
2. Find the strongest attack the model permits that the paper does not run.
   That is the reviewer's first question.
3. Check the figure against the code for boundary placement.
4. List every "we assume" and ask what breaks if it is false.
5. Check whether any claim in the abstract exceeds what the threat model scopes.
   Abstracts overreach far more often than technical sections.
