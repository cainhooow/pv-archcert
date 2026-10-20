# ADR-0022: Deterministic authority policy and five-state property verdicts

Status: Accepted for Milestone 4A. Extends ADRs 0003, 0020 and 0021.

Only authority policy interprets typed observations. `archcert-policy` is a pure
consumer of application plans/observations and domain source/execution types.
It cannot import the runner, materializer, source adapter, HTTP, signer or an LLM.
Application and domain do not depend on policy. CLI composes the evaluator after
execution; HTTP submission stays unavailable.

Replace the unused `PolicyEngine(EvidenceRecord) -> CertificationStatus` scaffold.
It accepted pre-interpreted verdicts and exposed certification prematurely. The
inactive evidence scaffold now references payloads without carrying a verdict.
There are no compatibility consumers of the replaced interfaces.

| Verdict | Meaning |
| --- | --- |
| PROVEN | Required authoritative evidence positively establishes the defined property |
| FAILED | Authoritative evidence establishes that the defined property is false |
| NOT_PROVEN | Required evidence is absent or insufficient, distinct from failure |
| NOT_APPLICABLE | Authority conditions explicitly exclude this target/authority profile |
| INCONCLUSIVE | Evidence exists but ambiguity, contradiction, infrastructure failure or unsupported versions prevent reliable interpretation |

Commands mean only that the explicitly authority-designated command completed
with exit zero in the bound, bounded environment. Tests do not prove coverage or
absence of defects; builds do not prove artifact security; typecheck does not
prove checker soundness. Source completeness uses the existing immutable snapshot
status, including unresolved LFS/submodule facts, without source parsing in policy.
Sandbox/network properties describe verified configuration before each planned
execution, not escape resistance, runtime attestation or a toolchain version.

Schema 1 has fixed property IDs, non-recursive typed rules, and explicit boolean
requirement/non-applicability permission. Command rules select exact authority
step IDs and categories and require `AuthorityRequired` provenance. A project's
label, command name, stdout, or requested category alone cannot satisfy them.
Project requests may add steps; all planned steps require the source/environment/
network facts in this development profile. No missing step infers non-applicability.
Authority applicability is either ALWAYS or an explicit selected-policy-profile set.
It uses the separately pinned bundle/profile ID, never project-requested execution
profiles or the presence/absence of a project step.

Expected execution IDs come separately from dispatch/controller results. Evidence
must match source commit/tree/SHA-256, whole plan digest, step, execution ID,
profile, factual discriminator/category, schema and allowed producer/version.
There is at most one execution per step; retries require a future explicit model.
The controller failure producer can report only an unavailable execution
(SandboxFailure with no exit), never successful source/isolation/completion facts.
A policy listing an unknown producer does not install an evaluator for it.

Identical redundant observations are deduplicated. Different authoritative facts
for one expected slot are INCONCLUSIVE. Unknown versions are INCONCLUSIVE.
Foreign bindings cannot establish a property (NOT_PROVEN); mixed invalid and valid
facts cannot silently pass. Missing facts are NOT_PROVEN. Completed exit 1–255 is
FAILED; absent/negative/out-of-range completion exits are INCONCLUSIVE. Timeouts and
resource limits fail the explicitly bounded completion property; start/runtime/
ambiguous termination failures are INCONCLUSIVE. A controller failure before runner
evidence exists creates only the typed unavailable-execution observation, never
invented source or isolation success.

Within a multi-slot property, deterministic precedence is INCONCLUSIVE, FAILED,
NOT_PROVEN, NOT_APPLICABLE, PROVEN, then reason-code enum order. The public stable
reason-code spelling is the interchange contract; schema changes must preserve
or explicitly version tie precedence. Evidence references sort by payload digest;
selectors sort by step. Contradictions are never resolved by arrival order.

P0 means critical source/isolation/authority assurance; P1 essential engineering;
P2 additional engineering; P3 informational engineering. P0/P1 always block when
unsatisfied; every mandatory property blocks at every severity. Optional P2/P3
findings may remain advisory. No risk acceptance, waivers or override is supported.
NOT_APPLICABLE satisfies a blocking requirement only with explicit authority
permission. Failures and missing required evidence never become a best-effort pass.
