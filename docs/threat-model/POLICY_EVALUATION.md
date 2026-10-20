# Policy evaluation threat model — Milestone 4A

This is a process-local development authority boundary, not independent certification.
Trusted components are the controller, source/plan constructors, authority bundle
provisioning, approved command choice, evaluator and existing runtime TCB. Target
files, stdout, labels, requests and commands are hostile. No signature authenticates
reports yet. Production authority storage must be separate or access-controlled;
`policies/` belongs to the ArchCert authority checkout, never a target snapshot.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Project selects weaker policy | Authority selects requirements | CLI embeds one independently pinned policy; strict project schema rejects policy fields | Operator CLI access is authority; authentication/service storage deferred |
| Policy tampering | Evaluated bytes match expected authority | Immutable parsed bundle; independent canonical SHA-256; selected ID/version/digest comparison | Hash is not authenticity; malicious authority/build/distribution can replace both |
| Policy version confusion | Version is exact and part of identity | Strict schema, explicit version, separate selection pin, no fallback | Version governance is administrative |
| Digest substitution | Identity derives from actual normalized policy | No authoring digest field; SHA-256 computed internally; full reference comparison | Trusted caller must independently pin selection |
| Observation substitution | Exact plan/step/execution/profile/producer binding | Source plus plan digest, independently supplied expected execution, schema and producer allowlist checks | Public typed observations are trusted controller inputs, not cryptographic attestations |
| Cross-source/commit/job reuse | Foreign evidence cannot prove this source | Compare full source commit/tree/snapshot, exact plan and independent expected execution IDs | Compromised controller can forge observations and bindings |
| Missing evidence treated as pass | Completeness required | Explicit NOT_PROVEN; empty-plan guard; mandatory fail-closed eligibility | Future profiles must retain conservative requirements |
| Runtime failure treated as target failure | Preserve reliability and target outcome separately | Start/sandbox failures INCONCLUSIVE; genuine nonzero normal exit FAILED; no-evidence controller emits unavailable execution only | Runtime can lie; cleanup availability is separately reported and is not a command-success property |
| Contradictory duplicates | Arrival order cannot decide truth | Deduplicate identical facts; distinct authoritative facts in a slot INCONCLUSIVE; sorted references | Conflict-resolution/retry protocols deferred |
| Unsupported version | Unknown semantics never silently pass | Explicit schema and evaluator-known producer/version intersection; unknowns INCONCLUSIVE | Compatibility updates require authority review |
| NOT_APPLICABLE abuse | Missing evidence cannot exclude a requirement | Only authority ALWAYS/explicit selected authority policy-profile conditions; explicit satisfaction permission | Bad authority policy can deliberately over-exclude |
| Severity downgrade | Project cannot weaken blockers | Severity in canonical identity; unknown project fields reject; P0/P1 always block, all mandatory severities block | Authority administrator can publish bad policy |
| Stdout spoofing | Target cannot create facts/verdicts/findings | Evaluator has no stdout field/parser; typed controller exit facts only; authority provenance/category/step checks | A deliberately misleading authority-selected command can still exit zero |
| Nondeterminism | Same inputs produce same decisions/IDs | Pure evaluator; explicit audit time excluded; sorted policy sets/results/refs; finite permutation tests | Dependency/serializer or evaluator updates need version discipline; cross-OS CI still desirable |
| Resource-exhausting policy | Bounded finite work, no arbitrary execution | Predecode byte cap, typed fixed-depth grammar, count/string/step caps, observation/execution caps | Process-wide admission/RSS/I/O/allocator failure remain external concerns |
| Project elevates requested TEST label | Only authority-designated command proves generic property | Exact policy step IDs/category plus AuthorityRequired origin; projects only add requests | Operator command review remains essential; no semantic quality proof |
| Controller failure spoofs success | Unavailable evidence cannot create positive facts | Controller failure producer restricted to SandboxFailure/no exit; cannot assert source/sandbox/network success | Compromised controller can impersonate an allowed runner producer |

No waiver, accepted risk, human override, dynamic policy plugin, LLM authority,
PostgreSQL, certificate construction or signing is implemented. Existing rootless
OCI assumptions, source-ingress limits and native Linux NOT YET QUALIFIED status
remain. Digest identity protects substitution only when the authority selection is
itself trusted. Retained JSON is unsigned and editable outside the live boundary.
