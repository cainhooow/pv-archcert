# ADR 0042: Semantic veto, immutable review evidence and bounded challenges

Status: Accepted design for Ironcrest; implementation status is recorded in the
current architecture snapshot. Date: October 20, 2026.

## Context

Semantic review can identify plausible defects that passing mechanical tests miss.
It is nondeterministic and vulnerable to hostile context. It cannot establish a
deterministic property or gain issuance authority.

## Decision

An application-owned SemanticReviewer port consumes a frozen bounded request and
returns response bytes or a classified provider failure. No provider SDK types
enter domain/application. The request binds project/job, source, baseline,
knowledge/impact digests, authority bundle and policy/profile identities, excerpts,
observations and limits. Authority instructions are a separate fixed contract;
every repository byte, filename, comment, test and agent claim is labeled data.
Target configuration cannot select an adapter, command, model or credential.

NO EXTERNAL SOURCE DISCLOSURE is the default. Automated tests use deterministic
replay. No paid provider is required. A future external adapter requires explicit
authority disclosure authorization and separate credential provisioning. It never
receives signer, ingress, database administrator or runtime credentials. A future
local process adapter must use an absolute authority-selected executable, literal
arguments, cleared environment, finite input/output and deadline, without a shell.

The accepted structured response is distinct from policy verdicts. Observations,
concerns, blockers, hypotheses, affected authority entries, blind spots and proposed
challenge templates have stable local IDs. Unknown fields and invalid bindings
reject. Raw accepted response bytes, digest, request digest, reported model,
adapter identity/version, timestamp, bounds, truncation and failures are retained.
A remote model name is not reproducibility. A later review may differ.

A deterministic semantic gate returns BLOCK, REQUIRE_MORE_EVIDENCE or CONTINUE.
Missing required review, provider failure, incomplete response or unresolved
required context prevents issuance. Authority-relevant blockers may veto issuance.
CONTINUE adds zero deterministic facts. Every existing deterministic requirement,
cleanup/integrity gate and signing boundary remains necessary. Historical bundles
do not acquire semantic requirements. Ironcrest requirements need a separately
pinned versioned authority profile.

Proposals name only a registered template, bounded parameters, related invariant
and reason. They cannot specify shell, image, executable, mount, network,
privilege, endpoint, resource limits or credentials. Only a digest-bound authority
registry can resolve proposals into additional validated checks. Unsupported
categories remain unsupported. Additional checks compose with all mandatory
checks and use the existing execution boundary. Authority test source is private
from the repository before execution; confidentiality from hostile code while
executing in the same sandbox is NOT PROVEN and is not promised.

## Evidence and recovery

Use Ravenport project/job-scoped immutable artifact storage and durable metadata.
Persist exact pinned inputs before invoking a reviewer. Resume accepted response
bytes without silently invoking a provider again. A crash with an invocation in
flight and no accepted response remains uncertain; automatic re-review requires
explicit policy. Persist the gate, challenge plan and accepted challenge execution
evidence before continuation. Recovery must revalidate all bindings, not replay
another source/project/job/policy's artifact or rerun valid accepted target work.

Certificate schema 1 and Ed25519 are unchanged. Existing schema-1 manifests have
no extension slot: any additive knowledge binding must use an explicitly versioned
evidence-manifest extension described and reviewed before implementation. Legacy
manifest construction must retain exact bytes. The new manifest binds the same
deterministic bundle plus typed knowledge/impact/review/challenge digests. Offline
verification continues to check the signed schema-1 payload and explicit trusted
key, with no provider, runtime, controller, database or knowledge service.

## Consequences and alternatives

Semantic false positives can block valid software; false negatives can miss real
defects. Neither is a deterministic correctness proof. Prompt injection containment
comes from bounded capabilities and gate logic, not a claim that a prompt is
cryptographically safe. Direct model verdicts, executable model commands, automatic
policy approval and target-supplied provider responses are rejected. Integration
must not claim completion until durable recovery, controlled challenge execution,
source-to-certificate and semantic-blocker demonstrations pass.

## Implemented controlled composition

Profile `ironcrest-controlled-v1` version 1.1.0 composes the unchanged review gate
with registered deterministic obligations. Its immutable gate artifact retains the
review decision and records REQUIRE_MORE_EVIDENCE while approved challenges remain
pending. Only complete non-blocking review may freeze that resolvable plan before
admission. Failed/incomplete required review still blocks. The gate artifact is
never rewritten to create proof; accepted challenge results and the independently
evaluated new deterministic policy must satisfy issuance separately.

The durable controller now restores accepted review without reinvocation, persists
challenge results and passes the private Ironcrest prerequisite to the existing
issuer. Controlled live blocker/outage paths never admit an execution job or enter
signing; a real challenge failure remains NOT_ELIGIBLE under semantic CLEAR. The
manifest extension is explicitly versioned in ADR 0044; certificate v1 and offline
verification retain their meaning. Local replay is the only configured provider,
so no live model-quality, drift resistance or universal bug-detection claim follows.
