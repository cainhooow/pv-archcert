# ADR 0043: Review before immutable execution admission

Status: Partially implemented: session journal, immutable publication, accepted-review
restore and transactional reviewed admission. Controller and issuance integration
remain outstanding.
Date: October 20, 2026.
Extends ADRs 0035–0037 and 0041–0042.

## Context

Ravenport JobInputs pins the complete execution plan before admission. An adaptive
challenge changes that plan's digest. Replacing an admitted plan would violate the
existing immutable-input contract. A semantic response is also nondeterministic;
an ordinary worker lease retry cannot authorize silently calling a provider again.
The current schema-1 artifact-kind constraint has no Ironcrest stages, and its
evidence manifest has no extension slot. In-memory restore does not solve these
durable orchestration requirements.

## Decision

Introduce a separate project-scoped authority review session before Ravenport
execution admission. Reserve its future job UUID without granting execution
authority. Pin accepted target and optional baseline submissions, full immutable
source identities, actor/project/repository, base plan, deterministic policy,
authority profile, knowledge bundles, extractor registry, challenge registry and
reviewer selection. Scope/grant and accepted-source checks precede any private
knowledge read. Target configuration supplies none of these authority inputs.

Keep the existing queued/running job and attempt semantics unchanged. The review
session may not execute targets. Only a complete accepted review, conservative
semantic gate and frozen authority challenge selection can produce the NEW final
plan for a separately admitted Ironcrest job. Every original mandatory step must
remain present with the same authority provenance, command, profile and budgets.
Preserve the reserved job identity and exact final plan/profile/policy pins at that
admission boundary; no later mutation or implicit latest selection is allowed.

Use the existing project-scoped ImmutableArtifactStore for bytes. Add separately
versioned PostgreSQL session metadata and create-only role references for the authority profile, knowledge,
impact, request, accepted review/failure, gate, challenge plan and challenge result.
Each role records schema/producer/digest/size and STAGING/AVAILABLE. Availability
requires bounded verified readback. Existing historical artifact rows, migrations
and certificate semantics must not be rewritten.

Provider invocation needs a separate durable claim after request preparation.
Exactly one concurrent controller may acquire that claim. Pin its request and
audit time before invocation. Never expire/reclaim it merely because a process
disappeared: the provider may have completed remotely. Persist immutable response
metadata before publication and independently verify bytes before acceptance.
Recovery with accepted response bytes restores and validates them without another
provider call. An in-flight invocation with no recoverable accepted response is
INCONCLUSIVE and blocks admission. A new review needs explicit authority policy
and a new session/review identity; it cannot overwrite the old result.

Local exact replay can have a separately explicit recovery policy because the
response bytes can be pinned before the adapter call. This does not establish
exactly-once external inference. No external provider or disclosure authorization
is added by this decision.

## Versioned authority profile

The application now constructs `ironcrest-controlled-v1` version `1.0.0` as an
immutable authority capability. Its canonical artifact pins the selected policy,
extractor registry, sorted authority knowledge bundles, controlled challenge
registry, mandatory local replay review, gate algorithm, required idempotency
challenge, knowledge/semantic limits and denied external disclosure. Request and
session validation reject mismatched selections. There is no repository parser or
deserialization path that grants this capability. The profile currently supports
the controlled settlement API only; it makes no general challenge support claim.
Historical policy bundles and certificates retain their existing identities and
semantics. This profile capability alone does not implement admission or issuance.

## Implemented admission transaction

`IroncrestWorkflow::freeze_admission` validates the separately versioned profile,
exact session/request/accepted review and base inputs, preserves every mandatory
step, resolves registered bounded challenges and publishes one final challenge
plan before admission. The retained authority recipe must reconstruct exactly the
new execution-plan digest. The schema-2 challenge-plan artifact binds the session
pin, base/final plan digests, registry, request, review and gate. The schema-2 gate
artifact binds its algorithm, profile, accepted review and exact required challenge
identities (registry, template version and final bounded parameters). CONTINUE
still grants no deterministic property; required challenge execution is a separate
obligation before issuance. A failed, incomplete or blocking review cannot obtain
the admission capability.

Migration 0005 adds create-only `ironcrest_admissions`. Under the session row lock,
admission compares the complete pin and all seven AVAILABLE reviewed role
references, rechecks the grant under a shared row lock and accepted target/baseline,
then inserts the reserved job ID, final inputs, complete evidence linkage and audit
in one transaction. Exact concurrent/restarted calls return the same job; conflicts
reject. Worker leases and historical job inputs are not repurposed. The capability
has no deserialization constructor. These application/storage APIs still require
controller and authenticated admission composition; they do not establish the
complete certification lifecycle alone.

## Continuation and signing

After admission, use the unchanged worker, rootless runner, exact-attempt gates,
leases, runtime reconciliation and cleanup. Its final immutable plan already
contains approved challenges. A committed valid WorkerResult remains reusable
under existing Ravenport recovery; do not rerun accepted target work to reconstruct
semantic metadata. Challenge result evidence must identify its authority test,
registry, plan, exact source and actual controller execution records.

A new Ironcrest authority profile/policy identity must require semantic review and
the selected deterministic challenge evidence. Historical policies acquire no such
requirement. Both controller continuation and certificate preparation must reject
missing, stale, foreign or incomplete Ironcrest evidence. Semantic CONTINUE adds
zero deterministic property proof; the existing issuer must still independently
re-evaluate every deterministic requirement.

Define an explicit schema-2 evidence manifest construction that binds the original
schema-1 deterministic manifest and typed Ironcrest artifact identities, including
the authority profile and all accepted knowledge/review/challenge evidence. Keep
legacy schema-1 manifest construction byte-for-byte unchanged. Certificate schema
1 still signs the resulting manifest digest with the existing Ed25519 boundary.
Offline verification requires no knowledge, provider, PostgreSQL or runtime.
Exact manifest grammar and compatibility vectors must accompany its implementation.

## Security implications and consequences

The authority session/store/controller remain trusted operational code. A digest
alone does not authenticate provenance or authorize cross-project access. Database
owner, same-UID/root and compromised authority provisioning remain residual risks.
Pending invocations and unavailable artifacts trade availability for conservative
admission. No force-pass, cleanup assertion, baseline downgrade, policy mutation or
new worker credential is introduced.

Required validation includes real PostgreSQL races and immutable pin checks, all
specified persistence crash checkpoints, cross-project/source/job/request replay,
no duplicate accepted review, no accepted target rerun, legacy certificate vectors,
Bottle rejection, semantic-blocker/no-certificate and authenticated successful
source-to-certificate/offline verification. Until those pass, Ironcrest remains
incomplete. Existing exact Stoneward qualification is neither broadened nor used
as proof of these new control-plane guarantees.

## Alternatives

Editing JobInputs after review invalidates admitted identity. Reusing worker lease
expiry for provider retry can produce a different review silently. Storage without
durable stage metadata cannot safely recover an accepted response. Changing the
certificate cryptographic format is unnecessary. These alternatives are rejected.
