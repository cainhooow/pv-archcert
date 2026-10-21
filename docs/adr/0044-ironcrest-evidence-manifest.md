# ADR 0044: Explicit Ironcrest evidence-manifest extension

Terminology: [ADR 0045](0045-roadmap-reconciliation.md) reconciles this work to M7 Asterwyn,
M8 Greywatch and their durable lifecycle integration. `Ironcrest` in retained
implementation identifiers and this document is a historical label. Canonical
M6 Ironcrest (Artifact Binding, Reproducible Builds & Release Permit) remains
PLANNED / NOT YET IMPLEMENTED. No security or compatibility semantics change.

Status: Implemented construction, compatibility guards and durable controller
composition; controlled source-to-certificate and restart regressions passed.
Date: October 21, 2026. Extends ADRs 0025, 0042 and 0043.

## Context

Schema-1 evidence manifests have no extension slot. Reinterpreting them would
change historical evidence identity. Certificate schema 1 already signs an exact
manifest digest, so an additive evidence format does not require new certificate
cryptography or an offline semantic service.

## Decision

Keep schema-1 manifest construction byte-for-byte unchanged. Define schema 2 as
restricted canonical JSON with exactly these producer fields:

- `schema`: 2;
- `kind`: `ARCHCERT_EVIDENCE_MANIFEST`;
- `deterministic_manifest`: the complete original schema-1 manifest object;
- `deterministic_manifest_sha256`: SHA-256 of its original canonical bytes;
- `ironcrest`: session UUID, complete immutable session pin, final execution-plan
  digest, and ordered `(role, ArtifactReference)` pairs.

The required role order is AUTHORITY_PROFILE, KNOWLEDGE, IMPACT, REQUEST, REVIEW,
GATE, CHALLENGE_PLAN, CHALLENGE_RESULT. Every reference includes exact SHA-256,
size, artifact schema and producer. Gate and final challenge-plan artifacts use
schema 2; the other current artifact kinds use schema 1. Reference schemas describe
actual artifact bytes, separately from database migration versions. Missing,
foreign, reordered or duplicate roles reject. Source, policy, final plan and
profile identities must match their corresponding deterministic/session context.
A schema-2 manifest cannot be wrapped again. No historical bytes are migrated.

`IroncrestWorkflow::record_challenges` accepts only the exact admitted job and
accepted attempt, rechecks reviewed object availability, validates the worker
result and persists canonical challenge results bound to registry, plan, source,
attempt and accepted worker-artifact digest. Failed/incomplete results are evidence
but cannot construct the additional Ironcrest issuance prerequisite. That private
capability has no deserialization API and adds no deterministic property proof.

The `ironcrest-controlled-v1` authority profile version 1.1.0 explicitly composes
the unchanged semantic-review gate with mandatory challenge obligations. Its gate
algorithm is `archcert-ironcrest-gate-v1/1.0.0`. The persisted gate retains both the
review decision and the authoritative decision. A review CONTINUE with pending
registered requirements becomes REQUIRE_MORE_EVIDENCE. Execution admission may
resolve only those frozen obligations; incomplete context/provider failure has no
resolvable obligation and remains blocked. The gate is never rewritten after
execution: the exact challenge result demonstrates satisfaction before issuance.
The earlier admission-only profile 1.0.0 and its artifacts are not reinterpreted.
An unsupported retained profile must fail closed, never select a newer default.

The separate `archcert-ironcrest-controlled-v1` policy version 1.0.0 requires both
the existing test step and `ironcrest-idempotency` under the existing deterministic
TEST_SUITE_COMPLETES rule. Its fixed canonical digest is independently reproduced
in the working evidence under its historical M6 label:
`2f0101fffb230caf6957065e91ba0655c25893dbee2f6105f44ce3e62cafef4e`.
The historical development policy is unchanged.
Certificate preparation for the new policy requires Ironcrest evidence and still
recomputes the full existing deterministic evaluation. PostgreSQL also refuses
direct historical-style admission for this new policy and blocks issuance
preparation/completion without the reviewed linkage and accepted challenge result.

Certificate schema 1, signed payload fields, Ed25519 signing and explicit-key
offline verification retain their meaning. The existing manifest-digest field now
binds schema 2 only for explicitly composed Ironcrest issuance. Offline signature
verification authenticates that digest; it does not rerun knowledge, semantic
review, challenges or policy, nor establish provider honesty.

## Security implications

A digest binds exact content, not authority provenance by itself. Controller,
metadata/object stores, authority provisioning and signing composition remain
trusted. Challenge output and semantic output cannot set policy verdicts. A
successful challenge is bounded deterministic evidence, not universal correctness.
A semantic CONTINUE alone cannot obtain the challenge prerequisite or make the
new deterministic policy eligible. Required context/provider failure remains
fail-closed. Evidence retention may contain private repository/authority material;
external disclosure remains denied by default.

## Alternatives and consequences

Changing schema-1 manifests silently is rejected. Certificate schema 2 and new
cryptography are unnecessary. Keeping only mutable database pointers would not
bind evidence and is rejected. Retaining the complete deterministic manifest costs
some metadata duplication while making historical semantics explicit. Consumers
must dispatch on manifest schema and must not interpret unknown versions as 1.
Existing certificate vectors continue to verify with their original public keys.
