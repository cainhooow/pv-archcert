# ADR 0046: Separate canonical knowledge from bounded semantic context

Status: Accepted. Date: October 21, 2026.
Extends ADRs 0041–0044; roadmap terminology follows ADR 0045.

## Context

The first immutable ArchCert preparation probe produced 1,616,710 knowledge bytes
and 580,549 impact bytes. Direct embedding exceeds the 1,048,576-byte reviewer
request ceiling. Increasing the limit or modifying canonical evidence would hide
the scalability and coverage problem. Canonical M6 remains planned; this is
pre-Genesis enablement within the implemented M7/M8 capabilities.

## Decision

Application owns a deterministic, versioned Semantic Context Packager. Canonical
knowledge and impact stay complete within extractor bounds, immutable and separately
persisted. A new schema-2 request embeds a separately canonicalized package and its
SHA-256. Historical schema-1 preparation remains available with identical semantics.
Responses bind the entire exact request digest, including package identity.

The new authority-only packaging capability pins algorithm, byte/count ceilings,
priority order and fallback behavior. It has no target deserializer. Mandatory
source/baseline/project/job, knowledge/impact, bundle, policy and authority profile
identities, complete policy requirements and authority assertions precede optional
repository data. All active approved findings and invariants are retained in full
bundles or packaging fails. Complete digest-checked profile and policy bytes are
mandatory reviewer context and also remain separate immutable evidence. Profile
contents include the exact semantic gate and challenge requirements. Target prose cannot assign priority.

Selection uses authority predicates (changed paths, mechanically impacted syntax,
unresolved edges, tests and entry/migration syntax) and canonical input ties. It
performs bounded scans/sorts over already bounded artifacts without recursive graph
expansion. Each selected item is serialized once for budget accounting. Excerpts
have aggregate/per-file ceilings; source size never serves as a request-size estimate.
The complete envelope is serialized and checked before any reviewer invocation.

Packages record included/excluded files, nodes, edges, tests, findings, invariants,
blind spots and source bytes, category/reason evidence, extractor coverage, impact
summary, configured request bytes and actual package bytes. Requests additionally
record their exact serialized size. Digest-only impact selection lists and omitted
repository context generate explicit SEMANTIC_CONTEXT_PARTIAL evidence. Original
coverage/blind spots remain bound by the full artifact digests, even when only a
bounded subset of their explanatory entries fits.

Authority classifies FULL_CONTEXT, PARTIAL_ACCEPTABLE or INSUFFICIENT_CONTEXT.
Partial acceptance is an explicit engineering profile choice, never complete
semantic coverage or deterministic proof. Existing profiles retain strict complete
context requirements. Mandatory overflow is INCONCLUSIVE and produces no accepted
request, provider invocation or certificate. A provider cannot promote coverage.

The request role persists the entire package and its digest atomically in the
existing immutable object journal. Thus the package checkpoint is the existing
request checkpoint: recovery reconstitutes the same bytes and must match the
create-only request reference before invocation/restore. No new mutable package
record or independent provider retry is introduced. Existing manifest roles bind
the package transitively through the exact request; schema-1 certificate signing
and offline verification require no new service.

## Security implications

Project/source/baseline/policy/profile/bundle/knowledge/impact identities and the
packaging policy/algorithm are all inside package identity. Request identity adds
reviewer selection and response limits. Identical prose under different scope
cannot authorize replay. A digest is an integrity reference, not a trust signature.
Authority provisioning and accepted input bounds remain trusted. Finite bounds do
not prove parser safety, universal model coverage or global denial-of-service
resistance. Repository and provider possess no runtime or signing capability.

## Alternatives and consequences

Raising the limit, trimming canonical evidence, provider-selected retrieval and
repository priority annotations are rejected. Bounded context necessarily loses
information; explicit omissions permit honest engineering review without claiming
whole-source reasoning. A profile requiring complete relevant context must remain
inconclusive on such packages. New authority profiles must pin this policy rather
than silently changing historical profile bytes.

Packager/policy version 1.1.0 explicitly requires complete digest-checked authority
profile context. Earlier development version 1.0.0 digest-only profile requests
are not reconstructed with these semantics; exact profile/request pin checks reject
them. The final provider boundary independently checks actual serialized bytes;
limit-1/limit/limit+1 regression cases count provider invocations.

Authority bundle arrays use canonical digest order, independently of provisioning
iteration order. Schema-1 incomplete-context review acceptance/restoration remains
available with its original REQUIRE_MORE_EVIDENCE gate; the new insufficient-package
pre-invocation rejection does not reinterpret historical review artifacts.
