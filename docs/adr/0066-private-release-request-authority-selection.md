# ADR 0066: Explicit private authority selection for build requests

Status: Accepted native request design; dispatcher and public transport remain
separate. Date: November 5, 2026. Extends ADRs 0020, 0032, 0048, 0057 and 0065.

## Context

A browser or project cannot select an M6 recipe, image, toolchain, policy or keys.
The existing certification authority grant does not implicitly authorize a release
build. Its established command-context identities must retain their exact meanings.

## Decision

Add an optional strict release-build selection to private authority provisioning.
It declares its schema, explicit supported recipe version, fixed Rust binary,
digest-pinned environment and dependency/toolchain inventories, approved source
policy digest and source/release public-key identities. It contains no executable
argv, private key, credential, runtime endpoint or target-controlled path. Unknown
fields/schema, unsupported recipe versions and invalid recipes fail closed.

Retain the existing command-context construction byte for byte. All four existing
operations keep that context even when release provisioning is present. Build
requests require a distinct domain-separated context binding the original context,
the complete explicit release selection and the unchanged mandatory M6 release
policy identity. Missing selection cannot activate build requests. Credentials
remain excluded from context identity; operation grants remain independently
provisioned under their appropriate context. Resolve all provisioning selections
and repository permissions before inserting any requested command grants.
Provisioning a mapping with an unsupported build selection fails before any grant
changes; other independently provisioned operations remain usable.

The native request port accepts only an authenticated command authorization, an
owned completed certification job ID and an idempotency key. Check current scope
and independent database operation grants before job lookup. Require exact
project/repository/actor ownership, consistent verified certificate/issuance
metadata, the selected source policy/key
and the original bounded certificate reference. Reload the complete accepted source
passively from its original submission and compare its exact identity. No source
execution, mutable branch lookup or acquisition credential is involved.

Freeze the build input exclusively from that original source/certificate and the
private fixed recipe/environment/policy/key selection. Reuse the existing scoped
journal acceptance and workflow-intent coalescing across client keys. Acceptance
records REQUESTED only; certificate metadata is not cryptographic proof. Only
ADR 0065 independent verification and atomic sealed admission may publish APPLIED.
The request port itself opens no M6 invocation, publishes no evidence and claims
no execution or signing capability.

## Security and compatibility

Existing grants without release selection retain their old interpretation and
all existing job/readiness request identities. A legacy credential mapping may
retain the previously unsupported build operation, but it cannot authenticate a
new build request without explicit selection. Its other operations retain their
existing behavior. Historical build requests under the old context cannot acquire
new semantics or authority through later provisioning. No stored command, source,
recipe, certificate, permit, claim or migration is rewritten.

This unit adds no controller-dispatch, daemon or browser build endpoint. Existing
dispatch continues to reject unsupported build contexts until separately
integrated and qualified. Current repository/operation grants and the source/
certificate object binding are independently rechecked at journal acceptance and
eventual atomic admission. Administrator presentation role grants no signing power.

## Validation and consequences

Test absence/unknown selection, every selected identity, credential-independent
context identity, preserved legacy context, unknown private configuration fields,
scope/operation denial before passive source access, source-store loss, selected
policy/key mismatch and concurrent duplicate keys using real PostgreSQL. Metadata
fixtures qualify request resolution only. Existing public-verifier and M6 claims
retain their distinct qualification. Public request and process-crash qualification
remain open; M9 is INCOMPLETE and later milestones remain NOT STARTED.
