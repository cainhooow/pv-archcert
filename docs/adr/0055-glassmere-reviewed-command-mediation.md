# ADR 0055: Reviewed certification command mediation

Status: Accepted design; HTTP and browser integration remain separately qualified.
Date: November 5, 2026. Extends ADRs 0043, 0050, 0053 and 0054.

## Context

The local job command executor intentionally cannot admit a reviewed profile.
Reviewed certification must retain the existing source/knowledge/review/gate/
challenge-plan chain, including all mandatory deterministic work. A browser
command must not replace that chain with a posted disposition or success flag.

## Decision

Add a distinct private command port that consumes the existing sealed
ReviewedIroncrestAdmission capability. Only the existing application workflow
constructs that value after validation and immutable publication. It remains
non-deserializable; neither browser JSON nor retained database JSON creates it.
No new signer, provider, runtime, review waiver or policy capability is added.

The original command binds an existing exact reviewed session and its base job
inputs. Before domain admission, compare the sealed capability's session, scope,
source, policy and base-plan identity with that request. Its final profile, image
and original attempt budget must also match. Only the already-validated additive
challenge plan may replace the base plan/retained recipe. Wrong capability or
context cannot select a newer default or create a different workflow.

Share the original row-locked reviewed-admission transaction body without changing
its SQL, argument order, source/baseline/grant checks, AVAILABLE role checks,
create-only linkage or reserved job identity. The legacy repository method keeps
its original transaction boundary. The new command path uses the same surrounding
transaction for domain admission, immutable linkage, domain audit and final command
receipt. Publication failure rolls everything back. Duplicate intent returns the
same original receipt and reserved workflow identity.

Expose an application restoration operation that accepts only an already retained
review role. It reuses the existing exact-request/hash/timestamp validation and
staged-publication recovery. It receives no SemanticReviewer and cannot claim or
invoke a provider. A missing or uncertain review denies certification admission;
it cannot be replaced with a successful response fixture. Supplemental CONTINUE
still supplies zero deterministic properties, and mandatory challenges still run
through the existing worker/controller lifecycle after admission.

## Security and qualification

Authentication, operation grants, exact authority selection and object scope remain
independent checks. Trusted composition must authorize the requested session before
private source/knowledge restoration. The application capability is passed only
between trusted services; public command DTOs contain scoped identifiers only.

Real PostgreSQL and immutable-store tests must cover identical-intent replay,
wrong session/capability, changed authority selection, receipt-publication rollback
and restoration without another provider invocation. They establish no model
correctness, target execution, native runtime enforcement or signature issuance.
HTTP role/CSRF/idempotency and actual process-kill recovery still require separate
validation. M9 remains in progress; M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Admitting a base job before review, accepting a serialized gate decision, calling
the local non-reviewed executor or treating semantic CONTINUE as proof would
weaken established authority boundaries. Reconstructing the original sealed value
costs bounded passive work and may deny availability when immutable bytes or exact
authority versions are unavailable. That uncertainty does not grant admission.
