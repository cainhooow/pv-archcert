# ADR 0063: Versioned readiness question transport

Status: Accepted daemon transport; browser readiness integration remains separate.
Date: November 5, 2026. Extends ADRs 0058, 0061 and 0062.

## Context

Readiness already has authenticated private admission, fenced evaluation through
the shared verifier and explicitly historical receipts. Its HTTP entrypoint must
preserve that distinction and accept no browser-supplied verification facts.

## Decision

Extend the existing opt-in command daemon routes with the fixed
REQUEST_RELEASE_READINESS_EVALUATION action. Its only action field is the exact
admitted invocation digest. Existing project/repository, expected authority-context
identity, separate command credential and explicit idempotency key remain required.
Use request schema 2 and the schema-2 historical receipt contract from ADR 0062.
Job actions retain request/receipt schema 1. A schema-1 readiness request and a
schema-2 job request fail closed; unknown fields cannot post source/certificate,
artifact/permit, policy, recipe, result, actor, executable or signing assertions.

The daemon checks current private credential mapping, repository/operation grants,
authority selection and original invocation ownership through existing application
mediation. It accepts the question and publishes no verification result itself.
The separately provisioned controller observes through the existing SELECT-only
adapter and public verifier, then publishes through original coordination fencing.
No observer, runtime, key or execution capability enters the HTTP request.

Same-key acceptance retains the original request and receipt. A different explicit
key requests a separate observation, as defined by the existing readiness journal
semantics. This creates no duplicate certification or build workflow. Historical
receipt GET requires current scope/operation authorization and the exact retained
authority context. Revoking credentials or backend grants cannot be bypassed by
replaying an original URL. APPLIED is evaluation, including possible denial; an
unavailable observer cannot become ALLOWED. An allowed receipt remains historical.

Keep existing body/URI/concurrency/service deadlines, no-store/nosniff response
headers, credential reload and opt-in mounting. Do not change M6 claims, evidence,
policy, timeout, runtime, signing or native qualification. Release-build and review
disposition remain absent from the wire vocabulary. Existing browser roles and
forms remain unchanged by this transport addition; browser readiness requires its
own role/CSRF/object mediation, receipt UI and qualification.

## Validation and consequences

Test unsupported schema combinations, authority-field rejection and missing,
legacy or wrong-operation credentials before storage. Real PostgreSQL establishes
same-key concurrent replay, distinct explicit observation keys, exact context,
object/project isolation, retained schema-2 receipts and private credential reload.
Use explicit unavailable observation capability in metadata HTTP fixtures; do not
manufacture a positive verifier result. Actual public-verifier/controller positive,
outage and SIGKILL qualification remains the separately retained ADR 0062 corpus.
Keep prior daemon/job and protocol regressions. Full browser integration, remaining
M9 corpora and exact final gates remain open; M9 is INCOMPLETE. M10, M11 and Genesis
remain NOT STARTED.

Posting readiness booleans, executing observation in an HTTP acceptance handler,
silently reinterpreting schema 1, or treating historical ALLOWED as a live lease was
rejected. Versioned identifier-only requests preserve a narrow, auditable question.
