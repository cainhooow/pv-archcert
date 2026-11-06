# ADR 0065: Verified, atomic private release-build request admission

Status: Accepted private application/storage design; public request selection,
dispatcher integration and browser transport remain separate.
Date: November 5, 2026. Extends ADRs 0048, 0053, 0055 and 0060.

## Context

The command journal can freeze an M6 build admission and its original registered
source-certificate reference. A frozen request or database certificate row does
not establish cryptographic validity. Separately opening a release invocation and
then recording the command receipt would leave partial accepted state on a crash.

## Decision

Add a narrow application public-verification port and a non-deserializable prepared
release-build capability. The preparer reloads current project/repository/operation
grants, checks the exact processing generation and selected authority context, then
reads the original project-scoped immutable certificate. Reject a reference above
the existing M6 decoder's 64 KiB bound before reading; independently compare the
returned size and digest. The trusted adapter selects an explicitly supported
recipe and public keys and delegates unchanged to M6 `verify_source`. It cannot
substitute a newer recipe, choose target-provided authority or sign anything.

The capability binds command identity, canonical frozen request and processing
generation. It is not a serialized browser assertion or execution claim. Atomic
storage mediation rechecks the original live command lease, current independent
grants, completed certification/source/certificate object binding and capability.
Changed selected context is a known no-effect rejection. Authentication, binding,
conflict, infrastructure and fencing errors propagate without positive admission.

Share the existing M6 open operation without changing its SQL, bind order,
preconditions, conflict behavior or BUILD_ADMITTED audit. Its original entry point
still validates canonical input before starting its original transaction. The new
entry point performs the same mutation inside the command transaction, publishing
the immutable invocation, release audit, command receipt and command audit together.
A failed receipt rolls all four back. No migration or historical identity changes.

APPLIED / ReleaseBuildRequested means the frozen M6 workflow was admitted. It does
not mean either build ran, was reproducible, received a permit or is release-ready.
This operation publishes no evidence roles and claims neither A nor B. Existing
M6 claim prerequisites prevent execution until the separately trusted M6 workflow
publishes its verified INPUT and SOURCE_CERTIFICATE bytes. That workflow must
resume exactly the admitted input under its original recipe/key selection; its
non-expiring independent execution claims, uncertainty and post-cleanup signing
semantics remain unchanged. A command lease never permits another M6 execution.

## Security, compatibility and consequences

The shared public-verifier adapter gains only source-verification behavior using
its existing explicit public trust selection and concurrency budget. Domain,
application and storage receive no cryptography implementation, private key,
runtime, shell, acquisition credential or authority-policy selector. This private
unit activates no daemon, controller-dispatch or browser release-build endpoint.
Those boundaries must independently resolve identifier-only requests against fixed
authority provisioning and qualify authentication/RBAC/idempotency/recovery.

Use real PostgreSQL for concurrent intent/receipt publication, rollback, current
grant denial, certificate substitution and expired-generation rejection. Metadata
fixtures establish mediation, not source certification, execution or native
qualification. Existing M6 regressions retain their original exact scope. Actual
process-crash and end-to-end build request qualification remain required before
M9 closure. M9 remains INCOMPLETE; M10, M11 and Genesis remain NOT STARTED.

Accepting posted certificate validity, admitting before independent verification,
publishing a receipt in a separate transaction or reclaiming a non-expiring build
claim through the command lease were rejected.
