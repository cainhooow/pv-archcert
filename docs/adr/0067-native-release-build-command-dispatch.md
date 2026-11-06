# ADR 0067: Private verified build-command dispatch and admission receipts

Status: Accepted native integration design; public build submission remains absent.
Date: November 5, 2026. Extends ADRs 0048, 0056, 0062, 0065 and 0066.

## Context

The private request resolver freezes fixed authority inputs, and the application
can seal independently verified admission. The controller must compose these
without acquiring another execution/signing path or reinterpreting historical
unsupported requests under newly provisioned authority.

## Decision

Add a fixed native `request-build` command accepting only project, repository,
owned certification job ID, expected current authority context and idempotency key.
Load the independent command mapping and exact owned mode-0600 token file. There
is no token argument, actor, recipe, image, policy, key, argv or runtime selector.
The existing native request port authorizes before passive exact-source loading
and queues REQUESTED only. HTTP and browser build actions remain unsupported.

Dispatch selects the context for the exact operation. Existing job/readiness
contexts retain their meanings; build requests require explicit ADR 0066 selection.
Old unsupported requests under the legacy context cannot acquire build authority.
Load an explicitly selected public-verifier configuration and a separate SELECT-only
observation database credential. Read the original bounded registered certificate
through the existing immutable store, delegate to unchanged M6 verification and
obtain the ADR 0065 sealed generation. Only its atomic admission executor may
publish APPLIED. No execution claim, runtime call, evidence publication or signing
occurs in this dispatcher.

Missing/unavailable verification before admission is a known no-effect rejection,
with INFRASTRUCTURE_UNAVAILABLE. Invalid source/certificate/selection binding before
admission is a known no-effect IDENTITY_MISMATCH rejection. Same-key replay retains
that rejection; a fresh explicit key may retry under ADR 0056. Grant/fencing errors
propagate. A conflicting immutable M6 admission is a known no-effect domain
precondition rejection after transaction rollback. Infrastructure or commit
uncertainty during atomic admission is never converted into a known rejection:
retain the original request for fenced recovery and read its durable receipt.

Build receipts use explicit public schema 3. APPLIED / RELEASE_BUILD_REQUESTED
means the M6 workflow was admitted, including idempotent reuse of its identical
admission. It does not mean builds completed, reproducibility was proven, a permit
was issued or release is allowed. A receipt carries only the exact invocation;
current state still requires the separate live query. Pending and rejected build
receipts use the same explicit grammar. Existing job receipts retain schema 1;
readiness retains schema 2 and HISTORICAL_OBSERVATION. Internal schema-1 request,
outcome, intent and audit bytes and every M6 cryptographic format remain unchanged.
Older consumers must reject schema 3. This response change adds no build request
variant to the public HTTP grammar.

## Qualification boundary

Use real PostgreSQL, actual controller processes and the retained public OpenSSL
conformance vector to qualify native dispatch, source verification, immutable
receipt projection, known no-effect retry, missing/bad verification and actual
SIGKILL after claim/publication. Synthetic job/source metadata supplies exact SQL
bindings only. It is not source acquisition, new certificate issuance, native
execution qualification or independent certification. Full request-to-dispatch
qualification must additionally use complete acquired source matching a retained
certificate; it remains required before M9 closure.

`scripts/test-glassmere-build` supplies this additional development composition:
explicit historical public selection, complete bounded local pack ingestion, exact
snapshot matching, passive retained-source reload, native request, public verifier
and atomic admission. Its importer copies only the original certificate bytes and
explicitly labeled completed-job metadata into a fresh isolated namespace. It does
not copy M6 claims, build evidence or release permits. A distinct import audit event
prevents describing the metadata as newly issued certification. Local import records
no SSH/device authentication or received refs; actual validated pack/source evidence
is retained separately. Original authority rows and artifacts remain untouched.
SIGKILL and replay assertions require one admission and no claims or new signatures.

Assert one admission/audit/receipt, unchanged immutable source/certificate bytes,
zero new execution claims, no evidence roles and no signatures. Resume after a
crash through the original command identity and fences. Existing non-expiring M6
claims remain outside command-lease recovery and can never be reclaimed by it.

The dispatcher keeps its existing lease bounds, SQL deadlines and fixed crash
checkpoints. No timeout, assertion or policy is relaxed. Explicitly provisioned
operator/database/OS identities retain the development trust limitations.
M9 remains INCOMPLETE; M10, M11 and Genesis remain NOT STARTED.
