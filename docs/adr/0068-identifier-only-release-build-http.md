# ADR 0068: Identifier-only release-build requests over scoped HTTP

Status: Accepted HTTP mediation; ADR 0069 separately extends browser mediation.
Date: November 5, 2026. Extends ADRs 0058, 0065, 0066 and 0067.

## Context

The native request-to-admission composition has now been exercised with complete
retained historical source, independent public certificate verification, actual
controller processes and PostgreSQL. The optional command API can expose the same
request without allowing a client to select build authority or claim completion.

## Decision

Add one closed `REQUEST_RELEASE_BUILD` action containing only an owned certification
job ID. It requires explicit request schema 3 and returns the existing schema-3
admission receipt. Job schema 1 and historical readiness schema 2 remain unchanged.
Reject posted source, certificate, recipe, policy, image, limits, keys, actor,
invocation or verification facts. Unknown schema/action combinations fail closed.

Use the existing opt-in loopback command API, independent per-operation credential,
per-request credential reload and exact project/repository/context authorization.
The context binds the private build selection under ADR 0066 and grants no new
authority. It does not require a new reviewed session: the selected completed
certification already contains its original immutable certification history.
The application still checks current grants, exact job ownership, completed state,
certificate metadata and complete retained source before queuing REQUESTED.

HTTP does not verify inline, run builds, publish evidence or sign. The separate
controller follows ADR 0067, obtains the sealed verified generation and atomically
admits the existing M6 workflow with its audit and receipt. APPLIED means admission
only. Coordination expiry never reclaims an M6 execution claim. Existing 4 KiB body,
768-byte URI, eight-slot and 15-second request bounds remain unchanged.

## Validation and limits

Protocol tests reject authority overrides and incompatible grammar. HTTP tests
exercise schema/credential denials without storage. The retained-source harness
also supports actual loopback daemon requests against isolated PostgreSQL, native
dispatch, SELECT-only public verification, duplicate keys and actual SIGKILL
recovery. Assert unchanged historical rows/source/certificate, one admission,
no claims, evidence roles or new signatures. Explicit development fixture import
is not a new certification, native runner qualification or independent authority.

Browser build integration, its role matrix and its end-to-end qualification remain
separate M9 work. This ADR does not close M9 or start M10, M11 or Genesis.
