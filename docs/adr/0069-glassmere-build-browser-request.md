# ADR 0069: Browser build requests and admission-only receipts

Status: Accepted bounded browser integration; M9 closure remains open.
Date: November 5, 2026. Extends ADRs 0059, 0064 and 0065–0068.

## Decision

Add an identifier-only build request for an exact project-scoped certification job.
The browser selects no source, certificate, recipe, environment, key, policy, limits
or invocation. Resolve the existing job through the scoped read-only query. The
form is offered for recorded COMPLETED state; current eligibility and certificate
ownership are independently enforced by the application/control plane on submission.

Require current authenticated Operator/Administrator role, versioned project grant,
exact Origin and session-bound CSRF. Recheck session/grants after passive lookup,
before broker submission. The independent private backend mapping must explicitly
grant REQUEST_RELEASE_BUILD in the same project/repository. Panel role alone grants
no backend authority. The broker now admits exactly five implemented operations;
this extends its finite mapping vocabulary from four to five, without changing any
request-size, response-size, timeout, concurrency, runtime or policy bound.

Encode request schema 3 and accept only schema-3 build receipts with exact scope,
operation/context/request identity and consistent terminal state/outcome. Build
receipts carry no historical-readiness marker. APPLIED requires the typed
RELEASE_BUILD_REQUESTED effect and a valid invocation identity. The authority
derives that invocation from the owned certification and its private fixed recipe;
the presentation adapter cannot independently derive it from the selected job ID.
The native resolver/verifier/atomic executor still establish the actual binding.
Existing schema-1 job and schema-2 readiness contracts retain their meanings.

Render admission distinctly from successful builds, reproducibility, permit issuance
or current readiness. Link the exact live readiness query separately. Receipt GET
and refresh submit no command. Original action keys retain their immutable receipt;
different keys coalesce the same workflow intent, except a known no-effect rejected
request may receive a fresh explicit action under ADR 0056. Coordination recovery
never grants or reclaims M6 execution ownership. The browser acquires no database
writer, source acquisition, Docker, shell, evidence publication or signing port.

## Permission matrix

Every allowed request also requires its independent backend grant and exact scope.

| Operation | Viewer | Operator | Reviewer | Administrator |
| --- | --- | --- | --- | --- |
| Read assigned projections/evidence | Yes | Yes | Yes | Yes |
| Request certification | No | Yes | No | Yes |
| Request release build admission | No | Yes | No | Yes |
| Request historical readiness observation | No | Yes | No | Yes |
| Cancel eligible queued work | No | Yes | No | Yes |
| Retry eligible infrastructure attempt | No | Yes | No | Yes |
| Inspect bounded panel audit | No | No | No | Yes |
| Human disposition / waiver | No | No | No | No |
| Administer users through browser | No | No | No | No |
| Direct certificate/permit signing | No | No | No | No |

ADR 0050 supplies no human waiver command. Reviewer stays read-only and Administrator
does not acquire signing/governance authority. This decision supersedes only the
unsupported browser-build row in ADR 0064; it adds no M10 governance operation.

## Qualification

Exercise every role against every implemented operation, direct forged CSRF,
project/object/target and authority-field requests, and revocation during lookup.
Use actual TCP to test schema substitution, wrong scope/operation/effect, malformed
invocation, state contradictions, unexpected freshness markers and response bounds.
These fixtures establish presentation/transport behavior, not deterministic proof.
Actual Chrome/panel/daemon/controller/PostgreSQL qualification must additionally use
complete retained source and original certificate bytes. Require one M6 admission,
no execution claims/evidence/signatures, retained historical identity, duplicate-key
and multi-tab coalescing, refresh safety and restart/recovery. Final M9 corpus and
engineering gates remain required before closure. Later milestones are not started.
