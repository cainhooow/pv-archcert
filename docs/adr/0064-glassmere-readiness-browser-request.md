# ADR 0064: Browser readiness questions and historical receipts

Status: Accepted bounded integration; full M9 qualification remains open.
ADR 0069 subsequently extends the browser-build permission row; readiness semantics remain unchanged.
Date: November 5, 2026. Extends ADRs 0059 and 0061–0063.

## Context

Readiness has a separately authenticated, identifier-only backend operation.
Browser mediation must retain current role/object checks and distinguish immutable
past observations from the live dependency check. A past ALLOWED receipt cannot
become current through page refresh or automatic freshness confirmation.

## Decision

Extend the narrow application presentation request with an exact release invocation
identifier. Preserve the existing port/type names for compatibility. Add a fixed
RELEASE form target; reject other operation/target pairs and posted attempt,
readiness, artifact, certificate, policy or execution fields. Resolve the invocation
through the scoped read-only query and validate schema/project/invocation/repository.
This passive lookup may observe existing readiness; it does not decide the new
command outcome. The dispatcher performs its own subsequent observation.

Require current authenticated Operator/Administrator role, project access, exact
Origin, session-bound CSRF and a current versioned panel grant. Recheck the session
and role after passive lookup, before the broker call. Independent private backend
mapping, command credentials, current repository/operation grants, authority
context and original invocation ownership remain mandatory. The panel keeps its
SELECT-only connection and receives no runtime, source-acquisition or signer.

The fixed loopback broker encodes readiness request schema 2. It accepts readiness
receipt schema 2 only with HISTORICAL_OBSERVATION, supported observation schema,
exact scope and well-formed identities/revision/time. State and blocker consistency
is required; ALLOWED must retain certificate/artifact/permit identities. On submit,
the returned invocation must match the requested invocation. This validates the
wire contract, not deterministic policy truth; the existing M6 verifier remains
the only production observation composition. Job schema 1 retains its grammar and
must not carry a readiness freshness marker. Request/body/concurrency/time bounds,
endpoint pinning and redirect/proxy prohibition remain unchanged. The mapping
vocabulary admits the four implemented operations only.

## Permission matrix

Every permitted command still requires its independent backend grant and scope.

| Operation | Viewer | Operator | Reviewer | Administrator |
| --- | --- | --- | --- | --- |
| Read assigned projections and live readiness | Yes | Yes | Yes | Yes |
| Request certification | No | Yes | No | Yes |
| Cancel eligible queued job | No | Yes | No | Yes |
| Retry eligible infrastructure attempt | No | Yes | No | Yes |
| Request historical readiness observation | No | Yes | No | Yes |
| Request release build | No | No | No | No |
| Human review disposition / waiver | No | No | No | No |
| Inspect bounded panel audit | No | No | No | Yes |
| Administer users through browser | No | No | No | No |
| Sign certificate or Release Permit directly | No | No | No | No |

ADR 0050 provides no human disposition/waiver workflow. Reviewer remains read-only;
this does not create a human approval bypass. User/role assignment remains external
audited provisioning. Administrator is not signing or governance authority.
Release-build mediation remains separate implementation work.

## Receipt behavior

Redirect accepted submission to a GET receipt. Repeated submission with the same
action key retains the original question and receipt; refresh performs no submit.
A different explicit readiness key asks a new question, unlike workflow intent
coalescing. Multiple questions create no certification or release-build workflow.

Render retained observations in a structured HISTORICAL_OBSERVATION section with
their exact source, certificate, artifact, permit, revision, evaluation time and
blockers. Never attach the live query's data-readiness/data-check-url attributes.
Even retained ALLOWED has no automatic current confirmation. Link the exact live
readiness page and a separate explicit new-question form. An unavailable result
remains explicit uncertainty; it authorizes no work repetition or release. All
displayed text is escaped and original browser/backend secrets remain excluded.

## Qualification and limitations

Exercise every role against every implemented operation, direct CSRF/forged-fact/
object denials, and role revocation during passive readiness lookup. Test the real
TCP broker against schema/marker substitution, misbound observations, malformed
identities, contradictions and streamed oversize. Metadata fixtures establish only
presentation/transport behavior, never signatures or execution qualification.

Actual browser qualification must additionally compose panel, daemon, dispatcher,
SELECT-only PostgreSQL and original retained M6 evidence. Preserve historical
source/signature identity, no new execution/claims/signatures, exact journal counts,
outage behavior and retained historical labels. Remaining M9 corpus and final gates
must still close before M10. M9 is INCOMPLETE; M10, M11 and Genesis are NOT STARTED.

Reusing the live readiness renderer for retained receipts, posting result booleans,
or granting commands from a presentation role alone was rejected. Historical truth
and current dependency availability remain visibly separate.
