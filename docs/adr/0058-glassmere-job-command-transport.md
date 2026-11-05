# ADR 0058: Job command transport and trusted polling

Status: Accepted design; browser, process-kill and complete M9 qualification remain
separate. Date: November 5, 2026. Extends ADRs 0035–0037 and 0053–0057.

## Context

The private command journal, atomic job executors and command-only credentials
need an authenticated service path. Accepting their internal serialized records
would expose authority recipes and permit callers to select frozen authority data.
HTTP acceptance must also remain independent of execution and signing ownership.

## Decision

Add opt-in loopback daemon routes for certification, eligible queued cancellation
and exact-attempt infrastructure recovery. Requests contain schema, project,
repository, expected authority-context identity and fixed object identifiers.
Strict transport DTOs reject actor/role, policy, recipe, limits, cleanup assertions,
signing fields and unknown actions. They translate into existing control-plane
methods; no transport DTO enters domain or application. Release-build, readiness
and ReviewDisposition requests are absent from this initial wire grammar. Their
absence grants no waiver or alternate execution path.

The daemon mounts these routes only when explicitly given a valid private
command-credential path. It checks migrations 0008–0010 without applying DDL and
reloads credentials for every request. The command token remains invalid on legacy
submission routes. Reject ambiguous authorization/idempotency headers. Require an
explicit idempotency key and current expected context for every mutation. Bound
JSON bodies to 4 KiB, command URIs to 768 bytes and concurrent request processing
to eight slots. A cooperative fifteen-second service deadline returns unavailable;
it changes no target timeout, attempt budget, lease, evidence or policy semantics.
An unknown commit must be resolved by the original key/receipt, never blind work
repetition. Command responses use no-store and nosniff headers. Daemon bearer
authentication is independent of panel cookies; browser origin/CSRF/RBAC mediation
remains necessary at the panel boundary before any browser command is exposed.

Non-mutating context discovery checks the current authenticated scope and reports
only selection identity and whether certification requires a reviewed session.
Acceptance returns a durable operational request, not a certificate, permit or
positive target verdict. Public receipts explicitly project identifiers, operation,
original context/request digest, creation time, state and typed safe outcome.
They omit actor mapping, frozen recipes, intent coordination and dispatcher leases.

Receipt inspection authenticates current scope and operation, checks current
repository authorization and the retained request's original command grant, and
requires the exact original context identity. It may inspect history after a
daemon restart selects new authority for future requests. Inspection never selects
old authority as current or changes any receipt. Mutations still require the current
context; altered original context or object/scope substitution denies access.
The older private same-context status method keeps its original behavior.

Explicit controller commands provision command grants after repository grants and
poll one durable command. The dispatcher selects authority independently from its
private configuration and rechecks the original context. It invokes existing
atomic local mediation or reconstructs the existing sealed reviewed admission
without a provider capability. Reviewed preparation renews only its command
coordination lease; it cannot revive worker, provider or M6 build ownership.
Missing mandatory review is a known rejection; infrastructure/commit uncertainty
remains retained for exact recovery. Unsupported release/readiness requests are
rejected before a domain operation, rather than passed to the job executor.

The polling command loads no runtime endpoint or signing key and never executes a
target. Existing worker/controller execution and post-cleanup signing remain
separate. Authority-only claimed/published checkpoints allow a regression harness
to kill a real process; neither browser nor target can select them.

## Security and qualification

Test strict DTO rejection, private receipt projection, token-namespace separation,
body/URI/concurrency bounds, private-file reload, duplicate keys/tabs, cross-object
scope, retained history and current-context mutation denial. Use real PostgreSQL
for durable acceptance and resulting domain/audit counts. Process-kill qualification
must actually kill the dispatcher; a controlled exit or rollback test is not a
substitute. These routes do not enable a Glassmere browser command by themselves.
Release/readiness mediation, browser workflows and full M9 closure remain open.
M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Executing jobs in an HTTP handler would mix availability and execution ownership.
Handing legacy credentials or resolved authority JSON to the panel would bypass
the new command boundary. Returning private journal records wholesale would expose
configuration and fencing capabilities. A PostgreSQL polling controller keeps
acceptance durable, allows independent restarts and uses the already established
application transitions. It also requires explicit service provisioning and
recovery qualification before milestone closure.
