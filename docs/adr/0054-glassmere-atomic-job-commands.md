# ADR 0054: Atomic operational job commands and queued cancellation

Status: Accepted design; transport and browser qualification remain separate.
Date: November 5, 2026. Extends ADRs 0035–0037, 0039, 0043 and 0053.

## Context

A command receipt published after a separate recovery transaction can lose its
connection to the original attempt if a worker advances the requeued job first.
Queued cancellation also needs an explicit application rule, rather than an
arbitrary state setter or an assertion that a running target has stopped.

## Decision

Mediate database-local commands through a narrow application port. Authenticate
and scope admission separately; claim through the private journal; then lock the
same journal generation, recheck the operation grant and exact selected authority
context, lock the affected job, apply the existing domain operation, record its
domain audit and publish its command receipt in one PostgreSQL transaction.
Database-local effects become visible to workers only with their final receipt.
An expired coordination lease cannot publish either half of that transaction.

Reuse the original admission and exact-attempt recovery implementations through
shared transaction helpers. Preserve their SQL, parameter order, locks, frozen
inputs, attempt budget, accepted-evidence exclusion and runtime fencing/cleanup
checks. Existing repository methods retain their original transaction boundaries.
The new command path additionally has the bounded journal statement/lock deadlines
from ADR 0053. It introduces no target execution or runtime cleanup capability.

Certification uses a journal-derived internal retry key, independent of all browser
keys. The local port supports existing non-reviewed admission only. A reviewed
request must use the existing reviewed application workflow and create-only
session/admission linkage; this local port cannot bypass it. Release builds and
readiness observations require their separate existing application/verifier ports.
An unsupported action is rejected by the local port without a domain mutation.

Queued cancellation is permitted only before execution ownership: the job must
be QUEUED, with no evaluation, issuance or certificate, no active attempt, and no
retained runtime whose fencing and successful cleanup are uncertain. The mutation
requires positive fencing/cleanup records for every retained attempt; missing
runtime metadata on an earlier attempt is conservatively denied. The mutation
locks the same job row as worker claim. Whichever commits first decides eligibility;
running, evaluating, signing and terminal jobs cannot be canceled by this operation.
Cancellation preserves all immutable inputs, attempts and evidence.

Use the existing terminal INCONCLUSIVE state with the already-defined structured
OPERATOR_CANCELLATION reason and a JobCanceled audit event. This makes the absence
of a certification result explicit and distinct from target/policy failure. Add a
dedicated domain cancellation transition; the generic historical transition graph
does not acquire a general queued-to-terminal shortcut. Migration 0009 extends the
database guard for this exact cancellation case only. Existing migration bytes,
states and historical outcomes remain unchanged. The unchanged v1 status DTO can
represent INCONCLUSIVE, but omits the job-level reason. Glassmere's scoped job
projection and command receipt retain the explicit cancellation distinction; no
older value is reinterpreted as successful proof.
The database reason comparison is NULL-safe: a missing reason cannot turn the
rejection predicate into SQL UNKNOWN and bypass its guard.

Retry remains infrastructure recovery of the exact expired generation. It cannot
retry terminal target/policy rejection, extend the authority attempt budget, assert
cleanup, discard AVAILABLE execution evidence or revive old ownership. User retry
additionally requires remaining original attempt capacity. Exhausted work is denied
by this port; the existing controller may separately finalize it as INCONCLUSIVE
through its unchanged recovery operation. Recovery and its receipt commit together,
so later workers do not make an earlier command
ambiguous. Duplicate commands never create another domain transition.

Known domain-precondition rejection produces an explicit rejected receipt without
a job mutation. Database failure, conflict, unknown commit or invalid ownership
rolls back; it is not converted into a successful operation or a target failure.
Recovery uses the retained original request, never a newer authority default.

## Security and qualification

These private ports do not enable HTTP commands or grant panel Administrator a
signing, runtime, user-administration or governance capability. Browser roles,
origin/CSRF, backend authentication, object scope and public receipt translation
remain required at their own boundaries. No human review waiver is introduced.

Real PostgreSQL tests must cover duplicate workflow intent, worker/cancel races,
running and terminal denial, exact-attempt recovery, uncertain cleanup, budget
exhaustion, revoked grants, stale coordination leases and atomic rollback. Actual
process-kill recovery and browser integration require separate execution evidence.
Native execution qualification is not established by database tests. M9 remains
in progress; M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Updating a job and later writing a receipt leaves an avoidable crash window.
Canceling a running target would require additional runtime termination authority
and cleanup qualification. A new CANCELED status is unnecessary because the
existing failure vocabulary already reserves explicit operator cancellation.
The narrower queued-only operation preserves conservative execution recovery.
