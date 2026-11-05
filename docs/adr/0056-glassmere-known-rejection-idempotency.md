# ADR 0056: Retained retry keys and fresh requests after known rejection

Status: Accepted design. Date: November 5, 2026. Extends ADRs 0053–0055.

## Context

An eligible job can change state between observation and its locked command
precondition check. Cleanup may also become established after an earlier retry
request was denied. Permanently coalescing every matching intent would prevent a
fresh user action even when that earlier request made no domain transition.
Conversely, an uncertain outcome must never become permission to repeat work.

## Decision

Every scoped idempotency key remains permanently bound to its original request
bytes, command identity and historical receipt. Same-key replay returns that
original command, including a rejected receipt. Changing its payload conflicts.
No alias, request, terminal receipt or audit history is rewritten or deleted.

Intent coalescing remains permanent for REQUESTED, PROCESSING, APPLIED and
INCONCLUSIVE commands. A different key cannot repeat an accepted workflow or turn
an unknown outcome into a retry permit. APPLIED describes the request operation:
an underlying target/policy failure does not turn its command into REJECTED.
Certification and M6 build truth remain in their separate durable workflows.

Only a known REJECTED request, which made no accepted domain transition, permits
a new explicit user action with a different key and the same intent. The new
request rechecks authentication, current operation grant, exact context, object
scope and locked domain eligibility. It receives its own command identity/audit;
the earlier rejection remains intact. While that fresh request is pending or
applied, additional keys coalesce into it. Browser refresh of an earlier submission
retains its original key and never silently creates a fresh action.

Migration 0010 replaces the all-history intent constraint with a unique index
covering every state except REJECTED. Scope/key uniqueness remains unchanged.
Acceptance first resolves an existing key, then serializes the short intent
selection/binding transaction with a PostgreSQL transaction advisory lock and
row-locks any coalesced command. The lock uses PostgreSQL's ordinary hash for
coordination, not for content identity or cryptography. Existing statement/lock
deadlines remain unchanged. Domain mutation and receipt still commit together.

## Security and compatibility

This is not retry until pass. Failed certification/build work has an APPLIED
request receipt and immutable failed/ineligible domain state; it remains coalesced.
The existing retry command still requires exact expired ownership, confirmed
cleanup and remaining original budget. INCONCLUSIVE remains coalesced because a
side effect may have occurred. External dispatchers may label a request REJECTED
only before an accepted domain transition; otherwise they must reconcile its
original immutable workflow or retain uncertainty.

Canonical schema-1 request bytes, digests, command IDs, key bindings and existing
receipts keep their meanings. Several historical rejected requests may now share
an intent digest; it identifies intended work, not one unique historical attempt.
Old command adapters requiring the removed full unique constraint fail closed and
must be upgraded with migration 0010. No historical migration is edited. This
changes no source certificate, permit, policy, profile or execution identity.

## Validation and consequences

Real PostgreSQL tests must cover same-key rejected replay, new-key fresh action,
concurrent coalescing, uncertain-outcome retention, applied target/policy failure,
scope and changed-payload denial. Count domain jobs/invocations when asserting
absence of duplicate workflows; a rejected no-effect command is not a workflow.
HTTP, browser and actual process-kill validation remain separate. M9 remains
in progress; M10, M11 and Genesis remain NOT STARTED.
