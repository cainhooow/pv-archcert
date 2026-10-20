# ADR 0036: Fenced worker attempts and conservative recovery

Status: Accepted design for Ravenport. Date: October 20, 2026.

## Context

Multiple workers and delayed messages must not produce duplicate authoritative
results. Network/process loss does not prove target failure or successful cleanup.

## Decision

Claim queued jobs with SELECT FOR UPDATE SKIP LOCKED in a short transaction.
Create a fresh AttemptId and random fencing token, persist worker and bounded
lease, and advance the job atomically. Start, renewal and result acceptance check
job, attempt, worker, fencing token, unexpired database timestamp and active state.
Renewals cannot revive expired/terminal attempts, exceed the configured maximum
attempt lifetime or change worker identity. Lease duration is 5–300 seconds;
workers renew before expiry and stop publication when ownership is uncertain.

Expiry recovery locks the same job row. Mark the old attempt LOST with worker
loss classification and retained lease/evidence timestamps. Create no target
failure claim. Queue a fresh attempt only within the authority-owned bounded
infrastructure retry budget. Otherwise end INCONCLUSIVE. Target failures and
policy rejection never trigger automatic retries. Persistence uncertainty causes
read/reconciliation of durable state, not blind repeat execution.

Once validated evidence is accepted, worker ownership ends. Restart after
execution resumes from retained observations; restart after evaluation resumes
from retained evaluation; restart during signing uses the same issuance identity.
All writes and audit events share their transaction. No cluster membership or
message broker is required. Workers and controllers poll PostgreSQL-backed ports.

## Security implications

Fencing ensures only one attempt's result is authoritative. An expired isolated
process might physically continue running; a database lease alone cannot stop a
partitioned target. Recovery must confirm/clean attempt-labeled runtime resources
before dispatching another target where exclusive physical execution is required.
No stale worker result can advance evaluation or signing. Attempt IDs bind all
stored result metadata. Worker authentication/capability delivery remains an
adapter concern; a decoded Protobuf assignment grants no authority by itself.

## Alternatives considered

Selecting the first pending row races. Advisory locks alone lose durable history.
Unbounded retries can turn flaky tests into certification. Restarting execution
after every controller crash discards known facts and increases target exposure.

## Consequences

Availability is conservative when cleanup or lease ownership is uncertain. Lease
and retry budgets are authority settings. Every failed/lost attempt remains
auditable, and database reconnect is safe through transaction preconditions and
idempotent operations. Cancellation is deferred until these core guarantees work.
