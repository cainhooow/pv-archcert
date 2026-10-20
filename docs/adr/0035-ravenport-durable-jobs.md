# ADR 0035: Durable certification jobs and PostgreSQL ownership

Status: Accepted design for Ravenport. Date: October 20, 2026.

## Context

Northgate source reception and certificate verification are independent, but the
execution CLI needs one healthy process. Acknowledged certification requests must
survive crashes without resolving mutable source, policy or runtime defaults.

## Decision

A CertificationJob pins project, repository, accepted submission and full exact
source identity; actor; policy ID/version/digest; authority execution profile,
immutable image and plan digest; bounded authority commands; creation time; and
an authority retry limit. No ref/latest lookup occurs during recovery.

Job states are QUEUED, RUNNING, EVALUATING, SIGNING, COMPLETED, NOT_ELIGIBLE,
INCONCLUSIVE. The last four except SIGNING are terminal. COMPLETED means a
verified certificate and immutable artifact metadata committed transactionally.
NOT_ELIGIBLE is a policy result, not infrastructure failure. INCONCLUSIVE means
authority recovery cannot establish a safe result. No arbitrary status setter.

CertificationAttempt has its own random ID, ordinal, worker identity, fencing
token, lease timestamps, start/end time, result/evidence and structured failure.
Attempt states are LEASED, RUNNING, EVIDENCE_READY, COMPLETED, FAILED, LOST.
Previous attempts and evidence are never overwritten by retries. A job can have
at most one active attempt. EVIDENCE_READY ends execution ownership and moves
continuation authority to the controller. Terminal state cannot return to queued.

Use PostgreSQL transactional metadata through an application repository port.
Domain/application contain no PostgreSQL, SQLx, S3 or Protobuf types. Select SQLx
with Tokio/PostgreSQL and explicit versioned migrations, no ORM. Runtime bound
queries avoid build-time database access; real PostgreSQL tests check every query,
constraints and locking semantics. Migrations run explicitly with migration
authority, never opportunistically in HTTP startup. Database schema and Protobuf
schema evolve independently. See the dependency review for exact dependency pins.

Transactions: (1) authorized admission + scoped idempotency + immutable inputs +
audit; (2) locked claim + new attempt + job ownership + audit; (3) fenced renewal
or attempt transition; (4) accepted immutable evidence metadata + attempt finish +
EVALUATING + audit; (5) evaluation decision + audit; (6) issuance preparation;
(7) verified certificate metadata + COMPLETED + audit. No database transaction
spans target execution, object upload or signing. Each state-changing transaction
checks its preconditions under a job row lock. PostgreSQL time governs leases.

## Security implications

Scope is project/repository/actor plus IdempotencyKey. Reuse with different pinned
inputs rejects. Authentication is not inferred from an existing submission UUID.
The database is trusted for operational state, not cryptographic certificate
validity. Signing private keys never enter its rows. Workers have execution
authority only and no direct signing or policy mutation capability.

## Alternatives considered

Process-local maps cannot recover acknowledged state. Files alone cannot safely
coordinate concurrent leases and scoped idempotency. An ORM adds no required
domain property. A broker/outbox is unnecessary: PostgreSQL itself is the durable
polling queue, so admission and work availability commit in one transaction.

## Consequences

PostgreSQL availability and backups become operational dependencies. State reads
survive service restarts. The controller must revalidate pinned inputs and durable
artifact bytes before evaluating or preparing a certificate. Deployment roles
separate migrations, control-plane writes and worker execution capabilities.

References: [SQLx](https://docs.rs/sqlx/latest/sqlx/),
[PostgreSQL row locking](https://www.postgresql.org/docs/current/sql-select.html).
