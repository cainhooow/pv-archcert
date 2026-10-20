# ADR 0039: Persistent local execution gates and durable cleanup fencing

Status: Accepted for the single-host rootless execution profile.
Date: October 20, 2026.

## Context

A database lease fences results but cannot prevent a suspended worker from
creating a later target. An empty runtime inventory is not proof of worker death.
Docker also cannot transactionally commit resource creation with PostgreSQL.

## Decision

Bind each attempt to one explicit endpoint, reported daemon ID and canonical
private local gate root before dispatch. The immutable AttemptId is the execution
generation; it is never reused. Workers retain no database credentials.

Every complete execution holds an exclusive nonblocking OS file lock on that
attempt's persistent gate through creation, start, observation and cleanup. Before
creating preparation containers, committing images or creating targets, append
and fsync a pending-creation marker. Clear it only after a successful completed
runtime response. Gate contents are bounded, append-only and fail closed on a
partial/invalid record. A worker may not create a gate or reopen revoked authority.

Recovery first uses PostgreSQL time to establish expired/closed attempt ownership.
An expired lease cannot be renewed. Take the same exclusive gate lock; failure
means BLOCKED, not permission to race a live/suspended execution. Append/fsync an
irreversible revocation before committing the database execution fence. Hold the
lock throughout reconciliation. If recovery crashes before the DB commit, the
closed local gate remains conservative; if it crashes afterward, future workers
already reject the gate. Repeated reconciliation continues from this state.

The old worker may remain alive between steps, but cannot pass the execution gate
again. A live worker holding the gate blocks destructive reconciliation until it
exits or an operator terminates that exact owned process. This intentionally
trades availability for physical execution exclusivity. No PID reuse heuristic
or lease-expiry inference substitutes for the gate.

Only exact DB-known attempt resources on the bound daemon may be removed. Validate
owner/version/job/attempt/execution labels and object identity before each
destructive action. Remove containers before preparation images and independently
verify absence. Unknown, legacy or mismatched ownership is reported and retained.
Never prune globally. Cleanup outcomes are separate bounded durable/audited states.

A pending create/commit after a crash remains BLOCKED even if inventory is empty:
the daemon might still complete an accepted operation. This milestone provides
no operator assertion that clears that uncertainty. It can clean known objects,
but cannot requeue while pending creation remains. A late start/attach cannot
recreate a removed container; complete-container removal closes that boundary.

RUNNING recovery names the exact expected AttemptId and requires both an
irreversible database fence and SUCCEEDED cleanup. A caller boolean is no longer
authority. LEASED-before-dispatch recovery remains possible without a runtime.
Normal accepted evidence closes execution authority and reconciliation can finish
cleanup before evaluation/signing continuation without rerunning the target.

## Security implications

This is a trusted-worker, single-host execution protocol. All controllers/workers
must share the same private local gate filesystem and explicit daemon. Same-UID,
root, database administrator, runtime administrator or modified worker executable
compromise remains outside this cooperative authority boundary. Target code has
neither gate paths/files nor runtime sockets mounted. No signing, policy mutation,
repository authorization or DB capability enters the worker.

The gate journal relies on local POSIX locks, create-new, descriptor/no-follow path
handling and fsync. It does not qualify arbitrary network filesystems or remote
worker clusters. Gate files are retained tombstones, not temporary artifacts to
delete during ordinary cleanup. Runtime labels are operational correlation, not
certificate identity or cryptographic attestation.

## Alternatives considered

Lease expiry or one empty inventory permits late work. A per-step DB read followed
by an unlocked Docker create still has a revocation race. Worker PID signalling
alone risks reuse/namespace mistakes and cannot fence a delayed assignment.
Database credentials in workers broaden authority without solving the runtime
transaction gap. Distributed consensus and a new isolation tier are unnecessary
for this bounded single-host profile.

## Consequences

Recovery can remain blocked indefinitely after uncertain creation; availability
must never override no-duplicate execution. Cleanup retries do not change target
verdicts. Native tests must demonstrate stale-step rejection, live-lock blocking,
actual worker SIGKILL, exact ownership checks, cleanup failure/retry and immutable
attempt history before qualification can be claimed.

Committed execution artifacts discovered between upload and evidence acceptance
are rehashed and validated against the exact job/attempt/pinned inputs. After
fenced cleanup, the controller adopts that AVAILABLE evidence transactionally
without reviving the lease or running targets again. Missing/corrupt committed
objects block continuation. Staging metadata alone is not accepted evidence.
The explicit recovery command requires the expected attempt ID; a caller's
cleanup assertion grants no authority.
