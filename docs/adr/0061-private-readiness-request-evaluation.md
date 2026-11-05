# ADR 0061: Fenced historical readiness requests

Status: Accepted private mediation design; HTTP and browser integration remain
separate. Date: November 5, 2026. Extends ADRs 0048, 0051, 0053 and 0060.

## Context

The command journal already identifies a requested readiness evaluation by exact
invocation and scope. Its original key must retain one historical receipt while a
new explicit key may ask a fresh question. A retained allowed result cannot become
current release authorization after dependencies or public trust selection change.

## Decision

Add a narrow application observation port and readiness-request evaluator. Reload
the scoped command through the journal's current repository/operation grants before
querying. Require its original command identity, processing generation and selected
authority context. Wrong operation or generation cannot use this evaluator.
Changed authority selection is a known rejection before observation.

The shared observation adapter delegates to its unchanged live M6 query/verifier.
It reads current explicit public trust selection, exact immutable release input,
registered bytes and dependency availability. The request's source/invocation is
never replaced by a newer source or recipe. The accepted result retains its actual
evaluation time and revision, which already binds verified facts, references and
public trust selection. An evaluation awaiting its first accepted result is a
fresh observation when performed; it is not recovery of a previously signed fact.

Publish APPLIED only for a well-formed observation with the requested scope and
invocation. APPLIED means the question was evaluated; the observation may itself
be RELEASE_DENIED. The existing database publication fence additionally compares
the exact immutable source and certificate binding. A wrong source cannot publish
an allowed receipt. Unsupported schema, contradictory state or unavailable
observation remains explicit INCONCLUSIVE, with a bounded existing failure code.
Authentication/authorization, conflict and publication/fencing errors propagate.

The journal rechecks grants and exact live coordination ownership during atomic
receipt/audit publication. Expiry/takeover cannot publish a stale generation's
result. Re-evaluating a read before any accepted receipt has no target side effect;
it acquires no M6 build claim, issues no permit and changes no release evidence.
An accepted receipt is immutable. Same-key replay returns it without evaluation;
a new explicit observation key retains the original schema-1 freshness semantics.

The trusted controller can compose this path only with an explicitly selected
private observation configuration and a separate SELECT-only
`ARCHCERT_OBSERVATION_DATABASE_URL`. It receives no additional runtime or signer
capability for observation. Missing capability records unavailability; invalid
provided configuration propagates its typed initialization error before an
observation is published. Existing job command arguments and execution paths keep
their meanings. This private change enables no daemon or browser action by itself.

## Security and compatibility

Browser input cannot submit readiness facts, policy results, keys or dependency
claims. Current use still requires a fresh live readiness query. A later receipt UI
must label observations historical and link the live query rather than display
cached ALLOWED as current. Presentation role and backend grants remain independent.

Historical request bytes/digests, response models, M6 recipe/claim/signing semantics,
leases, timeouts and native qualification remain unchanged. No new policy, review
waiver, revocation or governance feature is introduced. M9 remains INCOMPLETE;
M10, M11 and Genesis remain NOT STARTED.

## Validation and consequences

Use real PostgreSQL to test current-grant denial before observation, immutable
same-key receipts, explicit new-key observations, allowed/denied result separation,
uncertainty, schema/scope mismatch, wrong-source publication rollback and expired
coordination. Metadata observers qualify journal mediation only; existing M6
verifier and browser fixtures qualify their distinct boundaries. Actual transport,
browser and outage corpora remain separate requirements before M9 closure.

Duplicating M6 verification, accepting posted readiness booleans or treating a
retained observation as a release lease was rejected. The explicit read port and
fenced publication preserve the distinction between a question and authorization.
