# ADR 0053: Private operational command coordination

Status: Accepted design; the journal alone does not implement or qualify the HTTP
command surface. Date: November 5, 2026. Extends ADRs 0035–0037, 0043, 0048 and 0051.

## Context

Browser retries can carry different client keys for the same intended workflow.
The existing job repository deduplicates only an identical scoped key. A new
browser command also needs a retained original authority selection and a receipt
that cannot be mistaken for certification or release authorization.

## Decision

Introduce a versioned private application vocabulary and PostgreSQL journal for
resolved certification, release-build, readiness-observation, eligible cancellation
and exact-attempt infrastructure-recovery requests. These are fixed operations,
never executable strings. ReviewDisposition is absent: ADR 0050 establishes no
human waiver workflow, and this decision creates none. No policy, revocation,
exception, signing or arbitrary runtime command is introduced.

The journal accepts only internally resolved inputs. It is not a wire DTO and
must not be deserialized from browser input. Trusted composition authenticates
the actor, authorizes the operation and resolves original authority inputs first.
A separately provisioned command grant binds project, repository, actor, exact
authority-context digest and fixed operation. Existing repository grants enable
no new operations. Acceptance locks both grants before checking object scope.
The context digest identifies an explicit trusted selection; hashing target data
does not confer authority. Provisioning remains outside target and panel control.

Canonical restricted JSON schema 1 identifies the complete frozen request. The
scope and authority context are part of those bytes. A scoped retry-key alias is
immutable and rejects different bytes, including a changed authority context.
Workflow intent deduplicates identical resolved requests across different client
keys. A new explicit readiness-observation key may request a fresh historical
observation; replay of its original key retains its original receipt. Acceptance,
alias binding and audit commit together. Failed conflicting acceptance rolls back
all proposed rows. No historical job inputs or signed bytes are reinterpreted.
Short journal transactions use a three-second statement deadline and a two-second
lock deadline; contention returns unavailable rather than waiting indefinitely.

The journal transitions REQUESTED -> PROCESSING -> APPLIED / REJECTED /
INCONCLUSIVE. APPLIED describes the bounded application operation, never a source
verdict, signature or deployment capability. Public effects contain scoped object
references or an existing verifier observation. Frozen recipes, leases and private
configuration have no blanket public serializer. The adapter checks effect type,
identity and corresponding durable object state before accepting a receipt.

Dispatchers claim through SKIP LOCKED and a fresh opaque generation with a 5–300
second database-time coordination lease. Expired ownership cannot renew or publish.
Takeover changes the generation and retains the original request and dispatch
count. This lease coordinates application mediation only: it cannot revive a
worker lease, semantic-provider claim or non-expiring M6 build claim. Domain
operations still enforce their original source, review, cleanup, budget and
signing preconditions. Database-local mutations and their final command receipt
must share a transaction when those operations are connected; a journal receipt
is not a substitute for that integration. External outcomes require reconciliation
through their existing immutable identities, never blind execution after takeover.

Migration 0008 adds tables, explicit operation grants, immutable aliases and audit,
and guarded journal updates. It changes no existing job transition or migration.
The journal is private operational audit, not M10 private transparency. Normal
UPDATE/DELETE paths cannot rewrite retained requests, aliases, terminal receipts
or audit. Database-owner/TRUNCATE/backup tampering remains outside this safeguard.

## Security and qualification

The presentation graph receives no PostgreSQL write, Docker, signer or key
capability. A later typed broker must independently enforce role, CSRF, project,
repository, actor and object scope before this private port is reachable. No HTTP
operation is enabled by the journal's presence. A forged command UUID, digest or
browser role is never an authorization capability.

Real PostgreSQL tests must establish concurrency, scoped alias conflicts, grant
revocation, fencing, immutable history and reconnect behavior. They do not prove
target-runtime enforcement, browser authorization or crash-safe domain mediation.
Those require their own integration and failure-injection evidence before M9
closure. M10, M11 and Genesis remain NOT STARTED.

## Alternatives and consequences

Browser-only double-click prevention cannot cover HTTP retry or multiple tabs.
Reusing a client key alone cannot deduplicate different keys. A generic command
runner would introduce unnecessary ambient authority. A separate message broker
would split acceptance and work availability across systems; PostgreSQL already
provides the durable polling boundary.

The journal adds an operational lifecycle that needs explicit dispatcher recovery
and bounded transport integration. A stored readiness result remains historical;
current readiness must still recheck dependency availability and exact identities.
Revocation can leave a pending request inaccessible and undispatched; absence of
progress grants no positive authority claim.
