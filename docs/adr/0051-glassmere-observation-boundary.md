# ADR 0051: Glassmere private observation and release readiness

Status: Accepted design; implementation and qualification are reconciled separately.
Date: November 1, 2026. Extends ADRs 0035–0037, 0045 and 0048–0050.

## Context

The durable control plane has source certification, build and review records but
no private browser surface or coherent release-readiness query. PostgreSQL record
existence is not signature verification. Semantic CLEAR is not deterministic proof.
The browser must not acquire any certification, release or execution authority.

## Decision

THE PANEL OBSERVES AUTHORITY. THE PANEL DOES NOT BECOME AUTHORITY.

Glassmere is presentation, query and a boundary for explicitly supported typed
commands. Initially its authority data paths are read-only. Missing command
workflows remain unsupported; no generic shell, runtime cleanup override, human
waiver, state setter, policy editor, retention or revocation operation is added.
M10, M11 and Genesis remain NOT STARTED.

Application owns categorical readiness aggregation. The certificate adapter
reuses the existing selected-key certificate and M6 permit verifier, exact recipe
validation, independent build comparison and canonical permit-payload preparation.
It does not sign. Its output describes one project/repository/source/invocation/
artifact tuple. Every mandatory verification must be established; missing,
unsupported, stale or unavailable information denies. Semantic review can veto or
require more evidence and cannot create a positive deterministic result. Partial
knowledge is displayed as partial and is not silently upgraded to full coverage.
The result is an observation of existing M6 development authorization, not a new
permit, production custody claim, revocation check or deployment capability.

The presentation crate depends only on application/domain and HTTP/session
libraries. It cannot depend on certificate/crypto, source acquisition, provider,
runner, Docker or persistence implementations. The outer executable composes a
read-only query adapter with the existing public-key verifier. No private key
path, signing adapter, runtime endpoint or provider/Git credential is configured.
The verifier crate's existing issuance port is not exposed to presentation.

Use server-rendered semantic HTML, bundled CSS and a small same-origin JavaScript
freshness enhancement. Axum and Rust are already locked. No Node production
packages, framework, CDN, external telemetry, Markdown parser or runtime tool
download is needed. JavaScript formats backend state and invalidates freshness;
it never calculates release authorization. With scripts unavailable the page is
explicitly a historical snapshot and never a live release authorization display.
Rust source, Cargo.lock, compiler identity and executable digest bind the panel
build; this does not automatically certify the panel under M6.

## Query consistency and freshness

Use bounded REPEATABLE READ READ ONLY PostgreSQL transactions for each aggregate.
Never use existing FOR UPDATE workflow loaders for panel queries. Read exact
immutable object references and independently verify retrieved bytes. Do not
merge independently selected latest certificates, artifacts or sources. There is
no authoritative current source in the existing registry: label selected source
and bounded history explicitly rather than inventing a branch head or latest
accepted identity. Multi-repository projects require exact entity selection;
never project one first repository name onto unrelated jobs/reviews/releases.
Timeline sequence numbers remain scoped to their original
certification or release stream; independent streams have no invented total order.

No persistent Glassmere projection tables are introduced. Query state is disposable
and reconstructed on each request; projection-database migrations, backfill and
partial-update recovery are not applicable to this architecture. A content revision
identifies the semantic aggregate and a PostgreSQL snapshot token identifies its
read boundary. Neither max(sequence) nor wall time is treated as commit order.

Operational search uses fixed exact dimensions, canonical bounded values, bound SQL
parameters and 50-result keyset pages. Migration 0007 adds indexes without changing
authority records or transitions. The cursor is bound to project/dimension/value
but is not an authorization capability. Each page is a fresh read: new earlier
keys require restarting search and mutable-state filters can lose matches. Exact
job/session detail selection is independent of history-page position, retaining
the parent while scoped child collections paginate. Search metadata, including
STAGING references and recorded evaluation dispositions, creates no proof.

Responses are private/no-store. A readiness view is exact-source historical data
until a same-origin revision check succeeds. Losing that check, changing revision,
leaving the tab, restoring a page from history or exhausting the short freshness
budget visibly invalidates it. The budget limits observation age; it is not lease,
certificate expiry or authority ordering. Refresh reconstructs all state. No browser
storage, stream delivery or browser connection participates in workflow correctness.

## Identity and access

Reuse the operator-provisioned high-entropy bearer model for browser login: a
random 256-bit access credential is hashed with SHA-256 in a private configuration,
never a human password or a default account. Exchange through a same-origin POST
for an opaque random server-side session with explicit expiry. Keep only the
session identifier in an HttpOnly SameSite=Strict cookie. Production requires
Secure cookies and an explicitly configured HTTPS origin; loopback HTTP is an
explicit development mode. Do not trust forwarded headers or enable CORS.

Reload private grants for every request so revoked principals/roles stop access.
A session is bound to the grant revision; changing roles invalidates existing
sessions. Logout removes the server-side session; process restart invalidates
sessions. Do not offer password reset or browser credential persistence.
Bound active sessions and login attempts without permanent account lockout.

Viewer can read project-scoped projections and evidence. Operator, Reviewer and
Administrator are evaluated but grant no additional authority command until an
exact command is implemented and qualified. Administrator may inspect panel audit;
that privilege does not grant access to unassigned projects, users, signing or
policy configuration. Provisioning roles/grants remains outside the browser and
changes must use the operator's auditable provisioning procedure. This initial
restriction must not be described as a complete workflow-control implementation.

Check project scope before object lookup; bind every evidence/job/session/release
ID through its authorized aggregate. Protected missing and foreign IDs both return
NOT_FOUND. Writes (session login/logout included) require exact Origin validation;
logout additionally requires a session-bound CSRF value. No mutation through GET.

## Least privilege and deployment

Use a separately provisioned SELECT-only PostgreSQL role for observation. The web
process must fail startup with a writable database role. Artifact reads use a
read-only adapter/port; no publication/delete capability reaches presentation.
Local development filesystem ownership cannot protect against a compromised
same-UID/root process; production OS isolation and read-only mounts remain needed.
TLS terminates at a separately configured trusted reverse proxy. The application
uses its configured origin, never arbitrary X-Forwarded-* headers. Deployment
must restrict access to the loopback listener/proxy boundary.

Escape all repository/provider/evidence text. Evidence bytes use attachment plus
application/octet-stream and digest-only filenames. Bound page/filter/query/body,
response, preview, download and timeline sizes. Strict CSP uses self-hosted static
assets without inline scripts/styles, frame-ancestors none, nosniff, same-origin Referrer-Policy,
Permissions-Policy and HSTS for the configured TLS mode. Health is independent
from release readiness and exposes no connection strings or authority secrets.

## Alternatives and consequences

A frontend rules engine, raw domain serialization, shared controller DB credentials,
local passwords, a new framework, materialized read tables and merging latest
rows were rejected. On-demand reads cost more than cached projections but avoid a
second persistence lifecycle. Bounded collection pages must be explicit about
omitted history. M9 cannot close until its required integration, security, runtime,
UI, outage and exact-source regression evidence is recorded. A useful development
preview alone is not milestone qualification.
