# Glassmere private observation surface

M9 is INCOMPLETE. This implementation provides useful private read-only visibility;
it does not close the complete Glassmere operational and qualification scope.
[ADR 0051](../adr/0051-glassmere-observation-boundary.md) and the
[threat model](../threat-model/GLASSMERE.md) define the trust boundary.

Glassmere observes authority. It does not become authority.

## Deployment

Build with the repository-pinned Rust toolchain and Cargo.lock:

```sh
cargo build --release -p archcert-panel --locked
```

The frontend is server-rendered semantic HTML, controlled static CSS and a small
same-origin freshness script. There are no Node production dependencies, framework,
CDN, external font, analytics or remote error telemetry. The production artifact is
one Rust executable with embedded assets. Record source commit, Cargo.lock digest,
`rustc -Vv` and executable SHA-256 for each retained deployment; no automatic M6
certification of that executable is claimed.

Provision a separate PostgreSQL login role with CONNECT, schema USAGE and SELECT
on the existing authority tables. Do not grant table mutation, schema ownership,
role administration or controller credentials. Startup rejects table write/admin
privileges. Set the separately provisioned connection URL in
`ARCHCERT_OBSERVATION_DATABASE_URL`; never pass it in a browser or URL query.
Existing M0–M8 migrations must already have been applied by migration authority.
Glassmere does not migrate, backfill, repair or delete authority records.

Use a private owned regular configuration file (mode 0600, no symlink). Configuration
schema 1 has `origin`, `development_http`, `demonstration_data`, `audit_path` and
`principals`. Each principal has a non-secret `id`, a `token_sha256`, a role and
explicit project UUIDs. Generate a distinct random 32-byte credential per operator
with the operating system CSPRNG, store only its SHA-256 in provisioning, and deliver
the credential privately. This is a high-entropy bearer credential, not a password.
No default account, password reset or browser credential storage is provided.
Grant changes are external provisioning operations; deployments must retain their
own provisioning audit. Browser-based user/role management is unsupported.

The separate private query configuration contains schema 1, `artifact_root`,
`source_public_keys`, `release_public_keys` (lowercase raw Ed25519 public-key hex)
and `recipes` (explicit `environment` inventory/image pins plus `binary`). Select
only approved public trust and recipes. Do not derive trust from embedded keys,
repository configuration, browser requests or latest-version defaults. The web
process receives no certificate/permit private keys, runtime endpoint, Docker
socket, Git credential or provider credential.

```sh
archcert-panel --config /private/panel.json \
  --query-config /private/query.json --listen 127.0.0.1:8090
```

Production requires an explicitly configured HTTPS origin and Secure cookies.
Terminate TLS at a trusted reverse proxy on the same origin; restrict the backend
loopback listener to that boundary. No X-Forwarded-* headers are trusted. Broad CORS
and proxy-selected identity are unsupported. Explicit development HTTP accepts only
`http://127.0.0.1:<configured port>`. The private unencrypted development artifact
store retains its existing same-UID/root limitations; production OS isolation and
read-only filesystem/object credentials remain required.

## Authentication and permissions

Login exchanges the random credential for a server-side opaque session. The cookie
is HttpOnly, SameSite=Strict, Path=/, expires after 30 minutes and is Secure in TLS
mode. Logout invalidates the exact session; service restart invalidates all sessions.
Every request reloads the private grants and checks the session's grant revision.
Revoking or changing a role/project grant invalidates the previous session.

| Role | Current permission |
| --- | --- |
| Viewer | Read explicitly assigned projects and original registered evidence |
| Operator | Same read scope; authority workflow commands are unsupported |
| Reviewer | Same read scope; no new human disposition or waiver authority |
| Administrator | Same project scope plus bounded panel audit inspection |

Authenticated never means administrator. Administrator never means cross-project,
signing, runtime, policy or release authority. All unsupported mutation requests
are denied. Login/logout use exact Origin validation; logout additionally checks
a session-bound CSRF value. No GET mutates authority state. Browser workflow
submission, cancellation/retry, disposition and user/configuration edits are not
implemented and cannot be qualified through absent buttons.

Panel audit is a private append-only JSONL sink, bounded to 16 MiB. An operator must
archive/rotate it during a controlled service restart before that ceiling. Ordinary
panel users have no audit edit/delete endpoint. The retained panel audit is separate
from the database's certification/release forensic history. Login attempts are
bounded globally (20/minute), active sessions to 256, authenticated requests to
240/session/minute, concurrent HTTP work to eight and expensive verification to two.
These are operational limits, not certification policy or distributed protection.

## Read semantics and API

The server returns explicit query models under `/api/v1`. See
[the machine-readable route contract](openapi.json). A project read uses one
REPEATABLE READ READ ONLY transaction. At most 50 items per independently paged
collection are returned. `offset` is bounded to 100,000; project listing uses the
last project UUID as a keyset cursor. Browser input cannot raise page limits.
The response limit is 2 MiB, body limit 4 KiB, inert preview 8 KiB and original
object bound 64 MiB. A snapshot has a content revision, original MVCC snapshot token
and explicit UTC Unix evaluation seconds. IDs and stream sequences determine
presentation ordering; wall clocks do not reorder authority history.

The current registry has no authoritative current/latest source pointer. Source
history is exact and prominently labeled; no branch or lexicographic UUID is called
current or certified. Collection offsets are independent: a later timeline page
can exist after the last job page. Detail links retain their collection offset;
arbitrary deep linking outside that bounded page is a known limitation.

There are no materialized Glassmere projection tables. Restart/refetch reconstructs
query results from retained authoritative records and rehashed original bytes.
Deleting browser memory or panel session state cannot delete certification truth.
Projection database rebuild/update-failure tests are not applicable. Existing
workflow locking, leases, fences and cleanup are untouched.

Readiness verifies one immutable release invocation. The selected source certificate,
source scope, approved recipe/environment, complete independent A/B results,
recomputed reproducibility, both artifact byte streams, persisted canonical permit
payload and selected-key permit signature must all agree. It uses the existing M6
constructor/verifiers and does not create a new release decision engine. Missing,
invalid, unsupported or unavailable information denies with exact blocker codes.
The observation remains development M6 scope: no new expiry, revocation, production
custody or native-host qualification is inferred. Semantic CLEAR adds no proof.

Readiness pages begin as STALE / HISTORICAL SNAPSHOT. A same-origin no-store query
can confirm only the same exact revision. A changed revision, dependency outage,
missed confirmation budget, tab switch or history restoration invalidates freshness.
Scripts never recalculate release policy. With scripts disabled the historical
warning remains. Confirmation is not a lease for deployment at a later moment.

Evidence inspection rehashes registered project/entity/digest-bound original bytes.
Certificate and permit signatures are checked under selected public keys. Signature
validity is distinct from actual artifact authorization, which requires readiness or
the existing offline M6 gate. Previews are escaped, bounded and conservatively redact
representative credentials. Original downloads deliberately preserve bytes and may
contain confidential source material; they require authorization and use attachment,
nosniff, a digest filename and a digest header. Do not publish the private evidence
store. No Markdown HTML or arbitrary link is promoted into a verified citation.

## Local retained preview

`scripts/glassmere-preview` imports explicitly selected historical M6/M8 bytes into
a new demonstration database. It refuses existing output/database state, leaves
original records unchanged and can launch the integrated server detached. It needs
an operator-owned dedicated PostgreSQL container and built panel binary. It never
starts an execution daemon, worker, signer or provider. The pending fixture has no
dispatcher and cannot execute. Negative variants are explicit demonstration inputs;
only the unchanged exact historical tuple can pass its retained signed bindings.

Local credentials and database URL are written privately under ignored `target/`.
`preview.json` contains non-secret HEAD, URL, PID, mode and log locations. The final
handoff must rebuild/restart from its exact committed HEAD and verify the actual
retained instance. Preview availability itself is not M9 qualification.

M10 Crownvale, M11 Thornwick and Genesis / Firstwarden remain NOT STARTED.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.

Browser qualification uses the separately locked tools in `tools/glassmere-browser/`
(Node 26.10.0, npm 12.1.0, Playwright 1.56.1) and an explicitly installed Chrome.
Run `npm ci --ignore-scripts --prefix tools/glassmere-browser` and then
`node scripts/test-glassmere-browser` against the retained preview. This tooling is
never bundled or downloaded by the running panel.
