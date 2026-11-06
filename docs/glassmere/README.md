# Glassmere private observation surface

M9 is INCOMPLETE. This implementation provides private visibility and opt-in bounded requests;
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
own provisioning audit. The [provisioning tool and procedure](PROVISIONING.md)
provide private bootstrap, grant changes, credential rotation and revocation with
an explicit interrupted-publication audit. Browser-based user/role management is
unsupported.

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
| Operator | Same read scope; opt-in certification, queued cancellation, infrastructure recovery and historical readiness requests require separate backend grants |
| Reviewer | Same read scope; no new human disposition or waiver authority |
| Administrator | Same project scope plus bounded panel audit inspection; same separately granted requests as Operator |

Authenticated never means administrator. Administrator never means cross-project,
signing, runtime, policy or release authority. All unsupported mutation requests
are denied. Login/logout use exact Origin validation; logout additionally checks
a session-bound CSRF value. Commands additionally check that CSRF value,
current role and project/object scope. No GET mutates authority state. Disposition,
user/configuration edits and browser release-build commands remain unsupported. The
separate opt-in daemon supports identifier-only build requests under
[ADR 0068](../adr/0068-identifier-only-release-build-http.md). See
the complete [permission matrix and readiness decision](../adr/0064-glassmere-readiness-browser-request.md).

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

Registered JSON evidence has a structured display separate from selected-key
verification and original downloads. Known role/schema pairs up to 8 MiB expose
bounded identity/provenance fields and collection links. Collection pages retain
original array order and show at most 50 items (`collection` and `item_offset`);
nested object links allow focused inspection. Field count, depth and text length
are bounded, with explicit omission notices. Raw byte arrays and credential-like
fields are excluded. This conservative display redaction cannot establish that
source evidence contains no secrets; original downloads remain private and exact.
Unknown schemas, mismatched metadata, invalid JSON and oversized display inputs
show `UNSUPPORTED` and establish no positive authority result. The separate raw
preview is collapsed by default. Parsing, displayed runtime observations and
semantic CLEAR create no proof or new runtime qualification.

Job inspection includes the pinned attempt budget, evaluation phase time and
each retained attempt's identity, worker, state, lease/ending times, failure,
runtime fence and cleanup state. Missing timestamps remain `NOT RECORDED`;
execution completion does not imply certificate issuance. Runtime endpoints,
gate paths and lease capabilities are excluded. Recovery eligibility is explicitly
left to the controller's existing exact-attempt preconditions, rather than
inferred from a displayed deadline or cleanup label.

A project can register multiple repositories. Its overview explicitly requires
exact entity selection; each job, review session and release retains its own
repository binding. No lexicographically first repository is presented as primary.

The current registry has no authoritative current/latest source pointer. Source
history is exact and prominently labeled; no branch or lexicographic UUID is called
current or certified. Collection offsets are independent: a later timeline page
can exist after the last job page. Job and semantic-session detail links resolve
the exact object within its project, independently of its history-page position.
The parent remains visible while its bound evidence and audit events paginate.
Missing and foreign objects both return `NOT_FOUND`; no history scan is used to
locate an exact object.

The Search tab and `/api/v1/projects/{project}/search` accept fixed `kind` and
`value` dimensions: PROJECT UUID, COMMIT SHA, CERTIFICATE payload/envelope digest,
ARTIFACT digest, PERMIT payload/envelope digest, JOB UUID, STATUS and VERDICT.
Values must be canonical exact identities or the documented uppercase job states
and evaluation dispositions. Values are limited to 64 bytes, cursors to 256 bytes
and results to 50 per page. There are no wildcard or substring queries. Commit
lookup includes registered sources and their jobs, semantic sessions and releases.
Artifact lookup covers registered certification, semantic and release evidence;
STAGING matches remain STAGING and establish no byte availability or validity.

Search uses bound SQL values and the existing read-only transaction/statement
deadline. Migration 0007 adds lookup indexes and must be applied explicitly by
migration authority; the panel never applies it. A cursor binds the project,
dimension and value to a stable record key, without granting authorization.
Each page observes current records: concurrent inserts do not duplicate earlier
keys, new earlier keys require restarting the search, and changed states may
remove a record from a filter. Cursor order is not authority chronology. Source
matches expose their exact submission identity; no current-source pointer is
invented. Matching COMPLETED or ELIGIBLE metadata is not signature verification.

There are no materialized Glassmere projection tables. Restart/refetch reconstructs
query results from retained authoritative records and rehashed original bytes.
Deleting browser memory or panel session state cannot delete certification truth.
Projection database rebuild/update-failure tests are not applicable. Observation
reconstruction does not mutate workflow locking, leases, fences or cleanup.

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

[ADR 0061](../adr/0061-private-readiness-request-evaluation.md) additionally defines
a private readiness command evaluator. Its narrow observer reuses the live query;
the journal publishes only through current grants and the original coordination
fence. The receipt is historical even when its observation says RELEASE_ALLOWED.
Same-key replay preserves it; another explicit key requests a new observation.
The controller's `dispatch-command --observation-config /private/query.json`
requires a separate SELECT-only `ARCHCERT_OBSERVATION_DATABASE_URL` for that path.
Missing observation capability records unavailability; invalid provided
configuration fails initialization. This foundation enables no browser or daemon
readiness action and acquires no build/runtime/signing capability.

The private controller `request-readiness` entrypoint additionally requires its
separate scoped credential and expected authority-context identity under
[ADR 0062](../adr/0062-readiness-request-entrypoint.md). Its schema-2 public receipt
has `observation_freshness: HISTORICAL_OBSERVATION`; schema-1 job receipts remain
unchanged. See [private readiness qualification](READINESS_QUALIFICATION.md) for
explicit historical fixture selection and actual controller/outage/crash checks.

Under [ADR 0063](../adr/0063-readiness-command-transport.md), the opt-in daemon
command API also accepts schema-2 `REQUEST_RELEASE_READINESS_EVALUATION` with only
an `invocation` digest in its action. Existing scoped backend credentials and
grants, expected authority context and explicit idempotency key are mandatory.
The daemon records a question; the separately provisioned dispatcher evaluates it.
This enables no browser readiness form. Job request/receipt schema 1 remains
unchanged, and no caller can post readiness facts or a release recipe.

[ADR 0064](../adr/0064-glassmere-readiness-browser-request.md) adds the optional
browser form for that exact invocation. Current role/project/object/Origin/CSRF
checks and separate private backend grants remain mandatory. The receipt explicitly
labels its structured observation HISTORICAL_OBSERVATION, including a past ALLOWED.
It has no live-confirmation behavior. Refresh retains the original result; another
explicit question gets a new key. Use its separate exact live-query link to inspect
current readiness. No new build or signing capability is granted.

The [readiness qualification guide](READINESS_QUALIFICATION.md#browser-question-qualification)
documents the dedicated real-browser/controller/daemon/PostgreSQL corpus, explicit
historical evidence selection, role cycle, idempotency and artifact-outage checks.
It creates no new M6 execution, signature or native qualification.

Evidence inspection rehashes registered project/entity/digest-bound original bytes.
Certificate and permit signatures are checked under selected public keys. Signature
validity is distinct from actual artifact authorization, which requires readiness or
the existing offline M6 gate. Previews are escaped, bounded and conservatively redact
representative credentials. Original downloads deliberately preserve bytes and may
contain confidential source material; they require authorization and use attachment,
nosniff, a digest filename and a digest header. Do not publish the private evidence
store. No Markdown HTML or arbitrary link is promoted into a verified citation.

## Job command backend

[ADR 0058](../adr/0058-glassmere-job-command-transport.md) defines the separately
opt-in daemon command API and trusted controller polling for certification,
eligible queued cancellation and exact-attempt infrastructure recovery. The daemon
requires private command-only credentials; those tokens cannot authenticate legacy
submission. The panel can opt into the separate identifier-only broker described
below. Complete browser and durable workflow qualification remains open.
ADR 0063 extends the initial job grammar with schema-2 readiness questions.
Release-build commands and ReviewDisposition remain absent. A request receipt
is not a certificate, permit or positive target verdict.

Pass `--command-config /private/authority/glassmere/commands.json` to enable the
broker. The canonical owned configuration directory must be mode 0700 and the
regular file mode 0600, without symlinks or hardlinks. Its strict schema-1 fields
are `schema`, a literal loopback socket `endpoint`, and `mappings`. Each mapping
contains the exact panel `principal`, project UUID, `repository`, a nonempty
`operations` array and independently provisioned backend `token`. Supported
operations are `REQUEST_CERTIFICATION`, `CANCEL_ELIGIBLE_JOB`,
`RETRY_ELIGIBLE_JOB` and `REQUEST_RELEASE_READINESS_EVALUATION`.
No token example or default credential is provided. Never
reuse login or historical submission credentials, or share tokens across panel
principals. Backend credential and repository/operation grants must already exist;
the panel does not provision them or migrate its authority database.

Mappings reload on each request. Changing the endpoint requires restart. Client
calls are limited to four concurrent requests, two-second connection and ten-second
total bounds, 4-KiB bodies and 128-KiB streamed responses. Redirects and proxy
selection are unsupported. Operator and Administrator principals must have audited
`grant_generation` assignments before startup with commands enabled. Use the
provisioning procedure to upgrade legacy grants while preserving explicit scope.

Forms select existing scoped source/review/job/attempt/invocation IDs only. Reviewed profiles
require an existing owned reviewed session; the browser cannot provide its result.
Cancellation covers eligible queued work. Recovery cannot retry target/policy
failure, raise an attempt budget or assert runtime cleanup. Authority eligibility
is checked at durable mediation, regardless of a button or observed state.
Submissions carry a retained action key and redirect to a read-only receipt;
refreshing it never repeats submission. Different tabs and HTTP retries depend on
the backend's durable workflow intent coalescing. Readiness instead retains one
historical question per explicit key; another key asks a fresh question without
creating a certification/build workflow. Browser process loss owns no execution,
signing or coordination lease.

The [workflow qualification guide](WORKFLOW_QUALIFICATION.md) describes the
separate real-browser/daemon/PostgreSQL harness, its metadata-only fixtures,
durable count assertions and retained evidence. It does not qualify target
execution, signing or the remaining M9 scope.

## Development authority time

Lease qualification requires a stable authority database clock. Use one coherent
time source for the PostgreSQL host/VM. Competing VM clock correctors can invalidate
lease bounds; backward steps can extend an unchanged generation's apparent deadline.
The current implementation does not claim wall-clock rollback tolerance. Diagnose
clock/service state and retain failures before correcting development provisioning;
do not increase timeouts or suppress a lease guard to make tests pass. Bounded
clock samples establish only the observed local environment. They do not establish
production time discipline or native qualification. Recheck time services after a
development VM restart, which may restore its default service configuration.

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

The browser journey normally uses the installed Chrome channel. A separately
provisioned portable Chrome can be selected with `GLASSMERE_CHROME_EXECUTABLE`,
which must be an absolute regular-file path. Select and verify that browser
outside project inputs and retain its distribution/version identity with the
test output. The journey records the actual browser version and keeps the same
assertions. It never downloads or chooses a browser on behalf of the panel.
