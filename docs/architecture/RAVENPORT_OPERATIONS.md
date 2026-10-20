# Ravenport development operations

The PostgreSQL service is infrastructure. It is separate from the independently
provisioned rootless target execution daemon, network, credentials and filesystem.
No target container receives the compose network, database URL or object root.

```sh
docker compose -f compose.ravenport.yml up -d --wait
ARCHCERT_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/archcert \
  cargo run -p archcert-storage --example migrate --locked
ARCHCERT_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/archcert \
  ./scripts/test-ravenport
```

Tests require a real PostgreSQL server and create isolated randomly named schemas.
They do not require privileged Docker or testcontainers. An existing development
PostgreSQL instance is also supported. These explicit tests exercise actual row
locks and SKIP LOCKED; default ignored tests are never reported as executed.
The demonstration database/test schemas are local execution artifacts, not fixtures.
Resetting a volume is an explicit operator action; scripts do not delete databases.

Migrations are deterministic versioned SQL under crates/archcert-storage/migrations,
tracked and protected by SQLx checksums. Run them explicitly using migration
credentials before starting services. Changed/failed migrations reject. Candidate
repositories cannot select migrations or migration paths. No opportunistic DDL runs
at HTTP startup.

The development compose deployment deliberately uses a trusted local database
superuser with loopback-only trust authentication. This reduces isolation and is
not a production deployment. Production must provision distinct migration,
control-plane and worker identities: the migration principal owns DDL; the control
plane owns bounded metadata operations; workers receive execution assignments
rather than database superuser or schema mutation credentials. Audit permissions
must omit UPDATE/DELETE/TRUNCATE; triggers provide additional application defense,
not protection against a database owner. PostgreSQL compromise remains operational
state compromise. Offline certificate verification still requires its trusted key.

The initial persistence adapter is compiled without TLS and is qualified only for
local development. Remote deployment requires TLS validation and protected secret
provisioning. Never pass database/object-store credentials to RunnerInput, source
files, command argv, captured target environment or certificates.

The existing .gitignore already excludes target/, .env secrets and runtime-data/.
Historical milestone reports are tracked. Do not add a blanket docs/MILESTONE_*
ignore or remove those files. Proposed optional additions, if recurring output is
kept outside target/, are the specific docs/certificates/development/ and
 docs/source-ingress/development/ trees; currently they remain visibly untracked
for review. New engineering records stay untracked, while ADRs and architecture
contracts are committed with their implementation.

Bulk storage currently uses the explicitly selected unencrypted development
filesystem adapter through ImmutableArtifactStore. The port requires S3-compatible
conditional create-only put and verified bounded get, with project-scoped SHA-256
keys. No MinIO-specific behavior enters the application. The authority creates
an existing private 0700 absolute object root. Writes fsync bytes, publish without
replacement, fsync directories and rehash on retrieval. Database STAGING metadata
becomes AVAILABLE only after independent byte verification. Orphan staging files
and unreferenced immutable objects remain unavailable and require reviewed cleanup;
no background deletion can accidentally remove issued evidence. ArtifactCipher
reserves authenticated envelope encryption behind a provider port. Production
private storage needs an actual encryption adapter; none is simulated here.

The durable API starts with an explicit private configuration file and existing
migrations/grants. `ARCHCERT_DATABASE_URL` is authority process configuration only.
Start `archcertd --config /authority/control-plane.json --listen 127.0.0.1:8080`.
The private JSON contains source_store, artifact_root and grants. Each grant has
project, repository, actor, token_sha256, profile, image, authority_toml and
maximum_attempts. Use a high-entropy generated bearer token; store only its SHA-256
in configuration. Actor is an authority UUID, not a request field. Tokens, private
configuration and keys remain outside repositories/workspaces/artifact storage.

POST /api/v1/certifications requires Authorization: Bearer and Idempotency-Key.
Its strict JSON is project, repository, source_submission. Scope authorization
precedes accepted-source lookup. The source is reloaded/rehash-checked, complete
source is required, and the job pins policy/version/digest plus the authority plan,
profile/image and bounded retry settings. Reusing the scoped key with different
pinned inputs returns conflict. Successful requests return 202, actual durable job
ID, immutable source and state; the endpoint does not report certification success.
GET /api/v1/certifications/{id} enforces the same actor scope and reads PostgreSQL.
GET /api/v1/certifications/{id}/certificate exports the verified persisted envelope
only after completion, with independently rehashed artifact bytes.

The development authority uses private-file provisioning and loopback bearer
transport, not enterprise IAM/TLS. No remote listener is permitted by this daemon.
The daemon has no signing or target execution dependency; a separate trusted
controller is responsible for orchestration. Configuration loading and HTTP
startup do not grant new database permissions or run migrations.

The trusted controller is a separate executable with authority-only commands:

```sh
archcert-controller --config /authority/control-plane.json provision
archcert-controller --config /authority/control-plane.json run-once \
  --worker-binary /absolute/archcert-worker \
  --workspace-root /authority/workspaces \
  --docker /absolute/docker --endpoint unix:///authority/rootless.sock \
  --development-key /authority/signing/development.der \
  --public-key /authority/signing/public.hex
archcert-controller --config /authority/control-plane.json show JOB_UUID
archcert-controller --config /authority/control-plane.json recover JOB_UUID \
  --cleanup-confirmed
```

Run-once first resumes a retained EVALUATING/SIGNING job, otherwise claims queued
work. Operators may invoke it repeatedly under a service supervisor. PostgreSQL
is the queue; no broker/outbox is required. Default leases are 30 seconds, bounded
5–300 seconds; heartbeats renew at one third of the duration and never extend
an attempt beyond one hour. Uncertain renewal kills the execution process and
rejects publication; runtime cleanup still needs confirmation. The daemon never
loads signing keys. The controller clears the entire child environment and passes
only source/plan bytes plus explicit runtime configuration. The worker has no DB,
object-store or signing dependency. The existing fixed target environment remains
credential-free.

Lease expiry never proves target termination. LEASED attempts can recover before
target start; RUNNING attempts require an operator to confirm source workspace,
container and job-image cleanup before requeue. `recover` is an authority command,
not an anonymously callable endpoint. This development topology does not provide
remote process fencing or an automatic runtime orphan reconciler. A stale result
is transactionally fenced even if its target kept running. Maximum attempts are
pinned at admission (1–3); target/policy rejection never queues another attempt.

After evidence acceptance, continuation reads/revalidates the exact immutable
result artifact and original source/plan/policy. The evaluation phase time is
persisted with the EVALUATING transition. Infrastructure uncertainty is terminal
INCONCLUSIVE; policy rejection is NOT_ELIGIBLE. Neither can silently become active.
After eligibility, freeze issuance time/key/payload digest before signing; recovery
must reconstruct the identical canonical draft. A crash after signing repeats only
that certificate-specific operation. Deterministic Ed25519 yields the same envelope.
Persist/rehash the verified envelope before atomically committing COMPLETED,
certificate metadata and CertificateIssued audit. Source/policy/job/attempt bindings
are retained through immutable relational references, not a certification boolean.

`scripts/demo-ravenport` requires a dedicated empty development database, the
existing rootless OCI image, Git/SSH fixture prerequisites, and the historical
Bottle test checkout. Build all five executables first. Set ARCHCERT_DATABASE_URL,
ARCHCERT_TEST_DOCKER, ARCHCERT_TEST_ENDPOINT and ARCHCERT_TEST_IMAGE; optional
ARCHCERT_RAVENPORT_OUTPUT chooses a new output directory. It refuses overwrites.
The script performs real authenticated source push, concurrent HTTP admission,
service restarts, controller crash checkpoints, worker SIGKILL during execution,
explicit cleanup/recovery, offline verification and unchanged Bottle rejection.
Private SSH/signing material and bearer tokens are temporary outside the repo;
retained public evidence defaults to ignored target/m5.1/demonstration/.

The authority-only --stop-after test flag exits the controller at explicit lease,
artifact staging, evidence, evaluation, prepared issuance, signed, or certificate
upload boundaries. It is not read from project configuration or HTTP input.
The demonstration restores each stage using a new process and preserves attempts.

Stoneward adds a credential-free runtime diagnostic:
`archcert-worker --docker /absolute/docker --endpoint unix:///authority/rootless.sock doctor`.
It reports observed prerequisite identity without reading stdin or starting a
container; an invalid/unavailable runtime exits nonzero. This is a runtime
preflight check, not full service readiness or native qualification. See
[native qualification status](../qualification/NATIVE_LINUX_RUNNER.md) and
[ADR 0038](../adr/0038-stoneward-native-qualification-profile.md). Current running
attempt recovery still requires the explicit authority cleanup path above.
