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
