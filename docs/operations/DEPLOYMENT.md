# Running the existing ArchCert application

The [README](../../README.md) is the first-use path. This guide supplements its
process, custody and recovery contracts. [ADR 0071](../adr/0071-product-account-integration.md)
supersedes the separate API from ADR 0070. There is one application architecture.
M9 remains INCOMPLETE; M10, M11, Pre-Genesis and Genesis remain NOT STARTED.

## Service and capability inventory

| Component | Lifecycle | Required capability |
| --- | --- | --- |
| Dedicated PostgreSQL | Always on while operating | Durable source/job/account metadata; private persistent bind volume |
| `migrate` storage example | Explicit init/update/restore only | DDL owner; not an application startup privilege |
| `archcertd` | Supervised API | Existing durable admission/command boundary plus normal account/project provisioning; bounded DB writes; no runtime or signer |
| `archcert-panel` / Glassmere | Supervised web server | SELECT-only authorized observation, public verification, private bounded API client, existing sessions |
| OpenSSH / `archcert-gateway` | Supervised ingress / forced child | Exact grants, quarantine, validated Git objects, immutable snapshots; no target execution |
| `archcert-controller run-once` | Supervised trusted loop | Durable claiming, leases, fences, recovery gates, evidence publication, conditional development issuance |
| `archcert-worker` | Controller child | Sealed plan/source; explicit runtime; no DB, signing, object publication or acquisition credentials |
| Independent rootless OCI daemon | Host prerequisite | Network-denied execution, read-only source, resource bounds and cleanup evidence |
| Artifact store | Persistent private directory | Original immutable per-project/digest storage and verified reads |
| Signing identity | Explicit host provisioning | Private development key only selected by trusted controller; public key selected independently for verification |
| Glassmere sessions | Panel memory | Opaque server-side validation, expiry, logout and current generation checks; restart requires login |
| Original command broker | Optional configuration of existing services | Existing bounded review/readiness/M6 operations, independently provisioned grants |
| Semantic provider | Optional separate provisioning | Supplemental review only; no deterministic proof or execution/signing authority |
| M6 release tools | Optional exact native profile | Separate authority recipe, A/B build, artifact binding and permit verification |
| Test/browser tools | Engineering only | Isolated schemas/installations; not runtime dependencies or production assurance |

The helper starts existing executables, not a second backend. The API's account
adapter validates broker identity, current account generation/role and exact owned
project. Certification then calls the original admission route and control plane.
No worker receives database credentials. SSH inherits only PATH, HOME and private
TMPDIR. The panel's observation role cannot read password/account tables.

## Persistent layout

`ARCHCERT_HOME` defaults to `~/.local/share/archcert`, outside source trees. Its
root/subdirectories are 0700 and private files 0600 (executables 0700):

| Directory | Retained content |
| --- | --- |
| `database/` | PostgreSQL durable files |
| `artifacts/` | Immutable evidence and certificates |
| `sources/`, `git/` | Accepted/quarantine source, repository registrations, ingress host custody |
| `config/` | Trusted policy selection and private service projections/credentials |
| `bootstrap/` | Unconsumed setup secret and host recovery transients |
| `signing/`, `public/` | Explicit development private key / selected verification material |
| `workspaces/`, `workspaces.runtime/` | Worker workspace and retained runtime recovery gates |
| `audit/`, PostgreSQL audit tables | Operational and provisioning history |
| `logs/`, `health/`, `run/` | Private process logs, bounded observations, PID/coordination state |
| `backups/`, `bin/` | Complete private backups / selected executable installation |

Database migration, control and observation roles have independent passwords.
Control lacks DDL, migration-record mutation and audit UPDATE; observation is
SELECT-only and excludes account/provisioning tables. Same-UID/root and database
owner remain trusted in this development deployment. Private files/backups are
unencrypted at rest; this is not an adversarial multi-tenant custody boundary.

## macOS and Colima

The observed infrastructure context is `colima`. The separate `archcert-m3` VM
contains a **previously provisioned rootless** Docker service. Starting an ordinary
Colima VM does not install that service or qualify a runtime. Inspect it first:

```bash
colima start archcert-m3
colima ssh --profile archcert-m3 -- systemctl --user status docker --no-pager
```

For this existing VM, the rootless socket is `/run/user/501/docker.sock`. Select
the actual provisioned UID on another VM. Create a private local forward only if
that path is not already owned by a live process:

```bash
mkdir -p "$HOME/.local/share/archcert-runtime"
chmod 700 "$HOME/.local/share/archcert-runtime"
ssh -F "$HOME/.colima/ssh_config" -fNT \
  -L "$HOME/.local/share/archcert-runtime/rootless.sock:/run/user/501/docker.sock" \
  -o ExitOnForwardFailure=yes colima-archcert-m3
export ARCHCERT_RUNTIME_ENDPOINT="unix://$HOME/.local/share/archcert-runtime/rootless.sock"
export ARCHCERT_DOCKER="$(command -v docker)"
"$ARCHCERT_HOME/bin/archcert-worker" \
  --docker "$ARCHCERT_DOCKER" --endpoint "$ARCHCERT_RUNTIME_ENDPOINT" doctor
```

Do not delete an occupied socket blindly. Inspect its owner and the selected VM;
restart only your identified forward. ArchCert does not stop shared VMs/daemons,
prune unknown containers or promote the infrastructure daemon into execution
fallback. macOS/forwarded execution remains DEVELOPMENT TESTED / UNQUALIFIED for
native qualification. Doctor observations are not cryptographic host attestation.

## Recovery and forward compatibility

`init` refuses nonempty data. Preserve interrupted installation evidence. A consumed
bootstrap secret cannot be renewed; use audited host password recovery. Missing
PostgreSQL, invalid migration state or a corrupt private file must fail closed.
A missing cookie is never initialization evidence.

Account/project writes and audit commit transactionally before projection
publication. A pending marker denies normal account operation after interrupted
publication. To reconstruct retained assignments with services stopped:

```bash
./scripts/archcert-services down
./scripts/archcert-services publish
./scripts/archcert-services up
```

`publish` starts only the selected database as needed; it does not create accounts
or reinterpret policy. Never edit account generations, source digests or migration
rows manually. Review logs privately; do not paste credential-bearing config.

Upgrade applies migration 0012 to the existing five physical tables in place,
renames legacy database roles and private API/client configuration, and retains
previous config/binary under private `backups/pre-product-integration/`. Historical
IDs, triggers/sequence names and `local-certify-` idempotency keys remain unchanged
for compatibility. The old package is absent from the workspace and is never
launched. A legacy `local-api` PID record is recognized only for safe shutdown.
Do not start older binaries against the migrated database.

A restore creates a separate empty installation, replaces only that never-served
database schema with the verified backup, migrates forward, reconstructs private
projections and leaves runtime disabled. Restore source, evidence, configuration,
audit, gates and custody together. Database-only backups are insufficient.
Cross-host gates require explicit investigation; certificate verification alone
does not authorize renewed execution.

## Browser and integration validation

Use a dedicated fresh installation and the real Chrome binary. Install the locked
browser dependency first:

```bash
npm ci --prefix tools/glassmere-browser
export ARCHCERT_TEST_OUTPUT="$PWD/target/deployment-browser"
node scripts/test-archcert-onboarding
node scripts/test-archcert-certification
```

Set `ARCHCERT_HOME` to the isolated test installation. It must have explicit
rootless/signing provisioning before admission; alternatively the onboarding test
can provision it *after browser account creation* using
`ARCHCERT_TEST_CONFIGURE_AUTHORITY=1`, `ARCHCERT_TEST_IMAGE`,
`ARCHCERT_TEST_DOCKER`, and `ARCHCERT_TEST_ENDPOINT`. For a standalone Chrome for
Testing binary set `GLASSMERE_CHROME_EXECUTABLE` to its absolute executable path.
The tests retain private credentials outside Git and transient evidence under
ignored `target/`. Do not run first-registration tests against your human account.

Onboarding races two real browser setup forms, checks Origin/replay rejection,
logs in, creates an owned project, checks escaped metadata, pushes an actual Git
commit through Northgate and admits it via the original API. The results test
inspects actual isolated execution, evidence, downloaded certificate and offline
verification, temporary store-loss failure, a changed failing business case,
idempotency, CSRF/privilege rejection, grant/session invalidation and persistence.
No test manufactures a passing certificate. PostgreSQL and runtime tests require
actual dependencies; ignored tests do not count as passes.

See [Ravenport](../architecture/RAVENPORT_OPERATIONS.md),
[Glassmere provisioning](../glassmere/PROVISIONING.md),
[release operations](../release/README.md), [runner qualification](../qualification/NATIVE_LINUX_RUNNER.md)
and the [original engineering reference](ENGINEERING_REFERENCE.md).
