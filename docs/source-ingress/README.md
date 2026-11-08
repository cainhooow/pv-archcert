# Northgate development source ingress

Build with `cargo build -p archcert-cli -p archcert-gateway-cli`. Run
`./scripts/test-northgate` for the real OpenSSH Git push and adversarial fixture.
It requires Python 3, Git, OpenSSH ssh/sshd/ssh-keygen and a usable current OS
account. The default gateway integration test runs this fixture too; missing
prerequisites fail explicitly. The harness binds loopback, generates temporary
client/host keys, pins the host key, starts a restricted sshd and cleans up.

The deployment contract is:

```text
OpenSSH authenticated public key
 -> authority-owned restrict,command="... archcert-gateway receive --config ... --device-key PUBLIC_FINGERPRINT"
 -> SSH_ORIGINAL_COMMAND = git-receive-pack 'company/project.git'
 -> exact actor/device/project/repository grant
 -> private per-submission quarantine
 -> bounded Git pack + original ArchCert source validation
 -> immutable accepted source / structured ingress evidence
```

The authority configuration is strict JSON. See the executable fixture for a
complete runnable configuration and SSH server settings. Use canonical private
mode-0700 store directories and private mode-0600 operator configuration outside
all target-controlled paths. Use a dedicated service account with only restricted
keys and no ambient signing/runtime credentials. Install public keys only; host
and client private SSH material are managed by the operator/client, not ArchCert.
Do not enable password/keyboard authentication, user rc/environment/PTY/subsystems,
agent/X11/TCP/Unix forwarding or additional unrestricted keys. Set authentication,
startup, unused-connection and login limits as shown in the fixture. OpenSSH itself runs the fixed
forced command using the account command interpreter; candidate text never enters
that interpreter. No target script or repository hook runs on the gateway host.

The exact virtual route is authority-provisioned. With a configured endpoint:

```sh
git remote add archcert git@cert.example.internal:company/project.git
git push archcert HEAD
archcert source show SUBMISSION_UUID --store /authority/northgate-store
archcert certify --source-submission SUBMISSION_UUID \
  --source-store /authority/northgate-store --snapshot EXPECTED_SOURCE_SHA256 \
  --project PROJECT_UUID --repository REPOSITORY_ID \
  --workspace-root /authority/workspaces --profile python \
  --image python@sha256:AUTHORITY_PINNED_DIGEST \
  --docker /absolute/docker --endpoint unix:///authority/rootless.sock \
  --authority-config /authority/commands.toml \
  --development-key /authority/signing/development.der \
  --public-key /authority/signing/public.hex --output /authority/evidence/new
```

Push output says SOURCE ACCEPTED or SOURCE INCOMPLETE_EXTERNAL_SOURCE. It does not
report test/build/policy/certificate success. The later CLI call separately loads
and verifies immutable bytes, then executes the existing development chain under
its own authority. Ravenport additionally admits separate authenticated durable
certification jobs; see [operations](../architecture/RAVENPORT_OPERATIONS.md). The source
store is reusable across separately selected authority/execution/policy requests.

With the existing rootless OCI environment and pinned image:

```sh
ARCHCERT_TEST_DOCKER=/absolute/docker \
ARCHCERT_TEST_ENDPOINT=unix:///authority/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:AUTHORITY_PINNED_DIGEST \
./scripts/demo-northgate
```

The demo pushes the controlled historical fixture and Bottle through SSH, compares
exact identities, signs/verifies the controlled result and confirms unchanged
Bottle policy rejection. Public evidence is retained under development/. Private
SSH/signing keys remain temporary outside the source store and are destroyed by
harness cleanup. The demo refuses to overwrite retained evidence.

Controlled external resolution is a separate operator action:

```sh
archcert-gateway resolve ORIGINAL_SUBMISSION_UUID --config /authority/resolution.json
archcert source show NEW_SUBMISSION_UUID --store /authority/northgate-store
# A later certify request uses NEW_SUBMISSION_UUID and its new expected digest.
```

The private JSON configuration names `store`, `resolver_actor`, `parent_submission`,
`parent` (project, repository, exact identity), optional `lfs_root`, `lfs` grants
(path, SHA-256, size), and `submodules` grants (path, accepted child submission,
scoped exact source). `scripts/demo-northgate-resolution` contains a complete
runnable example. The LFS directory is private mode 0700, with mode-0600/0400 regular
single-link object files named by lowercase SHA-256. Provision it through an
operator-controlled channel. Candidate paths/URLs never choose storage locations.
The adapter verifies every digest/size and child identity before publishing a NEW
complete snapshot. The original remains incomplete and immutable. Configuration
and acquisition files are no longer needed afterward.

Run `./scripts/demo-northgate-resolution` with the same explicit OCI environment
for actual authenticated pushes, controlled LFS/submodule resolution, independent
Python identity reproduction, actual OCI reads of resolved source, development
signing and offline verification. It removes acquisition files and stops SSH before
execution. Public evidence goes to development/resolved; existing evidence is never
overwritten. `ARCHCERT_DEMO_OUTPUT` and `ARCHCERT_RESOLUTION_OUTPUT` can redirect
fresh demonstration output to an operator-selected directory.

Initial limitations: one session per store, finite local development retention,
self-contained packs, one create-only branch per push, a single selected-commit
shallow declaration, no branch-history certification, no durable jobs/database,
no HTTPS/embedded SSH server and no automatic remote LFS/submodule acquisition or
Git LFS Batch API server. Unresolved pointers/gitlinks remain incomplete and cannot
run or qualify for issuance. Resolved complete child snapshots can be reused;
recursive implicit fetching is unsupported. See ADR-0033 for canonicalization,
credential boundaries and recursive verification limits.

## Rejection diagnostics

The restricted gateway prints `NORTHGATE: CODE` and safe numeric budget details to
SSH stderr. Git stdout remains packet-line data only. Inspect the private
`SUBMISSION_UUID/evidence.json` for `diagnostics.stage`, `elapsed_ms`, `failure`
and pack-prefix `reception` measurements. Prefix measurements do not imply a
complete pack, checksum or digest. Historical evidence without diagnostics retains
unknown values; do not infer a resource failure from an opaque rejection.

Codes distinguish pack bytes/count/work, individual objects, delta safety bounds,
source bytes/files/blob/depth/visits, invalid objects/paths, incomplete object
closures, session timeout, capacity exhaustion, unavailable storage/adapter and
protocol rejection. Configured and observed numeric values are omitted when the
check supplies no measurement. A generic Git subprocess failure does not establish
a specific capacity cause. Rejection creates no accepted snapshot. A disconnect
after immutable publication can leave accepted source; inspect retained state
before retrying. Source acceptance grants no certification authority.

| Stable code | Established meaning |
| --- | --- |
| `AUTHENTICATION_DENIED`, `REPOSITORY_DENIED`, `RECEIVE_COMMAND_DENIED` | Fixed device mapping, exact grant or literal forced command denied |
| `INGRESS_PACK_TOO_LARGE` | Incoming pack byte cap reached, with an actual excess byte observed |
| `INGRESS_OBJECT_COUNT_EXCEEDED` | Pack header entry count exceeds the cap |
| `INGRESS_OBJECT_WORK_EXCEEDED` | Checked decoder or selected-source work budget exceeded |
| `INGRESS_OBJECT_TOO_LARGE` | Declared/resolved Git object exceeds its byte cap |
| `INGRESS_DELTA_LIMIT_EXCEEDED` | Independent delta depth or expansion safety bound exceeded |
| `SOURCE_SNAPSHOT_TOO_LARGE`, `SOURCE_FILE_COUNT_EXCEEDED`, `SOURCE_BLOB_TOO_LARGE` | Selected source content, leaf count or blob cap exceeded |
| `SOURCE_TREE_DEPTH_EXCEEDED`, `SOURCE_OBJECT_VISITS_EXCEEDED` | Selected closure nesting or read count exceeded |
| `SOURCE_PATH_REJECTED`, `SOURCE_OBJECT_INVALID` | Unsupported/colliding path or invalid object representation/identity |
| `SOURCE_INCOMPLETE` | Required selected-closure object or external content unavailable |
| `INGRESS_SESSION_TIMEOUT` | Authority deadline expired; acceptance did not publish after it |
| `INGRESS_CAPACITY_EXHAUSTED` | Busy receive lease or retained-attempt cap |
| `INGRESS_STORAGE_UNAVAILABLE` | Private storage/adapter access failed |
| `INGRESS_CONFIGURATION_INVALID` | Strict host configuration or its limits are invalid |
| `INGRESS_PROTOCOL_REJECTED` | Supported packet-line/ref/capability contract rejected |
| `SOURCE_REJECTED`, `INGRESS_INTERNAL_ERROR` | Rejection/internal failure without a more specific established cause |

## Authority-owned capacity

`GatewayConfiguration.source_limits` selects retained bytes, leaf count, blob size,
tree depth, selected-closure object visits, individual object bytes and source work.
`pack_limits` independently bounds transmitted bytes, advertised entries, object
bytes, decoded ancestry work, delta depth and expansion ratio. The shared typed
capacity rejects inconsistent object/work settings before any receive. Git's
`receive.maxInputSize` is generated from the same pack byte cap. `session_seconds`
bounds live input, framing/decoding, Git and pre-publication checks. No repository,
request, Git client or `archcert.toml` can raise these values.

| Resource | Historical/default admission | Implementation ceiling |
| --- | ---: | ---: |
| Complete pack | 64 MiB | 256 MiB |
| Pack entries | 25,000 | 100,000 |
| Pack object | 9 MiB | 32 MiB |
| Pack decoded work | 256 MiB | 1 GiB |
| Snapshot content | 64 MiB | 128 MiB |
| Snapshot leaves | 10,000 | 10,000 |
| Source blob | 8 MiB | 8 MiB |
| Tree depth | 32 | 32 |
| Selected object visits | 25,000 | 25,000 |
| Source object | 9 MiB | 9 MiB |
| Source work | 256 MiB | 512 MiB |
| Session seconds | 30 | 120 |
| Retained submissions | 32 | 32 |

Pack delta depth defaults to 32, with ceiling 64. Expansion ratio defaults to and
cannot exceed 4096, retaining the existing 1 KiB allowance. Every budget must be
positive; there is no unlimited mode. Ceilings are safety constraints, not a
recommendation to select every maximum. Measure the actual transmitted pack and
selected snapshot before approving a host selection. History compression can
consume most of a session before the first pack byte arrives.

For the existing product deployment, select a capacity through the host helper:

```sh
./scripts/archcert-services down
./scripts/archcert-services configure-ingress --capacity /absolute/private/capacity.json
./scripts/archcert-services up
```

The JSON contains exactly `pack_limits`, `source_limits`, `session_seconds` and
`max_submissions`, using the field names above and in the executable fixture.
Validate it separately with:

```sh
~/.local/share/archcert/bin/archcert-gateway validate-capacity \
  --config /absolute/private/capacity.json
```

Use a canonical private 0700 directory and 0600 regular single-link file outside
candidate control. The helper stores the validated selection under `ingress` in
private `platform.json`; the API projects it into generated `gateway.json`.
Do not edit the projection. Restart, update, grant changes, credential rotation
and regeneration preserve the host selection. Previously accepted source reloads
with its retained validated capacity; historical records keep original defaults.
These settings do not change source canonicalization, SHA-256 or certificates.

### Selected-commit shallow pushes

A normal empty receiver requires all transmitted history to be independently
bounded and decoded, even though certification binds one exact commit/tree.
Northgate accepts one shallow declaration only when it equals that selected commit.
A process-local `GIT_SHALLOW_FILE` can declare that boundary without modifying the
candidate repository, its refs, history, tracked content or original OID:

```sh
# Run in the original candidate repository. Use an authority/client-owned private
# directory outside the repository for this small process-local boundary file.
git rev-parse HEAD > /absolute/private/selected.shallow
GIT_SHALLOW_FILE=/absolute/private/selected.shallow \
  git -c core.sshCommand="$SSH_CMD" push archcert HEAD:refs/heads/candidate
```

To reproduce a historical incident, put the exact historical OID in that file and
use the same full OID as the push source, instead of `HEAD`. This changes only the
client's ancestry traversal for that process. The received commit still contains
its original parent fields and hashes to its original OID; its tree and all required
source objects must exist and validate independently. No ancestor or content is
fabricated. Missing selected closure, multiple/foreign shallow boundaries and
cross-submission thin bases reject. An accepted ref is immutable provenance; never
force-update it. Inspect accepted state before retrying an uncertain disconnect.

### Troubleshooting

SSH `Accepted publickey` establishes authentication, not successful source receive.
Inspect the exact registered route, then use the stable rejection code and retained
stage. `INGRESS_SESSION_TIMEOUT` can mean client pack preparation consumed the
session before data arrival. `INGRESS_PACK_TOO_LARGE` applies to transmitted bytes;
`SOURCE_SNAPSHOT_TOO_LARGE` applies to selected blob content, including reused blobs
at separate paths. Work budgets include repeated delta ancestry and object reads;
compressed disk size alone does not predict them.

`INGRESS_CONFIGURATION_INVALID` requires correcting private host provisioning.
`INGRESS_CAPACITY_EXHAUSTED` means a busy receive lease or finite retained attempts;
when no slot remains, another record cannot be retained. Preserve existing records
and investigate/archive deliberately. `INGRESS_STORAGE_UNAVAILABLE` requires checking
private storage/adapter readiness, ownership, permissions and disk headroom.
Generic invalid-object/protocol failures establish no specific budget cause.
Observed values are measured prefixes when reception stopped early; a complete
pack digest appears only after complete checksum-validated reception.

Run the focused real SSH regression with:

```sh
./scripts/test-northgate-capacity --binary target/debug/archcert-gateway
```

It covers exact/below/above source limits, pack/count/work/blob/object/depth/visits,
files, candidate override rejection, timeout, capacity, invalid configuration,
unavailable storage, immutable replay/reload and exact shallow identity. The
original `scripts/test-northgate` retains hostile protocol, path, key/grant, hook,
external-source and historical regressions. Source acceptance remains separate from
certification: the current product grants controlled Python checks; no authorized
Next.js/TypeScript/Bun profile is added here.

### Measured ArchSite capacity selection

The explicit example [archsite-capacity-v1.json](archsite-capacity-v1.json) selects
128 MiB pack/snapshot, 256 MiB pack/source work and a 120-second session, retaining
the original file/blob/object/depth/visit/delta/ratio/retention limits. It is ingress
capacity, not a certification profile. Copy it into private host configuration and
approve it through `configure-ingress`; repository bytes do not provision authority.

The isolated real SSH selected-commit push for original incident commit
`38e18597193d453fc8b269e20f09c76e250f3437`, tree
`d3a2cbcea553da1d831ab09c85906f28f88b0f83`, received 58,331,256 pack bytes and 3,532
objects. Independent validation retained 2,545 files / 70,012,087 source bytes.
Conservative decoder work was 210,645,449 bytes, below the unchanged 256 MiB cap.
The retained pre-publication duration was 81,317 ms; client wall time, including
process startup, was 117.744 seconds. Separate offline pack generation produced
slightly different compression bytes with the same source identities. These
measurements justify the bounded pilot selection; they do not qualify arbitrary
repositories, full historical graph ingestion or an execution/certification profile.

The original opaque rejection's first condition remains unknown. A traced push
reproduces the 30-second receive deadline before its first pack byte; replaying the
already-built 95,281,675-byte / 21,271-object historical pack reaches the 64 MiB cap
first. The selected snapshot independently exceeds 64 MiB. Preserve this distinction
when diagnosing the incident; do not report snapshot size as its proven first cause.

### Certification prerequisites remain separate

The development execution catalog has a generic `node` family allowing `node`,
`npm`, `pnpm` and `corepack`. That catalog entry is not an authorized ArchSite
certification recipe and does not allow `bun`. Product onboarding currently projects
one host-selected `python` grant. ArchSite's original incident commit declares
`bun@1.4.3`, Next.js `16.4.1` and TypeScript `^6.0.3`; none of its scripts were
executed during ingress. Do not submit it under the Python plan or infer passing
checks from complete source acceptance.

A later certification change needs an explicitly authorized Bun/Next.js/TypeScript
command recipe and policy, digest-pinned toolchain image, approved dependency
preparation with denied runtime network, and real runner qualification. It must
also address certification source transfer explicitly: the current worker restores
source with historical 64 MiB defaults and the generic immutable artifact adapter
has a 64 MiB per-artifact bound. This ingress change expands neither contract.
Northgate's accepted-source reader independently reloads the larger retained
snapshot, while the later job/artifact/worker pipeline remains outside this
qualification. Record `SOURCE ACCEPTED` and `CERTIFICATION PROFILE UNSUPPORTED`
for this pilot; no certification job, eligibility or certificate is implied.
