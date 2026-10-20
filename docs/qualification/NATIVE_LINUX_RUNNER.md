# Native Linux execution qualification

Status: **QUALIFIED on the exact Ubuntu/KVM/rootless profile below**, October 20,
2026. All required native demonstrations and final residue cleanup passed. This
is an execution/recovery qualification, not production certification.

## Qualified environment

The qualification account ran the controller and worker directly in a **KVM
virtualized native Linux guest**. This is not bare metal. It differs from the
macOS-controller/Colima development path; no broader Linux support is inferred.

| Property | Observed value |
| --- | --- |
| Distribution | Ubuntu 26.04.1 LTS, Resolute Raccoon |
| Kernel | 7.0.0-31-generic, #31-Ubuntu SMP PREEMPT_DYNAMIC Sat Aug 1 04:26:38 UTC 2026 |
| Architecture / virtualization | x86_64 / KVM |
| Authority identity | uid=1001, gid=1001; no docker group; no sudo/root steady-state execution |
| Service manager | systemd 259.5-0ubuntu3.4, healthy user manager |
| Endpoint | unix:///run/user/1001/docker.sock |
| Docker | client/server 29.1.3, dedicated rootless daemon |
| Runtime components | runc 1.4.0-0ubuntu1; containerd 2.2.2; rootlesskit 2.0.2; slirp4netns 1.3.3; docker-init 0.19.0 |
| Cgroups | cgroup v2, systemd driver; private target cgroup namespace |
| Security options | name=seccomp,profile=builtin; name=rootless; name=cgroupns |
| AppArmor | host enabled (Y); profile-list read denied; rootless security options omit AppArmor; target AppArmorProfile empty and process label runc (unconfined) |
| Filesystem | /dev/sda2, ext4, rw,relatime; Docker overlayfs; authority data on local ext4 |
| Docker data | /home/archcert-stoneward/.local/share/docker, separate from /var/lib/docker |
| User namespaces | enabled; max_user_namespaces=56958; uid/gid maps 0 -> 1001 length 1, 1 -> 165536 length 65536 |
| Rust / PostgreSQL | Rust 1.99.1; PostgreSQL 18.6 in the dedicated rootless test daemon |

The explicitly authorized rootful-endpoint denial probe failed with permission
denied. ArchCert never ran against or managed the unrelated rootful daemon.
The rootless daemon started empty; qualification-created resources were inventoried
and removed separately. Bootstrap used preprovisioned subordinate IDs/tools and
unprivileged user services; no host-wide service, firewall, SSH configuration or
privileged fallback was changed.

## Support matrix

| Environment | Status |
| --- | --- |
| Exact Ubuntu/KVM/rootless profile above | QUALIFIED |
| macOS x86_64 / Colima Ubuntu 24.04.4, kernel 6.8.0-117-generic, rootless Docker 29.5.2 / runc 1.3.5 / containerd 2.2.4 | DEVELOPMENT TESTED |
| Docker Desktop | NOT QUALIFIED |
| Podman | NOT QUALIFIED |
| Other Linux distributions/kernels/runtime combinations | NOT QUALIFIED |
| gVisor / Firecracker | NOT IMPLEMENTED |

## Runtime preflight and authority

Explicit authority-selected absolute Docker executable and local Unix endpoint
are required. Project DTO regressions reject socket, context, endpoint and TLS
credential selection. Every call clears ambient Docker configuration/environment
and uses private empty CLI configuration. Evidence retains the endpoint, local
socket incarnation, daemon ID, runtime/component versions and security reports.
These are observations, not cryptographic attestation. The observed daemon ID was
10911041-90ff-46ac-a55b-ca29edaebfde; service restart changed the socket incarnation.

Preflight requires rootless Linux, cgroup v2/systemd, runc, builtin seccomp and
memory/swap/PID/CPU support. Unknown warnings reject. The explicit allowlist covers
only missing cpuset and block-I/O controls; both were reported by this host and
neither is a claimed enforcement feature. Target stopped configuration and live
probes independently check private namespaces, UID/GID, limits and security flags.
`archcert-worker ... doctor` checks prerequisites without executing an assignment;
it does not establish full certification readiness. API health/readiness and
controller dependency diagnostics are separate.

## Observed guarantees

| Guarantee | Native observation |
| --- | --- |
| Memory/swap | memory.max enforced; memory.swap.max=0; 64 MiB exhaustion classified MemoryLimit/ResourceLimit using runtime OOM metadata, not exit code alone |
| PIDs | pids.max enforced; fork exhaustion produced EAGAIN below 16 children; process/nested-shell churn remained bounded; denial need not terminate a cooperative probe |
| CPU | cpu.max=100000 100000 by default; 10000 100000 test quota increased nr_throttled and throttled_usec; quota is aggregate CPU rate, not affinity or deterministic accumulated CPU time |
| Writable storage | /work, /tmp and /home/archcert each 32 MiB tmpfs; /output 16 MiB; writes actually reached ENOSPC on every path; memory charging also applies |
| Output/time | stdout/stderr floods caused external termination; hostile binary/ANSI bytes remained bounded numeric evidence; timeout killed entire container boundary, including TERM-resistant, detached and double-fork descendants |
| Source | /source write attempts failed; stopped-view reconstruction and before/after source identities matched accepted bytes; target had no host source mount |
| Filesystem/socket boundary | host canaries and authority paths unavailable; Docker/rootless/containerd/Podman/CRI sockets absent; private namespaced /proc, /sys and /dev still exist |
| Identity/capabilities | UID:GID 10001:10001, supplementary groups [10001]; CapEff/CapPrm/CapBnd all zero; NoNewPrivs=1; Seccomp=2; setuid/setgid(0) attempts returned EPERM |
| Host process boundary | target saw only its PID namespace, not known host PIDs; UID/GID maps matched rootless mapping |
| IPv4/IPv6 | external TCP/UDP no-route results; only lo; IPv6 enabled (disable_ipv6=0), only ::1; private IPv4 and IPv6 loopback exchanges succeeded |
| DNS/metadata/gateways | DNS lookup and direct TCP/UDP queries to configured resolver 10.0.2.3 denied; numeric TCP/UDP/HTTP routes to metadata/link-local/host gateway/LAN fixtures denied |
| Fenced recovery | real worker SIGKILL retained old target; direct recovery rejected; cleanup failure durably FAILED; stale saved assignment rejected all three later steps; reconciler SIGKILL left IN_PROGRESS; retry cleaned and confirmed absence before new attempt |
| DB/runtime disagreement | valid active execution retained; RUNNING without runtime objects required gate fencing; LOST/COMPLETED stale containers removed; unknown attempt retained/reported and startup admission blocked |
| Orphan images | preparation containers and committed job images reconciled by exact ownership; foreign-reference deletion failure blocked cleanup until retry; unrelated resources retained |
| Dependency/service restart | controller upload/evidence/evaluation/issuance/signature/certificate checkpoints resumed without target rerun; hardened transient user service resumed accepted evidence in one attempt |
| Runtime interruption | dedicated rootless Docker restart during execution yielded INCONCLUSIVE / INFRASTRUCTURE_FAILURE; never target test failure |
| PostgreSQL outage | process health stayed live, readiness became 503; admission/progress failed conservatively; restored DB resumed accepted evidence without rerun |
| Artifact outage | unavailable private artifact root blocked readiness/continuation and signing; restoring it resumed exact durable evidence; create-only/integrity/staging tests passed on ext4 |

Cleanup state is independent of target/policy outcomes. Exact local gate revocation
precedes the DB fence; confirmed runtime absence and durable SUCCEEDED cleanup
precede a new attempt. A busy/live worker gate or uncertain pending create/commit
blocks recovery even with an empty inventory. No manual cleanup assertion or global
prune bypass exists. Deadlines use Docker KILL and forced container removal;
a graceful TERM/stop-timeout lifecycle is not claimed. This is a trusted-worker, single-host protocol; all authorities
must share the same persistent gate root and daemon. See ADR 0039.

Runtime ownership labels are `archcert.owner=execution-v1`,
`archcert.ownership=2`, `archcert.certification-job`, `archcert.attempt` and
`archcert.execution`. The legacy `archcert.job` carries the execution ID, not
the durable job ID. Labels contain no secrets and are operational correlation,
not source/certificate identity. Standalone executions lack durable attempt
authority and are conservatively unknown to this recovery path.

Admission checks at least 1 GiB free and 1024 available inodes on gate/artifact
filesystems; inventory and workspace traversal are bounded. Scoped staging cleanup
retains active locked writers and unknown files and never deletes immutable final
objects. These thresholds are not reserved space, global scheduling or a host-wide
quota. Host disk/inode exhaustion was not induced on this shared host.

## Immutable inputs and native full flow

Controlled Northgate Git commit 67085b42fe02ff0832641629a31634338214be00,
tree c6365ec31116a8e66e83f91b058c472fe0064df7, snapshot SHA-256
5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af.
Policy archcert-development-v1 1.0.0, SHA-256
e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae;
plan 8ef37e471318bae8dae6778a4e023254e20a298c006f569c3dc229720d7cfb27.
Target image python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f.
The development PostgreSQL image was
postgres@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336.

The actual authenticated push, durable admission, worker execution, evidence
publication, deterministic policy, development Ed25519 signing, certificate
persistence and selected-key offline verification succeeded. Bottle commit
8ec5fe29420d14998c0d86885083983eaea8b839 retained snapshot
e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0;
it remained NOT_ELIGIBLE with no certificate. Private keys/tokens were temporary
and were destroyed; public engineering output and bounded logs remain outside Git.

## Commands and source revisions

Every native run recorded `git rev-parse HEAD`. Source was committed locally and
transferred exactly; no divergent remote implementation was used.

- 45df0967856d73619031f5b0095b63902e74cc5d: initial 15 native OCI groups.
- abb0d2c7c78aac52464bb02c58c24b6b4aa556a8: seven PostgreSQL groups.
- 072c76229bb8b5726de398e66891907fdda2fd32: 15 OCI plus three reconciliation groups.
- d4598d697626c69b6670675bc84ec54eee085da8: eight PostgreSQL groups, artifact integrity/staging and Northgate regressions.
- 1aabada4df3d9699eb9e50d9b0b756d227a12a63, then d6410c02a9c44429f7076b81246c47357d0f2d67: full durable recovery/outage flows; the latter added ownership disagreement and hardened transient user services.
- 22861a083a31ce4e81bd5e2b060df1aa50e3c15b: all seven gates, 207 workspace tests, eight PostgreSQL groups, two artifact groups, 13 protocol tests, Northgate SSH regressions and all 18 live OCI/reconciliation groups.
- 22ca8715ae33a8a57b2a60162c7a8ece982bf25e: repeated all gates/suites above, all 18 live groups including configured-resolver probes, then the complete durable/restart/outage/Bottle flow after rebuilding the workspace. This is the final qualified implementation revision.

No ignored test is counted as executed by the default suite: its 26 ignored tests
were separately exercised as eight PostgreSQL, 15 OCI and three reconciliation
tests. The macOS default gates also passed with 207 tests at 22861a0; those are
additional development checks. Preliminary failures were corrected and rerun:
the missing checkpoint CLI value, a default test's untracked-certificate dependency,
ext4 inode reuse/type detection and a macOS inherited publication-lock race.
No policy or security assertion was relaxed to obtain these results.

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
ARCHCERT_TEST_DATABASE_URL=AUTHORITY_DATABASE_URL ./scripts/test-ravenport
cargo test -p archcert-storage --test artifacts --locked
cargo test -p archcert-protocol --locked
./scripts/test-northgate
ARCHCERT_TEST_DOCKER=/usr/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///run/user/1001/docker.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/test-live-oci
ARCHCERT_STONEWARD_NATIVE=1 ./scripts/demo-ravenport
```

The demonstration also requires the explicit database/image/runtime/output variables
and historical Bottle checkout described in RAVENPORT_OPERATIONS. Its native outage
mode is destructive only to the documented dedicated test services. Production
recovery uses `archcert-controller ... reconcile` inspection, then `--apply` and
optionally `--recover`; every operation remains exact-attempt fenced.

## Known limitations and NOT PROVEN

Container escape resistance: **NOT PROVEN**. Rootless Docker reduces daemon/target
host authority through user namespaces but shares the guest kernel and is not a VM
boundary. Same-UID/root/runtime/database administrator or modified trusted worker
compromise remains in the authority TCB. Runtime identity is not attestation.
Builtin seccomp was observed; ArchCert does not own/hash its profile. AppArmor
confinement was not observed or enforced. Independent controlled setuid-binary
attribution to NNP, as distinct from capability/UID restrictions, is NOT PROVEN.

**HOST REBOOT RECOVERY NOT QUALIFIED**. No reboot was authorized or performed.
Power-loss/fault-injected fsync durability, arbitrary network filesystem behavior,
shared-kernel exploits, global host exhaustion and multi-host worker coordination
are not qualified. An interrupted unacknowledged daemon creation remains blocked;
there is no availability override. Local ext4 qualification relies on create-new,
atomic link/rename semantics, fsync, permissions, descriptor/no-follow and symlink
handling; it does not establish equivalent NFS behavior or secure media erasure.

Artifact storage remains unencrypted development storage. Loopback bearer/private
file authentication is development authentication, not production IAM. Signing is
DEVELOPMENT ONLY. No semantic AI, new verdicts, changed eligibility, stronger
isolation backend, custom encryption or production certification claim was added.

## Offline independence and final cleanup

The final certificate payload identity was
6db911077507712b3431b95dcd247fc8d119b1aba5dd9f9d7da9e79c72e8deea,
selected public key ID
5eee48d7bbb0db8e5c6f4caffcbe003acf848499c465275f33f00246af3f393b.
After the controller, worker, test PostgreSQL and rootless Docker were stopped,
`env -i archcert verify EXPORTED_CERTIFICATE --public-key EXPORTED_PUBLIC_KEY`
succeeded with SIGNATURE VALID / CERTIFIED / EXACT_SOURCE. Exported public bytes
also verified independently on the development machine. Verification used no
source, policy service, database or runtime connection.

The public evidence archive was exported and all 176 member digests checked before
remote deletion; raw logs, public certificates and operational evidence remain
under ignored local target/m5.2/native. Nothing ephemeral was added to Git.

Final dedicated-daemon inventory: zero containers, zero images, zero volumes;
only builtin bridge/host/none network objects remained. Those are daemon defaults,
not qualification-created networks. Both pinned prerequisite images and the test
PostgreSQL volume were removed. The user Docker service was then stopped/disabled,
its installed unit/context and data directory removed, and its temporary runtime
directory/socket removed. An explicit endpoint probe afterward failed, with no
rootful fallback. The unrelated rootful daemon was never managed.

Transferred checkouts/bundles, temporary SSH fixture/control data, databases,
accepted-source/artifact stores, workspaces/gate tombstones, temporary configs,
logs and remote certificates were removed. Gate deletion here retires the entire
disposable qualification environment; ordinary operational recovery must retain
its tombstones. No ArchCert/OCI target process or subordinate-UID process remained.
The final own-user process inventory contained the preexisting systemd user manager,
sd-pam, D-Bus, the qualification SSH session and the inspection shell; the latter
two ended when the local SSH master closed. No qualification user unit remained.

Intentionally retained prerequisite: installed user-home Rust/Cargo tooling and
public package caches (~/.rustup and ~/.cargo). They contain no ArchCert runtime
state or authority credentials and remain available for reproducibility. Host
runtime packages, subordinate-ID/bootstrap settings and unrelated services were
operator-provisioned and left alone. No qualification image or data is retained.
