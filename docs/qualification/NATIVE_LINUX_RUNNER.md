# Native Linux execution qualification

Status: **NOT YET QUALIFIED**. Stoneward is incomplete until its native execution
and recovery demonstrations pass on a documented host. A Linux VM controlled from
macOS does not qualify this deployment path. No environment is currently qualified.

## Environment and support matrix

| Environment | Status | Evidence |
| --- | --- | --- |
| macOS x86_64 controller / Colima Ubuntu 24.04.4, Linux 6.8.0-117-generic, rootless Docker 29.5.2 / runc 1.3.5 / containerd 2.2.4 | DEVELOPMENT TESTED | M3–M5.1 demonstrations and M5.2 live regressions |
| Native Linux | NOT QUALIFIED | Qualification host not yet available |
| Docker Desktop | NOT QUALIFIED | No qualification run |
| Podman | NOT QUALIFIED | No supported adapter or qualification run |
| gVisor | NOT IMPLEMENTED | Future isolation tier |
| Firecracker | NOT IMPLEMENTED | Future isolation tier |

The M5.2 development regression observed the exact VM/kernel/runtime versions
above, cgroup v2/systemd, rootlesskit 3.3.0 and builtin seccomp/rootless/cgroupns
reports. Its controller and default gates ran on Darwin 25.6.0 x86_64.

The intended qualification profile is one dedicated native Linux x86_64 host,
cgroup v2 with systemd delegation, rootless Docker, runc and builtin seccomp.
An intended profile is not a support claim. Record the actual distribution/kernel,
architecture, cgroup mode, Docker/rootlesskit/containerd/runc versions, filesystem
and mount options, security modules, user namespace mappings and delegation before
promoting an exact environment to QUALIFIED.

## Authority endpoint and preflight

The operator selects an absolute Docker executable and bounded explicit local
Unix socket endpoint. TCP/SSH endpoints, relative paths, parent traversal and
control characters reject. Project configuration cannot select Docker sockets,
contexts, runtime endpoints or TLS credentials. Each CLI invocation clears its
environment and uses a fresh empty private Docker configuration; ambient context,
proxy, credential-helper and TLS environment cannot select a different daemon.

Preflight requires Linux, rootless and builtin-seccomp reports, cgroup v2/systemd,
memory/swap/PID/CPU-limit support, no daemon warnings, and a runc default/runtime.
Target configuration independently requires runc and private cgroup namespaces.
Preparation containers explicitly select runc/private cgroups and never start.
Execution evidence records the selected `authority/endpoint`, reported daemon ID,
kernel, OS, architecture, cgroups, default runtime, security options and component
versions. These are observations, **not cryptographic runtime attestation**.
A Unix socket may itself be forwarded; its address does not establish locality
of the daemon or native host qualification.

```sh
archcert-worker --docker /usr/bin/docker \
  --endpoint unix:///run/user/1000/docker.sock doctor
```

The doctor command reads no assignment and starts no container. Success means the
reported runtime prerequisites passed; it does not establish effective namespace
mapping, live cgroup enforcement, approved image availability, storage/DB health
or readiness for a complete certification. Failure exits nonzero without emitting
positive runtime observations. Worker diagnostics acquire no DB or signing access.

## Required native demonstrations

Use the detailed [runner checklist](../runner/LINUX_QUALIFICATION.md), all default
gates, real PostgreSQL integration tests, artifact integrity tests, Northgate and
Protobuf regressions, every live OCI test and full durable flow. Retain bounded
raw logs and exact environment metadata outside Git. No ignored test counts as
executed. The baseline matrix in the local M5.2 working record identifies missing
per-property observations; it must not be substituted for execution evidence.

```sh
ARCHCERT_TEST_DATABASE_URL=AUTHORITY_DATABASE_URL ./scripts/test-ravenport
cargo test -p archcert-storage --test artifacts --locked
cargo test -p archcert-protocol --locked
./scripts/test-northgate
ARCHCERT_TEST_DOCKER=/usr/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///run/user/1000/docker.sock \
ARCHCERT_TEST_IMAGE='python@sha256:AUTHORITY_APPROVED_DIGEST' \
./scripts/test-live-oci
```

These commands document required invocations, not completed native results.
Crash/restart demonstrations must use dedicated disposable test services. Establish
worker death and prevent late target creation before claiming that an empty runtime
inventory permits retry. Lease expiry only fences authoritative database writes.

## Results and limitations

Development-only regression, October 20, 2026: all 15 live OCI groups passed under
Colima using the pre-provisioned Python image
`python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`.
Observed behavior includes actual OOM/PID/tmpfs enforcement, CPU throttling, dropped
capabilities, unprivileged identity, private namespaces, denied external IPv4/IPv6
TCP/UDP routes and available private IPv4/IPv6 loopback. The namespace had IPv6
enabled with only ::1 configured. All four writable tmpfs areas produced ENOSPC;
detached/double-fork timeout cases ended with no owned container/image remaining.
Bounded raw engineering evidence remains outside Git. These observations do not
qualify native execution, automatic orphan recovery or shared-kernel escape resistance.

Native commands executed: **none**. Native distribution, kernel, architecture,
runtime, cgroup mode, security modules and filesystem: **not observed**.
Native resource, network, privilege, reconciliation, daemon restart, worker loss,
service restart, PostgreSQL, storage and end-to-end results: **not qualified**.
**HOST REBOOT RECOVERY NOT QUALIFIED**.

Rootless Docker reduces daemon/target host authority through user namespaces; it
shares the host kernel and is not a VM boundary. Container escape resistance is
**NOT PROVEN**. Namespaced /proc, /sys and /dev may expose kernel/hardware facts;
total host invisibility is not claimed. CPU quota is a rate/period limit, not a
deterministic accumulated CPU-time budget. Builtin seccomp is runtime-owned;
ArchCert does not hash/attest its policy. AppArmor/SELinux protection must be
observed separately before any claim about a native profile.

The Ravenport filesystem object adapter remains explicitly unencrypted development
storage. It relies on private local POSIX filesystem permissions, no-follow path
handling, create-new publication, hard-link atomicity and fsync durability. Do not
extend these assumptions to arbitrary network filesystems. Loopback bearer tokens
and local authority files remain development authentication, not production IAM.
