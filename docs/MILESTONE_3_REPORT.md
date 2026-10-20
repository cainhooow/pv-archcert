# Milestone 3 engineering report — isolated execution plane

Observed October 19, 2026, with pinned Rust 1.99.1 and cargo-deny 0.20.2.
This is engineering self-validation, not independent certification, a formal
isolation proof, or a production deployment approval. No certificate was issued.

## IMPLEMENTED

ArchCert can consume a verified source-only RunnerInput, export reverified bytes
through its directory descriptor, establish a rootless OCI execution environment,
verify the actual stopped sandbox source/configuration, execute literal argv,
enforce network/resource/time/output restrictions, collect controller-owned
binary evidence, and attempt mandatory sandbox/image destruction on every path.
The control plane retains separate source-cleanup ownership.

The `archcert run` development CLI composes exact loose-object ingestion,
expected source SHA-256 checking, materialization, execution and explicit source
cleanup. It requires an authority profile and immutable image. Project TOML may
request structured commands but cannot define privilege, mounts, network, image,
environment or unlimited-resource authority settings. Unknown fields reject.

## ARCHITECTURE DECISIONS

ADRs 0011–0018 cover, respectively: hostile execution boundary, backend-independent
port, rootless OCI/CLI selection, credentials/environment exclusion, denied
network, resource enforcement, structured evidence and immutable-source/writable-
work separation. ADRs 0001–0010 were read and were not rewritten.

Domain/application layers have no Docker/containerd/Podman/runtime API dependency.
The blocking SandboxRunner port follows existing source preparation ports and
belongs on a dedicated worker. A future GVisorRunner or FirecrackerRunner can use
the same domain contract with its own actual source capability.

The Docker CLI adapter uses structural arguments, cleared environment, an empty
private configuration and bounded nonblocking I/O. It never invokes a host shell
or target executable on the host. The new tar 0.4.46 dependency has default xattr
features disabled; filetime 0.2.29 is its additional transitive dependency. Tar is
used for controlled transfer/parsing, never host extraction. No ArchCert unsafe
code or process-wide unsafe environment mutation was added.

## FILES CHANGED

New:

- `crates/archcert-domain/src/execution.rs`.
- `crates/archcert-application/src/execution.rs`.
- `crates/archcert-runner/Cargo.toml`, `src/lib.rs`, `src/docker.rs`,
  `src/process.rs`, `src/archive.rs`, `tests/oci.rs`.
- Runner fixtures `hostile.py`, `runtime_mock.py`, `docker-inspect.json` under
  `crates/archcert-runner/tests/fixtures/`.
- `apps/archcert-cli/tests/execution_cli.rs`.
- `docs/MILESTONE_3_BASELINE.md`, this report, ADRs 0011–0018,
  `docs/threat-model/EXECUTION.md`, `docs/runner/ROOTLESS_DRY_RUN.md`, and
  `docs/runner/BOTTLE_DRY_RUN.json` (actual controller evidence).

Updated:

- Root `Cargo.toml`/`Cargo.lock` and CLI manifest.
- Domain/application library module declarations.
- Application materialization contract documentation.
- Materialization library documentation, descriptor source capability/export
  implementation, shared filesystem verifier and materialization integration tests.
- CLI composition and strict project request parsing.
- README, architecture, development plan and bootstrap threat-model links/status.

The supplied directory has no Git metadata. This inventory records observed edits;
there is no index diff or new commit. Temporary clones, source packs, build output,
probe output and test workspaces reside under ignored `target/`.

## SECURITY PROPERTIES ESTABLISHED

- Execution receives a source-only capability, not a signer/store/database or
  authority cleanup parent. No repository transport credential is required.
- Descriptor export revalidates actual bytes, modes, inodes/devices, directory
  sets, budgets and canonical source identity after the previous handoff.
- No diagnostic workspace path is used for OCI mounting or transfer. No source
  descriptor is inherited by target code. No host bind mounts exist.
- Source is copied into a stopped preparation container, committed to a labeled
  job image, reconstructed from the actual stopped target /source view and checked
  against accepted SHA-256 before any target process starts.
- Target runs as fixed UID:GID 10001:10001 with read-only root/source and separate
  bounded private work/output/tmp/HOME. Source mutations and escaping source links
  cannot reach host data under the documented runtime/kernel assumptions.
- Target has no capabilities, no-new-privileges, builtin seccomp, private PID/
  cgroup namespaces, no host IPC/network/user namespace and no runtime socket,
  host devices, published ports or shared project volumes.
- Required rootless Linux, cgroup-v2/systemd CPU/memory/swap/PID support, builtin
  seccomp and selected container controls are checked before execution. Rootful
  operation was rejected live with NOT_PROVEN; there is no bypass.
- Target environment is constructed from five fixed sandbox keys. Host environment,
  developer HOME, SSH agent, cloud/DB/API/provider/package credentials, Docker
  contexts/config/proxies/auth helpers do not enter it.
- Network has no external route, including host gateway and metadata. Dependency
  installation and a network-enabled execution policy are absent.
- Controller bounds streams, hashes every observed byte incrementally, records
  digest scope/EOF and truncation, and serializes hostile bytes safely as arrays.
- Target exit and stdout claims have distinct authority: Completed includes exit
  7, and printed PASS text confers no verdict. Infrastructure/resource outcomes
  remain separate from future certification policy.
- External timeout/output termination acts on the whole container. Explicit cleanup
  and panic-unwind cleanup attempt removal; failures never become successful
  destruction or certification.

These are properties under the stated trusted infrastructure assumptions. They
are not proof against a vulnerable/compromised Linux kernel or runtime.

## PREVIOUS-MILESTONE DEFECTS FOUND

No reproduced Milestone 1 or 2 defect was identified. The permission seal's
owner/root/retained-FD limitation was already explicit. Milestone 3 closes the
execution handoff with a reverified descriptor export and actual read-only isolated
view. Reopening the diagnostic pathname would have introduced a new substitution
bug; that approach was rejected before implementation. New regressions cover
post-handoff mutation, cleanup revocation and authority-parent rename anchoring.

## RUNNER BACKEND

DockerRootlessRunner, adapter version archcert-docker-cli-v1. Observed Docker CLI
29.8.1 on macOS, Docker Engine 29.5.2, containerd 2.2.4, runc 1.3.5 and rootlesskit
3.3.0 inside Ubuntu 24.04.4 LTS Linux 6.8.0-117-generic x86_64.

The initial configured Colima daemon was stopped. A separate `archcert-m3` Colima
VM was created with host mounts and SSH-agent forwarding disabled, 2 CPUs and
3 GiB memory. Rootless Docker prerequisites were installed inside this disposable
test VM, then its user systemd daemon was started. The controller used an explicit
SSH-forwarded Unix socket to that daemon. The existing default profile/context
was not selected or repurposed. Runtime provisioning is trusted setup, distinct
from denied-network target execution. No target process runs as host or container
root. Docker daemon/runtime are trusted infrastructure.

Authority-provisioned Python image:
`python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`.
The provisioning tag was resolved before execution; every request records/uses
the immutable digest. The target runs from a separate immutable local job image
ID including accepted source. Job images are removed, never pushed to a registry.

## ISOLATION PROPERTIES

Rootless container controls were exercised inside a Linux VM controlled from
macOS. This is not Docker Desktop and does not establish native production Linux
operational guarantees. Container root, host root and the VM boundary are distinct.
Containers share the Linux kernel. Builtin seccomp is required; no bespoke
seccomp profile is claimed. Some proc/sys kernel/hardware information remains
visible despite private process namespaces and runtime default masks.

Defaults: 30 s target deadline, CPU quota 1 CPU, 256 MiB memory, no swap, 64 PIDs,
1 MiB per captured stream, 8 KiB prefixes, 32 MiB each for work/tmp/HOME and 16 MiB
for output. Tmpfs is also charged against memory. Core dumps are disabled, file
descriptors limited to 256, restart disabled and daemon logging disabled.

## TESTS ADDED

33 new unique tests: four domain, one application/mock port, two materialization
handoff regressions, 13 runner unit/mock tests, two CLI tests and 11 live OCI test
groups. The original 65 tests remain passing. Default workspace run: 87 passed,
11 explicitly ignored; separately requested live run: 11 passed, zero ignored.

Unit/mock coverage: structural request/argv/cwd; all resource fields; immutable
profile and denied network; environment exclusion; lifecycle transitions; byte
hashes beyond retained prefixes; ANSI/binary serialization; incomplete digest
scope; archive substitution/traversal/hardlinks/modes/extra directories/storage
bounds; actual captured Docker configuration downgrade matrix; rootless/cgroup/
seccomp prerequisites; runtime deadline; disconnected/orphan/absent cleanup;
unwinding cleanup; and exit/infrastructure/resource classification.

CLI tests verify structured TOML requests and rejection of privilege/network/mount/
secret/image/unlimited-resource fields, and the restricted dry-run interface.

## ADVERSARIAL TESTS

All 11 live OCI groups passed on the selected rootless daemon:

1. Normal stdout/stderr, exit zero, exit 7 and spoofed PASS output.
2. Complete-stream SHA-256 with truncated prefixes; binary and ANSI bytes.
3. Infinite loop, ignoring TERM, detached children and parent-exit child survival.
4. External termination of both stdout and stderr floods.
5. Memory exhaustion classified from runtime OOM metadata.
6. Fork exhaustion (EAGAIN) and actual CPU/memory/swap/PID cgroup ceilings.
7. Host environment credential canaries and initially empty synthetic HOME.
8. Host-only filesystem probes, read-only source, escaping source link, writable
   scratch boundaries and absent runtime sockets.
9. Denied DNS/TCP/HTTP/metadata/gateway routes; only loopback interface exists.
10. UID/GID 10001, capability mask zero, no-new-privileges, active seccomp and
    private proc namespace with no unrelated host processes.
11. Sandbox working directory and temporary disk ENOSPC.

A synthetic host-only marker was placed on the Linux VM; a local HTTP canary
server was provisioned and verified reachable outside the sandbox. Negative
numeric probes asserted route denial, independent of public Internet availability.
Tests independently query the daemon for job containers after cleanup and check
accepted source bytes. Source link targets are never followed by controller
verification. These tests do not demonstrate resistance to unknown container
escape vulnerabilities.

## COMMANDS ACTUALLY EXECUTED

Baseline and final full gates completed successfully:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
```

Focused commands included:

```bash
cargo test -p archcert-domain -p archcert-application -p archcert-materialization
cargo test -p archcert-application -p archcert-runner --lib
cargo test -p archcert-runner
cargo test -p archcert-cli
cargo tree -p archcert-runner --depth 1
```

Actual live test environment and final command:

```bash
ARCHCERT_TEST_DOCKER=/opt/local/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///Users/cainho/Projetos/archcert/target/m3-rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
cargo test -p archcert-runner --test oci -- --ignored --nocapture --test-threads=1
```

Provisioning/probes included `docker version`, `docker context ls`, `colima list`,
`colima start archcert-m3 --activate=false --mount none --ssh-agent=false
--ssh-config=false --cpu 2 --memory 3 --disk 12 --root-disk 12`, VM apt update and
installation of docker-ce-rootless-extras/uidmap/slirp4netns/dbus-user-session,
`dockerd-rootless-setuptool.sh install --force`, rootless `docker info`, an explicit
SSH Unix-socket forward, `docker pull python:3.13-slim` and digest inspection.
Installation `--force` permits setup alongside the VM's rootful daemon; it is not
a target privilege/isolation override. The actual selected daemon remained
rootless and the rootful socket was explicitly rejected.

A shallow HTTPS clone of https://github.com/bottlepy/bottle.git was acquired into
ignored target storage. Its packs were moved aside and unpacked into loose objects
with trusted Git tooling and cleared Git configuration; no project code executed
on the host. `source inspect` obtained independent accepted identity, then
`archcert run` executed the exact command recorded below. Post-run Docker container/
image listings by `archcert.owner=execution-v1` were empty.

Manual review searched runtime/app/domain/source handoff paths and explicitly:
`Command::new("sh")`, `Command::new("bash")`, privileged/host namespace flags,
`/var/run/docker.sock`, SSH_AUTH_SOCK, DATABASE_URL, OPENAI_API_KEY, AWS_,
GITHUB_TOKEN and NPM_TOKEN. All occurrences were rejection/assertion/canary test
code or architecture documentation. No production execution path contains a host
shell or prohibited privilege/network/socket setting. The only production
Command constructor invokes the explicit trusted Docker executable.

## RESULTS

All six final gates passed. `cargo deny` passed advisories, bans, licenses and
sources, retaining only existing syn/winnow duplicate-version warnings. All 87
default tests passed; all 11 live OCI groups separately passed. The final complete
live run took 89.29 s. The real Bottle dry-run also exited zero with both cleanup
operations confirmed.

Development failures were corrected, not counted as success: an accidental
module declaration duplication; generated redundant test module stubs; one Clippy
useless-Vec warning; a stopped-container ENV assertion that initially rejected
Docker's valueless removal markers; and a process-isolation fixture that initially
searched for a marker passed in its own argv. The actual env -i boundary remained
fixed; the process fixture now checks host PID absence and the sandbox-only proc
set. Repeated live tests after the corrections passed. No gate or failed fixture
was disabled to obtain these results.

## SKIPPED TESTS

The default workspace command explicitly ignores 11 OCI tests because they need
an authority endpoint and provisioned pinned image. Every one was run separately
with `--ignored` and passed; none was skipped in that explicit run. Native Linux
production operation, Docker Desktop, gVisor and Firecracker were not exercised.
Their guarantees are not inferred from the VM test. No unavailable backend was
silently substituted or advertised as proven.

## KNOWN LIMITATIONS

- Unix controller/source adapter, Linux rootless Docker backend, synchronous worker
  execution and a small supported image/toolchain profile set.
- Process-local source store and per-command dry-run. No production Git receiver,
  durable job scheduler, automatic project/framework discovery or command-plan
  execution. TOML command requests are checked but not automatically run.
- Images must be authority-provisioned and credential-free. Profile names do not
  independently attest toolchain versions beyond image identity. The local job
  image has a runtime content ID, not a pushed registry repository digest.
- Builds needing mutation must explicitly copy source into /work within isolation.
  No automatic package installation or dependency-fetch/restricted-egress phase.
- No exported artifacts; /output is bounded scratch. No broad magical redaction.
- CPU limits are quotas, not a separately attributed accumulated-time exception;
  PID/disk exhaustion may be handled by target code. Exit>=128 is a signal
  convention, not definitive signal causality.
- Hashes cover observed bytes. Prefix truncation preserves complete observed
  hashes; forced transport closure explicitly marks incomplete scope. Evidence
  collection can fail without returning target streams; cleanup still occurs.
- Control operations have 15 s deadlines plus at most 2 s drain; target timeout
  can incur kill/control overhead. A broken daemon may prevent termination.

## UNRESOLVED RISKS

Shared-kernel/runtime/daemon compromise, dependency vulnerabilities, side channels,
proc/sys host facts, trusted-image supply chain and operator authority mistakes
remain. Rootless mode is defense in depth, not a VM or escape proof. Dedicated
production Linux runner identities must have no authority secrets. Tests on this
VM do not replace independent review/fuzzing or production deployment validation.

Worker crash/abort, power loss, runtime outage or outstanding daemon operations
can leave labeled containers/images. Names/labels support future reconciliation,
but persistent orphan recovery and independent timeout supervision are absent.
Global job admission, image-cache/preparation storage quotas, I/O throttling,
durable authenticated audit/evidence storage and secure media erasure are absent.

## DEFERRED WORK

Dependency-fetch phases with restricted egress; writable-source-copy profiles;
artifact export and validation; durable scheduling/audit/evidence/recovery; backend
alternatives; independent review and parser/runtime fuzzing; production Linux
qualification; deterministic validation plans/policy evaluation; certificate
canonicalization/signing; semantic AI and framework discovery. No certificate,
release permit or project certification policy was implemented here.

## REAL-PROJECT READINESS

Demonstrated after all hostile fixtures passed, using Bottle at exact commit
`8ec5fe29420d14998c0d86885083983eaea8b839`, tree
`e0851c0b9e8f8c96e3d3bf2a1eb6bc07d9ed1667`, independent source SHA-256
`e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0`.

Structured command: program `python3`, argv `["/source/bottle.py", "--version"]`,
cwd `/source`, authority profile python3, pinned Python image above, network denied.
Runtime outcome Completed, exit 0, stdout `0.14-dev\n`, stderr empty; sandbox/job
image and original source workspace were destroyed. The CLI returned zero; the
materialization root was empty. Full actual evidence is retained in
[runner/BOTTLE_DRY_RUN.json](runner/BOTTLE_DRY_RUN.json). This demonstrates a
controlled real-code dry-run, not Bottle test coverage or certification.

See [runner guide](runner/ROOTLESS_DRY_RUN.md) for reproducible operator inputs.
The dedicated test VM was stopped after empty job-container/image listings to
release its memory. Its configuration remains available for reuse. Starting a
conforming runtime and restoring the explicit Unix-socket tunnel remain required
for another run; this does not alter the recorded evidence.

## NEXT RECOMMENDED MILESTONE

Milestone 4: explicit deterministic validation plans, immutable authority policy,
required-check evaluation and evidence manifests; only then narrowly scoped
certificate issuance under an approved signing design. Keep the signer unreachable
from runners. Add durable recovery/supervision and independently assess the source/
execution boundaries before production or public hostile submissions. Engineering
self-validation must remain distinct from independent certification.
