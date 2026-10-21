# ArchCert

ArchCert is building a software certification authority. The current implementation
produces source, materialization and isolated execution evidence, plus deterministic
unsigned policy evaluations and development Ed25519 certificates for exact source states.

Its core rule is simple:

> Trust claims less. Reproduce evidence. Bind results to immutable inputs. Sign the verdict.

The development implementation includes verified source preparation, authenticated
Northgate ingress, durable Ravenport jobs, Stoneward execution fencing, and the
controlled Ironcrest review-to-certificate lifecycle. Authority-resolved plans,
deterministic policy evaluation and canonical certificates retain offline verification. Signing is DEVELOPMENT
ONLY; ArchCert is not a production certifier.

## Certification lifecycle

The implemented development path is:

1. receive an exact Git commit through an ArchCert-controlled ingress;
2. quarantine and validate Git objects;
3. derive an immutable `SourceIdentity` containing commit, tree and an ArchCert SHA-256 snapshot digest;
4. for an Ironcrest grant, persist authority-selected knowledge, impact, review,
   semantic gate and a frozen registered challenge plan before admitting the job;
5. materialize source into an ephemeral isolated runner without Git credentials;
6. execute authority-controlled deterministic checks;
7. retain redacted evidence and hashes;
8. evaluate an immutable policy bundle;
9. destroy the untrusted execution environment;
10. only then cross the signing boundary and issue a certificate.

## Non-negotiable trust boundaries

- The target repository is untrusted input.
- `archcert.toml` may request additional checks but may not disable mandatory authority policy.
- The runner never receives production signing keys.
- The runner never receives control-plane database credentials.
- Git credentials are removed before target-controlled code executes.
- A certificate is valid only for its recorded immutable source and policy inputs.
- Semantic AI review cannot independently create a `CERTIFIED` verdict.
- ArchCert does not modify the source it certifies.

## Workspace

- `apps/archcertd`: authenticated loopback durable job admission/status API.
- `apps/archcert-cli`: command-line client and offline verification.
- `apps/archcert-controller`: durable trusted execution/issuance orchestration.
- `apps/archcert-worker`: credential-free execution process.
- `crates/archcert-domain`: infrastructure-free domain language.
- `crates/archcert-application`: application use cases and ports.
- `crates/archcert-knowledge`: passive bounded Rust syntax extraction over accepted source.
- `crates/archcert-semantic`: local exact semantic replay and an unavailable default adapter.
- `crates/archcert-protocol`: generated Protobuf contracts and checked HTTP/wire DTO adapters.
- `crates/archcert-control-plane`: authenticated admission/read composition.
- `crates/archcert-storage`: PostgreSQL metadata and immutable development objects.
- `crates/archcert-source`: loose/packed source validation and immutable snapshot boundary.
- `crates/archcert-gateway`: authenticated Git ingress, authorization and quarantine.
- `crates/archcert-materialization`: verified ephemeral Unix source preparation.
- `crates/archcert-runner`: rootless OCI execution adapter and hostile fixtures.
- `crates/archcert-evidence`: canonical detailed evidence bundles and manifests.
- `crates/archcert-policy`: deterministic authority policy and unsigned eligibility.
- `crates/archcert-crypto`: Ed25519 port, strict verification and isolated development key adapter.
- `crates/archcert-certificate`: fail-closed issuance and offline verification proofs.

The local Git gateway reads loose objects; Northgate adds restricted SSH push and
pack ingress. Ravenport adds durable development PostgreSQL jobs and immutable
artifact storage. Production deployment qualification and production
runner/key operations remain deferred. Ironcrest now gates execution admission and
issuance under a separate authority profile and deterministic policy. Semantic
CONTINUE creates no deterministic proof; BLOCK prevents certification, mandatory
reviewer failure stays inconclusive, and required challenges must pass. Historical
policy/certificate behavior remains unchanged. Only local exact semantic replay is
configured; external source disclosure is denied by default.

The controlled implementation retains semantic nondeterminism/provider-drift risks,
syntax-only extraction limits and explicit blind spots. Injection containment is
architectural, not a mathematical guarantee. No universal bug detection or
production certification authority is claimed. See [the current architecture](docs/architecture/CURRENT_ARCHITECTURE_SNAPSHOT.md),
[Ironcrest operations](docs/architecture/RAVENPORT_OPERATIONS.md#ironcrest-review-before-admission)
and [manifest compatibility](docs/adr/0044-ironcrest-evidence-manifest.md).

## Inspect exact source

```bash
cargo run -p archcert-cli -- source inspect /absolute/path/project.git FULL_COMMIT_OID \
  --project 00000000-0000-4000-8000-000000000001 --repository example/project
```

Supply an explicit bare or `.git` directory and a full commit ID. `HEAD`, packed
objects, alternates, non-Unix platforms, non-UTF-8/non-NFC filenames and symlinked
locator components are unsupported. Missing supported objects fail explicitly;
there is no Git CLI fallback. The command emits JSON source evidence. The CLI's
in-memory source store ends with the process; this is not a persisted artifact.
LFS pointers and submodules produce `INCOMPLETE_EXTERNAL_SOURCE`, never a falsely
complete source. No target project code executes.

See [source decisions](docs/adr/0005-local-git-quarantine.md),
[canonicalization and vectors](docs/adr/0006-canonical-source-identity.md),
[materialization boundary](docs/adr/0007-external-source-and-materialization.md)
and [threat model](docs/threat-model/GIT_INGESTION.md).

## Verify an ephemeral materialization

```bash
cargo run -p archcert-cli -- source inspect /absolute/path/project.git FULL_COMMIT_OID \
  --project 00000000-0000-4000-8000-000000000001 --repository example/project \
  --materialize-under /absolute/path/private-authority-workspaces
```

Supply an existing authority-owned mode-0700 directory with no symlink components.
ArchCert creates a fresh child, writes only accepted complete source, enumerates
and rehashes actual contents, applies a best-effort read-only permission seal,
reverifies at handoff, emits evidence, and explicitly deletes that child. No
target code runs. The materializer reads no Git or environment credentials.
Library callers receive a narrow source handle and a separate cleanup lease.
The source handle is for trusted sandbox setup, not direct target access.
See the [materialization decisions](docs/adr/0008-verified-materialization.md),
[filesystem assumptions](docs/adr/0009-unix-workspace-filesystem.md),
[runner handoff](docs/adr/0010-sealed-runner-input.md), and
[Milestone 2 report](docs/MILESTONE_2_REPORT.md).

## Documentation rule

Public APIs, domain invariants, trust assumptions, cryptographic operations and non-obvious security decisions require documentation. Comments explain *why*, not obvious syntax.

## Local quality gates

The intended bootstrap gates are:

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
```

Rust 1.99.1 is pinned in `rust-toolchain.toml`. `Cargo.lock` records the tested
dependency resolution. See the [pre-change baseline](docs/MILESTONE_1_BASELINE.md)
and [engineering report](docs/MILESTONE_1_REPORT.md) for observed validation and
limitations. Source integration tests require Git solely to manufacture temporary fixtures.
Runner mock tests additionally use the trusted host `/usr/bin/python3` simulator;
real OCI tests require separately provisioned rootless infrastructure.

## Milestone 3: isolated execution dry-run

The rootless Docker adapter now executes explicit commands against verified
source and returns engineering execution evidence. It requires a rootless Linux
OCI daemon with enforced cgroup budgets and built-in seccomp; rootful daemons
fail closed. No target code runs on the host, no host directory/socket is mounted,
network is denied and source is read-only. Writable work/HOME/tmp/output are
bounded private tmpfs mounts. Source cleanup stays with the control plane.

Use `cargo run -p archcert-cli -- run --help` and the
[rootless dry-run guide](docs/runner/ROOTLESS_DRY_RUN.md). See
[baseline review](docs/MILESTONE_3_BASELINE.md),
[execution threat model](docs/threat-model/EXECUTION.md), ADRs 0011–0018 and the
[Milestone 3 report](docs/MILESTONE_3_REPORT.md) for tested guarantees and limits.
Real OCI tests are explicitly ignored by default and require the guide's separate
runner test command. Exit zero is process success only; no certificate is issued.


## Milestone 3.5: architecture alignment

Application commands/results are independent of HTTP DTOs. The runner consumes an
application-owned verified source-export port; no production materialization adapter
dependency remains. ProjectConfiguration, AuthorityConfiguration and RuntimeConfiguration
are separate trust domains. `run --config FILE` and `config-check --file FILE` use
the same strict bounded parser; the [complete example](config/archcert.toml.example)
is parsed by a default regression test. Development catalog IDs are python, rust
and node. These names do not prove installed toolchain versions.

Authority-required steps compose before project requests into immutable ValidationPlan
steps. Structured ValidationObservation facts form the policy input boundary;
observations themselves produce no verdict. The historical bootstrap API returned
HTTP 501; Ravenport now admits durable jobs.
The original bootstrap adapter still reports UNAVAILABLE. See [ADRs 0019–0021](docs/adr/0019-application-protocol-and-bootstrap-submission.md),
[current architecture](docs/architecture/CURRENT_ARCHITECTURE_SNAPSHOT.md),
[TCB/dependency review](docs/architecture/TCB_AND_DEPENDENCIES.md),
[Milestone 3.5 report](docs/MILESTONE_3_5_REPORT.md) and
[native Linux qualification results](docs/qualification/NATIVE_LINUX_RUNNER.md).

Live isolation gates are opt-in via `./scripts/test-live-oci`; they are not run
in standard CI. Stoneward qualifies the exact Ubuntu 26.04.1 / kernel 7.0.0-31 /
KVM / rootless Docker 29.1.3 execution profile documented above. Other environments
remain unqualified; production IAM, storage encryption and key management remain
deferred. Northgate
adds SSH Git transport; development certificates/signatures are implemented in M4B below.


## Milestone 4A: deterministic unsigned policy evaluation

`archcert evaluate` uses the same source and execution arguments as `run` and adds
five-state property verdicts, structured findings, canonical policy SHA-256 and
fail-closed eligibility. It embeds the authority-owned development policy; project
configuration cannot select a weaker policy or supply mandatory command provenance.
A trusted operator may supply `--authority-config FILE` to compose mandatory steps
before additional `--config FILE` requests. No certificate is constructed or signed.

See the [policy development guide](docs/policy/README.md),
[baseline](docs/MILESTONE_4A_BASELINE.md),
[completion report](docs/MILESTONE_4A_REPORT.md) and
[threat model](docs/threat-model/POLICY_EVALUATION.md). Retained demonstrations cover
PROVEN/eligible, FAILED, NOT_PROVEN (Bottle version only) and INCONCLUSIVE commands.
Every report says UNSIGNED POLICY EVALUATION and NOT A CERTIFICATE.


## Milestone 4B: Eldermark development certificate authority

`archcert certify` executes and evaluates the exact source, rejects ineligible or
inconsistent results before private-key loading, freezes a canonical certificate,
signs with Ed25519, and verifies under the selected public key before reporting
CERTIFIED. A certificate authenticates ArchCert claims for EXACT_SOURCE; it does
not certify a branch, future source, build artifact or universal software security.

```bash
cargo run -p archcert-cli -- verify \
  docs/certificates/development/controlled/certificate.json \
  --public-key docs/certificates/development/controlled/public-key.hex
```

Verification is offline and requires only the certificate and an explicitly trusted
public key. The development key here is published as test evidence, not a production
trust anchor. NO EXPIRATION SEMANTICS YET. Revocation is NOT IMPLEMENTED.
Use `archcert development-keygen --help` and `archcert certify --help` for development
issuance. Private keys require an explicit owned mode-0700 directory outside target
repositories and workspace roots. No key selection belongs in project TOML.

See the [development certificate guide](docs/certificates/README.md),
[M4B baseline](docs/MILESTONE_4B_BASELINE.md), [completion report](docs/MILESTONE_4B_REPORT.md),
[ADRs 0025–0027](docs/adr/0025-canonical-certificate-and-evidence-manifest.md),
[signing threat model](docs/threat-model/CERTIFICATE_SIGNING.md) and
[crypto dependency review](docs/architecture/CRYPTO_DEPENDENCY_REVIEW.md).

## Northgate authenticated Git source ingress

Northgate adds an actual restricted OpenSSH `git push` path, bounded normal pack
and delta support, explicit actor/device/repository authorization, fresh quarantine
and immutable source reuse. Push success reports source acceptance only. A later
`archcert certify --source-submission ID --source-store ROOT ...` independently
invokes the existing development certification chain. Gateway dependencies exclude
execution, policy and signing. Source schema-1 SHA-256 remains compatible.

Run `./scripts/test-northgate` after building archcert-gateway-cli for real SSH
transport/authentication/adversarial tests. `./scripts/demo-northgate` uses the
existing rootless OCI environment for a full development certificate and Bottle
regression. See [development ingress](docs/source-ingress/README.md),
[baseline](docs/MILESTONE_5_BASELINE.md), [report](docs/MILESTONE_5_REPORT.md), and
[threat model](docs/threat-model/NORTHGATE.md). External-source acquisition has a
separate verification port and operator-only private LFS/accepted-child adapter.
Resolved content receives a new schema-2 snapshot verified through execution;
unresolved LFS/submodules cannot execute. `./scripts/demo-northgate-resolution`
exercises the resolved-source development certificate flow. Durable jobs/storage
are now implemented by Ravenport under its documented local development limits.

M5 Northgate's final internal protocol task is complete; see the
[Protobuf completion report](docs/MILESTONE_5_PROTOBUF_REPORT.md),
[protocol architecture](docs/architecture/PROTOBUF_PROTOCOL_CONTRACTS.md), and
[ADR 0034](docs/adr/0034-protobuf-internal-protocol-contracts.md).
Protocol Buffers are the primary internal machine-to-machine schema/wire format;
generated common/source v1 DTOs remain in the protocol layer. They do not replace
cryptographic canonical encodings. Operator `archcert-gateway export-proto --store
STORE SUBMISSION_UUID` exports source-only observations in binary form. That
Northgate slice introduced no persistence. Ravenport now supplies the durable
control plane described in [operations](docs/architecture/RAVENPORT_OPERATIONS.md).

## Ravenport durable certification

Ravenport adds PostgreSQL-backed jobs/attempts, scoped idempotency, transactional
worker leases, immutable digest-bound artifacts, structured audit and recoverable
certificate issuance. The authenticated loopback API returns actual durable job
state; a separate controller dispatches a credential-free Protobuf worker process.
Policy/profile/source inputs are pinned before execution. Policy rejection never
retries until pass. Signing retries bind the exact prepared payload/key/time.

Use [operations](docs/architecture/RAVENPORT_OPERATIONS.md),
[ADRs 0035–0037](docs/adr/0035-ravenport-durable-jobs.md), and the
[threat model](docs/threat-model/RAVENPORT.md). `scripts/test-ravenport` runs real
PostgreSQL concurrency tests; `scripts/demo-ravenport` reproduces authenticated
source-to-certificate, interrupted-worker recovery, crash checkpoints and Bottle
rejection. The development adapter uses unencrypted scoped filesystem objects,
loopback authority authentication and explicit cleanup confirmation for lost running
workers. Production IAM/TLS, remote workers, encrypted storage/KMS and deployment
qualification remain separate work. Offline verification still needs no database.
