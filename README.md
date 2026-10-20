# ArchCert

ArchCert is building a software certification authority. The current implementation
produces source, materialization and isolated execution evidence, plus deterministic
unsigned policy evaluations.

Its core rule is simple:

> Trust claims less. Reproduce evidence. Bind results to immutable inputs. Sign the verdict.

This repository implements Milestones 1–4A: verified source preparation, a rootless
execution plane, authority-resolved plans and deterministic property evaluation.
It does not issue certificates and is not a production certifier.

## Future bootstrap goal

The first trustworthy vertical slice is:

1. receive an exact Git commit through an ArchCert-controlled ingress;
2. quarantine and validate Git objects;
3. derive an immutable `SourceIdentity` containing commit, tree and an ArchCert SHA-256 snapshot digest;
4. create a certification job;
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

- `apps/archcertd`: bootstrap HTTP process; submission returns 501 UNAVAILABLE.
- `apps/archcert-cli`: command-line client.
- `crates/archcert-domain`: infrastructure-free domain language.
- `crates/archcert-application`: application use cases and ports.
- `crates/archcert-protocol`: client/API DTOs.
- `crates/archcert-source`: source-ingress and snapshot boundary.
- `crates/archcert-materialization`: verified ephemeral Unix source preparation.
- `crates/archcert-runner`: rootless OCI execution adapter and hostile fixtures.
- `crates/archcert-evidence`: inactive generic evidence scaffold.
- `crates/archcert-policy`: deterministic authority policy and unsigned eligibility.
- `crates/archcert-crypto`: inactive future signing scaffold.

The local Git gateway reads loose objects; production Git transport, durable
persistence, production runner operations, signing and semantic review remain deferred.

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
observations themselves produce no verdict. The bootstrap API creates no jobs and returns HTTP 501
with UNAVAILABLE. See [ADRs 0019–0021](docs/adr/0019-application-protocol-and-bootstrap-submission.md),
[current architecture](docs/architecture/CURRENT_ARCHITECTURE_SNAPSHOT.md),
[TCB/dependency review](docs/architecture/TCB_AND_DEPENDENCIES.md),
[Milestone 3.5 report](docs/MILESTONE_3_5_REPORT.md) and
[native Linux qualification plan](docs/runner/LINUX_QUALIFICATION.md).

Live isolation gates are opt-in via `./scripts/test-live-oci`; they are not run
in standard CI. Native Linux deployment remains NOT YET QUALIFIED. Certificates, signatures, production jobs and Git transport remain deferred.


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
