# ArchCert Architecture Specification — Bootstrap v0.1

This document describes the intended architecture, followed by implemented slices.
SSH/HTTPS ingestion, durable jobs and signing in the target flow below remain future
requirements. M4A implements deterministic unsigned policy eligibility. The [current snapshot](CURRENT_ARCHITECTURE_SNAPSHOT.md)
and [M4A report](../MILESTONE_4A_REPORT.md) describe executable behavior.

## Purpose

ArchCert prevents rapid human/agentic software delivery from reaching release merely because the implementing agent reports success. It independently reconstructs evidence and binds its verdict to immutable inputs.

ArchCert certifies claims under recorded conditions; it does not claim to prove that arbitrary software is universally correct.

## Trust domains

### 1. Control plane — trusted

Owns projects, jobs, policy selection, evidence metadata and orchestration. It does not execute target code in-process.

### 2. Source ingress/quarantine — hostile-input boundary

Receives Git objects through SSH/HTTPS, validates them, resolves the requested commit and creates an immutable source snapshot. No target-controlled executable code runs in this boundary.

### 3. Execution plane — untrusted

Materializes the exact snapshot into an ephemeral sandbox. Target build scripts, tests, migrations and package scripts are treated as hostile.

### 4. Policy authority — trusted

Evaluates evidence against immutable authority-owned policy. Project configuration may add checks but cannot disable mandatory policy.

### 5. Signing authority — highest trust

Receives only an approved canonical certificate payload after untrusted execution has ended. It is unreachable from certification runners.

## Initial source flow

```text
Developer / Agent
      |
      | git push archcert <commit>
      v
Git Gateway
      |
      v
Quarantine
      |
      +-- validate Git objects
      +-- resolve commit/tree
      +-- resolve required source objects
      +-- build normalized source manifest
      +-- SHA-256 manifest
      v
Immutable Source Snapshot
      |
      v
Certification Job
      |
      v
Source Materializer
      |
      | credentials removed
      v
Ephemeral Runner
```

The runner must never clone the repository using persistent Git credentials.

## Milestone 1 implementation

`archcert-domain::source` owns validated paths, source completeness, canonical
manifest hashing and immutable retained bytes. `archcert-application::source`
owns submission/evidence/events and the gateway, quarantine, source store and
future materializer ports. `archcert-source` depends on these inward-facing
contracts and implements Unix loose-object ingestion and process-local storage.
The CLI composes these adapters without starting a certification job.

See ADRs [0005](../adr/0005-local-git-quarantine.md),
[0006](../adr/0006-canonical-source-identity.md) and
[0007](../adr/0007-external-source-and-materialization.md) for the exact supported
subset, canonical preimage, budgets, external-source states and credential
boundary. Logical quarantine does not imply OS-level isolation. At the end of
Milestone 1, production Git transport, durable storage and filesystem materialization
remained deferred; Milestone 2 below implements the filesystem preparation boundary.

## Milestone 2 implementation

`archcert-domain::materialization` supplies portable identities, limits and
lifecycle/errors. `archcert-application::materialization` owns requests, scoped
store retrieval, evidence/events and the source-only runner input contract.
`archcert-materialization` implements descriptor-relative Unix workspaces,
independent filesystem reconstruction, a limited read-only seal and explicit
cleanup. The source store and cleanup authority never enter runner input.

See ADRs [0008](../adr/0008-verified-materialization.md),
[0009](../adr/0009-unix-workspace-filesystem.md) and
[0010](../adr/0010-sealed-runner-input.md), and the
[materialization threat model](../threat-model/MATERIALIZATION.md).
Milestone 2 preparation itself starts no target process. Milestone 3 now establishes
OS isolation/read-only source and verifies the stopped target view before execution;
the materializer permission seal remains explicitly best effort.

## Bootstrap release sequence

ArchCert 1.0 is a genesis trust release. It requires traditional high-assurance controls such as human review, pinned toolchains, security review, reproducible-build work where practical and signed release artifacts.

After genesis, version N-1 may independently certify candidate version N. Self-checking is valuable but must never be represented as independent certification of the same binary by itself.

## Milestone 3 implementation

`archcert-domain::execution` defines structural commands, immutable authority image
profiles, finite resource/network policy and operational evidence. The application
SandboxRunner port consumes only RunnerInput and selected authority policy;
`archcert-runner` implements DockerRootlessRunner. No Docker/API type enters the
domain/application. The synchronous port belongs on a dedicated execution worker.

Source export follows held descriptors and rehashes actual bytes, never reopening
diagnostic paths. Stopped preparation transfers accepted source into a labelled
job image; stopped target reconstruction verifies the actual /source view. Target
then runs as UID:GID 10001:10001 on a read-only root, with bounded private work/
output/tmp/HOME, no host mounts, no external network, no capabilities and no-new-
privileges. Runtime rootless/cgroups/seccomp configuration must be established
before any target starts. Kernel/runtime remain trusted; containers are not VMs.

Controller-captured binary output has incremental hashes, bounded byte prefixes
and explicit completeness/truncation. Runtime exit and target text are separate;
no output file or printed PASS creates authority. Sandbox/image destruction and
control-plane source cleanup remain separate operations. No certification/signing
or semantic AI is added. See ADRs 0011–0018, the [execution threat model](../threat-model/EXECUTION.md),
[runner guide](../runner/ROOTLESS_DRY_RUN.md) and Milestone 3 report for deployment
assumptions, actual observations and deferred recovery work.


## Milestone 3.5 alignment

Protocol depends on application commands/results; application depends on domain.
VerifiedSourceExport is an application capability implemented by materialization,
consumed generically by the runner. Project requests cannot construct authority or
runtime configuration. Authority registry resolution composes mandatory and project
steps into ValidationPlan, then source-bound ExecutionRequest. ValidationObservation
provides structured facts without policy interpretation. See ADRs 0019–0021.

The CLI accepts strict TOML through --config and direct operator development argv;
both resolve through the authority catalog. Current bootstrap submission returns
501 UNAVAILABLE with no ID or queued-work claim. Toolchain versions are NotObserved;
client/server/runtime reports are observed runtime identity, not attestation.
