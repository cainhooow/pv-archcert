# Milestone 3.5 — Architecture alignment and hardening

Engineering self-validation on the supplied macOS workspace, October 19, 2026
(local time; UTC evidence timestamps fall on October 20).
No independent certification, policy verdict, certificate or signature is issued.
The supplied directory has no Git metadata; original files were retained under
ignored target/m35-review for comparison. Historical reports/ADRs were not rewritten.

## IMPLEMENTED

Transport-independent submission commands/results and explicit protocol mappings;
a truthful disabled bootstrap submission response; one bounded strict project
configuration parser shared by config-check/run; separate authority/runtime trust
domains; static authority profile registry; immutable resolved validation steps
with mandatory/project provenance; source-bound execution preparation; typed
source/execution/producer-bound observations; observed runtime identity and explicit
unobserved toolchain status; inward verified-source export port; automated dependency
guard; documented opt-in live gates and native Linux qualification plan.

The CLI's --config executes resolved requested steps in fresh materializations and
sandboxes. Direct operator argv follows the same plan resolution. All output remains
ENGINEERING_EXECUTION_EVIDENCE. No Milestone 4 evaluator/inheritance engine is added.

## ARCHITECTURAL CORRECTIONS

The pre-edit review and six passing baseline gates are recorded in
[MILESTONE_3_5_BASELINE.md](MILESTONE_3_5_BASELINE.md). The full repository architecture,
ADRs 0001–0018, M1–M3 reports, all manifests, CLI/daemon, inward contracts, strict
parser/example, materializer/runner verification paths and CI were reviewed before
code edits. No separately named Current Architecture Snapshot existed; the available
repository architecture and supplied findings were used, with a clarification
request sent. A new current snapshot now records executable post-correction behavior.

Application owns SubmitCertificationCommand/Result, not protocol DTOs. Protocol
maps both directions; daemon assigns HTTP semantics. Submission requires no async
macro. Generic SandboxRunner<S> consumes the application VerifiedSourceExport port;
the materializer retains the concrete descriptor verifier. No Unix descriptor or
Docker implementation moved inward. Source export and stopped-view verification
remain unchanged in strength.

ADRs [0019](adr/0019-application-protocol-and-bootstrap-submission.md),
[0020](adr/0020-configuration-authority-and-profile-registry.md) and
[0021](adr/0021-validation-plan-observations-and-source-export.md) cover the five
required decision areas plus adapter handoff/observation identity without introducing
separate ADRs for every type.

## DEPENDENCY GRAPH BEFORE / AFTER

Before (relevant production edges):

```text
CLI -> source/materialization/runner/application/domain
runner -> concrete materialization + application/domain
application -> protocol -> domain
archcertd -> application + protocol
```

After:

```text
protocol -> application -> domain
archcertd -> protocol mappings + application command port
CLI -> application plans/ports + source/materialization/runner composition
source/materialization/runner -> application + domain
runner -- test fixtures only --> materialization
```

The Cargo metadata guard rejects any domain workspace dependency or listed obvious
infrastructure dependency, any application workspace dependency except domain, and
production runner -> materialization. Domain/application dev-dependencies are also
checked. Active CLI/daemon links cannot pull in inactive evidence/policy/crypto
scaffolds. The guard is part of cargo test --workspace and separately runnable.

## CONFIGURATION CONTRACT

Project schema 1 has schema, project.name and optional execution.profile/commands.
Each command requires name/program/args and optionally working_directory (default
/source) and evidence category (default EXECUTION; TYPECHECK/TEST/BUILD supported).
The example documents every field and parses through the production parser in CI.
Input is limited to 256 KiB before decode; names, command count, argv and sandbox cwd
are bounded. Unknown schemas/fields, duplicates, malformed commands/cwd/categories
reject. Profile availability and executable approval reject at authority resolution;
config-check uses the same development catalog without image/runtime selection.

Project TOML cannot request network enablement, image, endpoint, mounts, environment,
privileges, host root or resource limits. Such fields reject explicitly, including
at nested tables. There is no permissive legacy parser or fallback. Runtime settings
are never populated from project-controlled deserialization. External --config is
a development request and does not become accepted-source provenance.

## AUTHORITY BOUNDARIES

ProjectConfiguration produces ProjectExecutionRequest only. AuthorityConfiguration
owns approved profiles and mandatory steps; RuntimeConfiguration carries operator
client path/endpoint/workspace root. Authority profiles bind executable sets, pinned
images, defaults/maxima, denied network and fixed environment. Every limit dimension
is checked against its maximum when authority code selects alternate limits.
Development default=max; project limit fields do not exist.

CLI --profile/--image is explicitly trusted operator provisioning of one static
catalog entry. It cannot be treated as a safe interface for arbitrary project-supplied
CLI arguments. Application supports multiple profiles/mandatory steps; current CLI
sets no mandatory certification policy. Profiles python/rust/node identify executable
families, never installed toolchain proof; node22 is removed. ToolchainObservation
is NotObserved. Mismatched image/profile naming produces no proven version fact.

## VALIDATION PLAN MODEL

Authority mandatory steps compose first, then project steps. Immutable resolved
ValidatedExecutionStep contains id, structural program/argv/cwd, approved profile,
evidence category and typed StepOrigin (AUTHORITY_REQUIRED/PROJECT_REQUESTED).
Project collisions reject; no project removal/provenance field exists. No policy
inheritance engine, result interpretation or verdict is present.

ValidationObservation has typed identity (execution, step, fact kind), exact source,
versioned producer and structured result: execution outcome/exit/requested category,
source-view identity match, verified denied-network configuration and established
sandbox environment with NotObserved toolchain. Conversion rejects cross-plan
command/profile/image/limit attribution. TEST/BUILD means requested category, not
semantic test/build validity. Existing source/materialization identities and adapter
versions remain; execution adds producer crate version and observed runtime identity.
Evidence is neither canonicalized nor signed.

## TCB CHANGES

See [TCB_AND_DEPENDENCIES.md](architecture/TCB_AND_DEPENDENCIES.md) for ACTIVE TCB,
FUTURE TCB, OUTSIDE CURRENT TCB, security-sensitive role classification and the
complete locked third-party inventory. Application no longer pulls protocol into
source/materializer/runner consumers. Runner's concrete materialization edge is
now dev-only. Existing TOML moves into application rather than being a second CLI
parser; no third-party package/version was added. Removed unused direct serde
links from CLI/runner and unnecessary application async-trait. Necessary CLI
composition remains active trust. Inactive generic evidence/policy/crypto scaffolds
remain outside execution links, enforced automatically.

Daemon/protocol only serve liveness and disabled submission and cannot dispatch
source/execution work. They are trusted for their own response behavior, not part
of current source/execution processing. Kernel/runtime/image/filesystem/operator
trust remains. Client path/version/server/runtime/kernel/OS reports are observed
runtime identity, never executable attestation or cryptographic runtime provenance.

## DEFECTS FOUND

Corrected application/protocol direction, adapter-owned cross-adapter contract,
rejected example configuration, split parsing/execution preparation, misleading
run help, unverified version-suggesting profile name and fabricated pending API
state. The endpoint now returns HTTP 501 {"status":"UNAVAILABLE"}, no ID or
persisted-work claim; no production job system was implemented.

The hostile-input review found a fail-closed runtime parsing gap: absent/nonboolean
OOMKilled could be treated as false when classifying a normal exit. It now yields
SandboxFailure; the regression first establishes a genuine complete-stream exit-zero
control case, then tests null/nonboolean OOM fields. Source ingestion, materializer,
archive and output bounds retained their checks. No additional reproduced source
identity/materialization defect was found.

No ArchCert-owned unsafe Rust, unwrap() or expect() exists. The sole explicit
panic! is the existing test-only authority-panic injection for unwind cleanup.
Indexing in source parsing follows validated ASCII OID widths, delimiter positions,
checked slice bounds or short-circuit length checks; filesystem traversal uses
validated nonempty SourcePath components and bounded readlink buffers. Runtime JSON
uses Value indexing (missing keys become null) plus checked extraction; the OOM gap
above is fixed. Configuration decoding is bounded before allocation; archive input,
per-entry data, output prefixes and decompression work remain bounded. Allocation
failure/system I/O starvation and malicious trusted dependencies are not claimed
impossible; fuzzing/admission/OS supervision remain deferred.

## SECURITY REGRESSIONS CHECKED

M1 exact SHA-1/SHA-256 objects, independent canonical vectors/permutations, immutable
retained bytes, incomplete-source guards, budgets and no Git fallback. M2 scoped
lookup, inode/device/no-follow/exclusive operations, path/symlink/hardlink safety,
retained-writer mutation rejection, parent-rename anchoring, independent hash/mode/
directory verification, seal/handoff and separate explicit cleanup. M3 descriptor
export, actual stopped-view verification, rootless requirement, no network/host
mounts/socket, UID10001/read-only root, cap-drop ALL/no-new-privileges/builtin seccomp,
private namespaces/HOME, cleared client and fixed target environment, CPU/memory/
swap/PID/tmpfs limits, timeout/descendants, bounded binary streams/digests and cleanup.
Existing argv/downgrade assertions explicitly cover these controls; none were
removed/loosened. New export port delegates to the unchanged descriptor verifier.
No signing/credentials/store/cleanup parent crosses target execution.

## TESTS ADDED

19 new unique default tests (106 total, previously 87):

- Two Cargo architecture guard tests.
- Ten project/authority tests: production example, unknown schema/fields, escalation
  matrix, invalid/duplicate commands, bounded decode, profile/program authority,
  mandatory preservation/collision, all nine resource ceilings and registry validity.
- Three observation tests: toolchain mismatch remains unobserved, source/execution/
  producer-bound zero/nonzero facts, and rejected cross-plan attribution.
- CLI config-to-plan rejection before runtime contact, plus updated existing strict
  config/help tests for truthful development execution and --config.
- Protocol command/result mappings and exact UNAVAILABLE serialization.
- Actual bootstrap handler HTTP 501/body/no-job semantics.
- Runner malformed OOM inspect classification and observed client/server/runtime fields.

All original tests remain. The eleven ignored live OCI groups remain opt-in, with
a small audited exec-only wrapper requiring all three environment settings.

## COMMANDS ACTUALLY EXECUTED

Baseline and final full gates (all passed):

```bash
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check
./scripts/check-architecture
```

Final default result: 106 passed, zero failed, eleven explicitly ignored live tests.
cargo-deny advisories/bans/licenses/sources passed; existing syn/winnow duplicate
warnings remain justified by upstream macro/TOML requirements. Logs are in ignored
target/m35-final-*.log. Additional development commands included cargo fmt, unlocked
cargo check to update workspace-only lockfile edges, focused application/runner tests,
cargo tree --workspace --edges normal --depth 1, locked Cargo metadata, CLI config-check,
source/unsafe/panic/dependency searches and original-file comparisons.

Live preparation reused the existing dedicated archcert-m3 VM, with host mounts and
SSH-agent forwarding disabled; no new shared default daemon was selected:

```bash
/opt/local/bin/colima start archcert-m3 --activate=false
/opt/local/bin/colima --profile archcert-m3 ssh -- systemctl --user is-active docker
/opt/local/bin/colima --profile archcert-m3 ssh -- id -u
ssh -F /Users/cainho/.colima/_lima/colima-archcert-m3/ssh.config \
  -o ControlMaster=no -o ExitOnForwardFailure=yes -N \
  -L /Users/cainho/Projetos/archcert/target/m35-rootless.sock:/run/user/501/docker.sock \
  lima-colima-archcert-m3
ARCHCERT_TEST_DOCKER=/opt/local/bin/docker \
ARCHCERT_TEST_ENDPOINT=unix:///Users/cainho/Projetos/archcert/target/m35-rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/test-live-oci
```

The external-project commands actually executed were:

```bash
cargo run -p archcert-cli -- source inspect \
  /Users/cainho/Projetos/archcert/target/m3-bottle/.git \
  8ec5fe29420d14998c0d86885083983eaea8b839 \
  --project 00000000-0000-4000-8000-000000000001 --repository bottlepy/bottle
cargo run -p archcert-cli -- run \
  --git-dir /Users/cainho/Projetos/archcert/target/m3-bottle/.git \
  --commit 8ec5fe29420d14998c0d86885083983eaea8b839 \
  --snapshot e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0 \
  --project 00000000-0000-4000-8000-000000000001 --repository bottlepy/bottle \
  --workspace-root /Users/cainho/Projetos/archcert/target/m3-workspaces \
  --profile python \
  --image python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
  --docker /opt/local/bin/docker \
  --endpoint unix:///Users/cainho/Projetos/archcert/target/m35-rootless.sock \
  --config docs/runner/BOTTLE_REQUEST.toml
/opt/local/bin/colima stop archcert-m3
```

Development failures are not counted as successful gates: generated redundant test
module stubs caused duplicated tests/missing-doc warnings and were removed; a focused
mock test exceeded its existing five-second budget during concurrent compilation/live
resource fixtures; the first live run passed ten groups but missed a timeout startup
marker assertion. No deadline/assertion was loosened and no failing group disabled.
The final default suite ran sequentially and passed. Live repeat result is below.
Incorrect Colima profile/SSH alias attempts were corrected to explicit profile and
Lima host names; the stale M3 socket was never assumed to be working.

## LIVE OCI RESULT

Final serial rerun: **11 passed, zero failed, zero ignored**, in 90.64 seconds.
The prior failing group passed without any changed deadline/assertion. Independent
job-label queries found no remaining containers or images; source workspace root
was empty. Log: target/m35-live-oci-final.log. Native Linux remains **NOT YET QUALIFIED** regardless of
VM result. Current observed platform: macOS Darwin 25.6 x86_64 controller, Docker
client 29.8.1, Colima Ubuntu 24.04.4 Linux 6.8.0-117-generic, rootless Docker 29.5.2,
containerd v2.2.4, runc 1.3.5 and rootlesskit 3.3.0. The existing pinned Python image
was reused without a pull. Tests have an explicit opt-in command; standard CI
clearly states LIVE OCI GATES — NOT RUN IN STANDARD CI.

The real Bottle command was rerun through the documented --config path, using the
existing manually acquired/pack-converted M3 repository and the new BOTTLE_REQUEST.toml.
Exact commit 8ec5fe29420d14998c0d86885083983eaea8b839, tree
e0851c0b9e8f8c96e3d3bf2a1eb6bc07d9ed1667 and independent SHA-256
e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0 were reproduced.
Outcome Completed, exit 0, stdout 0.14-dev followed by newline, stderr empty,
explicit sandbox/job-image and source cleanup successful. Toolchain NotObserved
remains explicit; this is a Bottle version command, not a Python version probe or
Bottle test coverage. Full evidence: [BOTTLE_DRY_RUN_M3_5.json](runner/BOTTLE_DRY_RUN_M3_5.json).
The documented CLI commands were executed with /opt/local/bin/docker, the explicit
m35-rootless Unix endpoint, target/m3-bottle/.git and target/m3-workspaces. No new
clone or pack conversion was performed in M3.5. After independent cleanup checks,
the dedicated VM was stopped again.

## KNOWN LIMITATIONS

Unix source/controller adapter, selected loose Git objects only, process-local
store, no pack parsing/authenticated Git gateway/ref mapping/LFS/submodule acquisition
or durable source storage. [Next ingress requirements](architecture/SOURCE_INGRESS_NEXT.md)
formalize those gaps. Bottle clone/pack-to-loose conversion remains manual trusted
test preparation outside ArchCert; the new documented execution request needs no
manual Python glue. Existing M3 clone/converted objects can be reused for the same
exact accepted commit; this is not a new production ingress capability.

Static catalog/operator image provisioning only, no toolchain probes, no authenticated
authority config service, no organization/technology inheritance engine, no global
admission/I/O/storage quotas, no dependency-fetch phase or artifact export. Command
labels are not semantic validation. The CLI is a synchronous development worker,
not a scheduler/API dispatcher. A later step's setup failure may stop the CLI before
printing an accumulated multi-step report; per-step source cleanup remains explicit
and previously completed execution cleanup has already occurred. Durable observation
storage/job recovery is intentionally absent.

## UNRESOLVED RISKS

Shared-kernel/container/runtime/client/image supply-chain compromise, dependency bugs,
parser fuzzing gaps, same-UID/root/local-filesystem assumptions, side channels and
operator authority mistakes. Runtime identity reports are not binary attestation.
Unsigned process-local evidence can be replaced outside this execution boundary.
Worker crash/abort, daemon outage or late operations can leave labelled orphans;
mandatory best-effort/explicit cleanup is not persistent reconciliation or secure
erasure. Native production Linux configuration has not been exercised. Timing-sensitive
live startup assertions require a sufficiently responsive dedicated development
runtime; passing them does not establish operational latency guarantees.

## DEFERRED WORK

Milestone 4 deterministic policy evaluation against observations; separate future
policy composition/inheritance engine, durable evidence/source/job storage and
recovery, authenticated Git ingress/packfiles/external source resolution, native Linux
qualification, independent review/fuzzing/admission control. No certificate.json,
Ed25519/key storage, release permit, CERTIFIED/REJECTED evaluator, semantic AI, web
panel, production scheduler/Git server/API or persistent database was begun.

## READINESS FOR MILESTONE 4

Structural inputs are available: authority-resolved immutable ValidationPlan steps,
clear step provenance, source-bound execution and transport-independent typed facts.
M4 can consume ValidationObservation without importing Docker inspect structures or
trusting project output. Its authority/evidence evaluation semantics still require
implementation and review. This milestone establishes an engineering input boundary,
not production qualification or independent certification.
