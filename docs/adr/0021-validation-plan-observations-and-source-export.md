# ADR-0021: Resolved validation plans, factual observations and verified source export

Status: Accepted for Milestone 3.5; extends ADRs 0012 and 0018.

ProjectExecutionRequest contains only requested profile and named structural steps.
AuthorityConfiguration resolves it into a ValidationPlan of ValidatedExecutionStep:
id, program/argv/cwd (ExecutionCommand), resolved ExecutionProfile, evidence category
and StepOrigin. ProjectRequested and AuthorityRequired are distinct typed origins.
Mandatory steps compose first, cannot be removed, and ID collisions reject. No
project origin/removal field exists. Organization/technology inheritance is deferred;
future layers must preserve this additive invariant rather than reinterpret project
configuration as policy authority.

A ValidationPlan is a controlled execution plan, not a verdict. It exposes an
immutable step slice and no deserialization/removal API. A validated step binds to
RunnerInput to create ExecutionRequest. CLI --config uses the same bounded parser
as config-check; direct operator argv constructs a project request through the
same authority resolution. Each step gets a fresh source materialization/sandbox;
all selected steps run and produce structured engineering evidence. Current CLI
images supply one profile; the application can compose multiple provisioned profiles.
Configuration external to accepted source remains a development request, not source
provenance or authenticated authority. No project command is executed on the host.

ValidationObservation records typed (execution ID, step ID, fact kind), source
identity, producer version and structured facts: operational exit/outcome, source
identity match, denied network, established sandbox environment with explicit
NotObserved toolchain. Evidence category TEST/BUILD is a request label, not proof
that meaningful tests/builds happened. Conversion checks command/profile/image/limits
against the resolved step and rejects inconsistent attribution. No PASS booleans,
output interpretation, policy verdicts, evidence canonicalization or signing exist.

The runner no longer needs a concrete MaterializedDirectory. Application owns
VerifiedSourceExport, requiring bounded final byte/mode/identity verification from
retained capabilities, no diagnostic path reopen, and no source/cleanup credentials.
The materializer implements this port with its unchanged descriptor-based verifier.
The runner is generic over that capability, repeats export before transfer and
before target start, and still verifies the actual stopped target /source view.
The concrete materialization dependency remains test-only for composition fixtures.
This abstraction removes a real adapter edge while preserving security-relevant
behavior; it does not expose raw FDs to targets or move Unix syscalls inward.

Existing execution IDs and source/workspace identities remain stable typed evidence
identities. ObservedRuntimeIdentity adds configured client path, reported client and
server versions, kernel/OS/cgroup and runtime component reports. These are bounded
observations from trusted runtime reports, never executable attestation or
cryptographic provenance. A replaced/malicious client/daemon remains in the TCB.
