//! Hostile execution contracts. These types confer no certification verdict.

use crate::{Sha256Digest, SourceIdentity, materialization::WorkspaceId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// Authority-generated job identity, also used for orphan discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ExecutionId(Uuid);

impl ExecutionId {
    /// Generates a new opaque execution identity.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl TryFrom<String> for ExecutionId {
    type Error = ExecutionError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&text).map_err(|_| ExecutionError::SourceIntegrity)?;

        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != text
        {
            return Err(ExecutionError::SourceIntegrity);
        }

        Ok(Self(id))
    }
}

impl Default for ExecutionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Only implemented egress policy. Unsupported future policies cannot deserialize here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// No external interfaces, DNS, host gateway or metadata route.
    Denied,
}

/// Explicit authority limits. CPU is a rate ceiling, bounded in total by timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Wall-clock milliseconds, enforced by the controller.
    pub timeout_ms: u64,
    /// CPU quota in thousandths of one CPU.
    pub cpu_millis: u32,
    /// Memory plus tmpfs charge; swap is disabled.
    pub memory_bytes: u64,
    /// Cgroup process/thread ceiling.
    pub pids: u32,
    /// Maximum observed stdout bytes before terminating the sandbox.
    pub stdout_bytes: u64,
    /// Maximum observed stderr bytes before terminating the sandbox.
    pub stderr_bytes: u64,
    /// Per-stream retained prefix, also capped by its stream limit.
    pub excerpt_bytes: u64,
    /// Per-mount tmpfs bound for /work, /tmp and /home/archcert.
    pub scratch_bytes: u64,
    /// /output tmpfs ceiling; artifacts are not exported in this milestone.
    pub output_bytes: u64,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            cpu_millis: 1000,
            memory_bytes: 256 * 1024 * 1024,
            pids: 64,
            stdout_bytes: 1024 * 1024,
            stderr_bytes: 1024 * 1024,
            excerpt_bytes: 8192,
            scratch_bytes: 32 * 1024 * 1024,
            output_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ExecutionLimits {
    /// Rejects zero, excessive or inconsistent authority budgets before runtime access.
    pub fn validate(&self) -> Result<(), ExecutionError> {
        if !(1..=3_600_000).contains(&self.timeout_ms)
            || !(1..=8000).contains(&self.cpu_millis)
            || !(16 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&self.memory_bytes)
            || !(1..=1024).contains(&self.pids)
            || !(1..=16 * 1024 * 1024).contains(&self.stdout_bytes)
            || !(1..=16 * 1024 * 1024).contains(&self.stderr_bytes)
            || self.excerpt_bytes == 0
            || self.excerpt_bytes > self.stdout_bytes.min(self.stderr_bytes)
            || self.scratch_bytes == 0
            || self.scratch_bytes > self.memory_bytes
            || self.output_bytes == 0
            || self.output_bytes > self.memory_bytes
        {
            return Err(ExecutionError::InvalidLimits);
        }

        Ok(())
    }
}

/// Structured argv, with no implicit shell parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCommand")]
pub struct ExecutionCommand {
    program: String,
    args: Vec<String>,
    working_directory: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommand {
    program: String,
    args: Vec<String>,
    working_directory: String,
}

impl TryFrom<RawCommand> for ExecutionCommand {
    type Error = ExecutionError;

    fn try_from(c: RawCommand) -> Result<Self, Self::Error> {
        Self::new(c.program, c.args, c.working_directory)
    }
}

impl ExecutionCommand {
    /// Accepts a program name or absolute sandbox path and literal arguments.
    pub fn new(
        program: String,
        args: Vec<String>,
        working_directory: String,
    ) -> Result<Self, ExecutionError> {
        if program.is_empty()
            || program.len() > 256
            || program.starts_with('-')
            || !program
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.+".contains(&b))
            || program.split('/').any(|c| c == ".." || c == ".")
            || (program.contains('/') && !program.starts_with('/'))
            || args.len() > 256
            || args.iter().any(|s| s.contains('\0'))
            || args.iter().map(String::len).sum::<usize>() > 64 * 1024
        {
            return Err(ExecutionError::InvalidCommand);
        }

        let valid_cwd = ["/source", "/work"].iter().any(|root| {
            working_directory == *root
                || working_directory
                    .strip_prefix(&format!("{root}/"))
                    .is_some_and(|p| crate::source::SourcePath::from_bytes(p.as_bytes()).is_ok())
        });

        if !valid_cwd {
            return Err(ExecutionError::InvalidCommand);
        }

        Ok(Self {
            program,
            args,
            working_directory,
        })
    }

    /// Literal executable; it is executed only inside the sandbox.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Literal argument vector.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Absolute sandbox directory, limited to /source or /work and descendants.
    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }
}

/// Authority-approved profile. It cannot be created by deserializing project TOML.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionProfile {
    name: String,
    image: String,
    programs: Vec<String>,
    limits: ExecutionLimits,
}

impl ExecutionProfile {
    /// Selects an immutable locally provisioned OCI digest, commands and limits.
    pub fn new(
        name: String,
        image: String,
        programs: Vec<String>,
        limits: ExecutionLimits,
    ) -> Result<Self, ExecutionError> {
        limits.validate()?;
        let Some((repository, digest)) = image.split_once("@sha256:") else {
            return Err(ExecutionError::InvalidProfile);
        };

        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || repository.is_empty()
            || repository.starts_with('-')
            || !repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-:".contains(&b))
            || Sha256Digest::parse(digest.to_owned()).is_err()
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || programs.is_empty()
            || programs.len() > 32
            || programs
                .iter()
                .any(|p| ExecutionCommand::new(p.clone(), vec![], "/source".into()).is_err())
        {
            return Err(ExecutionError::InvalidProfile);
        }

        Ok(Self {
            name,
            image,
            programs,
            limits,
        })
    }

    /// Profile policy name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Immutable OCI repository digest. Automatic pulls are disabled.
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Authority resource policy.
    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Selects finite authority budgets; profile registry enforces its narrower maximum.
    pub fn with_limits(&self, limits: ExecutionLimits) -> Result<Self, ExecutionError> {
        limits.validate()?;
        let mut profile = self.clone();
        profile.limits = limits;

        Ok(profile)
    }

    /// Approved executable set, independent of actual observed toolchain versions.
    pub fn programs(&self) -> &[String] {
        &self.programs
    }

    /// Fails closed for executables outside the selected profile.
    pub fn authorize(&self, command: &ExecutionCommand) -> Result<(), ExecutionError> {
        if self.programs.iter().any(|p| p == command.program()) {
            Ok(())
        } else {
            Err(ExecutionError::CommandNotAllowed)
        }
    }
}

/// Fixed synthetic environment; host variables and project environment overrides are excluded.
pub fn sandbox_environment() -> BTreeMap<String, String> {
    [
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("HOME", "/home/archcert"),
        ("TMPDIR", "/tmp"),
        ("LANG", "C.UTF-8"),
        ("HOSTNAME", "archcert"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

/// Fail-closed setup/infrastructure errors, separate from target exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, Serialize)]
pub enum ExecutionError {
    /// Invalid structural command or working directory.
    #[error("invalid execution command")]
    InvalidCommand,
    /// Invalid resource policy.
    #[error("invalid execution limits")]
    InvalidLimits,
    /// Profile must bind an immutable approved image and bounded policy.
    #[error("invalid authority execution profile")]
    InvalidProfile,
    /// Program is outside the selected profile.
    #[error("command is not allowed by the execution profile")]
    CommandNotAllowed,
    /// Source failed descriptor export or isolated-view reconstruction.
    #[error("execution source integrity failure")]
    SourceIntegrity,
    /// Rootless Linux, cgroup v2/systemd controllers or seccomp are not established.
    #[error("required rootless execution environment NOT_PROVEN")]
    EnvironmentNotProven,
    /// Authority CLI/endpoint configuration is invalid.
    #[error("invalid runtime configuration")]
    InvalidRuntimeConfiguration,
    /// Trusted runtime operation failed or exceeded its controller deadline/budget.
    #[error("sandbox runtime failure")]
    RuntimeFailure,
    /// Trusted image violates environment/volume/entrypoint policy.
    #[error("runner image policy violation")]
    ImagePolicy,
    /// Cleanup failed; execution must not be reported as successful.
    #[error("sandbox cleanup failed")]
    CleanupFailed,
}

/// Operational states. Only explicit successful destruction reaches Destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExecutionState {
    /// Authority setup in progress.
    Preparing,
    /// Actual stopped sandbox verified.
    Ready,
    /// Target may execute.
    Running,
    /// Controller is terminating the sandbox.
    Terminating,
    /// Runtime exit observed; cleanup still required.
    Finished,
    /// Sandbox and job image removed.
    Destroyed,
}

impl ExecutionState {
    /// Enforces forward progress; rejection can enter termination during setup.
    pub fn advance(self, next: Self) -> Result<Self, ExecutionError> {
        use ExecutionState::*;
        if matches!(
            (self, next),
            (Preparing, Ready)
                | (Ready, Running)
                | (Running, Terminating)
                | (Running, Finished)
                | (Terminating, Finished)
                | (Finished, Destroyed)
                | (Preparing, Terminating)
                | (Ready, Terminating)
        ) {
            Ok(next)
        } else {
            Err(ExecutionError::RuntimeFailure)
        }
    }
}

/// Execution outcome only; zero exit does not certify a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    /// Target exited (possibly nonzero).
    Completed,
    /// External wall-clock deadline terminated the sandbox.
    TimedOut,
    /// Controller output budget or runtime memory enforcement terminated execution.
    ResourceLimit,
    /// Runtime/control or evidence collection failed.
    SandboxFailure,
    /// Target failed to start.
    StartFailure,
    /// Runtime reports termination by signal; causality may be unknown.
    Terminated,
}

/// Observed termination cause; never infer a PID/CPU exhaustion from arbitrary log text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// Ordinary process exit.
    Exit,
    /// External timeout.
    Timeout,
    /// Stdout byte ceiling.
    StdoutLimit,
    /// Stderr byte ceiling.
    StderrLimit,
    /// Runtime reports OOM kill.
    MemoryLimit,
    /// Runtime exit >=128, signal convention only (not proof of actual signal).
    SignalConvention,
    /// Infrastructure/evidence failure.
    RuntimeFailure,
}

/// Bounded hostile bytes. JSON escapes byte values by serializing an integer array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedStream {
    /// SHA-256 of every byte actually observed, including bytes outside the prefix.
    pub sha256: Sha256Digest,
    /// Number of bytes observed and hashed.
    pub observed_bytes: u64,
    /// Safe byte prefix; never render directly to a terminal.
    pub excerpt: Vec<u8>,
    /// Prefix omits some observed bytes.
    pub truncated: bool,
    /// EOF was observed. False means digest covers an explicitly incomplete stream.
    pub complete: bool,
}

/// Observed CLI/daemon reports. This is not executable attestation or provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedRuntimeIdentity {
    /// Configured client path; replacement of the binary is outside this observation.
    pub client_path: String,
    /// Client-reported version.
    pub client_version: String,
    /// Server-reported version.
    pub server_version: String,
    /// Reported runtime component versions, kernel and operating system facts.
    pub runtime_information: BTreeMap<String, String>,
}

/// Image/profile naming cannot establish a toolchain version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolchainObservation {
    /// No controlled toolchain/version probe was performed.
    NotObserved,
}

/// Structured runner/controller evidence. Target files and log claims have no authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    /// Authority execution/job ID.
    pub execution: ExecutionId,
    /// Accepted exact source identity.
    pub source: SourceIdentity,
    /// Bound source workspace ID.
    pub workspace: WorkspaceId,
    /// Adapter name.
    pub backend: String,
    /// Versioned adapter semantics; client/server observations are recorded separately.
    pub backend_version: String,
    /// Producer crate version, separate from runtime reports.
    pub producer_version: String,
    /// Observed runtime identity; no executable attestation claim.
    pub observed_runtime: ObservedRuntimeIdentity,
    /// Toolchain availability/version has not been probed.
    pub toolchain: ToolchainObservation,
    /// Approved OCI repository digest.
    pub image_digest: String,
    /// Runtime content ID of approved image.
    pub base_image_id: String,
    /// Runtime content ID including accepted source layer.
    pub execution_image_id: String,
    /// Authority profile name.
    pub profile: String,
    /// Literal command executed.
    pub command: ExecutionCommand,
    /// Enforced egress policy.
    pub network: NetworkPolicy,
    /// Enforced authority budgets.
    pub limits: ExecutionLimits,
    /// Exact approved target environment key names.
    pub environment_keys: Vec<String>,
    /// Required effective container UID:GID.
    pub container_user: String,
    /// UTC Unix milliseconds before setup.
    pub started_at_ms: u64,
    /// UTC Unix milliseconds after termination/evidence gathering.
    pub ended_at_ms: u64,
    /// Monotonic duration including setup/termination, excluding cleanup.
    pub duration_ms: u64,
    /// Runtime-observed exit code, absent if not observed.
    pub exit_code: Option<i64>,
    /// Observed termination classification.
    pub termination: TerminationReason,
    /// Explicitly bounded stdout bytes and digest scope.
    pub stdout: CapturedStream,
    /// Explicitly bounded stderr bytes and digest scope.
    pub stderr: CapturedStream,
    /// Execution outcome, never certification policy.
    pub outcome: ExecutionOutcome,
}

/// Structured lifecycle events returned to the authority; persistence is deferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ExecutionEvent {
    /// Authority request validated.
    ExecutionPrepared,
    /// Container created; target has not started.
    SandboxCreated,
    /// Source/config verification succeeded; target start requested.
    ExecutionStarted,
    /// External deadline expired.
    ExecutionTimedOut,
    /// Target or infrastructure attempt finished.
    ExecutionCompleted,
    /// Explicit container/job-image removal succeeded.
    SandboxDestroyed,
    /// Removal failed; orphan intervention required.
    SandboxCleanupFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_is_structural_and_cwd_is_confined() -> Result<(), ExecutionError> {
        let c = ExecutionCommand::new(
            "cargo".into(),
            vec!["test".into(), "--locked".into(), "$(touch /x); hi".into()],
            "/source".into(),
        )?;

        assert_eq!(c.args()[2], "$(touch /x); hi");

        for p in ["sh -c test", "../cargo", "./cargo", "-x", ""] {
            assert!(ExecutionCommand::new(p.into(), vec![], "/source".into()).is_err());
        }

        for cwd in [
            "/",
            "/work/../source",
            "/source/",
            "/home",
            "/source2",
            "/work//x",
        ] {
            assert!(ExecutionCommand::new("cargo".into(), vec![], cwd.into()).is_err());
        }

        Ok(())
    }

    #[test]
    fn every_resource_limit_is_validated() {
        let valid = ExecutionLimits::default();

        assert!(valid.validate().is_ok());

        for n in 0..10 {
            let mut l = valid;

            match n {
                0 => l.timeout_ms = 0,
                1 => l.cpu_millis = 0,
                2 => l.memory_bytes = 0,
                3 => l.pids = 0,
                4 => l.stdout_bytes = 0,
                5 => l.stderr_bytes = 0,
                6 => l.excerpt_bytes = u64::MAX,
                7 => l.scratch_bytes = 0,
                8 => l.output_bytes = 0,
                _ => l.timeout_ms = u64::MAX,
            }

            assert_eq!(l.validate(), Err(ExecutionError::InvalidLimits));
        }
    }

    #[test]
    fn immutable_authority_profile_and_clean_environment() -> Result<(), ExecutionError> {
        let image = format!("archcert/runner@sha256:{}", "a".repeat(64));
        let profile = ExecutionProfile::new(
            "rust".into(),
            image,
            vec!["cargo".into()],
            ExecutionLimits::default(),
        )?;

        assert!(
            profile
                .authorize(&ExecutionCommand::new(
                    "cargo".into(),
                    vec![],
                    "/work".into()
                )?)
                .is_ok()
        );
        assert_eq!(
            profile.authorize(&ExecutionCommand::new(
                "sh".into(),
                vec![],
                "/source".into()
            )?),
            Err(ExecutionError::CommandNotAllowed)
        );

        for image in ["rust:latest", "rust:1", "--privileged", "x@sha256:ab"] {
            assert!(
                ExecutionProfile::new(
                    "rust".into(),
                    image.into(),
                    vec!["cargo".into()],
                    ExecutionLimits::default()
                )
                .is_err()
            );
        }

        let env = sandbox_environment();

        assert_eq!(env.len(), 5);
        assert_eq!(env["HOME"], "/home/archcert");

        for key in [
            "SSH_AUTH_SOCK",
            "DATABASE_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "DOCKER_HOST",
            "KUBECONFIG",
        ] {
            assert!(!env.contains_key(key));
        }

        assert_eq!(
            serde_json::to_value(NetworkPolicy::Denied).ok(),
            Some(serde_json::json!("Denied"))
        );

        Ok(())
    }

    #[test]
    fn lifecycle_never_confuses_unfinished_with_destroyed() -> Result<(), ExecutionError> {
        use ExecutionState::*;
        assert!(Preparing.advance(Destroyed).is_err());
        assert!(Running.advance(Destroyed).is_err());
        assert_eq!(
            Preparing
                .advance(Ready)?
                .advance(Running)?
                .advance(Terminating)?
                .advance(Finished)?
                .advance(Destroyed)?,
            Destroyed
        );
        assert!(Destroyed.advance(Running).is_err());

        Ok(())
    }
}
