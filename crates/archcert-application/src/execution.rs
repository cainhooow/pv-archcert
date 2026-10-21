//! Narrow execution port. No runtime, store, signer or cleanup-lease dependency.

use crate::materialization::{CleanupStatus, MaterializedSource, RunnerInput};
use archcert_domain::execution::{
    ExecutionCommand, ExecutionError, ExecutionEvent, ExecutionEvidence, ExecutionProfile,
};
use serde::Serialize;

/// Only source capability and authority-approved execution policy cross this port.
pub struct ExecutionRequest<S: MaterializedSource> {
    input: RunnerInput<S>,
    profile: ExecutionProfile,
    command: ExecutionCommand,
}

impl<S: MaterializedSource> ExecutionRequest<S> {
    /// Checks authority policy before allocating a sandbox.
    pub fn new(
        input: RunnerInput<S>,
        profile: ExecutionProfile,
        command: ExecutionCommand,
    ) -> Result<Self, ExecutionError> {
        profile.limits().validate()?;
        profile.authorize(&command)?;

        if input.source().workspace() != input.workspace()
            || input.source().identity() != input.expected_source_identity()
        {
            return Err(ExecutionError::SourceIntegrity);
        }

        Ok(Self {
            input,
            profile,
            command,
        })
    }

    /// Narrow source-only input; no source store or parent/cleanup capability.
    pub fn input(&self) -> &RunnerInput<S> {
        &self.input
    }

    /// Authority-approved policy; project input cannot replace its settings.
    pub fn profile(&self) -> &ExecutionProfile {
        &self.profile
    }

    /// Literal target argv and sandbox working directory.
    pub fn command(&self) -> &ExecutionCommand {
        &self.command
    }
}

/// Structured execution evidence and independently reported sandbox cleanup.
#[derive(Debug, Serialize)]
pub struct ExecutionResult {
    /// Runner-owned observations, never target-generated status files.
    pub evidence: ExecutionEvidence,
    /// Separate sandbox cleanup result, always Destroyed for successful return.
    pub cleanup: CleanupStatus,
    /// Ordered lifecycle events; not durable audit storage.
    pub events: Vec<ExecutionEvent>,
}

/// Setup, evidence or cleanup failure; target nonzero exit is not this error.
#[derive(Debug, Serialize)]
pub struct ExecutionFailure {
    /// Authority/infrastructure failure.
    pub error: ExecutionError,
    /// Evidence retained when available, including when cleanup fails.
    pub evidence: Option<Box<ExecutionEvidence>>,
    /// Explicit destruction outcome, separate from execution.
    pub cleanup: CleanupStatus,
    /// Ordered audit events through failure and cleanup.
    pub events: Vec<ExecutionEvent>,
}

impl std::fmt::Display for ExecutionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for ExecutionFailure {}

/// Blocking worker port, matching the existing synchronous source preparation ports.
/// Implement on dedicated workers; do not call on an asynchronous reactor thread.
pub trait SandboxRunner<S: MaterializedSource> {
    /// Runs hostile code only after establishing isolation, then attempts destruction
    /// on every path. No certificate or policy verdict is produced.
    fn execute(&self, request: ExecutionRequest<S>) -> Result<ExecutionResult, ExecutionFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materialization::{MaterializationEvidence, SealStatus, VerificationStatus};
    use archcert_domain::{
        GitObjectId, ProjectId, SourceIdentity,
        execution::ExecutionLimits,
        materialization::{
            MaterializationLimits, MaterializationState, SnapshotReference, WorkspaceId,
        },
        source::{RepositoryId, digest_bytes},
    };

    struct Source {
        workspace: WorkspaceId,
        identity: SourceIdentity,
    }

    impl MaterializedSource for Source {
        fn workspace(&self) -> WorkspaceId {
            self.workspace
        }

        fn identity(&self) -> &SourceIdentity {
            &self.identity
        }
    }

    fn input() -> Result<RunnerInput<Source>, Box<dyn std::error::Error>> {
        let digest = digest_bytes(b"accepted");
        let identity = SourceIdentity {
            commit: GitObjectId::parse("a".repeat(40))?,
            tree: GitObjectId::parse("b".repeat(40))?,
            snapshot_sha256: digest.clone(),
        };
        let workspace = WorkspaceId::new();
        let evidence = MaterializationEvidence {
            snapshot: SnapshotReference {
                project: ProjectId::new(),
                repository: RepositoryId::parse("test/runner")?,
                identity: identity.clone(),
            },
            workspace,
            materializer_version: "mock".into(),
            expected_digest: digest.clone(),
            observed_digest: digest,
            entry_count: 1,
            total_bytes_written: 8,
            status: MaterializationState::Sealed,
            verification: VerificationStatus::Verified,
            seal: SealStatus::UnixPermissionsReadOnly,
            started_at: 1,
            verified_at: 2,
            sealed_at: 3,
            handed_off_at: None,
            limits: MaterializationLimits::default(),
        };

        Ok(RunnerInput::from_sealed(
            Source {
                workspace,
                identity,
            },
            &evidence,
        )?)
    }

    struct MockRunner;

    impl SandboxRunner<Source> for MockRunner {
        fn execute(
            &self,
            _: ExecutionRequest<Source>,
        ) -> Result<ExecutionResult, ExecutionFailure> {
            Err(ExecutionFailure {
                error: ExecutionError::EnvironmentNotProven,
                evidence: None,
                cleanup: CleanupStatus::NotCreated,
                events: vec![ExecutionEvent::ExecutionPrepared],
            })
        }
    }

    #[test]
    fn request_policy_is_enforced_before_any_backend_and_mock_needs_no_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = ExecutionProfile::new(
            "mock".into(),
            format!("test@sha256:{}", "a".repeat(64)),
            vec!["cargo".into()],
            ExecutionLimits::default(),
        )?;
        let rejected = ExecutionRequest::new(
            input()?,
            profile.clone(),
            ExecutionCommand::new("sh".into(), vec![], "/source".into())?,
        );

        assert!(matches!(rejected, Err(ExecutionError::CommandNotAllowed)));

        let request = ExecutionRequest::new(
            input()?,
            profile,
            ExecutionCommand::new(
                "cargo".into(),
                vec!["metadata".into(), "--offline".into()],
                "/source".into(),
            )?,
        )?;

        assert_eq!(
            request.input().source().workspace(),
            request.input().workspace()
        );

        let failure = MockRunner
            .execute(request)
            .err()
            .ok_or("mock should reject")?;

        assert_eq!(failure.error, ExecutionError::EnvironmentNotProven);
        assert_eq!(failure.cleanup, CleanupStatus::NotCreated);
        assert!(failure.evidence.is_none());

        Ok(())
    }
}
