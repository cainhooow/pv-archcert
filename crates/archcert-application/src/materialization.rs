//! Credential-free source preparation contracts; no filesystem or runtime dependencies.

use crate::source::SourceStore;
use archcert_domain::{
    Sha256Digest, SourceIdentity,
    materialization::{
        MaterializationError, MaterializationLimits, MaterializationState, SnapshotReference,
        WorkspaceId,
    },
    source::SourceSnapshot,
};
use serde::Serialize;

/// Authority request for an exact accepted source; no destination or repository URL is accepted.
#[derive(Debug, Clone, Serialize)]
pub struct MaterializationRequest {
    /// Scoped source-store lookup and expected source identity.
    pub snapshot: SnapshotReference,
    /// Authority budgets for writes and every verification pass.
    pub limits: MaterializationLimits,
}

/// Explicit verification outcome recorded independently of lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VerificationStatus {
    /// Actual filesystem bytes independently matched the expected digest.
    Verified,
}

/// Strength of the filesystem seal, not a cryptographic immutability claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SealStatus {
    /// Private owner-read-only files/directories; owner/root can undo this seal.
    UnixPermissionsReadOnly,
}

/// Independently reconstructed source and operational audit metadata.
#[derive(Debug, Clone, Serialize)]
pub struct MaterializationEvidence {
    /// Authority-scoped source identity, retained by the control plane only.
    pub snapshot: SnapshotReference,
    /// Fresh opaque workspace identity.
    pub workspace: WorkspaceId,
    /// Versioned adapter semantics.
    pub materializer_version: String,
    /// Caller-supplied accepted source digest.
    pub expected_digest: Sha256Digest,
    /// Digest reconstructed by enumerating and reading actual filesystem entries.
    pub observed_digest: Sha256Digest,
    /// Verified leaves, including symlinks.
    pub entry_count: u64,
    /// Exact accepted payload bytes written, including symlink targets.
    pub total_bytes_written: u64,
    /// Explicit lifecycle state.
    pub status: MaterializationState,
    /// Successful independent verification.
    pub verification: VerificationStatus,
    /// Explicitly limited seal guarantee.
    pub seal: SealStatus,
    /// UTC Unix seconds at the start of materialization.
    pub started_at: u64,
    /// UTC Unix seconds after the write pass was independently verified.
    pub verified_at: u64,
    /// UTC Unix seconds after permissions and post-seal verification.
    pub sealed_at: u64,
    /// UTC Unix seconds when final verification allowed handoff.
    pub handed_off_at: Option<u64>,
    /// Authority limits applied to writes and verification.
    pub limits: MaterializationLimits,
}

/// Structured audit transitions, not a durable event log.
#[derive(Debug, Clone, Serialize)]
pub enum MaterializationEvent {
    /// Fresh attempt began with an opaque authority identity.
    Started(WorkspaceId),
    /// Reconstructed filesystem identity matched expected source.
    Verified(Sha256Digest),
    /// Sealing and post-seal verification succeeded.
    Sealed(WorkspaceId),
    /// Final verification permitted narrow runner input issuance.
    RunnerInputIssued(WorkspaceId),
    /// No runner input is released on this error.
    Rejected(MaterializationError),
    /// Explicit deletion succeeded (no secure erasure claim).
    WorkspaceDestroyed(WorkspaceId),
}

/// Cleanup state accompanies rejection so leftover workspaces are never called destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CleanupStatus {
    /// Failure happened before workspace creation.
    NotCreated,
    /// Explicit cleanup completed.
    Destroyed,
    /// Cleanup failed and authority intervention may be required.
    Failed,
}

/// Structured failure retains audit transitions and cleanup outcome.
#[derive(Debug)]
pub struct MaterializationFailure {
    /// Input/authority/integrity error.
    pub error: MaterializationError,
    /// Ordered events; no issuance event follows rejection.
    pub events: Vec<MaterializationEvent>,
    /// Whether an ephemeral workspace could be deleted.
    pub cleanup: CleanupStatus,
}

impl MaterializationFailure {
    /// Records a rejection before any destination exists.
    pub fn before_creation(error: MaterializationError) -> Self {
        Self {
            events: vec![MaterializationEvent::Rejected(error.clone())],
            error,
            cleanup: CleanupStatus::NotCreated,
        }
    }
}

impl std::fmt::Display for MaterializationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for MaterializationFailure {}

/// Narrow input for a trusted sandbox setup adapter, never a source-store handle.
///
/// The opaque source capability contains only materialized source. It is not itself
/// OS isolation: execution adapters must expose a verified read-only isolated source view.
/// It must not be passed directly to untrusted code in the authority process.
pub struct RunnerInput<S: MaterializedSource> {
    source: S,
    expected_source_identity: SourceIdentity,
    workspace: WorkspaceId,
}

/// Platform-specific source-only capability implemented by trusted filesystem adapters.
/// Implementations must contain neither acquisition credentials nor cleanup/store authority.
/// Constructors remain private to the platform adapter that verifies and seals the source.
pub trait MaterializedSource {
    /// Fresh authority identity bound to this actual source handle.
    fn workspace(&self) -> WorkspaceId;

    /// Accepted source identity bound to the independently verified handle.
    fn identity(&self) -> &SourceIdentity;
}

/// Source export port for trusted sandbox preparation. Implementations must reverify
/// actual bytes/modes/identity through retained capabilities on every call, within
/// authority budgets, without reopening diagnostic paths or following symlinks.
/// Returned bytes carry no descriptors, credentials or cleanup/store authority.
pub trait VerifiedSourceExport: MaterializedSource {
    /// Credential-free canonicalization recipe for independently rehashing exports.
    /// Existing schema-1 adapters retain their original manifest identity.
    fn source_binding(&self) -> archcert_domain::source::SourceBinding {
        archcert_domain::source::SourceBinding::default()
    }

    /// Performs final integrity verification and returns bounded owned source bytes.
    fn verified_files(
        &self,
    ) -> Result<Vec<archcert_domain::source::SourceFile>, MaterializationError>;
}

impl<S: MaterializedSource> RunnerInput<S> {
    /// Issues input only from verified/sealed matching evidence. The trusted platform
    /// adapter must have reconstructed and verified its actual source capability.
    pub fn from_sealed(
        source: S,
        evidence: &MaterializationEvidence,
    ) -> Result<Self, MaterializationError> {
        if evidence.status != MaterializationState::Sealed
            || evidence.expected_digest != evidence.observed_digest
            || evidence.expected_digest != evidence.snapshot.identity.snapshot_sha256
            || evidence.handed_off_at.is_some()
            || source.workspace() != evidence.workspace
            || source.identity() != &evidence.snapshot.identity
        {
            return Err(MaterializationError::MaterializationIntegrityMismatch);
        }

        Ok(Self {
            source,
            expected_source_identity: evidence.snapshot.identity.clone(),
            workspace: evidence.workspace,
        })
    }

    /// Materialized source capability; no cleanup parent, store, Git or API access.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Previously accepted Git and ArchCert identities.
    pub fn expected_source_identity(&self) -> &SourceIdentity {
        &self.expected_source_identity
    }

    /// Opaque authority workspace identity.
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }
}

/// Completed source preparation; cleanup authority is deliberately separate from runner input.
pub struct MaterializationResult<S: MaterializedSource, C> {
    /// Narrow capability passed to trusted sandbox setup.
    pub runner_input: RunnerInput<S>,
    /// Authority-only cleanup lease; never pass it to an untrusted runner.
    pub cleanup: C,
    /// Structural evidence; terminal formatting is diagnostic only.
    pub evidence: MaterializationEvidence,
    /// Ordered successful transitions.
    pub events: Vec<MaterializationEvent>,
}

/// Filesystem adapter port; implementations must not execute source or consult Git/environment credentials.
pub trait SourceMaterializer {
    /// Platform source handle containing no acquisition/cleanup authority.
    type Source: MaterializedSource;

    /// Authority-owned ephemeral workspace cleanup handle.
    type Cleanup;

    /// Creates a fresh workspace, verifies actual contents, seals, then verifies again at handoff.
    fn prepare(
        &self,
        snapshot: &SourceSnapshot,
        request: &MaterializationRequest,
    ) -> Result<MaterializationResult<Self::Source, Self::Cleanup>, MaterializationFailure>;
}

/// Retrieves exact accepted source and delegates only its bytes to the materializer.
/// Repository/source-store credentials never enter the returned runner input.
pub fn materialize_source<M: SourceMaterializer>(
    store: &dyn SourceStore,
    materializer: &M,
    request: &MaterializationRequest,
) -> Result<MaterializationResult<M::Source, M::Cleanup>, MaterializationFailure> {
    let snapshot = store.load(&request.snapshot).map_err(|error| {
        MaterializationFailure::before_creation(match error {
            archcert_domain::source::SourceError::SnapshotUnavailable => {
                MaterializationError::SnapshotUnavailable
            }
            other => MaterializationError::SnapshotInvalid(other),
        })
    })?;

    if snapshot.project() != request.snapshot.project
        || snapshot.repository() != &request.snapshot.repository
        || snapshot.identity() != &request.snapshot.identity
    {
        return Err(MaterializationFailure::before_creation(
            MaterializationError::InternalMaterializationFailure,
        ));
    }

    snapshot
        .verify(&request.snapshot.identity.snapshot_sha256)
        .map_err(|e| {
            MaterializationFailure::before_creation(MaterializationError::SnapshotInvalid(e))
        })?;
    snapshot.require_complete().map_err(|_| {
        MaterializationFailure::before_creation(MaterializationError::SnapshotNotComplete)
    })?;

    materializer.prepare(&snapshot, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::{
        GitObjectId, ProjectId,
        source::{RepositoryId, digest_bytes},
    };

    struct TestSource {
        workspace: WorkspaceId,
        identity: SourceIdentity,
    }

    impl MaterializedSource for TestSource {
        fn workspace(&self) -> WorkspaceId {
            self.workspace
        }

        fn identity(&self) -> &SourceIdentity {
            &self.identity
        }
    }

    fn evidence() -> Result<MaterializationEvidence, Box<dyn std::error::Error>> {
        let digest = digest_bytes(b"test fixture");

        Ok(MaterializationEvidence {
            snapshot: SnapshotReference {
                project: ProjectId::new(),
                repository: RepositoryId::parse("test/source")?,
                identity: SourceIdentity {
                    commit: GitObjectId::parse("a".repeat(40))?,
                    tree: GitObjectId::parse("b".repeat(40))?,
                    snapshot_sha256: digest.clone(),
                },
            },
            workspace: WorkspaceId::new(),
            materializer_version: "test-only".to_owned(),
            expected_digest: digest.clone(),
            observed_digest: digest,
            entry_count: 1,
            total_bytes_written: 12,
            status: MaterializationState::Sealed,
            verification: VerificationStatus::Verified,
            seal: SealStatus::UnixPermissionsReadOnly,
            started_at: 1,
            verified_at: 2,
            sealed_at: 3,
            handed_off_at: None,
            limits: MaterializationLimits::default(),
        })
    }

    #[test]
    fn runner_input_requires_matching_sealed_identity_and_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = evidence()?;
        let capability = || TestSource {
            workspace: valid.workspace,
            identity: valid.snapshot.identity.clone(),
        };
        let ready = RunnerInput::from_sealed(capability(), &valid)?;

        assert_eq!(ready.workspace(), valid.workspace);
        assert_eq!(ready.expected_source_identity(), &valid.snapshot.identity);

        for mutation in 0..5 {
            let mut invalid = valid.clone();

            match mutation {
                0 => invalid.status = MaterializationState::Verified,
                1 => invalid.observed_digest = digest_bytes(b"wrong"),
                2 => invalid.workspace = WorkspaceId::new(),
                3 => invalid.snapshot.identity.commit = GitObjectId::parse("c".repeat(40))?,
                _ => invalid.handed_off_at = Some(4),
            }

            assert!(matches!(
                RunnerInput::from_sealed(capability(), &invalid),
                Err(MaterializationError::MaterializationIntegrityMismatch)
            ));
        }

        Ok(())
    }

    #[test]
    fn evidence_timestamps_do_not_participate_in_identity_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut proof = evidence()?;
        proof.started_at = 10;
        proof.verified_at = 20;
        proof.sealed_at = 30;
        let source = TestSource {
            workspace: proof.workspace,
            identity: proof.snapshot.identity.clone(),
        };
        let ready = RunnerInput::from_sealed(source, &proof)?;

        assert_eq!(
            ready.expected_source_identity().snapshot_sha256,
            proof.observed_digest
        );

        Ok(())
    }
}
