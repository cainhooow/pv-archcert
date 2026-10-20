//! Source-to-filesystem invariants without filesystem or runner dependencies.

use crate::{
    ProjectId, SourceIdentity,
    source::{RepositoryId, SourceError, SourceLimits},
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;
use uuid::Uuid;

/// Authority-generated opaque workspace identity. Never derived from source paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    /// Creates a random UUID v4 workspace identity.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    /// Accepts only canonical lowercase RFC 4122 UUID v4 text.
    pub fn parse(text: &str) -> Result<Self, MaterializationError> {
        let id = Uuid::parse_str(text).map_err(|_| MaterializationError::InvalidWorkspaceId)?;
        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != text
        {
            return Err(MaterializationError::InvalidWorkspaceId);
        }
        Ok(Self(id))
    }
}
impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}
impl Display for WorkspaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}
impl TryFrom<String> for WorkspaceId {
    type Error = MaterializationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<WorkspaceId> for String {
    fn from(value: WorkspaceId) -> Self {
        value.to_string()
    }
}

/// Authority-scoped immutable lookup key; a digest alone does not identify provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotReference {
    /// Registered project.
    pub project: ProjectId,
    /// Registered repository label, never a transport locator.
    pub repository: RepositoryId,
    /// Exact expected Git and ArchCert identities.
    pub identity: SourceIdentity,
}

/// Materialization budgets reuse source file/byte/depth limits without changing their meaning.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MaterializationLimits {
    /// Leaf count, total payload bytes, single payload size and directory depth.
    /// Git-specific budgets are unused because no Git objects participate here.
    pub source: SourceLimits,
    /// Maximum symlink leaves, also charged as files and bytes.
    pub max_symlinks: u64,
    /// Maximum directories beneath the workspace root.
    pub max_directories: u64,
}
impl Default for MaterializationLimits {
    fn default() -> Self {
        Self {
            source: SourceLimits::default(),
            max_symlinks: 1000,
            max_directories: 10_000,
        }
    }
}

/// Explicit failed filesystem work budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MaterializationBudget {
    /// Leaf entries.
    Entries,
    /// Total payload bytes.
    Bytes,
    /// Individual payload bytes.
    SingleFile,
    /// Directory depth (root is zero).
    Depth,
    /// Symbolic links.
    Symlinks,
    /// Directories excluding the root.
    Directories,
}

/// Fail-closed materialization errors; malformed source is distinct from authority I/O failure.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
pub enum MaterializationError {
    /// Workspace identifiers must not contain path syntax or noncanonical UUID text.
    #[error("invalid workspace identity")]
    InvalidWorkspaceId,
    /// Authority store does not contain the exact scoped source.
    #[error("accepted snapshot unavailable")]
    SnapshotUnavailable,
    /// Snapshot bytes/metadata failed independent verification.
    #[error("invalid accepted snapshot: {0}")]
    SnapshotInvalid(SourceError),
    /// Required LFS/submodule bytes remain unresolved.
    #[error("snapshot is not complete")]
    SnapshotNotComplete,
    /// Authority root must be private, owned, absolute and free of symlink components.
    #[error("unsafe authority workspace root")]
    UnsafeDestination,
    /// Exclusive creation found a pre-existing name; it is never reused or emptied.
    #[error("destination already exists or is not empty")]
    DestinationNotEmpty,
    /// Fresh workspace creation failed.
    #[error("destination creation failed")]
    DestinationCreationFailed,
    /// A source name fails independent path validation.
    #[error("path escape or unsupported source name")]
    PathEscapeAttempt,
    /// An entry changed inode/type, was hard-linked, or crossed filesystem boundaries.
    #[error("filesystem entry type or identity conflict")]
    EntryTypeConflict,
    /// Link target is not representable by the current filesystem API.
    #[error("unsupported filesystem feature or source representation")]
    UnsupportedFilesystemFeature,
    /// Exclusive regular-file creation or exact write failed.
    #[error("file creation or write failed")]
    FileCreationFailed,
    /// Link creation failed; no target is dereferenced as a fallback.
    #[error("symlink creation failed")]
    SymlinkCreationFailed,
    /// Descriptor-relative permission application failed.
    #[error("permission application failed")]
    PermissionApplicationFailed,
    /// Actual filesystem cannot be inspected safely.
    #[error("filesystem verification failed")]
    VerificationFailed,
    /// Reconstructed bytes, paths, directories or modes do not match accepted source.
    #[error("materialization integrity mismatch")]
    MaterializationIntegrityMismatch,
    /// A configured budget or hard parser depth bound was exceeded.
    #[error("materialization limit exceeded: {0:?}")]
    LimitExceeded(MaterializationBudget),
    /// Sealing failed, so runner input must not be issued.
    #[error("source seal failed")]
    SealFailed,
    /// Cleanup failed; source may remain and requires authority intervention.
    #[error("workspace cleanup failed")]
    CleanupFailed,
    /// A lifecycle operation was requested out of order.
    #[error("invalid materialization state transition")]
    InvalidStateTransition,
    /// Authority state/clock/adapter invariants failed.
    #[error("internal materialization failure")]
    InternalMaterializationFailure,
}

/// Operational lifecycle, separate from source identity and certification verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaterializationState {
    /// Source writes may be in progress; not eligible for handoff.
    Materializing,
    /// Actual filesystem independently matched the expected identity.
    Verified,
    /// Read-only permission seal and post-seal verification succeeded.
    Sealed,
    /// Final verification succeeded and the narrow input was issued.
    HandedOff,
    /// Workspace was explicitly deleted; this does not claim secure erasure.
    Destroyed,
}
impl MaterializationState {
    /// Enforces forward-only transitions and explicit destruction from any live state.
    pub fn advance(self, next: Self) -> Result<Self, MaterializationError> {
        if matches!(
            (self, next),
            (Self::Materializing, Self::Verified)
                | (Self::Verified, Self::Sealed)
                | (Self::Sealed, Self::HandedOff)
        ) || (self != Self::Destroyed && next == Self::Destroyed)
        {
            Ok(next)
        } else {
            Err(MaterializationError::InvalidStateTransition)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workspace_identity_is_opaque_and_canonical() -> Result<(), MaterializationError> {
        let id = WorkspaceId::new();
        assert_eq!(WorkspaceId::parse(&id.to_string())?, id);
        assert_ne!(id, WorkspaceId::new());
        for invalid in [
            "../escape",
            "/tmp/source",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-00000000000A",
        ] {
            assert_eq!(
                WorkspaceId::parse(invalid),
                Err(MaterializationError::InvalidWorkspaceId)
            );
        }
        Ok(())
    }
    #[test]
    fn only_verified_sealed_source_reaches_handoff() -> Result<(), MaterializationError> {
        use MaterializationState::*;
        assert_eq!(
            Materializing.advance(HandedOff),
            Err(MaterializationError::InvalidStateTransition)
        );
        assert_eq!(
            Verified.advance(HandedOff),
            Err(MaterializationError::InvalidStateTransition)
        );
        assert_eq!(
            Destroyed.advance(Materializing),
            Err(MaterializationError::InvalidStateTransition)
        );
        assert_eq!(
            Materializing
                .advance(Verified)?
                .advance(Sealed)?
                .advance(HandedOff)?
                .advance(Destroyed)?,
            Destroyed
        );
        Ok(())
    }
    #[test]
    fn malformed_source_and_internal_failures_stay_distinct() {
        assert_ne!(
            MaterializationError::PathEscapeAttempt,
            MaterializationError::InternalMaterializationFailure
        );
        assert_eq!(
            MaterializationError::MaterializationIntegrityMismatch.to_string(),
            "materialization integrity mismatch"
        );
    }
}
