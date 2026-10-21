//! Transport-independent source-ingress read model. These observations confer no
//! authentication, snapshot, execution, policy, or certification capability.

use archcert_domain::{
    GitObjectId, ProjectId, SourceIdentity,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    source::{RepositoryId, SourceError, SourcePath, SourceStatus},
};

/// Current ingress lifecycle, separate from certification and source completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionStatus {
    /// Reception has started.
    Received,
    /// Received objects remain untrusted.
    Quarantined,
    /// Independent bounded validation is in progress.
    Validating,
    /// Structurally accepted source still needs external bytes.
    IncompleteExternalSource,
    /// Complete immutable source was accepted; this is not certification.
    Accepted,
    /// The attempt failed.
    Rejected,
}

/// Acquisition provenance, never an authorization grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTransport {
    /// Restricted OpenSSH public-key receive.
    SshPublicKey,
    /// Separate operator-only controlled local external resolution.
    AuthorityPrivateSourceResolution,
}

/// Authority-selected Git object format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectAlgorithm {
    /// Git SHA-1 objects, independent of ArchCert source SHA-256.
    Sha1,
    /// Git SHA-256 objects.
    Sha256,
}

impl GitObjectAlgorithm {
    fn matches(self, oid: &GitObjectId) -> bool {
        oid.as_str().len()
            == match self {
                Self::Sha1 => 40,
                Self::Sha256 => 64,
            }
    }
}

/// Credential-free summary of a resolved source binding. The actual immutable
/// recipe and bytes remain in SourceSnapshot; this summary cannot reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResolutionSummary {
    /// Previous submission, which remains immutable and incomplete.
    pub parent_submission: SourceSubmissionId,
    /// Original commit/tree and independent source digest.
    pub original: SourceIdentity,
    /// Separate operator attribution, not the original submitter.
    pub resolver_actor: GitActorId,
    /// Number of verified top-level LFS replacements.
    pub lfs_resolved: u64,
    /// Number of verified top-level child expansions.
    pub submodules_resolved: u64,
}

/// Source identity and completeness observations, not accepted source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceState {
    /// Immutable Git and ArchCert identities.
    pub identity: SourceIdentity,
    /// Existing canonical source schema, distinct from protocol package version.
    pub schema_version: u32,
    /// Complete versus unresolved external source.
    pub completeness: SourceStatus,
    /// Unresolved top-level LFS pointers.
    pub lfs_unresolved: u64,
    /// Unresolved top-level gitlinks.
    pub submodules_unresolved: u64,
    /// Resolved schema-2 provenance summary, absent for schema 1.
    pub resolution: Option<SourceResolutionSummary>,
}

impl SourceState {
    /// Checks the existing completeness and source-schema summary semantics.
    /// A consistent summary is still not proof of retained source bytes.
    pub fn validate(&self) -> Result<(), SourceError> {
        let invalid = SourceError::InternalIntegrityFailure;

        if self.identity.commit.as_str().len() != self.identity.tree.as_str().len()
            || (self.completeness == SourceStatus::IncompleteExternalSource)
                != (self.lfs_unresolved != 0 || self.submodules_unresolved != 0)
        {
            return Err(invalid);
        }

        match (self.schema_version, &self.resolution) {
            (1, None) => Ok(()),
            (2, Some(resolution))
                if self.completeness == SourceStatus::Complete
                    && resolution.original.commit == self.identity.commit
                    && resolution.original.tree == self.identity.tree
                    && resolution.original.snapshot_sha256 != self.identity.snapshot_sha256
                    && (resolution.lfs_resolved != 0 || resolution.submodules_resolved != 0) =>
            {
                Ok(())
            }
            _ => Err(invalid),
        }
    }
}

/// Source-only ingress state at an adapter-facing inspection boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSubmissionState {
    /// Operational submission identity, unrelated to source identity.
    pub submission: SourceSubmissionId,
    /// Authority project scope.
    pub project: ProjectId,
    /// Authority repository label, never a path or URL.
    pub repository: RepositoryId,
    /// Original authenticated actor attribution.
    pub actor: GitActorId,
    /// Public SSH key fingerprint, never private material.
    pub device: DeviceKeyId,
    /// Acquisition provenance.
    pub transport: SourceTransport,
    /// Mutable branch provenance only, absent before a command is received.
    pub submitted_refs: Vec<String>,
    /// Exact requested commit, absent before command parsing.
    pub requested_commit: Option<GitObjectId>,
    /// Authority-selected Git object format.
    pub object_algorithm: GitObjectAlgorithm,
    /// Validated source observations, absent before acceptance or after rejection.
    pub source: Option<SourceState>,
    /// Explicit lifecycle state, never inferred from field presence.
    pub status: SubmissionStatus,
    /// UTC Unix seconds, excluded from all source identities.
    pub received_at: u64,
    /// UTC immutable acceptance seconds, absent before acceptance.
    pub accepted_at: Option<u64>,
}

impl SourceSubmissionState {
    /// Checks consistency without accepting bytes or granting authority. Protocol
    /// adapters must separately validate their own encodings and unknown values.
    pub fn validate(&self) -> Result<(), SourceError> {
        let invalid = SourceError::InternalIntegrityFailure;
        let accepted = matches!(
            self.status,
            SubmissionStatus::Accepted | SubmissionStatus::IncompleteExternalSource
        );

        if self.submitted_refs.len() > 1
            || self.submitted_refs.iter().any(|r| !valid_ref(r))
            || self
                .requested_commit
                .as_ref()
                .is_some_and(|oid| !self.object_algorithm.matches(oid))
            || self.source.is_some() != accepted
            || self.accepted_at.is_some() != accepted
            || self.accepted_at.is_some_and(|t| t < self.received_at)
        {
            return Err(invalid);
        }

        if let Some(source) = &self.source {
            source.validate()?;

            if self.submitted_refs.len() != 1
                || self.requested_commit.as_ref() != Some(&source.identity.commit)
                || !self.object_algorithm.matches(&source.identity.tree)
                || (self.status == SubmissionStatus::Accepted)
                    != (source.completeness == SourceStatus::Complete)
            {
                return Err(invalid);
            }

            match (source.schema_version, &source.resolution, self.transport) {
                (1, None, SourceTransport::SshPublicKey) => {}
                (2, Some(resolution), SourceTransport::AuthorityPrivateSourceResolution)
                    if resolution.parent_submission != self.submission => {}
                _ => return Err(invalid),
            }
        }

        Ok(())
    }
}

fn valid_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    value.len() <= 256
        && SourcePath::from_bytes(branch.as_bytes()).is_ok()
        && !branch.contains("..")
        && !branch.contains("@{")
        && branch
            .split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
}
