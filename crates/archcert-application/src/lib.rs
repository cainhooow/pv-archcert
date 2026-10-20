//! Application use cases and transport-independent ports for ArchCert.

use archcert_domain::GitObjectId;
use thiserror::Error;

pub mod configuration;
pub mod execution;
pub mod ingress;
pub mod materialization;
pub mod source;
pub mod validation;

/// Transport-independent certification submission request; no HTTP semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitCertificationCommand {
    /// Authority project reference, still requiring future authentication/resolution.
    pub project_id: String,
    /// Exact source commit request.
    pub commit: GitObjectId,
    /// Requested authority profile.
    pub profile: String,
}

/// Submission capability outcome. No job exists in the bootstrap implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitCertificationResult {
    /// Submission and persistence have not been implemented; nothing was queued.
    Unavailable,
}

/// Application-layer errors.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// The request violates an application precondition.
    #[error("invalid certification request: {0}")]
    InvalidRequest(String),
}

/// Submission port, independent of the transport and future job implementation.
pub trait SubmitCertification: Send + Sync {
    /// Reports capability availability. Implementations must not imply nonexistent work.
    fn submit(
        &self,
        command: SubmitCertificationCommand,
    ) -> Result<SubmitCertificationResult, ApplicationError>;
}

/// Disabled bootstrap submission; no job identity, persistence or scheduler.
pub struct BootstrapSubmitCertification;
impl SubmitCertification for BootstrapSubmitCertification {
    fn submit(
        &self,
        command: SubmitCertificationCommand,
    ) -> Result<SubmitCertificationResult, ApplicationError> {
        if command.project_id.trim().is_empty() || command.profile.trim().is_empty() {
            return Err(ApplicationError::InvalidRequest(
                "project_id and profile cannot be empty".into(),
            ));
        }
        Ok(SubmitCertificationResult::Unavailable)
    }
}

/// Credential-free contracts for controlled external source acquisition.
pub mod external_source;

/// Future control-plane job request for already accepted immutable source.
/// This is distinct from SourceSubmission and creates no job by construction.
#[derive(Debug, Clone)]
pub struct CertificationJobRequest {
    /// Exact accepted scoped source; no repository URL or mutable ref.
    pub source: archcert_domain::materialization::SnapshotReference,
    /// Separately selected authority policy identity.
    pub policy_sha256: archcert_domain::Sha256Digest,
    /// Authority execution profile selection, independent of ingress.
    pub execution_profile: String,
}
