//! Application use cases and transport-independent ports for ArchCert.

use archcert_domain::GitObjectId;
use thiserror::Error;

pub mod configuration;
pub mod execution;
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
