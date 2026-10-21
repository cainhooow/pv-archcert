//! Internal Protobuf contracts and bootstrap HTTP DTO mappings. Application
//! commands/results own no transport semantics. Protobuf is not a cryptographic
//! canonical serialization format.

pub mod protobuf;

use archcert_application::{SubmitCertificationCommand, SubmitCertificationResult};
use archcert_domain::GitObjectId;
use serde::{Deserialize, Serialize};

/// Bootstrap HTTP request. This API currently creates no certification job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitCertificationRequest {
    /// Requested authority project reference.
    pub project_id: String,
    /// Exact source commit request.
    pub commit: GitObjectId,
    /// Requested profile; confers no authority.
    pub profile: String,
}

impl From<SubmitCertificationRequest> for SubmitCertificationCommand {
    fn from(request: SubmitCertificationRequest) -> Self {
        Self {
            project_id: request.project_id,
            commit: request.commit,
            profile: request.profile,
        }
    }
}

/// Honest bootstrap response; deliberately contains no job/certification ID.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CertificationResponse {
    /// Capability status, never a queued-job state.
    pub status: SubmissionStatus,
}

/// Transport representation of the unavailable submission capability.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmissionStatus {
    /// No job was created, queued or persisted.
    Unavailable,
}

impl From<SubmitCertificationResult> for CertificationResponse {
    fn from(result: SubmitCertificationResult) -> Self {
        match result {
            SubmitCertificationResult::Unavailable => Self {
                status: SubmissionStatus::Unavailable,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_maps_commands_and_unavailable_results() -> Result<(), Box<dyn std::error::Error>> {
        let request = SubmitCertificationRequest {
            project_id: "authority/project".into(),
            commit: GitObjectId::parse("a".repeat(40))?,
            profile: "node".into(),
        };
        let command: SubmitCertificationCommand = request.clone().into();

        assert_eq!(command.project_id, request.project_id);
        assert_eq!(command.commit, request.commit);
        assert_eq!(command.profile, request.profile);

        let response = CertificationResponse::from(SubmitCertificationResult::Unavailable);

        assert_eq!(
            serde_json::to_value(response)?,
            serde_json::json!({"status":"UNAVAILABLE"})
        );

        Ok(())
    }
}

/// Durable authenticated job submission/status HTTP projections.
pub mod jobs;
