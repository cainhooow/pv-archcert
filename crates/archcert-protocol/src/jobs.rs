//! Durable HTTP DTOs map transport-independent application read models.
use archcert_application::jobs::{CertificationJob, RuntimeCleanupState};
use archcert_domain::{
    ProjectId, SourceIdentity,
    ingress::SourceSubmissionId,
    jobs::{AttemptId, AttemptState, JobId, JobState, PolicyPin},
    source::RepositoryId,
};
use serde::{Deserialize, Serialize};
/// Exact accepted source request. Authority policy/runtime/actor come from authenticated grants.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCertificationRequest {
    /// Requested authorized project.
    pub project: ProjectId,
    /// Requested authorized repository.
    pub repository: RepositoryId,
    /// Existing immutable accepted source submission.
    pub source_submission: SourceSubmissionId,
}
/// Public durable status without credentials, internal paths or command recipes.
#[derive(Serialize)]
pub struct CertificationJobResponse {
    /// Durable job ID, never a certificate ID.
    pub job_id: JobId,
    /// Durable lifecycle state.
    pub state: JobState,
    /// Exact immutable source.
    pub source: SourceIdentity,
    /// Pinned authority policy.
    pub policy: PolicyPin,
    /// Durable attempt history.
    pub attempts: Vec<AttemptResponse>,
    /// Canonical payload digest only after verified persisted issuance.
    pub certificate_sha256: Option<archcert_domain::Sha256Digest>,
}
/// Safe attempt status projection.
#[derive(Serialize)]
pub struct AttemptResponse {
    /// Exact attempt.
    pub attempt_id: AttemptId,
    /// One-based retry ordinal.
    pub ordinal: u16,
    /// Explicit durable attempt state.
    pub state: AttemptState,
    /// Structured failure without private diagnostics.
    pub failure: Option<archcert_domain::jobs::FailureCategory>,
    /// Bounded operational cleanup, without runtime endpoints or private paths.
    pub runtime_cleanup: Option<RuntimeCleanupState>,
    /// Irreversible execution revocation, separate from target verdict semantics.
    pub execution_fenced: bool,
}
impl From<CertificationJob> for CertificationJobResponse {
    fn from(j: CertificationJob) -> Self {
        Self {
            job_id: j.id,
            state: j.state,
            source: j.inputs.source,
            policy: j.inputs.policy,
            attempts: j
                .attempts
                .into_iter()
                .map(|a| AttemptResponse {
                    attempt_id: a.id,
                    ordinal: a.ordinal,
                    state: a.state,
                    failure: a.failure,
                    runtime_cleanup: a.runtime.as_ref().map(|r| r.cleanup),
                    execution_fenced: a.runtime.as_ref().is_some_and(|r| r.fenced),
                })
                .collect(),
            certificate_sha256: j.certificate.map(|c| c.issuance.certificate_sha256),
        }
    }
}
