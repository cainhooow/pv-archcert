//! Narrow operational requests and safe receipt views for authenticated presentation.
//! No authority recipe, signing, runtime or transport capability crosses this port.

use super::*;
use archcert_domain::ingress::SourceSubmissionId;

/// User-selected identifiers only; authority inputs are resolved by the control plane.
#[derive(Clone)]
pub enum RequestedJobAction {
    /// Existing accepted source and its mandatory reviewed session, if applicable.
    RequestCertification {
        /// Exact accepted source ID.
        submission: SourceSubmissionId,
        /// Existing owned reviewed session; never a posted review result.
        reviewed_session: Option<JobId>,
    },
    /// Eligible owned queued work only.
    CancelEligibleJob {
        /// Exact job ID.
        job: JobId,
    },
    /// Existing infrastructure-only recovery under the original attempt budget.
    RetryEligibleJob {
        /// Exact job ID.
        job: JobId,
        /// Exact expired generation.
        attempt: AttemptId,
    },
}

impl RequestedJobAction {
    /// Closed operation selected by this request.
    pub fn operation(&self) -> ControlOperation {
        match self {
            Self::RequestCertification { .. } => ControlOperation::RequestCertification,
            Self::CancelEligibleJob { .. } => ControlOperation::CancelEligibleJob,
            Self::RetryEligibleJob { .. } => ControlOperation::RetryEligibleJob,
        }
    }
}

/// Exact user intent, without an actor, permission, recipe or executable input.
#[derive(Clone)]
pub struct RequestedJobCommand {
    /// Independently authorized project.
    pub project: ProjectId,
    /// Exact repository selected from scoped observation.
    pub repository: RepositoryId,
    /// Authority identity observed before this explicit action.
    pub authority_context: Sha256Digest,
    /// Identifier-only action.
    pub action: RequestedJobAction,
}

/// Current authenticated selection. It grants no new execution or signing authority.
pub struct CommandContextObservation {
    /// Exact project.
    pub project: ProjectId,
    /// Exact repository.
    pub repository: RepositoryId,
    /// One permitted operation.
    pub operation: ControlOperation,
    /// Exact current selection, excluding credentials.
    pub authority_context: Sha256Digest,
    /// Whether certification must select an existing reviewed session.
    pub requires_reviewed_session: bool,
}

/// Safe operational receipt. APPLIED does not mean certified or release allowed.
pub struct CommandReceiptObservation {
    /// Durable request identity.
    pub id: ControlCommandId,
    /// Exact project.
    pub project: ProjectId,
    /// Exact repository.
    pub repository: RepositoryId,
    /// Fixed operation.
    pub operation: ControlOperation,
    /// Original authority selection.
    pub authority_context: Sha256Digest,
    /// Original request content identity.
    pub request_sha256: Sha256Digest,
    /// Operational state, distinct from target truth.
    pub state: ControlCommandState,
    /// Original database creation time.
    pub created_at: i64,
    /// Safe typed effect or known refusal/uncertainty.
    pub outcome: Option<ControlCommandOutcome>,
}

/// Exact historical receipt selector; it cannot select authority for execution.
#[derive(Clone)]
pub struct CommandReceiptSelection {
    /// Durable request ID.
    pub id: ControlCommandId,
    /// Authorized project.
    pub project: ProjectId,
    /// Exact repository.
    pub repository: RepositoryId,
    /// Required operation scope.
    pub operation: ControlOperation,
    /// Exact original context, independently compared with the retained receipt.
    pub authority_context: Sha256Digest,
}

/// Bounded command mediation, separate from the SELECT-only observation port.
/// The principal is authenticated by presentation and mapped by private provisioning;
/// it is never an authority actor or permission supplied by a browser.
#[async_trait]
pub trait GlassmereCommandBroker: Send + Sync {
    /// Observe one independently selected authority context for an explicitly mapped scope.
    async fn context(
        &self,
        principal: &str,
        project: ProjectId,
        repository: &RepositoryId,
        operation: ControlOperation,
    ) -> Result<CommandContextObservation, JobStoreError>;

    /// Submit identifier-only intent through independent backend authentication and grants.
    async fn submit(
        &self,
        principal: &str,
        request: &RequestedJobCommand,
        key: &IdempotencyKey,
    ) -> Result<CommandReceiptObservation, JobStoreError>;

    /// Inspect one retained receipt; refresh must not create a new request.
    async fn receipt(
        &self,
        principal: &str,
        selection: &CommandReceiptSelection,
    ) -> Result<CommandReceiptObservation, JobStoreError>;
}
