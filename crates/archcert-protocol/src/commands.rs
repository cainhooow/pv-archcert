//! Bounded command HTTP contracts. Private resolved authority inputs are not wire types.

use archcert_application::glassmere::commands::{
    ControlCommandOutcome, ControlCommandRecord, ControlCommandState, ControlOperation,
};
use archcert_domain::{
    ProjectId, Sha256Digest,
    ingress::SourceSubmissionId,
    jobs::{AttemptId, ControlCommandId, JobId},
    source::RepositoryId,
};
use serde::{Deserialize, Serialize};

/// Identifier-only request. Actor, policy, recipes, limits and capabilities are absent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateControlCommandRequest {
    /// Explicit transport version: one for job actions, two for readiness questions.
    pub schema: u32,
    /// Exact authenticated project scope.
    pub project: ProjectId,
    /// Exact authenticated repository scope.
    pub repository: RepositoryId,
    /// Previously observed authority selection; never selects new authority inputs.
    pub authority_context: Sha256Digest,
    /// Closed supported request with identifiers only.
    pub action: ControlActionRequest,
}

/// Fixed operations whose application mediation is available.
/// Other operations remain unavailable until their separate mediation is connected.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ControlActionRequest {
    /// Ask a fresh historical question about one exact owned admitted release.
    RequestReleaseReadinessEvaluation {
        /// Immutable invocation, never posted verification facts or build inputs.
        invocation: archcert_domain::release::BuildInvocationIdentity,
    },
    /// Request exact accepted source with an existing reviewed session when mandatory.
    RequestCertification {
        /// Immutable accepted source ID.
        source_submission: SourceSubmissionId,
        /// Existing owned session; omission cannot downgrade mandatory review.
        reviewed_session: Option<JobId>,
    },
    /// Request cancellation before execution ownership; server rechecks eligibility.
    CancelEligibleJob {
        /// Exact owned job.
        job: JobId,
    },
    /// Request bounded infrastructure recovery; no cleanup assertion is accepted.
    RetryEligibleJob {
        /// Exact owned job.
        job: JobId,
        /// Exact expired generation.
        attempt: AttemptId,
    },
}

impl ControlActionRequest {
    /// Explicit request grammar. Existing job operations retain schema 1;
    /// readiness requires schema 2 and its versioned historical receipt contract.
    pub fn schema(&self) -> u32 {
        match self {
            Self::RequestReleaseReadinessEvaluation { .. } => 2,
            Self::RequestCertification { .. }
            | Self::CancelEligibleJob { .. }
            | Self::RetryEligibleJob { .. } => 1,
        }
    }

    /// Application permission class; the transport DTO never enters application ports.
    pub fn operation(&self) -> ControlOperation {
        match self {
            Self::RequestReleaseReadinessEvaluation { .. } => {
                ControlOperation::RequestReleaseReadinessEvaluation
            }
            Self::RequestCertification { .. } => ControlOperation::RequestCertification,
            Self::CancelEligibleJob { .. } => ControlOperation::CancelEligibleJob,
            Self::RetryEligibleJob { .. } => ControlOperation::RetryEligibleJob,
        }
    }
}

/// Scope for non-mutating authority-context discovery and exact receipt lookup.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCommandQuery {
    /// Exact project, never inferred from an object ID.
    pub project: ProjectId,
    /// Exact repository.
    pub repository: RepositoryId,
    /// Independently provisioned operation permission.
    pub operation: ControlOperation,
    /// Required on receipt lookup; omitted only for context discovery.
    pub authority_context: Option<Sha256Digest>,
}

/// Current selection identity. It is not a workflow acceptance or signing permission.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCommandContextResponse {
    /// Explicit transport version.
    pub schema: u32,
    /// Authenticated scope.
    pub project: ProjectId,
    /// Authenticated repository.
    pub repository: RepositoryId,
    /// One authenticated operation.
    pub operation: ControlOperation,
    /// Current exact authority selection, excluding credentials and paths.
    pub authority_context: Sha256Digest,
    /// Whether certification must name an existing owned reviewed session.
    pub requires_reviewed_session: bool,
}

/// Explicit public projection. APPLIED never means certified or release allowed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCommandResponse {
    /// Explicit public grammar: job receipts 1, historical readiness 2, build admission 3.
    pub schema: u32,
    /// Durable request identity, never a certificate ID.
    pub command_id: ControlCommandId,
    /// Exact authenticated project.
    pub project: ProjectId,
    /// Exact authenticated repository.
    pub repository: RepositoryId,
    /// Fixed operation.
    pub operation: ControlOperation,
    /// Original frozen authority selection.
    pub authority_context: Sha256Digest,
    /// Original request content identity, without its private bytes.
    pub request_sha256: Sha256Digest,
    /// Operational request state, separate from target truth.
    pub state: ControlCommandState,
    /// Database creation time in UTC seconds.
    pub created_at: i64,
    /// Safe typed result only after durable publication.
    pub outcome: Option<ControlCommandOutcome>,
    /// Schema 2 readiness receipts are always historical, including retained ALLOWED.
    /// Absent from the unchanged schema 1 job receipt grammar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_freshness: Option<ReadinessReceiptFreshness>,
}

/// An observation receipt never grants current deployment authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessReceiptFreshness {
    /// Recheck the live readiness query before making a current decision.
    HistoricalObservation,
}

impl From<ControlCommandRecord> for ControlCommandResponse {
    fn from(record: ControlCommandRecord) -> Self {
        let operation = record.command.action.operation();
        let readiness = operation == ControlOperation::RequestReleaseReadinessEvaluation;
        let schema = match operation {
            ControlOperation::RequestReleaseBuild => 3,
            ControlOperation::RequestReleaseReadinessEvaluation => 2,
            _ => 1,
        };

        Self {
            schema,
            command_id: record.id,
            project: record.command.scope.project,
            repository: record.command.scope.repository,
            operation,
            authority_context: record.command.authority_context,
            request_sha256: record.request_sha256,
            state: record.state,
            created_at: record.created_at,
            outcome: record.outcome,
            observation_freshness: readiness
                .then_some(ReadinessReceiptFreshness::HistoricalObservation),
        }
    }
}
