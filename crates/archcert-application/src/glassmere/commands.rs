//! Durable operational requests. Request acceptance creates no certification proof.

mod presentation;
mod readiness;
mod release_build;

pub use presentation::*;
pub use readiness::{ReadinessRequestEvaluator, ReleaseReadinessObserver};
pub use release_build::{
    ControlReleaseCommandExecutor, PreparedReleaseBuild, ReleaseBuildRequestPreparer,
    ReleaseBuildSourceVerifier,
};

use crate::{
    glassmere::ReleaseReadiness,
    ironcrest::ReviewedIroncrestAdmission,
    jobs::{ArtifactReference, CertificationJob, JobStoreError, RuntimeCleanupState},
    release::{ReleaseAdmission, release_bytes, release_reference},
};
use archcert_domain::{
    ProjectId, Sha256Digest,
    ingress::GitActorId,
    jobs::{
        AttemptId, AttemptState, ControlCommandId, FailureCategory, IdempotencyKey, JobId,
        JobInputs, JobState, LeaseToken,
    },
    release::BuildInvocationIdentity,
    source::{RepositoryId, digest_bytes},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// First explicit command-persistence grammar. Historical job inputs stay unchanged.
pub const CONTROL_COMMAND_SCHEMA: u32 = 1;

/// Frozen internal metadata bound; browser requests use a smaller transport limit.
pub const MAX_CONTROL_COMMAND_BYTES: usize = 128 * 1024;

/// Authenticated control-plane scope, resolved independently of browser input.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandScope {
    /// Exact granted project.
    pub project: ProjectId,
    /// Exact granted repository.
    pub repository: RepositoryId,
    /// Authority actor selected by authenticated provisioning, never a posted role.
    pub actor: GitActorId,
}

/// Closed operational vocabulary. It contains no signing, runtime, waiver or SQL operation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResolvedControlAction {
    /// Authority-resolved original inputs; reviewed profiles additionally bind their session.
    RequestCertification {
        /// Frozen source, policy, profile, plan and original authority attempt budget.
        inputs: Box<JobInputs>,
        /// Exact pre-admission review; absence cannot downgrade a mandatory review.
        reviewed_session: Option<JobId>,
    },
    /// Frozen existing M6 input and registered source-certificate reference.
    RequestReleaseBuild {
        /// Exact authority recipe/environment/key identities and accepted source.
        admission: Box<ReleaseAdmission>,
        /// Registered original envelope; the controller must independently verify it.
        source_certificate: ArtifactReference,
    },
    /// A fresh read-only observation request, never frontend-supplied readiness facts.
    RequestReleaseReadinessEvaluation {
        /// Exact project-scoped invocation.
        invocation: BuildInvocationIdentity,
    },
    /// Cancellation eligibility is rechecked under the same lock as job claiming.
    CancelEligibleJob {
        /// Exact owned job; running work cannot be canceled by this request.
        job: JobId,
    },
    /// Existing infrastructure-only recovery; no target/policy retry or cleanup assertion.
    RetryEligibleJob {
        /// Exact owned job.
        job: JobId,
        /// Exact expired generation whose durable fencing/cleanup must be established.
        attempt: AttemptId,
    },
}

/// Closed operation vocabulary for independently provisioned command permissions.
/// These values cannot carry executable strings or authority configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlOperation {
    /// Request the existing exact-source certification workflow.
    RequestCertification,
    /// Request the existing artifact-bound build workflow.
    RequestReleaseBuild,
    /// Record a fresh bounded readiness observation.
    RequestReleaseReadinessEvaluation,
    /// Cancel eligible owned work before execution ownership.
    CancelEligibleJob,
    /// Recover one eligible expired attempt within its original budget.
    RetryEligibleJob,
}

impl ControlOperation {
    /// Stable grant/audit spelling, preserving schema-1 command bytes.
    pub fn name(self) -> &'static str {
        match self {
            Self::RequestCertification => "REQUEST_CERTIFICATION",
            Self::RequestReleaseBuild => "REQUEST_RELEASE_BUILD",
            Self::RequestReleaseReadinessEvaluation => "REQUEST_RELEASE_READINESS_EVALUATION",
            Self::CancelEligibleJob => "CANCEL_ELIGIBLE_JOB",
            Self::RetryEligibleJob => "RETRY_ELIGIBLE_JOB",
        }
    }
}

impl ResolvedControlAction {
    /// Permission class of this internally resolved action.
    pub fn operation(&self) -> ControlOperation {
        match self {
            Self::RequestCertification { .. } => ControlOperation::RequestCertification,
            Self::RequestReleaseBuild { .. } => ControlOperation::RequestReleaseBuild,
            Self::RequestReleaseReadinessEvaluation { .. } => {
                ControlOperation::RequestReleaseReadinessEvaluation
            }
            Self::CancelEligibleJob { .. } => ControlOperation::CancelEligibleJob,
            Self::RetryEligibleJob { .. } => ControlOperation::RetryEligibleJob,
        }
    }

    /// Fixed audit and permission name; not an executable command name.
    pub fn name(&self) -> &'static str {
        self.operation().name()
    }
}

/// Internal resolved request. Content identity does not establish authorization:
/// trusted composition must select authority context and authenticate scope first.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedControlCommand {
    /// Explicit persistence interpretation version.
    pub schema: u32,
    /// Independently authenticated scope.
    pub scope: CommandScope,
    /// Exact provisioned authority selection, excluding credentials.
    pub authority_context: Sha256Digest,
    /// Fixed operation with original frozen inputs and references.
    pub action: ResolvedControlAction,
}

impl ResolvedControlCommand {
    /// Validate internal bindings before persistence. This grants no authority capability.
    pub fn validate(&self) -> Result<(), JobStoreError> {
        if self.schema != CONTROL_COMMAND_SCHEMA {
            return Err(JobStoreError::Invalid);
        }

        match &self.action {
            ResolvedControlAction::RequestCertification { inputs, .. } => {
                inputs.validate()?;

                if inputs.project != self.scope.project
                    || inputs.repository != self.scope.repository
                    || inputs.actor != self.scope.actor
                {
                    return Err(JobStoreError::Invalid);
                }
            }
            ResolvedControlAction::RequestReleaseBuild {
                admission,
                source_certificate,
            } => {
                let source = &admission.input.certified_source;
                let bytes = release_bytes(&admission.input)?;

                if source.project != self.scope.project
                    || source.repository != self.scope.repository
                    || admission.actor != self.scope.actor
                    || admission.input_reference != release_reference(&bytes)
                    || source_certificate.schema != 1
                    || source_certificate.size == 0
                    || source_certificate.size > 4 * 1024 * 1024
                    || source_certificate.producer.is_empty()
                    || source_certificate.producer.len() > 128
                {
                    return Err(JobStoreError::Invalid);
                }
            }
            _ => {}
        }

        if self.bytes()?.len() > MAX_CONTROL_COMMAND_BYTES {
            return Err(JobStoreError::Invalid);
        }

        Ok(())
    }

    /// Canonical versioned request bytes; private authority recipes must not enter public DTOs.
    pub fn bytes(&self) -> Result<Vec<u8>, JobStoreError> {
        release_bytes(self)
    }

    /// Content identity only. The repository separately checks grants and object scope.
    pub fn digest(&self) -> Result<Sha256Digest, JobStoreError> {
        Ok(digest_bytes(&self.bytes()?))
    }

    /// Deduplicate workflow intent independently of browser-generated retry keys.
    /// Separate explicit readiness requests may record fresh historical observations;
    /// repeating their same key still resolves to exactly the same request.
    pub fn intent(&self, key: &IdempotencyKey) -> Result<Sha256Digest, JobStoreError> {
        let mut bytes = self.bytes()?;

        if matches!(
            self.action,
            ResolvedControlAction::RequestReleaseReadinessEvaluation { .. }
        ) {
            bytes.extend_from_slice(b"\nREADINESS_REQUEST_KEY_V1\n");
            bytes.extend_from_slice(key.as_str().as_bytes());
        }

        Ok(digest_bytes(&bytes))
    }

    /// Validate public effect identity before a trusted dispatcher publishes its receipt.
    /// This checks bindings, not whether the underlying operation was authorized or executed.
    pub fn validate_outcome(&self, outcome: &ControlCommandOutcome) -> Result<(), JobStoreError> {
        if release_bytes(outcome)?.len() > MAX_CONTROL_COMMAND_BYTES {
            return Err(JobStoreError::Invalid);
        }

        let ControlCommandOutcome::Applied { effect } = outcome else {
            return Ok(());
        };

        let valid = match (&self.action, effect.as_ref()) {
            (
                ResolvedControlAction::RequestCertification {
                    reviewed_session, ..
                },
                CommandEffect::CertificationRequested { job, session },
            ) => {
                session == reviewed_session
                    && (job.is_some() || session.is_some())
                    && session.is_none_or(|id| job.is_none_or(|job| job == id))
            }
            (
                ResolvedControlAction::RequestReleaseBuild { admission, .. },
                CommandEffect::ReleaseBuildRequested { invocation },
            ) => *invocation == admission.input.identity()?,
            (
                ResolvedControlAction::RequestReleaseReadinessEvaluation { invocation },
                CommandEffect::ReadinessEvaluated { observation },
            ) => {
                observation.schema == super::PROJECTION_SCHEMA
                    && observation.subject.project == self.scope.project
                    && observation.subject.repository == self.scope.repository.as_str()
                    && observation.subject.invocation == invocation.0.as_str()
                    && (observation.state == super::ReleaseState::ReleaseAllowed)
                        == observation.blockers.is_empty()
            }
            (
                ResolvedControlAction::CancelEligibleJob { job },
                CommandEffect::JobCanceled { job: affected },
            ) => job == affected,
            (
                ResolvedControlAction::RetryEligibleJob { job, attempt },
                CommandEffect::JobRecoveryRequested {
                    job: affected,
                    attempt: generation,
                },
            ) => job == affected && attempt == generation,
            _ => false,
        };

        if valid {
            Ok(())
        } else {
            Err(JobStoreError::Invalid)
        }
    }

    /// Bind an existing sealed application admission to the original reviewed request.
    /// Only its validated additive plan/recipe may differ from the frozen base inputs.
    pub fn validate_reviewed_admission(
        &self,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<(), JobStoreError> {
        self.validate()?;
        let ResolvedControlAction::RequestCertification {
            inputs,
            reviewed_session: Some(session),
        } = &self.action
        else {
            return Err(JobStoreError::Invalid);
        };

        let pin = admission.pin();
        let admitted = admission.inputs();
        if admission.id() != *session
            || pin.project != inputs.project
            || pin.repository != inputs.repository
            || pin.actor != inputs.actor
            || pin.submission != inputs.submission
            || pin.source != inputs.source
            || pin.policy != inputs.policy
            || pin.base_plan_sha256 != inputs.plan_sha256
        {
            return Err(JobStoreError::Invalid);
        }

        if admitted.project != inputs.project
            || admitted.repository != inputs.repository
            || admitted.actor != inputs.actor
            || admitted.submission != inputs.submission
            || admitted.source != inputs.source
            || admitted.policy != inputs.policy
        {
            return Err(JobStoreError::Invalid);
        }

        if admitted.profile != inputs.profile
            || admitted.image != inputs.image
            || admitted.maximum_attempts != inputs.maximum_attempts
        {
            return Err(JobStoreError::Invalid);
        }

        Ok(())
    }
}

/// Operational request state. APPLIED never means a certificate or permit was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlCommandState {
    /// Frozen and durably accepted, with no implied execution or signature.
    Requested,
    /// A fenced trusted dispatcher is mediating the request.
    Processing,
    /// Its bounded application operation or historical observation was recorded.
    Applied,
    /// An explicit application precondition or supported-scope check rejected it.
    Rejected,
    /// The outcome could not be established; never a positive certification result.
    Inconclusive,
}

/// Fixed public refusal categories without paths, credentials or infrastructure diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandFailure {
    /// Original authority interpretation cannot be reconstructed under the exact pins.
    UnsupportedAuthorityContext,
    /// Exact scope, source or immutable identity no longer matches.
    IdentityMismatch,
    /// Existing state, lease, cleanup or attempt-budget preconditions deny continuation.
    DomainPrecondition,
    /// Mandatory review remains blocked or unavailable; no waiver is introduced.
    ReviewRequired,
    /// A mandatory dependency or observation is unavailable.
    InfrastructureUnavailable,
    /// No accepted durable result establishes what happened externally.
    UncertainOutcome,
}

/// Public effect reference. It never carries frozen recipes, fencing capabilities or keys.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CommandEffect {
    /// Exact pre-admission or admitted certification workflow, not an issued certificate.
    CertificationRequested {
        /// Present only after an actual job was admitted.
        job: Option<JobId>,
        /// Exact mandatory review session when applicable.
        session: Option<JobId>,
    },
    /// Exact deterministic M6 invocation requested through trusted composition.
    ReleaseBuildRequested {
        /// Immutable invocation identity, not a permit identity.
        invocation: BuildInvocationIdentity,
    },
    /// Historical observation; current use still requires fresh dependency/revision checks.
    ReadinessEvaluated {
        /// Exact existing M6 verification result, never supplied by a browser.
        observation: Box<ReleaseReadiness>,
    },
    /// Cancellation of eligible queued work, preserving every earlier attempt.
    JobCanceled {
        /// Exact affected job.
        job: JobId,
    },
    /// Existing exact-attempt recovery was mediated; current job state is read separately.
    JobRecoveryRequested {
        /// Exact affected job.
        job: JobId,
        /// Original generation, never a new execution identity chosen by a client.
        attempt: AttemptId,
    },
}

/// Durable terminal outcome; source truth and operational authorization remain separate.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ControlCommandOutcome {
    /// Bounded operation recorded; effect references do not establish certification.
    Applied {
        /// Exact resulting workflow or historical observation.
        effect: Box<CommandEffect>,
    },
    /// Known rejection; no frontend heuristic may convert it into acceptance.
    Rejected {
        /// Fixed rejection category.
        reason: CommandFailure,
    },
    /// Unknown or infrastructure-impaired result, never success.
    Inconclusive {
        /// Fixed uncertainty category.
        reason: CommandFailure,
    },
}

impl ControlCommandOutcome {
    /// Terminal journal category; it never describes certification truth.
    pub fn state(&self) -> ControlCommandState {
        match self {
            Self::Applied { .. } => ControlCommandState::Applied,
            Self::Rejected { .. } => ControlCommandState::Rejected,
            Self::Inconclusive { .. } => ControlCommandState::Inconclusive,
        }
    }
}

/// Internal durable read. It deliberately has no blanket wire serializer.
#[derive(Clone)]
pub struct ControlCommandRecord {
    /// Immutable request identity.
    pub id: ControlCommandId,
    /// Original exact authority-selected request, never a newer recovery default.
    pub command: ResolvedControlCommand,
    /// Content identity of the original request.
    pub request_sha256: Sha256Digest,
    /// Original semantic workflow intent within authenticated scope.
    pub intent_sha256: Sha256Digest,
    /// Operational request state.
    pub state: ControlCommandState,
    /// Database UTC creation seconds.
    pub created_at: i64,
    /// Monotonic dispatch generation count, separate from target attempt budgets.
    pub dispatches: u32,
    /// Frozen result only after its durable publication.
    pub outcome: Option<ControlCommandOutcome>,
}

/// Trusted dispatcher fencing capability. Never serialize it or send it into execution.
pub struct ControlCommandLease {
    /// Exact immutable request.
    pub command: ControlCommandId,
    /// Separately provisioned trusted dispatcher identity.
    pub dispatcher: String,
    /// Opaque generation; previous dispatchers cannot publish a later result.
    pub token: LeaseToken,
}

/// Internal dispatch assignment with original pinned inputs.
pub struct ControlCommandAssignment {
    /// Exact retained request.
    pub record: ControlCommandRecord,
    /// Current coordination ownership, separate from any target-execution lease.
    pub lease: ControlCommandLease,
}

/// Narrow durable coordination port. Domain operations retain their existing authorization,
/// immutable-input, execution, cleanup and signing preconditions.
#[async_trait]
pub trait ControlCommandRepository: Send + Sync {
    /// Recheck grant/object scope and atomically bind retry key, intent, request and audit.
    async fn accept(
        &self,
        command: &ResolvedControlCommand,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError>;

    /// Scope before lookup; a UUID or digest alone grants no access.
    async fn get(
        &self,
        scope: &CommandScope,
        id: ControlCommandId,
    ) -> Result<ControlCommandRecord, JobStoreError>;

    /// Claim one request with bounded database time and a fresh fencing generation.
    async fn claim(
        &self,
        dispatcher: &str,
        lease_seconds: u32,
    ) -> Result<Option<ControlCommandAssignment>, JobStoreError>;

    /// Renew only live exact ownership; no target or provider claim is revived.
    async fn renew(
        &self,
        lease: &ControlCommandLease,
        lease_seconds: u32,
    ) -> Result<(), JobStoreError>;

    /// Publish one exact bounded outcome with audit under current dispatcher fencing.
    async fn finish(
        &self,
        lease: &ControlCommandLease,
        outcome: &ControlCommandOutcome,
    ) -> Result<(), JobStoreError>;
}

/// Decide queued cancellation from retained facts, never a browser eligibility flag.
/// Previously started attempts require the existing durable fence/cleanup result.
pub fn queued_cancellation_state(job: &CertificationJob) -> Result<JobState, JobStoreError> {
    if job.state != JobState::Queued
        || job.failure.is_some()
        || job.evaluation_at.is_some()
        || job.evaluation.is_some()
        || job.issuance.is_some()
        || job.certificate.is_some()
        || job.attempts.iter().any(|attempt| {
            attempt.state != AttemptState::Lost
                || attempt.failure != Some(FailureCategory::WorkerLoss)
                || attempt.evidence.is_some()
                || attempt.runtime.as_ref().is_none_or(|runtime| {
                    !runtime.fenced || runtime.cleanup != RuntimeCleanupState::Succeeded
                })
        })
    {
        return Err(JobStoreError::Precondition);
    }

    job.state.cancel_queued().map_err(Into::into)
}

/// User-requested retry must have remaining original authority capacity.
/// The existing controller recovery may separately finalize exhausted work as inconclusive.
pub fn require_retry_capacity(job: &CertificationJob) -> Result<(), JobStoreError> {
    if job.state != JobState::Running
        || job.attempts.len() >= usize::from(job.inputs.maximum_attempts)
    {
        return Err(JobStoreError::Precondition);
    }

    Ok(())
}

/// Atomic local mediation only. No runtime, review-provider or signing capability.
#[async_trait]
pub trait ControlJobCommandExecutor: Send + Sync {
    /// Recheck exact coordination ownership, authority selection and grants, then
    /// commit the domain transition, domain audit and command outcome together.
    async fn apply_job_command(
        &self,
        lease: &ControlCommandLease,
        selected_context: &Sha256Digest,
    ) -> Result<ControlCommandOutcome, JobStoreError>;
}

/// Reviewed mediation requires the existing sealed application admission, never a posted gate.
#[async_trait]
pub trait ReviewedControlCommandExecutor: Send + Sync {
    /// Atomically commit the original reviewed admission/linkage, audit and command receipt.
    async fn apply_reviewed_certification(
        &self,
        lease: &ControlCommandLease,
        selected_context: &Sha256Digest,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<ControlCommandOutcome, JobStoreError>;
}
