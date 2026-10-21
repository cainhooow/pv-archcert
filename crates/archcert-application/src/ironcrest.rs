//! Durable pre-admission review metadata. A session grants no execution or signing.

use crate::{
    jobs::{ArtifactReference, JobStoreError},
    semantic::ReviewBinding,
};
use archcert_domain::{
    ProjectId, Sha256Digest, SourceIdentity,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{JobId, PolicyPin},
    source::RepositoryId,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

mod admission;

pub use admission::*;

mod issuance;

pub use issuance::*;

mod profile;

mod workflow;

pub use profile::*;

pub use workflow::*;

/// An authority-selected accepted baseline, never a target-selected revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselinePin {
    /// Accepted submission in the same project/repository.
    pub submission: SourceSubmissionId,
    /// Full immutable identity.
    pub source: SourceIdentity,
}

/// Frozen inputs before knowledge packaging and provider invocation. Decoding
/// this data is not acceptance: the repository must authorize/recheck accepted source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IroncrestSessionPin {
    /// Authority project.
    pub project: ProjectId,
    /// Authority repository.
    pub repository: RepositoryId,
    /// Separately authenticated authorized actor.
    pub actor: GitActorId,
    /// Exact accepted target submission.
    pub submission: SourceSubmissionId,
    /// Full immutable source identity.
    pub source: SourceIdentity,
    /// Authority-selected accepted baseline, if present.
    pub baseline: Option<BaselinePin>,
    /// Immutable deterministic policy; historical bundles are not reinterpreted.
    pub policy: PolicyPin,
    /// Original immutable mandatory plan, before additive challenges.
    pub base_plan_sha256: Sha256Digest,
    /// Authority-owned versioned Ironcrest requirements.
    pub authority_profile_sha256: Sha256Digest,
    /// Authority-selected extractor registry semantics.
    pub extractor_registry_sha256: Sha256Digest,
    /// Authority-selected bounded challenge registry.
    pub challenge_registry_sha256: Sha256Digest,
    /// Canonical sorted authority bundles.
    pub authority_bundles: Vec<Sha256Digest>,
}

impl IroncrestSessionPin {
    /// Bound trusted inputs; source/grant acceptance is separately checked in storage.
    pub fn validate(&self) -> Result<(), JobStoreError> {
        if self.policy.id.is_empty()
            || self.policy.id.len() > 128
            || self.policy.version.is_empty()
            || self.policy.version.len() > 128
            || self.authority_bundles.len() > 16
            || self
                .authority_bundles
                .windows(2)
                .any(|w| w[0].as_str() >= w[1].as_str())
        {
            return Err(JobStoreError::Invalid);
        }

        Ok(())
    }

    /// A request must reproduce all pinned source/authority identities and the
    /// reserved job identity. Knowledge/impact digests are checked against roles.
    pub fn matches_review(&self, id: JobId, binding: &ReviewBinding) -> bool {
        binding.project == self.project
            && binding.job == id
            && binding.source == self.source
            && binding.baseline == self.baseline.as_ref().map(|b| b.source.clone())
            && binding.policy == self.policy
            && binding.authority_profile_sha256 == self.authority_profile_sha256
            && binding.authority_bundles == self.authority_bundles
    }
}

/// Immutable stage identities. These cannot be selected through target configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IroncrestEvidenceRole {
    /// Actual authority profile bytes, separately selected before review.
    AuthorityProfile,
    /// Canonical source knowledge.
    Knowledge,
    /// Canonical baseline impact.
    Impact,
    /// Exact provider input.
    Request,
    /// Exact accepted semantic response or failure.
    Review,
    /// Deterministic gate evidence.
    Gate,
    /// Frozen additive authority challenges.
    ChallengePlan,
    /// Actual accepted deterministic challenge execution evidence.
    ChallengeResult,
}

impl IroncrestEvidenceRole {
    /// Fixed database spelling, never arbitrary SQL text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityProfile => "AUTHORITY_PROFILE",
            Self::Knowledge => "KNOWLEDGE",
            Self::Impact => "IMPACT",
            Self::Request => "REQUEST",
            Self::Review => "REVIEW",
            Self::Gate => "GATE",
            Self::ChallengePlan => "CHALLENGE_PLAN",
            Self::ChallengeResult => "CHALLENGE_RESULT",
        }
    }
}

/// Create-only staged/available role reference. Bytes live in the existing scoped store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IroncrestEvidenceReference {
    /// Fixed role.
    pub role: IroncrestEvidenceRole,
    /// Exact canonical object metadata.
    pub artifact: ArtifactReference,
    /// Only verified readback can make this true.
    pub available: bool,
}

/// Non-executing durable read model. It carries no provider invocation capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IroncrestSession {
    /// Reserved future certification job UUID.
    pub id: JobId,
    /// Frozen authority inputs.
    pub pin: IroncrestSessionPin,
    /// Database UTC Unix seconds.
    pub created_at: u64,
    /// A claim is never silently expired/reassigned.
    pub review_claimed: bool,
    /// Frozen invocation audit time when claimed.
    pub review_timestamp: Option<u64>,
    /// Immutable role metadata, including interrupted staging.
    pub evidence: Vec<IroncrestEvidenceReference>,
}

/// Explicit operational recovery state; none of these values authorizes inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IroncrestReviewRecovery {
    /// Exact prepared inputs still need their first durable invocation claim.
    AwaitingFirstInvocation,
    /// A process may have called the provider; a new session/operator policy is
    /// required. Restart never grants another invocation.
    OperatorRecoveryRequired,
    /// Retained metadata permits only recovery of the exact accepted response bytes.
    RestoreAcceptedResponse,
    /// An available accepted result can be reused without provider invocation.
    AcceptedResponseAvailable,
}

impl IroncrestSession {
    /// Distinguishes uncertain in-flight outcome from safely reusable acceptance.
    pub fn review_recovery(&self) -> IroncrestReviewRecovery {
        if let Some(response) = self
            .evidence
            .iter()
            .find(|e| e.role == IroncrestEvidenceRole::Review)
        {
            return if response.available {
                IroncrestReviewRecovery::AcceptedResponseAvailable
            } else {
                IroncrestReviewRecovery::RestoreAcceptedResponse
            };
        }

        if self.review_claimed {
            IroncrestReviewRecovery::OperatorRecoveryRequired
        } else {
            IroncrestReviewRecovery::AwaitingFirstInvocation
        }
    }
}

/// Private authority capability for the first provider invocation. No Debug,
/// Serialize or target transport is provided. Expiry never reissues this token.
#[derive(Clone)]
pub struct ReviewInvocation {
    /// Random fencing identity selected by the metadata authority.
    pub token: JobId,
    /// Stable database audit time, preserved across response publication recovery.
    pub timestamp: u64,
}

/// Durable project-scoped journal port, independent of PostgreSQL and object adapters.
#[async_trait]
pub trait IroncrestRepository: Send + Sync {
    /// Transactionally admit the reserved job with the exact validated immutable
    /// source, authority profile, evidence chain and final execution plan. Exact
    /// retries return the same job; mismatches and partial review reject.
    async fn admit_reviewed(
        &self,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<crate::jobs::CertificationJob, JobStoreError>;

    /// Read an already admitted job only if its create-only reviewed linkage
    /// exactly matches the revalidated application capability. Never creates work.
    async fn admitted_review(
        &self,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<crate::jobs::CertificationJob, JobStoreError>;

    /// Authorize and create a reserved non-executing session, or return its exact replay.
    async fn open_session(
        &self,
        id: JobId,
        pin: &IroncrestSessionPin,
    ) -> Result<IroncrestSession, JobStoreError>;

    /// Scope must be checked before returning private metadata.
    async fn review_session(
        &self,
        project: ProjectId,
        id: JobId,
    ) -> Result<IroncrestSession, JobStoreError>;

    /// Register one exact role before uploading bytes. Review publication requires
    /// the original claim token; a second provider response cannot replace it.
    async fn stage_review_evidence(
        &self,
        project: ProjectId,
        id: JobId,
        role: IroncrestEvidenceRole,
        reference: &ArtifactReference,
        invocation: Option<&ReviewInvocation>,
    ) -> Result<(), JobStoreError>;

    /// Mark exact staged metadata available only after caller verified scoped readback.
    async fn review_evidence_available(
        &self,
        project: ProjectId,
        id: JobId,
        role: IroncrestEvidenceRole,
        reference: &ArtifactReference,
    ) -> Result<(), JobStoreError>;

    /// Atomically grant at most one invocation after exact knowledge/impact/request
    /// availability. None means already claimed: read accepted evidence or remain
    /// inconclusive; it never authorizes a retry.
    async fn claim_review(
        &self,
        project: ProjectId,
        id: JobId,
        binding: &ReviewBinding,
        request: &ArtifactReference,
    ) -> Result<Option<ReviewInvocation>, JobStoreError>;
}
