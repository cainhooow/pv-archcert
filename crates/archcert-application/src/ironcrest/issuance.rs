//! Deterministic challenge evidence and a narrow Ironcrest issuance prerequisite.
use super::*;
use crate::{
    challenges::IDEMPOTENCY_STEP,
    jobs::CertificationJob,
    knowledge::{CanonicalArtifact, canonical_bytes},
    worker::WorkerResult,
};
use archcert_domain::{
    execution::{ExecutionOutcome, TerminationReason},
    jobs::JobState,
    source::digest_bytes,
};

/// Public evidence read model, not an admission, evaluation or issuance capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IroncrestEvidenceBinding {
    /// Exact reserved session and certification job.
    pub session: JobId,
    /// All reviewed immutable authority/source/baseline pins.
    pub pin: IroncrestSessionPin,
    /// One final immutable admitted execution plan.
    pub plan_sha256: Sha256Digest,
    /// Fixed role order, complete canonical artifact references including results.
    pub roles: Vec<(IroncrestEvidenceRole, ArtifactReference)>,
}
/// Private construction requires accepted challenge execution. This adds no
/// deterministic policy property and cannot replace independent policy evaluation.
#[derive(Debug)]
pub struct IroncrestIssuanceEvidence {
    binding: IroncrestEvidenceBinding,
}
impl IroncrestIssuanceEvidence {
    /// Immutable read model for explicit schema-2 evidence binding.
    pub fn binding(&self) -> &IroncrestEvidenceBinding {
        &self.binding
    }
}
/// Retained challenge outcome, including deterministic failures and uncertainty.
#[derive(Debug)]
pub struct IroncrestChallengeEvidence {
    binding: IroncrestEvidenceBinding,
    satisfied: bool,
}
impl IroncrestChallengeEvidence {
    /// Whether every required challenge completed successfully with confirmed cleanup.
    pub fn satisfied(&self) -> bool {
        self.satisfied
    }
    /// Only satisfied requirements can supply the additional issuance prerequisite.
    pub fn for_issuance(self) -> Result<IroncrestIssuanceEvidence, JobStoreError> {
        if !self.satisfied {
            return Err(JobStoreError::Precondition);
        }
        Ok(IroncrestIssuanceEvidence {
            binding: self.binding,
        })
    }
}
impl IroncrestWorkflow<'_> {
    /// Persist exact accepted challenge records before deterministic evaluation.
    /// The controller must decode the same independently rehashed immutable worker
    /// artifact referenced by the accepted attempt. This API performs no execution.
    pub async fn record_challenges(
        &self,
        admission: &ReviewedIroncrestAdmission,
        job: &CertificationJob,
        result: &WorkerResult,
    ) -> Result<IroncrestChallengeEvidence, JobStoreError> {
        if job.id != admission.id()
            || job.inputs != *admission.inputs()
            || !matches!(job.state, JobState::Evaluating | JobState::Signing)
        {
            return Err(JobStoreError::Precondition);
        }
        let accepted = self.repository.admitted_review(admission).await?;
        if accepted.inputs != job.inputs
            || accepted.attempts.last().map(|a| a.id) != job.attempts.last().map(|a| a.id)
        {
            return Err(JobStoreError::Precondition);
        }
        let attempt = job.attempts.last().ok_or(JobStoreError::Precondition)?;
        if attempt.state != archcert_domain::jobs::AttemptState::EvidenceReady
            || attempt
                .runtime
                .as_ref()
                .is_some_and(|r| r.cleanup != crate::jobs::RuntimeCleanupState::Succeeded)
        {
            return Err(JobStoreError::Precondition);
        }
        let worker_artifact = attempt
            .evidence
            .as_ref()
            .ok_or(JobStoreError::Precondition)?;
        result.validate(job.id, attempt.id, &job.inputs)?;
        self.artifacts
            .get(job.inputs.project, worker_artifact)
            .await?;
        let session = self
            .repository
            .review_session(job.inputs.project, job.id)
            .await?;
        if session.pin != *admission.pin() {
            return Err(JobStoreError::Precondition);
        }
        for (role, reference) in admission.evidence() {
            if !session
                .evidence
                .iter()
                .any(|e| e.role == *role && e.available && e.artifact == *reference)
            {
                return Err(JobStoreError::Precondition);
            }
            self.artifacts.get(job.inputs.project, reference).await?;
        }
        let challenge = result
            .steps
            .iter()
            .find(|s| s.step == IDEMPOTENCY_STEP)
            .ok_or(JobStoreError::Precondition)?;
        let satisfied = challenge.source_cleaned
            && challenge.sandbox_cleaned
            && challenge.evidence.as_ref().is_some_and(|e| {
                e.outcome == ExecutionOutcome::Completed
                    && e.exit_code == Some(0)
                    && e.termination == TerminationReason::Exit
                    && e.stdout.complete
                    && e.stderr.complete
            });
        let artifact=CanonicalArtifact::freeze(&serde_json::json!({
            "schema":1,"kind":"ARCHCERT_CHALLENGE_RESULT","session":job.id,
            "attempt":attempt.id,"pin":admission.pin(),"plan_sha256":job.inputs.plan_sha256,
            "worker_artifact":worker_artifact,
            "worker_result_sha256":digest_bytes(&canonical_bytes(result).map_err(|_|JobStoreError::Invalid)?),
            "challenge_plan_sha256":admission.evidence().iter().find(|(r,_)|*r==IroncrestEvidenceRole::ChallengePlan)
                .ok_or(JobStoreError::Precondition)?.1.sha256,
            "challenge_registry_sha256":admission.pin().challenge_registry_sha256,
            "required_results":[challenge],"satisfied":satisfied
        }),8*1024*1024).map_err(|_|JobStoreError::Invalid)?;
        let reference = self
            .persist(
                job.inputs.project,
                job.id,
                IroncrestEvidenceRole::ChallengeResult,
                &artifact,
                None,
            )
            .await?;
        let mut roles = admission.evidence().to_vec();
        roles.push((IroncrestEvidenceRole::ChallengeResult, reference));
        Ok(IroncrestChallengeEvidence {
            binding: IroncrestEvidenceBinding {
                session: job.id,
                pin: admission.pin().clone(),
                plan_sha256: job.inputs.plan_sha256.clone(),
                roles,
            },
            satisfied,
        })
    }
}
