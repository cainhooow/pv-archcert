//! Immutable object publication and provider-free accepted-review recovery.
use super::*;
use crate::{
    artifacts::ImmutableArtifactStore,
    knowledge::{CanonicalArtifact, ImpactArtifact, KnowledgeArtifact, canonical_bytes},
    semantic::*,
};
use archcert_domain::source::digest_bytes;

/// Exact canonical object metadata used by the Ironcrest producer.
pub fn ironcrest_reference(artifact: &CanonicalArtifact) -> ArtifactReference {
    ArtifactReference {
        sha256: artifact.digest().clone(),
        size: artifact.bytes().len() as u64,
        schema: serde_json::from_slice::<serde_json::Value>(artifact.bytes())
            .ok()
            .and_then(|v| v.get("schema").and_then(|n| n.as_u64()))
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1),
        producer: "archcert-ironcrest-v1/0.1.0".into(),
    }
}
/// Journal + existing immutable byte store composition. It holds no runtime,
/// source mutation, signer, transport or provider credential capability.
pub struct IroncrestWorkflow<'a> {
    /// Durable metadata authority.
    pub repository: &'a dyn IroncrestRepository,
    /// Project-scoped immutable object store.
    pub artifacts: &'a dyn ImmutableArtifactStore,
}
impl IroncrestWorkflow<'_> {
    /// Freeze the exact knowledge/impact/request chain before provider invocation.
    /// Repeating after any completed publication reuses identical immutable bytes.
    pub async fn prepare(
        &self,
        request: &SemanticReviewRequest,
        knowledge: &KnowledgeArtifact,
        impact: &ImpactArtifact,
        profile: &CanonicalArtifact,
    ) -> Result<(), JobStoreError> {
        self.prepare_with_checkpoints(request, knowledge, impact, profile, &|_| Ok(()))
            .await
    }
    /// The same immutable preparation with authority-owned interruption hooks after
    /// each AVAILABLE stage. Hooks grant no execution or provider capability.
    pub async fn prepare_with_checkpoints(
        &self,
        request: &SemanticReviewRequest,
        knowledge: &KnowledgeArtifact,
        impact: &ImpactArtifact,
        profile: &CanonicalArtifact,
        checkpoint: &(dyn Fn(IroncrestEvidenceRole) -> Result<(), JobStoreError> + Sync),
    ) -> Result<(), JobStoreError> {
        let binding = request.binding();
        let session = self
            .repository
            .review_session(binding.project, binding.job)
            .await?;
        if !session.pin.matches_review(binding.job, binding)
            || binding.knowledge_sha256 != *knowledge.artifact().digest()
            || binding.impact_sha256 != *impact.artifact().digest()
            || session.pin.authority_profile_sha256 != *profile.digest()
            || session.pin.extractor_registry_sha256
                != digest_bytes(
                    &canonical_bytes(&knowledge.body().extractors)
                        .map_err(|_| JobStoreError::Invalid)?,
                )
        {
            return Err(JobStoreError::Precondition);
        }
        for (role, artifact) in [
            (IroncrestEvidenceRole::AuthorityProfile, profile),
            (IroncrestEvidenceRole::Knowledge, knowledge.artifact()),
            (IroncrestEvidenceRole::Impact, impact.artifact()),
            (IroncrestEvidenceRole::Request, request.artifact()),
        ] {
            self.persist(binding.project, binding.job, role, artifact, None)
                .await?;
            checkpoint(role)?;
        }
        Ok(())
    }
    /// Reuse accepted/staged response bytes first. A claimed invocation without
    /// recoverable response metadata/bytes blocks; it never silently calls again.
    pub async fn review_or_restore(
        &self,
        request: &SemanticReviewRequest,
        reviewer: &dyn SemanticReviewer,
    ) -> Result<SemanticReviewArtifact, JobStoreError> {
        if !request.context_sufficient()
            || request.artifact().bytes().len() > request.limits().request_bytes
        {
            return Err(JobStoreError::Precondition);
        }
        let binding = request.binding();
        let session = self
            .repository
            .review_session(binding.project, binding.job)
            .await?;
        if !session.pin.matches_review(binding.job, binding) {
            return Err(JobStoreError::Precondition);
        }
        if let Some(e) = session
            .evidence
            .iter()
            .find(|e| e.role == IroncrestEvidenceRole::Review)
        {
            return self.restore(request, e, session.review_timestamp).await;
        }
        let Some(invocation) = self
            .repository
            .claim_review(
                binding.project,
                binding.job,
                binding,
                &ironcrest_reference(request.artifact()),
            )
            .await?
        else {
            // A concurrent first controller may have published while this caller
            // waited for the row lock. Re-read once; never infer a retry permit.
            let session = self
                .repository
                .review_session(binding.project, binding.job)
                .await?;
            let evidence = session
                .evidence
                .iter()
                .find(|e| e.role == IroncrestEvidenceRole::Review)
                .ok_or(JobStoreError::Precondition)?;
            return self
                .restore(request, evidence, session.review_timestamp)
                .await;
        };
        let output =
            review_with_byte_bound(request, reviewer, request.limits().request_bytes).await;
        let artifact = SemanticReviewArtifact::accept(request, output, invocation.timestamp)
            .map_err(|_| JobStoreError::Invalid)?;
        self.persist(
            binding.project,
            binding.job,
            IroncrestEvidenceRole::Review,
            artifact.artifact(),
            Some(&invocation),
        )
        .await?;
        Ok(artifact)
    }
    async fn restore(
        &self,
        request: &SemanticReviewRequest,
        evidence: &IroncrestEvidenceReference,
        timestamp: Option<u64>,
    ) -> Result<SemanticReviewArtifact, JobStoreError> {
        let binding = request.binding();
        let bytes = self
            .artifacts
            .get(binding.project, &evidence.artifact)
            .await?;
        let artifact = SemanticReviewArtifact::restore(request, &bytes, &evidence.artifact.sha256)
            .map_err(|_| JobStoreError::Invalid)?;
        if timestamp != Some(artifact.timestamp()) {
            return Err(JobStoreError::Precondition);
        }
        if !evidence.available {
            self.repository
                .review_evidence_available(
                    binding.project,
                    binding.job,
                    IroncrestEvidenceRole::Review,
                    &evidence.artifact,
                )
                .await?;
        }
        Ok(artifact)
    }
    /// Stage, publish, independently verify and mark AVAILABLE. A crash after
    /// metadata/upload is recoverable with exact bytes; replacement always rejects.
    pub async fn persist(
        &self,
        project: ProjectId,
        id: JobId,
        role: IroncrestEvidenceRole,
        artifact: &CanonicalArtifact,
        invocation: Option<&ReviewInvocation>,
    ) -> Result<ArtifactReference, JobStoreError> {
        let reference = ironcrest_reference(artifact);
        self.repository
            .stage_review_evidence(project, id, role, &reference, invocation)
            .await?;
        self.artifacts
            .put(project, &reference, artifact.bytes())
            .await?;
        let bytes = self.artifacts.get(project, &reference).await?;
        if bytes != artifact.bytes()
            || digest_bytes(&bytes) != reference.sha256
            || bytes.len() as u64 != reference.size
        {
            return Err(JobStoreError::Invalid);
        }
        self.repository
            .review_evidence_available(project, id, role, &reference)
            .await?;
        Ok(reference)
    }
    /// Persist the deterministic semantic gate without adding policy facts.
    pub async fn persist_gate(
        &self,
        request: &SemanticReviewRequest,
        review: &SemanticReviewArtifact,
    ) -> Result<SemanticGateDecision, JobStoreError> {
        let binding = request.binding();
        let session = self
            .repository
            .review_session(binding.project, binding.job)
            .await?;
        if !session.pin.matches_review(binding.job, binding)
            || !session.evidence.iter().any(|e| {
                e.role == IroncrestEvidenceRole::Request
                    && e.available
                    && e.artifact == ironcrest_reference(request.artifact())
            })
            || session.review_timestamp != Some(review.timestamp())
            || !session.evidence.iter().any(|e| {
                e.role == IroncrestEvidenceRole::Review
                    && e.available
                    && e.artifact == ironcrest_reference(review.artifact())
            })
        {
            return Err(JobStoreError::Precondition);
        }
        let decision = semantic_gate(request, Some(review));
        let mut required_challenges = Vec::new();
        if decision == SemanticGateDecision::Continue {
            let registry = crate::challenges::AuthorityChallengeRegistry::from_digest(
                &session.pin.challenge_registry_sha256,
            )
            .map_err(|_| JobStoreError::Precondition)?;
            let (template, repetitions) = registry
                .requirement(review)
                .map_err(|_| JobStoreError::Precondition)?;
            let identity = serde_json::json!({
                "registry_sha256":session.pin.challenge_registry_sha256,
                "template_id":template,"version":"1.0.0","parameters":{"repetitions":repetitions}
            });
            required_challenges.push(serde_json::json!({
                "identity":identity,
                "sha256":digest_bytes(&canonical_bytes(&identity).map_err(|_|JobStoreError::Invalid)?)
            }));
        }
        let review_decision = decision;
        let decision = if review_decision == SemanticGateDecision::Continue
            && !required_challenges.is_empty()
        {
            SemanticGateDecision::RequireMoreEvidence
        } else {
            review_decision
        };
        let artifact = CanonicalArtifact::freeze(&serde_json::json!({
            "schema":2,"kind":"ARCHCERT_SEMANTIC_GATE","binding":request.binding(),
            "algorithm":IRONCREST_GATE_ALGORITHM,
            "authority_profile_sha256":session.pin.authority_profile_sha256,
            "request_sha256":request.artifact().digest(),"review_sha256":review.artifact().digest(),
            "review_decision":review_decision,"decision":decision,"required_challenges":required_challenges
        }),65536).map_err(|_|JobStoreError::Invalid)?;
        self.persist(
            request.binding().project,
            request.binding().job,
            IroncrestEvidenceRole::Gate,
            &artifact,
            None,
        )
        .await?;
        Ok(decision)
    }
}
