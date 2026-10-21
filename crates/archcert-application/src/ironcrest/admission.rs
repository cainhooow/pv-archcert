//! Exact reviewed inputs become one new immutable execution admission.

use super::*;
use crate::{
    challenges::AuthorityChallengeRegistry,
    knowledge::{CanonicalArtifact, ImpactArtifact, KnowledgeArtifact, canonical_bytes},
    semantic::{
        SemanticGateDecision, SemanticReviewArtifact, SemanticReviewRequest, semantic_gate,
    },
    validation::{AuthorityConfiguration, ValidationPlan},
    worker::{pinned_plan, resolve_authority_plan},
};
use archcert_domain::{jobs::JobInputs, source::digest_bytes};

/// Borrowed authority composition. None of these selections come from target data.
pub struct IroncrestAdmissionContext<'a> {
    /// Frozen pre-admission session identity.
    pub id: JobId,
    /// Versioned authority controls selected before knowledge access.
    pub profile: &'a IroncrestAuthorityProfile,
    /// Original mandatory execution inputs.
    pub base_inputs: &'a JobInputs,
    /// Exact accepted knowledge.
    pub knowledge: &'a KnowledgeArtifact,
    /// Exact accepted baseline impact.
    pub impact: &'a ImpactArtifact,
    /// Exact persisted request.
    pub request: &'a SemanticReviewRequest,
    /// Accepted persisted review, including its frozen invocation time.
    pub review: &'a SemanticReviewArtifact,
    /// Authority-controlled challenge registry.
    pub registry: &'a AuthorityChallengeRegistry,
}

/// Admission capability. Only successful application validation/publication can
/// construct it. Decoding database or repository bytes cannot grant admission.
#[derive(Debug, Serialize)]
pub struct ReviewedIroncrestAdmission {
    id: JobId,
    pin: IroncrestSessionPin,
    inputs: JobInputs,
    evidence: Vec<(IroncrestEvidenceRole, ArtifactReference)>,
}

impl ReviewedIroncrestAdmission {
    /// Reserved session and job ID, unchanged by admission.
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Full authority/source/baseline inputs for transactional comparison.
    pub fn pin(&self) -> &IroncrestSessionPin {
        &self.pin
    }

    /// Exact final immutable execution inputs.
    pub fn inputs(&self) -> &JobInputs {
        &self.inputs
    }

    /// Complete reviewed role identities. Order is fixed by this producer.
    pub fn evidence(&self) -> &[(IroncrestEvidenceRole, ArtifactReference)] {
        &self.evidence
    }
}

fn inputs_match(pin: &IroncrestSessionPin, base: &JobInputs) -> bool {
    pin.project == base.project
        && pin.repository == base.repository
        && pin.actor == base.actor
        && pin.submission == base.submission
        && pin.source == base.source
        && pin.policy == base.policy
        && pin.base_plan_sha256 == base.plan_sha256
}

fn retained_recipe(plan: &ValidationPlan, profile: &str) -> Result<String, JobStoreError> {
    let commands: Vec<_> = plan
        .steps()
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.id(),
                "program": s.command().program(),
                "args": s.command().args(),
                "working_directory": s.command().working_directory(),
                "evidence": s.evidence_category()
            })
        })
        .collect();
    toml::to_string(&serde_json::json!({
        "schema": 1,
        "project": {
            "name": "Ironcrest frozen authority plan"
        },
        "execution": {
            "profile": profile,
            "commands": commands
        }
    }))
    .map_err(|_| JobStoreError::Invalid)
}

impl IroncrestWorkflow<'_> {
    /// Revalidate every accepted identity and freeze all additive challenges BEFORE
    /// admission. Repetition can only recover identical create-only role bytes.
    /// BLOCK and unresolved review/failure return without execution authority.
    pub async fn freeze_admission(
        &self,
        context: IroncrestAdmissionContext<'_>,
    ) -> Result<ReviewedIroncrestAdmission, JobStoreError> {
        let c = context;
        let pin = self
            .repository
            .review_session(c.base_inputs.project, c.id)
            .await?
            .pin;

        c.profile.validate_pin(&pin)?;
        c.profile.validate_request(c.request)?;

        if !inputs_match(&pin, c.base_inputs)
            || !pin.matches_review(c.id, c.request.binding())
            || pin.challenge_registry_sha256 != *c.registry.artifact().digest()
        {
            return Err(JobStoreError::Precondition);
        }

        let base = pinned_plan(c.base_inputs)?;

        self.prepare(c.request, c.knowledge, c.impact, c.profile.artifact())
            .await?;

        let decision = self.persist_gate(c.request, c.review).await?;

        if decision == SemanticGateDecision::Block
            || semantic_gate(c.request, Some(c.review)) != SemanticGateDecision::Continue
        {
            return Err(JobStoreError::Precondition);
        }

        let profiles = AuthorityConfiguration::development(vec![(
            c.base_inputs.profile.clone(),
            c.base_inputs.image.clone(),
        )])
        .map_err(|_| JobStoreError::Invalid)?;
        let execution_profile = profiles
            .profile(&c.base_inputs.profile)
            .map_err(|_| JobStoreError::Invalid)?;

        let selection = c
            .registry
            .plan(c.request, c.review, execution_profile)
            .map_err(|_| JobStoreError::Invalid)?;
        let final_plan = selection
            .extend_authority_plan(&base)
            .map_err(|_| JobStoreError::Invalid)?;

        let mut inputs = c.base_inputs.clone();
        inputs.authority_toml = retained_recipe(&final_plan, &inputs.profile)?;
        inputs.plan_sha256 = final_plan.digest().map_err(|_| JobStoreError::Invalid)?;

        // Worker reconstruction must produce the identical authority plan.
        let reconstructed =
            resolve_authority_plan(&inputs.profile, &inputs.image, &inputs.authority_toml)?;

        if reconstructed.digest().map_err(|_| JobStoreError::Invalid)? != inputs.plan_sha256 {
            return Err(JobStoreError::Precondition);
        }

        let session = self.repository.review_session(pin.project, c.id).await?;
        let gate = session
            .evidence
            .iter()
            .find(|e| e.role == IroncrestEvidenceRole::Gate && e.available)
            .ok_or(JobStoreError::Precondition)?;

        let frozen = CanonicalArtifact::freeze(
            &serde_json::json!({
                "schema": 2,
                "kind": "ARCHCERT_CHALLENGE_PLAN",
                "session": c.id,
                "pin": pin,
                "binding": c.request.binding(),
                "request_sha256": c.request.artifact().digest(),
                "review_sha256": c.review.artifact().digest(),
                "gate_sha256": gate.artifact.sha256,
                "registry_sha256": c.registry.artifact().digest(),
                "base_plan_sha256": pin.base_plan_sha256,
                "final_plan_sha256": inputs.plan_sha256,
                "challenges": selection.challenges()
            }),
            65536,
        )
        .map_err(|_| JobStoreError::Invalid)?;

        self.persist(
            pin.project,
            c.id,
            IroncrestEvidenceRole::ChallengePlan,
            &frozen,
            None,
        )
        .await?;

        let session = self.repository.review_session(pin.project, c.id).await?;
        let mut evidence = Vec::new();

        for role in [
            IroncrestEvidenceRole::AuthorityProfile,
            IroncrestEvidenceRole::Knowledge,
            IroncrestEvidenceRole::Impact,
            IroncrestEvidenceRole::Request,
            IroncrestEvidenceRole::Review,
            IroncrestEvidenceRole::Gate,
            IroncrestEvidenceRole::ChallengePlan,
        ] {
            let e = session
                .evidence
                .iter()
                .find(|e| e.role == role && e.available)
                .ok_or(JobStoreError::Precondition)?;
            // AVAILABLE metadata alone never establishes artifact availability.
            let bytes = self.artifacts.get(pin.project, &e.artifact).await?;

            if bytes.len() as u64 != e.artifact.size || digest_bytes(&bytes) != e.artifact.sha256 {
                return Err(JobStoreError::Precondition);
            }

            evidence.push((role, e.artifact.clone()));
        }

        // Bind immutable knowledge limits as well as extractor/authority identities.
        if canonical_bytes(&c.knowledge.body().limits).map_err(|_| JobStoreError::Invalid)?
            != canonical_bytes(&c.profile.knowledge_limits()).map_err(|_| JobStoreError::Invalid)?
        {
            return Err(JobStoreError::Precondition);
        }

        Ok(ReviewedIroncrestAdmission {
            id: c.id,
            pin,
            inputs,
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_recipe_reconstructs_authority_plan() -> Result<(), Box<dyn std::error::Error>> {
        let image = format!("python@sha256:{}", "d".repeat(64));
        let original = resolve_authority_plan(
            "python",
            &image,
            include_str!("../../../../docs/policy/CONTROLLED_AUTHORITY.toml"),
        )?;
        let text = retained_recipe(&original, "python")?;
        let reconstructed = resolve_authority_plan("python", &image, &text)?;

        assert_eq!(original.digest()?, reconstructed.digest()?);

        Ok(())
    }
}
