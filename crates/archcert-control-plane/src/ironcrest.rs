//! Authority composition for pre-admission Ironcrest sessions. No signing/runtime.
use super::*;
use archcert_application::{
    challenges::AuthorityChallengeRegistry, ironcrest::*, knowledge::*, semantic::*,
};

/// Owned revalidated authority context. Immutable publication/review orchestration
/// stays behind application services; this adapter selects accepted source and ports.
pub struct PreparedIroncrestReview {
    /// Reserved job/session identity.
    pub id: JobId,
    /// Original mandatory inputs, never an admitted mutable execution plan.
    pub base_inputs: JobInputs,
    /// Versioned controls.
    pub profile: IroncrestAuthorityProfile,
    /// Accepted target knowledge, checked against existing role identity on publication.
    pub knowledge: KnowledgeArtifact,
    /// Pinned baseline impact.
    pub impact: ImpactArtifact,
    /// Immutable semantic request.
    pub request: SemanticReviewRequest,
    /// Authority registry only.
    pub registry: AuthorityChallengeRegistry,
}
impl PreparedIroncrestReview {
    /// Borrow original authority objects for immutable application admission.
    pub fn admission_context<'a>(
        &'a self,
        review: &'a SemanticReviewArtifact,
    ) -> IroncrestAdmissionContext<'a> {
        IroncrestAdmissionContext {
            id: self.id,
            profile: &self.profile,
            base_inputs: &self.base_inputs,
            knowledge: &self.knowledge,
            impact: &self.impact,
            request: &self.request,
            review,
            registry: &self.registry,
        }
    }
}
fn authority(
    project: ProjectId,
    policy: &PolicyPin,
) -> Result<
    (
        KnowledgeEngine,
        Vec<AuthorityKnowledgeBundle>,
        AuthorityChallengeRegistry,
        IroncrestAuthorityProfile,
    ),
    JobStoreError,
> {
    let engine = KnowledgeEngine::new(
        vec![Box::new(archcert_knowledge::RustSyntaxExtractor)],
        KnowledgeLimits::default(),
    )
    .map_err(|_| JobStoreError::Invalid)?;
    let bundles = vec![
        controlled_settlement_knowledge(project, policy.sha256.clone())
            .map_err(|_| JobStoreError::Invalid)?,
    ];
    let registry = AuthorityChallengeRegistry::controlled().map_err(|_| JobStoreError::Invalid)?;
    let mut identities: Vec<_> = bundles
        .iter()
        .map(|b| b.artifact().digest().clone())
        .collect();
    identities.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let profile = IroncrestAuthorityProfile::controlled(
        policy.clone(),
        engine
            .registry_digest()
            .map_err(|_| JobStoreError::Invalid)?,
        identities,
        &registry,
    )
    .map_err(|_| JobStoreError::Invalid)?;
    Ok((engine, bundles, registry, profile))
}
fn policy_pin() -> Result<PolicyPin, JobStoreError> {
    let bundle =
        archcert_policy::ironcrest_controlled_bundle().map_err(|_| JobStoreError::Invalid)?;
    let p = bundle.identity();
    Ok(PolicyPin {
        id: p.id.clone(),
        version: p.version.clone(),
        sha256: p.sha256.clone(),
    })
}
impl ControlPlane {
    /// Authenticated source selection before any private source/knowledge lookup.
    /// The caller supplies source and scope only; provider/profile/baseline/challenge
    /// selections belong exclusively to the externally provisioned authority grant.
    pub async fn open_ironcrest(
        &self,
        actor: GitActorId,
        project: ProjectId,
        repository: RepositoryId,
        submission: SourceSubmissionId,
        id: JobId,
    ) -> Result<IroncrestSession, JobStoreError> {
        let grant = self.configuration.grant_for(&actor, project, &repository)?;
        if !grant.ironcrest
            || !self
                .repository
                .authorized(project, &repository, &actor)
                .await?
        {
            return Err(JobStoreError::Unauthorized);
        }
        let reader =
            archcert_gateway::AcceptedSubmissionReader::open(&self.configuration.source_store)
                .map_err(|_| JobStoreError::Unavailable)?;
        let source = reader
            .load(&submission)
            .map_err(|_| JobStoreError::Invalid)?
            .snapshot;
        if source.project() != project || source.repository() != &repository {
            return Err(JobStoreError::Unauthorized);
        }
        source
            .require_complete()
            .map_err(|_| JobStoreError::Invalid)?;
        let baseline = if let Some(submission) = &grant.ironcrest_baseline {
            let base = reader
                .load(submission)
                .map_err(|_| JobStoreError::Invalid)?
                .snapshot;
            if base.project() != project || base.repository() != &repository {
                return Err(JobStoreError::Unauthorized);
            }
            base.require_complete()
                .map_err(|_| JobStoreError::Invalid)?;
            self.repository.register_source(submission, &base).await?;
            Some(BaselinePin {
                submission: submission.clone(),
                source: base.identity().clone(),
            })
        } else {
            None
        };
        let policy = policy_pin()?;
        let (engine, bundles, registry, profile) = authority(project, &policy)?;
        let plan = resolve_authority_plan(&grant.profile, &grant.image, &grant.authority_toml)?;
        self.repository
            .register_source(&submission, &source)
            .await?;
        let pin = IroncrestSessionPin {
            project,
            repository,
            actor,
            submission,
            source: source.identity().clone(),
            baseline,
            policy,
            base_plan_sha256: plan.digest().map_err(|_| JobStoreError::Invalid)?,
            authority_profile_sha256: profile.artifact().digest().clone(),
            extractor_registry_sha256: engine
                .registry_digest()
                .map_err(|_| JobStoreError::Invalid)?,
            challenge_registry_sha256: registry.artifact().digest().clone(),
            authority_bundles: bundles
                .iter()
                .map(|b| b.artifact().digest().clone())
                .collect(),
        };
        profile.validate_pin(&pin)?;
        self.repository.open_session(id, &pin).await
    }
    /// Restore authority-selected source/baseline/profile without consulting target
    /// configuration or mutable refs. Changed authority versions/recipes fail closed.
    pub async fn prepare_ironcrest(
        &self,
        project: ProjectId,
        id: JobId,
    ) -> Result<PreparedIroncrestReview, JobStoreError> {
        let session = self.repository.review_session(project, id).await?;
        let pin = &session.pin;
        let grant = self
            .configuration
            .grant_for(&pin.actor, project, &pin.repository)?;
        if !grant.ironcrest
            || !self
                .repository
                .authorized(project, &pin.repository, &pin.actor)
                .await?
        {
            return Err(JobStoreError::Unauthorized);
        }
        let policy = policy_pin()?;
        if policy != pin.policy {
            return Err(JobStoreError::Precondition);
        }
        let (engine, bundles, registry, profile) = authority(project, &policy)?;
        profile.validate_pin(pin)?;
        let base_inputs = JobInputs {
            project,
            repository: pin.repository.clone(),
            submission: pin.submission.clone(),
            source: pin.source.clone(),
            actor: pin.actor.clone(),
            policy,
            profile: grant.profile.clone(),
            image: grant.image.clone(),
            plan_sha256: pin.base_plan_sha256.clone(),
            authority_toml: grant.authority_toml.clone(),
            maximum_attempts: grant.maximum_attempts,
        };
        archcert_application::worker::pinned_plan(&base_inputs)?;
        let source = self.source(&base_inputs)?;
        let baseline = if let Some(base) = &pin.baseline {
            let mut inputs = base_inputs.clone();
            inputs.submission = base.submission.clone();
            inputs.source = base.source.clone();
            Some(self.source(&inputs)?)
        } else {
            None
        };
        let selected = baseline
            .as_ref()
            .map(|s| {
                SelectedBaseline::accepted(
                    s,
                    "Pinned accepted authority baseline from the Ironcrest session".into(),
                )
            })
            .transpose()
            .map_err(|_| JobStoreError::Invalid)?;
        let baseline_knowledge = baseline
            .as_ref()
            .map(|s| engine.extract(s, &bundles, None))
            .transpose()
            .map_err(|_| JobStoreError::Invalid)?;
        let knowledge = engine
            .extract(&source, &bundles, selected.as_ref())
            .map_err(|_| JobStoreError::Invalid)?;
        let impact = analyze_impact(&knowledge, baseline_knowledge.as_ref())
            .map_err(|_| JobStoreError::Invalid)?;
        let bundle =
            archcert_policy::ironcrest_controlled_bundle().map_err(|_| JobStoreError::Invalid)?;
        let request = SemanticReviewRequest::prepare(
            ReviewContext {
                job: id,
                source: &source,
                knowledge: &knowledge,
                impact: &impact,
                bundles: &bundles,
                policy: &base_inputs.policy,
                policy_bytes: bundle.canonical_bytes(),
                authority_profile_sha256: profile.artifact().digest().clone(),
                observations: &[],
                claims: &[],
            },
            profile.reviewer(),
            profile.semantic_limits(),
        )
        .map_err(|_| JobStoreError::Invalid)?;
        profile.validate_request(&request)?;
        Ok(PreparedIroncrestReview {
            id,
            base_inputs,
            profile,
            knowledge,
            impact,
            request,
            registry,
        })
    }
}
