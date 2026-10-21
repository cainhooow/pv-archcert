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
    /// Non-authoritative practical timing observations, excluded from identities.
    pub measurements: serde_json::Value,
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
    rust: bool,
    request_bound: Option<usize>,
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
        (if rust {
            controlled_rust_knowledge
        } else {
            controlled_settlement_knowledge
        })(project, policy.sha256.clone())
        .map_err(|_| JobStoreError::Invalid)?,
    ];
    let registry = (if rust {
        AuthorityChallengeRegistry::rust_workspace
    } else {
        AuthorityChallengeRegistry::controlled
    })()
    .map_err(|_| JobStoreError::Invalid)?;
    let mut identities: Vec<_> = bundles
        .iter()
        .map(|b| b.artifact().digest().clone())
        .collect();
    identities.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let extractor_registry = engine
        .registry_digest()
        .map_err(|_| JobStoreError::Invalid)?;
    let profile = if rust {
        let packaging = SemanticPackagingPolicy::rust_controlled()
            .with_request_limit(request_bound.unwrap_or(1024 * 1024))
            .map_err(|_| JobStoreError::Invalid)?;
        IroncrestAuthorityProfile::rust_workspace_with_packaging(
            policy.clone(),
            extractor_registry,
            identities,
            &registry,
            packaging,
        )
    } else {
        IroncrestAuthorityProfile::controlled(
            policy.clone(),
            extractor_registry,
            identities,
            &registry,
        )
    }
    .map_err(|_| JobStoreError::Invalid)?;
    Ok((engine, bundles, registry, profile))
}
fn policy_pin(rust: bool) -> Result<PolicyPin, JobStoreError> {
    let bundle = (if rust {
        archcert_policy::rust_controlled_bundle
    } else {
        archcert_policy::ironcrest_controlled_bundle
    })()
    .map_err(|_| JobStoreError::Invalid)?;
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
        let rust = grant.profile == "rust-workspace-v1";
        let policy = policy_pin(rust)?;
        let (engine, bundles, registry, profile) =
            authority(project, &policy, rust, grant.semantic_request_bytes)?;
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
        let rust = grant.profile == "rust-workspace-v1";
        let policy = policy_pin(rust)?;
        if policy != pin.policy {
            return Err(JobStoreError::Precondition);
        }
        let (engine, bundles, registry, profile) =
            authority(project, &policy, rust, grant.semantic_request_bytes)?;
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
        let extraction_started = std::time::Instant::now();
        let baseline_knowledge = baseline
            .as_ref()
            .map(|s| engine.extract(s, &bundles, None))
            .transpose()
            .map_err(|_| JobStoreError::Invalid)?;
        let knowledge = engine
            .extract(&source, &bundles, selected.as_ref())
            .map_err(|_| JobStoreError::Invalid)?;
        let extraction_millis = extraction_started.elapsed().as_millis();
        let impact_started = std::time::Instant::now();
        let impact = analyze_impact(&knowledge, baseline_knowledge.as_ref())
            .map_err(|_| JobStoreError::Invalid)?;
        let impact_millis = impact_started.elapsed().as_millis();
        let packaging_started = std::time::Instant::now();
        let bundle = (if rust {
            archcert_policy::rust_controlled_bundle
        } else {
            archcert_policy::ironcrest_controlled_bundle
        })()
        .map_err(|_| JobStoreError::Invalid)?;
        let context = ReviewContext {
            job: id,
            source: &source,
            knowledge: &knowledge,
            impact: &impact,
            bundles: &bundles,
            policy: &base_inputs.policy,
            policy_bytes: bundle.canonical_bytes(),
            authority_profile_sha256: profile.artifact().digest().clone(),
            authority_profile_bytes: Some(profile.artifact().bytes()),
            observations: &[],
            claims: &[],
        };
        let request = if let Some(packaging) = profile.packaging_policy() {
            SemanticReviewRequest::prepare_bounded(
                context,
                profile.reviewer(),
                profile.semantic_limits(),
                packaging.clone(),
            )
        } else {
            SemanticReviewRequest::prepare(context, profile.reviewer(), profile.semantic_limits())
        }
        .map_err(|_| JobStoreError::Invalid)?;
        profile.validate_request(&request)?;
        let measurements = serde_json::json!({"source_files":source.files().len(),"knowledge_bytes":knowledge.artifact().bytes().len(),
            "impact_bytes":impact.artifact().bytes().len(),"package_bytes":request.package().map(|p|p.artifact().bytes().len()),
            "request_bytes":request.artifact().bytes().len(),"extraction_millis":extraction_millis,"impact_millis":impact_millis,
            "packaging_millis":packaging_started.elapsed().as_millis()});
        Ok(PreparedIroncrestReview {
            measurements,
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
