//! Real PostgreSQL and private filesystem journal recovery tests. The journal
//! binary is separate from short-lease execution fixtures; its own claim race
//! remains concurrent. Run both binaries through scripts/test-ravenport.
use archcert_application::jobs::*;
use archcert_domain::{GitObjectId, ProjectId, Sha256Digest, ingress::*, jobs::*, source::*};
use archcert_storage::PostgresJobRepository;
use sqlx::{PgPool, postgres::PgPoolOptions};
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct CountingSemanticReviewer(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl archcert_application::semantic::SemanticReviewer for CountingSemanticReviewer {
    async fn review(
        &self,
        request: &archcert_application::semantic::SemanticReviewRequest,
    ) -> Result<
        archcert_application::semantic::ReviewerOutput,
        archcert_application::semantic::SemanticReviewError,
    > {
        use archcert_application::semantic::*;
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ReviewerOutput {
            reported: ReviewerSelection::replay(),
            truncated: false,
            bytes: serde_json::to_vec(&SemanticReviewResponse {
                schema: 1,
                request_sha256: request.artifact().digest().clone(),
                complete: true,
                items: vec![],
                proposed_challenges: vec![],
            })
            .map_err(|_| SemanticReviewError::Malformed)?,
        })
    }
}
#[tokio::test]
#[ignore = "requires real PostgreSQL and private immutable artifact storage"]
async fn ironcrest_response_publication_recovery_reuses_accepted_provider_work() -> R {
    use archcert_application::{
        artifacts::ImmutableArtifactStore, ironcrest::*, knowledge::*, semantic::*,
    };
    use archcert_storage::artifacts::FilesystemArtifactStore;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    let (repo, pool) = database().await?;
    let request = request(&repo).await?;
    let inputs = request.inputs;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let artifacts =
        FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
    let source = SourceSnapshot::seal(
        inputs.project,
        inputs.repository.clone(),
        inputs.source.commit.clone(),
        inputs.source.tree.clone(),
        vec![],
        1,
        1700000000,
    )?;
    let knowledge =
        KnowledgeEngine::new(vec![], KnowledgeLimits::default())?.extract(&source, &[], None)?;
    let impact = analyze_impact(&knowledge, None)?;
    let profile = CanonicalArtifact::freeze(
        &serde_json::json!({"kind":"CONTROLLED_JOURNAL_PROFILE"}),
        65536,
    )?;
    let policy_bytes = br#"{"kind":"controlled-journal-policy"}"#;
    let policy = PolicyPin {
        sha256: digest_bytes(policy_bytes),
        ..inputs.policy.clone()
    };
    let pin = IroncrestSessionPin {
        project: inputs.project,
        repository: inputs.repository.clone(),
        actor: inputs.actor.clone(),
        submission: inputs.submission.clone(),
        source: inputs.source.clone(),
        baseline: None,
        policy: policy.clone(),
        base_plan_sha256: inputs.plan_sha256.clone(),
        authority_profile_sha256: profile.digest().clone(),
        extractor_registry_sha256: digest_bytes(&canonical_bytes(&knowledge.body().extractors)?),
        challenge_registry_sha256: digest_bytes(b"challenge-registry"),
        authority_bundles: vec![],
    };
    let prepare = |id| {
        SemanticReviewRequest::prepare(
            ReviewContext {
                job: id,
                source: &source,
                knowledge: &knowledge,
                impact: &impact,
                bundles: &[],
                policy: &policy,
                policy_bytes,
                authority_profile_sha256: pin.authority_profile_sha256.clone(),
                observations: &[],
                claims: &[],
            },
            ReviewerSelection::replay(),
            SemanticLimits::default(),
        )
    };
    let reviewer = CountingSemanticReviewer(AtomicUsize::new(0));
    let id = JobId::new();
    repo.open_session(id, &pin).await?;
    let request = prepare(id)?;
    let workflow = IroncrestWorkflow {
        repository: &repo,
        artifacts: &artifacts,
    };
    // Crash after knowledge publication: repeated preparation reuses the exact role.
    workflow
        .persist(
            pin.project,
            id,
            IroncrestEvidenceRole::AuthorityProfile,
            &profile,
            None,
        )
        .await?;
    workflow
        .persist(
            pin.project,
            id,
            IroncrestEvidenceRole::Knowledge,
            knowledge.artifact(),
            None,
        )
        .await?;
    workflow
        .prepare(&request, &knowledge, &impact, &profile)
        .await?;
    let accepted = workflow.review_or_restore(&request, &reviewer).await?;
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        workflow.persist_gate(&request, &accepted).await?,
        SemanticGateDecision::RequireMoreEvidence
    );
    let reconnected = PostgresJobRepository::from_pool(pool.clone());
    let resumed = IroncrestWorkflow {
        repository: &reconnected,
        artifacts: &artifacts,
    };
    resumed
        .prepare(&request, &knowledge, &impact, &profile)
        .await?;
    let restored = resumed.review_or_restore(&request, &reviewer).await?;
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 1);
    assert_eq!(accepted.artifact().bytes(), restored.artifact().bytes());
    assert_eq!(
        resumed.persist_gate(&request, &restored).await?,
        SemanticGateDecision::RequireMoreEvidence
    );
    // A different valid response for the same request is not the accepted role.
    let alternate = SemanticReviewArtifact::accept(
        &request,
        Err(SemanticReviewError::Unavailable),
        accepted.timestamp(),
    )?;
    assert!(resumed.persist_gate(&request, &alternate).await.is_err());
    let second = JobId::new();
    repo.open_session(second, &pin).await?;
    let second_request = prepare(second)?;
    workflow
        .prepare(&second_request, &knowledge, &impact, &profile)
        .await?;
    let invocation = repo
        .claim_review(
            pin.project,
            second,
            second_request.binding(),
            &ironcrest_reference(second_request.artifact()),
        )
        .await?
        .ok_or("invocation")?;
    let response = SemanticReviewArtifact::accept(
        &second_request,
        reviewer.review(&second_request).await,
        invocation.timestamp,
    )?;
    let reference = ironcrest_reference(response.artifact());
    repo.stage_review_evidence(
        pin.project,
        second,
        IroncrestEvidenceRole::Review,
        &reference,
        Some(&invocation),
    )
    .await?;
    artifacts
        .put(pin.project, &reference, response.artifact().bytes())
        .await?;
    // Crash after upload but before AVAILABLE: adopt exact existing bytes, no call.
    let restored = resumed
        .review_or_restore(&second_request, &reviewer)
        .await?;
    assert_eq!(restored.artifact().bytes(), response.artifact().bytes());
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 2);
    assert!(
        repo.review_session(pin.project, second)
            .await?
            .evidence
            .iter()
            .any(|e| e.role == IroncrestEvidenceRole::Review && e.available)
    );
    let third = JobId::new();
    repo.open_session(third, &pin).await?;
    let third_request = prepare(third)?;
    workflow
        .prepare(&third_request, &knowledge, &impact, &profile)
        .await?;
    repo.claim_review(
        pin.project,
        third,
        third_request.binding(),
        &ironcrest_reference(third_request.artifact()),
    )
    .await?
    .ok_or("claim")?;
    // Unknown in-flight result cannot become permission for another invocation.
    assert!(
        resumed
            .review_or_restore(&third_request, &reviewer)
            .await
            .is_err()
    );
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 2);
    assert!(artifacts.get(ProjectId::new(), &reference).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn ironcrest_review_claims_are_scoped_single_and_durable_without_execution_authority() -> R {
    use archcert_application::{ironcrest::*, semantic::ReviewBinding};
    let (repo, pool) = database().await?;
    repo.check_ironcrest_readiness().await?;
    let request = request(&repo).await?;
    let inputs = &request.inputs;
    let id = JobId::new();
    let pin = IroncrestSessionPin {
        project: inputs.project,
        repository: inputs.repository.clone(),
        actor: inputs.actor.clone(),
        submission: inputs.submission.clone(),
        source: inputs.source.clone(),
        baseline: None,
        policy: inputs.policy.clone(),
        base_plan_sha256: inputs.plan_sha256.clone(),
        authority_profile_sha256: digest_bytes(b"authority-profile"),
        extractor_registry_sha256: digest_bytes(b"extractors"),
        challenge_registry_sha256: digest_bytes(b"challenges"),
        authority_bundles: vec![],
    };
    let (a, b) = tokio::join!(repo.open_session(id, &pin), repo.open_session(id, &pin));
    assert_eq!(a?.id, b?.id);
    assert_eq!(repo.review_session(pin.project, id).await?.pin, pin);
    assert!(repo.review_session(ProjectId::new(), id).await.is_err());
    let mut different = pin.clone();
    different.authority_profile_sha256 = digest_bytes(b"downgrade");
    assert!(repo.open_session(id, &different).await.is_err());
    let mut unauthorized = pin.clone();
    unauthorized.actor = GitActorId::parse(JobId::new().to_string())?;
    assert!(
        repo.open_session(JobId::new(), &unauthorized)
            .await
            .is_err()
    );
    let reference = |bytes: &[u8]| ArtifactReference {
        sha256: digest_bytes(bytes),
        size: bytes.len() as u64,
        schema: 1,
        producer: "archcert-ironcrest-v1/0.1.0".into(),
    };
    let profile = reference(b"authority-profile");
    let knowledge = reference(b"knowledge");
    let impact = reference(b"impact");
    let prepared = reference(b"request");
    let binding = ReviewBinding {
        project: pin.project,
        job: id,
        source: pin.source.clone(),
        baseline: None,
        knowledge_sha256: knowledge.sha256.clone(),
        impact_sha256: impact.sha256.clone(),
        policy: pin.policy.clone(),
        authority_profile_sha256: pin.authority_profile_sha256.clone(),
        authority_bundles: vec![],
    };
    assert!(
        repo.claim_review(pin.project, id, &binding, &prepared)
            .await
            .is_err()
    );
    assert!(
        repo.stage_review_evidence(
            pin.project,
            id,
            IroncrestEvidenceRole::Request,
            &prepared,
            None
        )
        .await
        .is_err()
    );
    for (role, artifact) in [
        (IroncrestEvidenceRole::AuthorityProfile, &profile),
        (IroncrestEvidenceRole::Knowledge, &knowledge),
        (IroncrestEvidenceRole::Impact, &impact),
        (IroncrestEvidenceRole::Request, &prepared),
    ] {
        repo.stage_review_evidence(pin.project, id, role, artifact, None)
            .await?;
        let staged = repo.review_session(pin.project, id).await?;
        assert!(
            !staged
                .evidence
                .iter()
                .find(|e| e.role == role)
                .ok_or("staged")?
                .available
        );
        repo.review_evidence_available(pin.project, id, role, artifact)
            .await?;
        repo.review_evidence_available(pin.project, id, role, artifact)
            .await?;
        assert!(
            repo.stage_review_evidence(pin.project, id, role, &reference(b"replacement"), None)
                .await
                .is_err()
        );
    }
    let (first, second) = tokio::join!(
        repo.claim_review(pin.project, id, &binding, &prepared),
        repo.claim_review(pin.project, id, &binding, &prepared)
    );
    let (first, second) = (first?, second?);
    assert_ne!(first.is_some(), second.is_some());
    let invocation = first.or(second).ok_or("single claim")?;
    let reconnected = PostgresJobRepository::from_pool(pool.clone());
    let restored = reconnected.review_session(pin.project, id).await?;
    assert!(restored.review_claimed);
    assert_eq!(restored.review_timestamp, Some(invocation.timestamp));
    assert!(
        reconnected
            .claim_review(pin.project, id, &binding, &prepared)
            .await?
            .is_none()
    );
    let mut foreign = binding.clone();
    foreign.source.snapshot_sha256 = digest_bytes(b"foreign");
    assert!(
        reconnected
            .claim_review(pin.project, id, &foreign, &prepared)
            .await
            .is_err()
    );
    let review = reference(b"accepted semantic response");
    assert!(
        repo.stage_review_evidence(
            pin.project,
            id,
            IroncrestEvidenceRole::Review,
            &review,
            None
        )
        .await
        .is_err()
    );
    let wrong = ReviewInvocation {
        token: JobId::new(),
        timestamp: invocation.timestamp,
    };
    assert!(
        repo.stage_review_evidence(
            pin.project,
            id,
            IroncrestEvidenceRole::Review,
            &review,
            Some(&wrong)
        )
        .await
        .is_err()
    );
    repo.stage_review_evidence(
        pin.project,
        id,
        IroncrestEvidenceRole::Review,
        &review,
        Some(&invocation),
    )
    .await?;
    // A crash after response metadata/upload can adopt the exact pinned bytes;
    // it does not acquire another provider invocation capability.
    reconnected
        .review_evidence_available(pin.project, id, IroncrestEvidenceRole::Review, &review)
        .await?;
    assert!(
        repo.stage_review_evidence(
            pin.project,
            id,
            IroncrestEvidenceRole::Review,
            &reference(b"different response"),
            Some(&invocation)
        )
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "UPDATE ironcrest_sessions SET invocation=NULL,review_timestamp=NULL WHERE id=$1"
        )
        .bind(id.to_string())
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM ironcrest_evidence WHERE session=$1")
            .bind(id.to_string())
            .execute(&pool)
            .await
            .is_err()
    );
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_attempts")
        .fetch_one(&pool)
        .await?;
    assert_eq!((jobs, attempts), (0, 0));
    let existing = repo.create(request.clone()).await?;
    assert!(repo.open_session(existing.id, &pin).await.is_err());
    Ok(())
}
async fn database() -> R<(PostgresJobRepository, PgPool)> {
    let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&url).await?;
    let schema = format!("ravenport_{}", JobId::new().to_string().replace('-', ""));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |c, _| {
            let sql = schema.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(sql)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let repo = PostgresJobRepository::from_pool(pool.clone());
    repo.migrate().await?;
    repo.migrate().await?;
    repo.check_readiness().await?;
    Ok((repo, pool))
}
async fn request(repo: &PostgresJobRepository) -> R<CreateJob> {
    let project = ProjectId::new();
    let repository = RepositoryId::parse("regression/source")?;
    let actor = GitActorId::parse(JobId::new().to_string())?;
    let submission = SourceSubmissionId::new();
    let source = SourceSnapshot::seal(
        project,
        repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1700000000,
    )?;
    repo.grant(project, &repository, &actor).await?;
    repo.register_source(&submission, &source).await?;
    Ok(CreateJob {
        inputs: JobInputs {
            project,
            repository,
            submission,
            source: source.identity().clone(),
            actor,
            policy: PolicyPin {
                id: "development".into(),
                version: "1.0.0".into(),
                sha256: Sha256Digest::parse("c".repeat(64))?,
            },
            profile: "python".into(),
            image: format!("python@sha256:{}", "d".repeat(64)),
            plan_sha256: Sha256Digest::parse("e".repeat(64))?,
            authority_toml: "schema = 1".into(),
            maximum_attempts: 2,
        },
        idempotency: IdempotencyKey::parse("request-1".into())?,
    })
}

struct AdmissionFixture {
    pin: archcert_application::ironcrest::IroncrestSessionPin,
    inputs: JobInputs,
    source: SourceSnapshot,
    profile: archcert_application::ironcrest::IroncrestAuthorityProfile,
    knowledge: archcert_application::knowledge::KnowledgeArtifact,
    impact: archcert_application::knowledge::ImpactArtifact,
    registry: archcert_application::challenges::AuthorityChallengeRegistry,
}
impl AdmissionFixture {
    fn review_request(
        &self,
        id: JobId,
    ) -> R<archcert_application::semantic::SemanticReviewRequest> {
        use archcert_application::semantic::*;
        Ok(SemanticReviewRequest::prepare(
            ReviewContext {
                job: id,
                source: &self.source,
                knowledge: &self.knowledge,
                impact: &self.impact,
                bundles: &[],
                policy: &self.inputs.policy,
                policy_bytes: br#"{"kind":"controlled-admission-policy"}"#,
                authority_profile_sha256: self.profile.artifact().digest().clone(),
                observations: &[],
                claims: &[],
            },
            self.profile.reviewer(),
            self.profile.semantic_limits(),
        )?)
    }
    fn context<'a>(
        &'a self,
        id: JobId,
        request: &'a archcert_application::semantic::SemanticReviewRequest,
        review: &'a archcert_application::semantic::SemanticReviewArtifact,
    ) -> archcert_application::ironcrest::IroncrestAdmissionContext<'a> {
        archcert_application::ironcrest::IroncrestAdmissionContext {
            id,
            profile: &self.profile,
            base_inputs: &self.inputs,
            knowledge: &self.knowledge,
            impact: &self.impact,
            request,
            review,
            registry: &self.registry,
        }
    }
}
async fn admission_fixture(repo: &PostgresJobRepository) -> R<AdmissionFixture> {
    use archcert_application::{
        challenges::AuthorityChallengeRegistry, ironcrest::*, knowledge::*,
    };
    let mut inputs = request(repo).await?.inputs;
    inputs.authority_toml = include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml").into();
    inputs.plan_sha256 = archcert_application::worker::resolve_authority_plan(
        &inputs.profile,
        &inputs.image,
        &inputs.authority_toml,
    )?
    .digest()?;
    inputs.policy.id = IRONCREST_CONTROLLED_POLICY_ID.into();
    inputs.policy.sha256 = digest_bytes(br#"{"kind":"controlled-admission-policy"}"#);
    let source = SourceSnapshot::seal(
        inputs.project,
        inputs.repository.clone(),
        inputs.source.commit.clone(),
        inputs.source.tree.clone(),
        vec![],
        1,
        1700000000,
    )?;
    let knowledge =
        KnowledgeEngine::new(vec![], KnowledgeLimits::default())?.extract(&source, &[], None)?;
    let impact = analyze_impact(&knowledge, None)?;
    let registry = AuthorityChallengeRegistry::controlled()?;
    let extractors = digest_bytes(&canonical_bytes(&knowledge.body().extractors)?);
    let profile = IroncrestAuthorityProfile::controlled(
        inputs.policy.clone(),
        extractors.clone(),
        vec![],
        &registry,
    )?;
    let pin = IroncrestSessionPin {
        project: inputs.project,
        repository: inputs.repository.clone(),
        actor: inputs.actor.clone(),
        submission: inputs.submission.clone(),
        source: inputs.source.clone(),
        baseline: None,
        policy: inputs.policy.clone(),
        base_plan_sha256: inputs.plan_sha256.clone(),
        authority_profile_sha256: profile.artifact().digest().clone(),
        extractor_registry_sha256: extractors,
        challenge_registry_sha256: registry.artifact().digest().clone(),
        authority_bundles: vec![],
    };
    Ok(AdmissionFixture {
        pin,
        inputs,
        source,
        profile,
        knowledge,
        impact,
        registry,
    })
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and private immutable artifact storage"]
async fn ironcrest_admission_freezes_exact_plan_transactionally_and_rejects_replay() -> R {
    use archcert_application::{ironcrest::*, worker::pinned_plan};
    use archcert_storage::artifacts::FilesystemArtifactStore;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    let (repo, pool) = database().await?;
    let f = admission_fixture(&repo)
        .await
        .map_err(|e| format!("fixture: {e}"))?;
    assert!(
        repo.create(CreateJob {
            inputs: f.inputs.clone(),
            idempotency: IdempotencyKey::parse("forbidden-direct-ironcrest".into())?
        })
        .await
        .is_err()
    );
    let id = JobId::new();
    repo.open_session(id, &f.pin).await?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let artifacts =
        FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
    let workflow = IroncrestWorkflow {
        repository: &repo,
        artifacts: &artifacts,
    };
    let request = f.review_request(id)?;
    workflow
        .prepare(&request, &f.knowledge, &f.impact, f.profile.artifact())
        .await?;
    let reviewer = CountingSemanticReviewer(AtomicUsize::new(0));
    let review = workflow.review_or_restore(&request, &reviewer).await?;
    // Gate publication alone creates no execution job.
    workflow.persist_gate(&request, &review).await?;
    assert!(repo.get(id).await.is_err());
    let admission = workflow
        .freeze_admission(f.context(id, &request, &review))
        .await
        .map_err(|e| format!("freeze admission: {e}"))?;
    assert!(repo.get(id).await.is_err());
    assert_ne!(admission.inputs().plan_sha256, f.inputs.plan_sha256);
    let base = pinned_plan(&f.inputs)?;
    let final_plan = pinned_plan(admission.inputs())?;
    assert_eq!(final_plan.steps().len(), base.steps().len() + 1);
    for (before, after) in base.steps().iter().zip(final_plan.steps()) {
        assert_eq!(
            archcert_application::knowledge::canonical_bytes(before)?,
            archcert_application::knowledge::canonical_bytes(after)?
        );
    }
    // Force failure of the second transactional write. The job insert must roll
    // back with its linkage; retry does not observe a partially admitted job.
    sqlx::query(
        "ALTER TABLE ironcrest_admissions ADD CONSTRAINT interrupt_admission CHECK (false)",
    )
    .execute(&pool)
    .await?;
    assert!(repo.admit_reviewed(&admission).await.is_err());
    assert!(repo.get(id).await.is_err());
    sqlx::query("ALTER TABLE ironcrest_admissions DROP CONSTRAINT interrupt_admission")
        .execute(&pool)
        .await?;
    let (first, second) = tokio::join!(
        repo.admit_reviewed(&admission),
        repo.admit_reviewed(&admission)
    );
    assert_eq!(first?.id, id);
    assert_eq!(second?.id, id);
    let reconnected = PostgresJobRepository::from_pool(pool.clone());
    let resumed = IroncrestWorkflow {
        repository: &reconnected,
        artifacts: &artifacts,
    };
    let restored = resumed.review_or_restore(&request, &reviewer).await?;
    let again = resumed
        .freeze_admission(f.context(id, &request, &restored))
        .await?;
    assert_eq!(
        reconnected.admit_reviewed(&again).await?.inputs,
        *admission.inputs()
    );
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM ironcrest_admissions")
        .fetch_one(&pool)
        .await?;
    assert_eq!((count, links), (1, 1));
    assert!(
        sqlx::query("UPDATE ironcrest_admissions SET binding='{}'::jsonb")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM ironcrest_admissions")
            .execute(&pool)
            .await
            .is_err()
    );
    for field in 0..7 {
        let mut changed = f.inputs.clone();
        match field {
            0 => changed.project = ProjectId::new(),
            1 => changed.repository = RepositoryId::parse("foreign/repository")?,
            2 => changed.actor = GitActorId::parse(JobId::new().to_string())?,
            3 => changed.submission = SourceSubmissionId::new(),
            4 => changed.source.snapshot_sha256 = digest_bytes(b"different-source"),
            5 => changed.policy.sha256 = digest_bytes(b"different-policy"),
            _ => changed.plan_sha256 = digest_bytes(b"different-base-plan"),
        }
        let mut c = f.context(id, &request, &review);
        c.base_inputs = &changed;
        assert!(
            resumed.freeze_admission(c).await.is_err(),
            "mismatch {field}"
        );
    }
    // Exercise each review replay dimension with the SAME reserved job UUID.
    // Rejection must not depend only on a foreign job identity.
    for dimension in 0..5 {
        use archcert_application::{knowledge::*, semantic::*};
        let source = SourceSnapshot::seal(
            if dimension == 1 {
                ProjectId::new()
            } else {
                f.inputs.project
            },
            f.inputs.repository.clone(),
            if dimension == 0 {
                GitObjectId::parse("c".repeat(40))?
            } else {
                f.inputs.source.commit.clone()
            },
            f.inputs.source.tree.clone(),
            vec![],
            1,
            1700000000,
        )?;
        let selected = if dimension == 4 {
            Some(SelectedBaseline::accepted(
                &source,
                "Controlled alternative baseline".into(),
            )?)
        } else {
            None
        };
        let engine = KnowledgeEngine::new(vec![], KnowledgeLimits::default())?;
        let knowledge = engine.extract(&source, &[], selected.as_ref())?;
        let baseline = if dimension == 4 {
            Some(engine.extract(&source, &[], None)?)
        } else {
            None
        };
        let impact = analyze_impact(&knowledge, baseline.as_ref())?;
        let mut policy = f.inputs.policy.clone();
        let bytes = if dimension == 2 {
            br#"{"kind":"different-controlled-policy"}"#.as_slice()
        } else {
            br#"{"kind":"controlled-admission-policy"}"#.as_slice()
        };
        policy.sha256 = digest_bytes(bytes);
        let foreign = SemanticReviewRequest::prepare(
            ReviewContext {
                job: id,
                source: &source,
                knowledge: &knowledge,
                impact: &impact,
                bundles: &[],
                policy: &policy,
                policy_bytes: bytes,
                authority_profile_sha256: if dimension == 3 {
                    digest_bytes(b"different-profile")
                } else {
                    f.pin.authority_profile_sha256.clone()
                },
                observations: &[],
                claims: &[],
            },
            f.profile.reviewer(),
            f.profile.semantic_limits(),
        )?;
        assert!(
            resumed
                .review_or_restore(&foreign, &reviewer)
                .await
                .is_err(),
            "replay dimension {dimension}"
        );
        assert!(
            resumed.persist_gate(&foreign, &review).await.is_err(),
            "gate replay dimension {dimension}"
        );
    }
    let mut foreign_registry = f.pin.clone();
    foreign_registry.challenge_registry_sha256 = digest_bytes(b"foreign-challenge-registry");
    assert!(repo.open_session(id, &foreign_registry).await.is_err());
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 1);
    // A trusted controller recording eligible metadata still cannot prepare
    // signing before the mandatory reviewed challenge result is available.
    let assignment = repo.claim("issuance-guard", 30).await?.ok_or("claim")?;
    repo.start(&assignment.lease).await?;
    let execution = ArtifactReference {
        sha256: digest_bytes(b"database-only-execution"),
        size: 23,
        schema: 1,
        producer: "storage-regression".into(),
    };
    repo.stage_artifact(id, Some(assignment.lease.attempt), "EXECUTION", &execution)
        .await?;
    repo.artifact_available(id, Some(assignment.lease.attempt), "EXECUTION", &execution)
        .await?;
    repo.accept_evidence(&assignment.lease, &execution).await?;
    let evaluation = ArtifactReference {
        sha256: digest_bytes(b"database-only-evaluation"),
        size: 24,
        schema: 1,
        producer: "storage-regression".into(),
    };
    repo.stage_artifact(id, None, "EVALUATION", &evaluation)
        .await?;
    repo.artifact_available(id, None, "EVALUATION", &evaluation)
        .await?;
    repo.record_evaluation(id, &evaluation, EvaluationDecision::Eligible)
        .await?;
    assert!(
        repo.prepare_issuance(
            id,
            &PreparedIssuance {
                certificate_sha256: digest_bytes(b"unissued"),
                signing_key_id: "a".repeat(64),
                issued_at: 1700000000
            }
        )
        .await
        .is_err()
    );
    assert!(repo.get(id).await?.issuance.is_none());
    // Same text/response cannot authorize another reserved job or baseline.
    let other = JobId::new();
    let mut other_pin = f.pin.clone();
    other_pin.baseline = Some(BaselinePin {
        submission: f.inputs.submission.clone(),
        source: f.inputs.source.clone(),
    });
    repo.open_session(other, &other_pin).await?;
    assert!(
        resumed
            .freeze_admission(f.context(other, &request, &review))
            .await
            .is_err()
    );
    let foreign = admission_fixture(&repo).await?;
    let foreign_id = JobId::new();
    repo.open_session(foreign_id, &foreign.pin).await?;
    assert!(
        resumed
            .freeze_admission(foreign.context(foreign_id, &request, &review))
            .await
            .is_err()
    );
    for field in 0..4 {
        let mut changed = f.pin.clone();
        match field {
            0 => changed.authority_profile_sha256 = digest_bytes(b"different-profile"),
            1 => changed.challenge_registry_sha256 = digest_bytes(b"different-registry"),
            2 => changed.extractor_registry_sha256 = digest_bytes(b"different-extractor"),
            _ => changed
                .authority_bundles
                .push(digest_bytes(b"different-bundle")),
        }
        let other = JobId::new();
        repo.open_session(other, &changed).await?;
        assert!(
            resumed
                .freeze_admission(f.context(other, &request, &review))
                .await
                .is_err()
        );
    }
    Ok(())
}

struct PublicationInterruption<'a> {
    inner: &'a dyn archcert_application::artifacts::ImmutableArtifactStore,
    kind: &'static str,
    armed: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl archcert_application::artifacts::ImmutableArtifactStore for PublicationInterruption<'_> {
    async fn put(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
        bytes: &[u8],
    ) -> Result<(), JobStoreError> {
        self.inner.put(project, reference, bytes).await?;
        let body: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| JobStoreError::Invalid)?;
        if body["kind"] == self.kind && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(JobStoreError::Unavailable);
        }
        Ok(())
    }
    async fn get(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
    ) -> Result<Vec<u8>, JobStoreError> {
        self.inner.get(project, reference).await
    }
}
async fn advance_review(
    workflow: &archcert_application::ironcrest::IroncrestWorkflow<'_>,
    f: &AdmissionFixture,
    id: JobId,
    request: &archcert_application::semantic::SemanticReviewRequest,
    reviewer: &dyn archcert_application::semantic::SemanticReviewer,
) -> Result<archcert_application::ironcrest::ReviewedIroncrestAdmission, JobStoreError> {
    workflow
        .prepare(request, &f.knowledge, &f.impact, f.profile.artifact())
        .await?;
    let review = workflow.review_or_restore(request, reviewer).await?;
    workflow
        .freeze_admission(f.context(id, request, &review))
        .await
}
#[tokio::test]
#[ignore = "requires real PostgreSQL and private immutable artifact storage"]
async fn ironcrest_pre_admission_publication_interruptions_recover_identical_artifacts() -> R {
    use archcert_application::ironcrest::*;
    use archcert_storage::artifacts::FilesystemArtifactStore;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let (repo, pool) = database().await?;
    for kind in [
        "ARCHCERT_KNOWLEDGE",
        "ARCHCERT_IMPACT",
        "ARCHCERT_SEMANTIC_REQUEST",
        "ARCHCERT_SEMANTIC_REVIEW",
        "ARCHCERT_SEMANTIC_GATE",
        "ARCHCERT_CHALLENGE_PLAN",
    ] {
        let f = admission_fixture(&repo).await?;
        let id = JobId::new();
        repo.open_session(id, &f.pin).await?;
        let request = f.review_request(id)?;
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let store =
            FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
        let interrupted = PublicationInterruption {
            inner: &store,
            kind,
            armed: AtomicBool::new(true),
        };
        let workflow = IroncrestWorkflow {
            repository: &repo,
            artifacts: &interrupted,
        };
        let reviewer = CountingSemanticReviewer(AtomicUsize::new(0));
        assert!(
            advance_review(&workflow, &f, id, &request, &reviewer)
                .await
                .is_err(),
            "checkpoint {kind}"
        );
        assert!(
            !interrupted.armed.load(Ordering::SeqCst),
            "checkpoint reached {kind}"
        );
        assert!(repo.get(id).await.is_err());
        let before = repo.review_session(f.pin.project, id).await?;
        let reconnected = PostgresJobRepository::from_pool(pool.clone());
        let resumed = IroncrestWorkflow {
            repository: &reconnected,
            artifacts: &store,
        };
        let admission = advance_review(&resumed, &f, id, &request, &reviewer).await?;
        assert_eq!(
            reviewer.0.load(Ordering::SeqCst),
            1,
            "invocations after {kind}"
        );
        let after = reconnected.review_session(f.pin.project, id).await?;
        for retained in before.evidence {
            assert!(after.evidence.iter().any(|e| e.role == retained.role
                && e.artifact == retained.artifact
                && e.available));
        }
        reconnected.admit_reviewed(&admission).await?;
        assert_eq!(repo.get(id).await?.inputs, *admission.inputs());
    }
    Ok(())
}
struct VetoReviewer {
    unavailable: bool,
}
#[async_trait::async_trait]
impl archcert_application::semantic::SemanticReviewer for VetoReviewer {
    async fn review(
        &self,
        request: &archcert_application::semantic::SemanticReviewRequest,
    ) -> Result<
        archcert_application::semantic::ReviewerOutput,
        archcert_application::semantic::SemanticReviewError,
    > {
        use archcert_application::semantic::*;
        if self.unavailable {
            return Err(SemanticReviewError::Unavailable);
        }
        Ok(ReviewerOutput {
            reported: ReviewerSelection::replay(),
            truncated: false,
            bytes: serde_json::to_vec(&SemanticReviewResponse {
                schema: 1,
                request_sha256: request.artifact().digest().clone(),
                complete: true,
                items: vec![SemanticItem {
                    id: "authority-blocker".into(),
                    kind: SemanticItemKind::BlockingConcern,
                    text: "Controlled authority-relevant blocking concern".into(),
                    related_authority_ids: vec![request.binding().policy.id.clone()],
                }],
                proposed_challenges: vec![],
            })
            .map_err(|_| SemanticReviewError::Malformed)?,
        })
    }
}
#[tokio::test]
#[ignore = "requires real PostgreSQL and private immutable artifact storage"]
async fn ironcrest_durable_blocker_and_provider_failure_never_admit_execution() -> R {
    use archcert_application::{ironcrest::*, semantic::*};
    use archcert_storage::artifacts::FilesystemArtifactStore;
    use std::os::unix::fs::PermissionsExt;
    let (repo, pool) = database().await?;
    for unavailable in [false, true] {
        let f = admission_fixture(&repo).await?;
        let id = JobId::new();
        repo.open_session(id, &f.pin).await?;
        let request = f.review_request(id)?;
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let store =
            FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
        let workflow = IroncrestWorkflow {
            repository: &repo,
            artifacts: &store,
        };
        workflow
            .prepare(&request, &f.knowledge, &f.impact, f.profile.artifact())
            .await?;
        let review = workflow
            .review_or_restore(&request, &VetoReviewer { unavailable })
            .await?;
        let expected = if unavailable {
            SemanticGateDecision::RequireMoreEvidence
        } else {
            SemanticGateDecision::Block
        };
        assert_eq!(workflow.persist_gate(&request, &review).await?, expected);
        assert!(
            workflow
                .freeze_admission(f.context(id, &request, &review))
                .await
                .is_err()
        );
        assert!(repo.get(id).await.is_err());
        let session = repo.review_session(f.pin.project, id).await?;
        assert!(session.review_claimed);
        assert!(
            session
                .evidence
                .iter()
                .any(|e| e.role == IroncrestEvidenceRole::Gate && e.available)
        );
    }
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    let certificates:i64=sqlx::query_scalar("SELECT count(*) FROM certification_jobs WHERE issuance IS NOT NULL OR certificate IS NOT NULL").fetch_one(&pool).await?;
    assert_eq!((jobs, certificates), (0, 0));
    Ok(())
}
