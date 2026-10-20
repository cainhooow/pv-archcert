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
        SemanticGateDecision::Continue
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
        SemanticGateDecision::Continue
    );
    // A different valid response for the same request is not the accepted role.
    let alternate = SemanticReviewArtifact::accept(
        &request,
        Err(SemanticReviewError::Unavailable),
        1700000001,
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
