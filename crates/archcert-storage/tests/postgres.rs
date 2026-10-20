//! Real PostgreSQL regression tests. Run explicitly through scripts/test-ravenport.
use archcert_application::jobs::*;
use archcert_domain::{GitObjectId, ProjectId, Sha256Digest, ingress::*, jobs::*, source::*};
use archcert_storage::PostgresJobRepository;
use sqlx::{PgPool, postgres::PgPoolOptions};
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
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
fn artifact() -> R<ArtifactReference> {
    Ok(ArtifactReference {
        sha256: digest_bytes(b"fixture"),
        size: 7,
        schema: 1,
        producer: "regression".into(),
    })
}
async fn make_available(
    repo: &PostgresJobRepository,
    id: JobId,
    a: Option<AttemptId>,
    kind: &str,
) -> R<ArtifactReference> {
    let r = artifact()?;
    repo.stage_artifact(id, a, kind, &r).await?;
    repo.artifact_available(id, a, kind, &r).await?;
    Ok(r)
}
#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn concurrent_admission_is_idempotent_and_pins_inputs() -> R {
    let (repo, pool) = database().await?;
    let req = request(&repo).await?;
    let (a, b) = tokio::join!(repo.create(req.clone()), repo.create(req.clone()));
    let a = a?;
    let b = b?;
    assert_eq!(a.id, b.id);
    let reloaded = PostgresJobRepository::from_pool(pool.clone())
        .get(a.id)
        .await?;
    assert_eq!(reloaded.inputs, req.inputs);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    for change in 0..4 {
        let mut other = req.clone();
        match change {
            0 => other.inputs.policy.version = "2.0.0".into(),
            1 => other.inputs.image = format!("python@sha256:{}", "f".repeat(64)),
            2 => other.inputs.authority_toml = "changed".into(),
            _ => other.inputs.plan_sha256 = digest_bytes(b"other"),
        };
        assert!(matches!(
            repo.create(other).await,
            Err(JobStoreError::Conflict)
        ));
    }
    let mut wrong = req.clone();
    wrong.inputs.source.snapshot_sha256 = digest_bytes(b"wrong");
    assert!(matches!(
        repo.create(wrong).await,
        Err(JobStoreError::Unauthorized)
    ));
    let mut wrong = req;
    wrong.inputs.actor = GitActorId::parse(JobId::new().to_string())?;
    assert!(matches!(
        repo.create(wrong).await,
        Err(JobStoreError::Unauthorized)
    ));
    assert!(
        sqlx::query("UPDATE audit_events SET event='edited'")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query(
            "UPDATE certification_jobs SET inputs=inputs || '{\"profile\":\"latest\"}'::jsonb"
        )
        .execute(&pool)
        .await
        .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn workers_race_with_real_skip_locked_and_wrong_renewals_reject() -> R {
    let (repo, _) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let (a, b) = tokio::join!(repo.claim("worker-a", 30), repo.claim("worker-b", 30));
    let a = a?;
    let b = b?;
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let lease = a.or(b).ok_or("no winner")?.lease;
    assert_eq!(lease.job, id);
    let mut wrong = lease.clone();
    wrong.worker = "impostor".into();
    assert!(repo.renew(&wrong, 30).await.is_err());
    wrong = lease.clone();
    wrong.token = LeaseToken::new();
    assert!(repo.start(&wrong).await.is_err());
    assert!(repo.renew(&lease, 301).await.is_err());
    repo.renew(&lease, 30).await?;
    repo.start(&lease).await?;
    assert!(repo.start(&lease).await.is_err());
    assert!(
        repo.complete(
            id,
            &PersistedCertificate {
                issuance: PreparedIssuance {
                    certificate_sha256: digest_bytes(b"payload"),
                    signing_key_id: "a".repeat(64),
                    issued_at: 1
                },
                artifact: artifact()?,
                signature: "a".repeat(128),
                verified: true
            }
        )
        .await
        .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn expired_worker_is_fenced_and_history_survives_retry() -> R {
    let (repo, pool) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let first = repo.claim("lost-worker", 5).await?.ok_or("no claim")?;
    // Controlled database clock fixture: expiry without sleeping or weakening production bounds.
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1")
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    repo.recover(id, first.lease.attempt).await?;
    let second = repo
        .claim("replacement", 5)
        .await?
        .ok_or("no replacement")?;
    assert_ne!(first.lease.attempt, second.lease.attempt);
    assert!(repo.renew(&first.lease, 5).await.is_err());
    assert!(
        repo.accept_evidence(&first.lease, &artifact()?)
            .await
            .is_err()
    );
    repo.start(&second.lease).await?;
    let binding = RuntimeBinding {
        endpoint: "unix:///test-only.sock".into(),
        daemon_id: "test-runtime".into(),
        gate_root: "/authority/gates".into(),
    };
    repo.bind_runtime(&second.lease, &binding).await?;
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1 WHERE state='RUNNING'")
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(repo.recover(id, second.lease.attempt).await.is_err());
    assert!(
        repo.finish_cleanup(
            id,
            second.lease.attempt,
            &binding,
            RuntimeCleanupState::Succeeded
        )
        .await
        .is_err()
    );
    repo.fence_runtime(id, second.lease.attempt, &binding)
        .await?;
    repo.finish_cleanup(
        id,
        second.lease.attempt,
        &binding,
        RuntimeCleanupState::Failed,
    )
    .await?;
    assert!(repo.recover(id, second.lease.attempt).await.is_err());
    repo.fence_runtime(id, second.lease.attempt, &binding)
        .await?;
    repo.finish_cleanup(
        id,
        second.lease.attempt,
        &binding,
        RuntimeCleanupState::Succeeded,
    )
    .await?;
    repo.recover(id, second.lease.attempt).await?;
    let job = repo.get(id).await?;
    assert_eq!(job.state, JobState::Inconclusive);
    assert_eq!(job.attempts.len(), 2);
    assert!(
        job.attempts
            .iter()
            .all(|a| a.failure == Some(FailureCategory::WorkerLoss))
    );
    assert!(repo.claim("third", 5).await?.is_none());
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn staging_and_signing_recovery_require_exact_durable_bindings() -> R {
    let (repo, pool) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let a = repo.claim("worker", 30).await?.ok_or("no claim")?;
    repo.start(&a.lease).await?;
    let r = artifact()?;
    repo.stage_artifact(id, Some(a.lease.attempt), "EXECUTION", &r)
        .await?;
    assert!(repo.accept_evidence(&a.lease, &r).await.is_err());
    let mut wrong = r.clone();
    wrong.size += 1;
    assert!(
        repo.stage_artifact(id, Some(a.lease.attempt), "EXECUTION", &wrong)
            .await
            .is_err()
    );
    repo.artifact_available(id, Some(a.lease.attempt), "EXECUTION", &r)
        .await?;
    repo.accept_evidence(&a.lease, &r).await?;
    assert!(repo.renew(&a.lease, 30).await.is_err());
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    let repo = PostgresJobRepository::from_pool(pool.clone());
    assert_eq!(repo.get(id).await?.state, JobState::Evaluating);
    let evaluation = make_available(&repo, id, None, "EVALUATION").await?;
    repo.record_evaluation(id, &evaluation, EvaluationDecision::Eligible)
        .await?;
    let issuance = PreparedIssuance {
        certificate_sha256: digest_bytes(b"payload"),
        signing_key_id: "a".repeat(64),
        issued_at: 1700000000,
    };
    repo.prepare_issuance(id, &issuance).await?;
    repo.prepare_issuance(id, &issuance).await?;
    let mut wrong = issuance.clone();
    wrong.issued_at += 1;
    assert!(repo.prepare_issuance(id, &wrong).await.is_err());
    let cert = PersistedCertificate {
        issuance,
        artifact: make_available(&repo, id, None, "CERTIFICATE").await?,
        signature: "a".repeat(128),
        verified: true,
    };
    repo.note_failure(id, FailureCategory::SigningFailure)
        .await?;
    assert_eq!(
        repo.get(id).await?.failure,
        Some(FailureCategory::SigningFailure)
    );
    // Close every connection and build a new pool to prove durable reconnect behavior.
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await?;
    let options = pool
        .connect_options()
        .as_ref()
        .clone()
        .options([("search_path", schema)]);
    pool.close().await;
    let new_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    let repo = PostgresJobRepository::from_pool(new_pool);
    repo.complete(id, &cert).await?;
    repo.complete(id, &cert).await?;
    let job = repo.get(id).await?;
    assert_eq!(job.state, JobState::Completed);
    assert_eq!(job.certificate, Some(cert));
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    assert!(repo.claim("another", 5).await?.is_none());
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn negative_policy_never_retries_until_pass() -> R {
    let (repo, _) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let a = repo.claim("worker", 30).await?.ok_or("no claim")?;
    repo.start(&a.lease).await?;
    let r = make_available(&repo, id, Some(a.lease.attempt), "EXECUTION").await?;
    repo.accept_evidence(&a.lease, &r).await?;
    let e = make_available(&repo, id, None, "EVALUATION").await?;
    repo.record_evaluation(id, &e, EvaluationDecision::NotEligible)
        .await?;
    assert_eq!(repo.get(id).await?.state, JobState::NotEligible);
    assert!(repo.claim("retry", 30).await?.is_none());
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn inconclusive_evidence_is_terminal_and_cannot_be_reinterpreted() -> R {
    let (repo, _) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let a = repo.claim("uncertain", 30).await?.ok_or("no claim")?;
    repo.start(&a.lease).await?;
    let r = make_available(&repo, id, Some(a.lease.attempt), "EXECUTION").await?;
    repo.accept_evidence(&a.lease, &r).await?;
    let e = make_available(&repo, id, None, "EVALUATION").await?;
    repo.record_evaluation(id, &e, EvaluationDecision::Inconclusive)
        .await?;
    let job = repo.get(id).await?;
    assert_eq!(job.state, JobState::Inconclusive);
    assert_eq!(job.failure, Some(FailureCategory::InfrastructureFailure));
    assert!(job.evaluation_at.is_some());
    assert!(
        repo.record_evaluation(id, &e, EvaluationDecision::Eligible)
            .await
            .is_err()
    );
    assert!(repo.claim("retry", 30).await?.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn runtime_cleanup_requires_exact_binding_revocation_and_durable_success() -> R {
    let (repo, pool) = database().await?;
    let id = repo.create(request(&repo).await?).await?.id;
    let a = repo
        .claim("runtime-worker", 5)
        .await?
        .ok_or("missing claim")?;
    repo.start(&a.lease).await?;
    let binding = RuntimeBinding {
        endpoint: "unix:///dedicated.sock".into(),
        daemon_id: "dedicated-runtime".into(),
        gate_root: "/authority/gates".into(),
    };
    repo.bind_runtime(&a.lease, &binding).await?;
    assert!(repo.cleanup_candidate(id, a.lease.attempt).await.is_err());
    assert!(
        repo.fence_runtime(id, a.lease.attempt, &binding)
            .await
            .is_err()
    );
    let mut wrong = binding.clone();
    wrong.daemon_id = "another-runtime".into();
    assert!(repo.bind_runtime(&a.lease, &wrong).await.is_err());
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1 WHERE id=$1")
        .bind(a.lease.attempt.to_string())
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    repo.block_cleanup(id, a.lease.attempt, &binding).await?;
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    assert!(
        repo.finish_cleanup(
            id,
            a.lease.attempt,
            &binding,
            RuntimeCleanupState::Succeeded
        )
        .await
        .is_err()
    );
    assert!(
        repo.fence_runtime(id, AttemptId::new(), &binding)
            .await
            .is_err()
    );
    assert!(
        repo.fence_runtime(id, a.lease.attempt, &wrong)
            .await
            .is_err()
    );
    repo.fence_runtime(id, a.lease.attempt, &binding).await?;
    assert!(repo.renew(&a.lease, 5).await.is_err());
    assert!(repo.bind_runtime(&a.lease, &binding).await.is_err());
    repo.finish_cleanup(id, a.lease.attempt, &binding, RuntimeCleanupState::Failed)
        .await?;
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    let repo = PostgresJobRepository::from_pool(pool.clone());
    assert_eq!(
        repo.cleanup_candidate(id, a.lease.attempt).await?.cleanup,
        RuntimeCleanupState::Failed
    );
    repo.fence_runtime(id, a.lease.attempt, &binding).await?;
    repo.finish_cleanup(
        id,
        a.lease.attempt,
        &binding,
        RuntimeCleanupState::Succeeded,
    )
    .await?;
    assert!(
        repo.finish_cleanup(id, a.lease.attempt, &binding, RuntimeCleanupState::Failed)
            .await
            .is_err()
    );
    assert!(repo.recover(id, AttemptId::new()).await.is_err());
    repo.recover(id, a.lease.attempt).await?;
    let next = repo.claim("replacement", 5).await?.ok_or("missing retry")?;
    assert_ne!(next.lease.attempt, a.lease.attempt);
    assert!(repo.recover(id, a.lease.attempt).await.is_err());
    let events: Vec<String> =
        sqlx::query_scalar("SELECT event FROM audit_events WHERE attempt=$1 ORDER BY sequence")
            .bind(a.lease.attempt.to_string())
            .fetch_all(&pool)
            .await?;
    assert!(events.iter().any(|e| e == "ExecutionFenced"));
    assert!(events.iter().any(|e| e == "CleanupBlocked"));
    assert!(events.iter().any(|e| e == "CleanupSucceeded"));
    Ok(())
}
