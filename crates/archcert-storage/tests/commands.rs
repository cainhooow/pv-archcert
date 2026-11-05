//! Real PostgreSQL command coordination; no browser or target execution is simulated.

use archcert_application::{glassmere::commands::*, jobs::*};
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{ControlCommandId, IdempotencyKey, JobId, JobInputs, JobState, LeaseToken, PolicyPin},
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};
use archcert_storage::PostgresJobRepository;
use sqlx::{PgPool, postgres::PgPoolOptions};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn fixture() -> R<(PostgresJobRepository, PgPool, ResolvedControlCommand)> {
    let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&url).await?;
    let schema = format!("commands_{}", JobId::new().to_string().replace('-', ""));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |c, _| {
            let schema = schema.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(schema)
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

    let scope = CommandScope {
        project: ProjectId::new(),
        repository: RepositoryId::parse("command/source")?,
        actor: GitActorId::parse(JobId::new().to_string())?,
    };
    let submission = SourceSubmissionId::new();
    let source = SourceSnapshot::seal(
        scope.project,
        scope.repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1_700_000_000,
    )?;
    repo.grant(scope.project, &scope.repository, &scope.actor)
        .await?;
    repo.register_source(&submission, &source).await?;
    let command = ResolvedControlCommand {
        schema: CONTROL_COMMAND_SCHEMA,
        authority_context: digest_bytes(b"explicit command fixture authority"),
        action: ResolvedControlAction::RequestCertification {
            inputs: Box::new(JobInputs {
                project: scope.project,
                repository: scope.repository.clone(),
                actor: scope.actor.clone(),
                submission,
                source: source.identity().clone(),
                policy: PolicyPin {
                    id: "development".into(),
                    version: "1.0.0".into(),
                    sha256: digest_bytes(b"policy"),
                },
                profile: "python".into(),
                image: format!("python@sha256:{}", "d".repeat(64)),
                plan_sha256: digest_bytes(b"plan"),
                authority_toml: "schema = 1".into(),
                maximum_attempts: 2,
            }),
            reviewed_session: None,
        },
        scope,
    };

    Ok((repo, pool, command))
}

fn key(value: &str) -> R<IdempotencyKey> {
    Ok(IdempotencyKey::parse(value.into())?)
}

async fn enable(repo: &PostgresJobRepository, command: &ResolvedControlCommand) -> R {
    repo.grant_control_command(&command.scope, &command.authority_context, &command.action)
        .await?;
    Ok(())
}

async fn admitted_job(repo: &PostgresJobRepository, command: &ResolvedControlCommand) -> R<JobId> {
    let ResolvedControlAction::RequestCertification { inputs, .. } = &command.action else {
        return Err("wrong fixture operation".into());
    };
    let job = JobRepository::create(
        repo,
        CreateJob {
            inputs: inputs.as_ref().clone(),
            idempotency: key(&JobId::new().to_string())?,
        },
    )
    .await?;

    Ok(job.id)
}

async fn assignment(
    repo: &PostgresJobRepository,
    command: &ResolvedControlCommand,
) -> R<ControlCommandAssignment> {
    enable(repo, command).await?;
    repo.accept(command, &key("request")?).await?;

    Ok(ControlCommandRepository::claim(repo, "dispatcher", 30)
        .await?
        .ok_or("no command claim")?)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_concurrent_keys_share_one_intent_and_conflicts_roll_back() -> R {
    let (repo, pool, command) = fixture().await?;
    enable(&repo, &command).await?;
    let first_key = key("tab-one")?;
    let second_key = key("tab-two")?;
    let (first, second, same_key) = tokio::join!(
        repo.accept(&command, &first_key),
        repo.accept(&command, &second_key),
        repo.accept(&command, &first_key),
    );
    let first = first?;
    assert_eq!(first.id, second?.id);
    assert_eq!(first.id, same_key?.id);
    assert_eq!(repo.accept(&command, &first_key).await?.id, first.id);

    let mut changed = command.clone();
    if let ResolvedControlAction::RequestCertification { inputs, .. } = &mut changed.action {
        inputs.plan_sha256 = digest_bytes(b"different plan");
    }
    assert!(matches!(
        repo.accept(&changed, &first_key).await,
        Err(JobStoreError::Conflict)
    ));
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM control_command_keys),(SELECT count(*) FROM control_command_audit)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 2, 3));

    let reopened = PostgresJobRepository::from_pool(pool.clone());
    let reloaded = ControlCommandRepository::get(&reopened, &command.scope, first.id).await?;
    assert_eq!(reloaded.request_sha256, command.digest()?);
    assert_eq!(reloaded.command.bytes()?, command.bytes()?);
    assert_eq!(reloaded.state, ControlCommandState::Requested);
    assert_eq!(reloaded.dispatches, 0);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_requires_explicit_operation_context_and_current_grants() -> R {
    let (repo, pool, command) = fixture().await?;
    let retry_key = key("request")?;
    assert!(matches!(
        repo.accept(&command, &retry_key).await,
        Err(JobStoreError::Unauthorized)
    ));
    enable(&repo, &command).await?;
    let accepted = repo.accept(&command, &retry_key).await?;

    let mut substituted = command.clone();
    substituted.authority_context = digest_bytes(b"new selection without grant");
    assert!(matches!(
        repo.accept(&substituted, &retry_key).await,
        Err(JobStoreError::Unauthorized)
    ));
    enable(&repo, &substituted).await?;
    assert!(matches!(
        repo.accept(&substituted, &retry_key).await,
        Err(JobStoreError::Conflict)
    ));

    sqlx::query("DELETE FROM control_command_grants")
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.accept(&command, &retry_key).await,
        Err(JobStoreError::Unauthorized)
    ));
    assert!(matches!(
        ControlCommandRepository::get(&repo, &command.scope, accepted.id).await,
        Err(JobStoreError::Unauthorized)
    ));
    assert!(
        ControlCommandRepository::claim(&repo, "dispatcher", 30)
            .await?
            .is_none()
    );
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM control_commands")
        .fetch_one(&pool)
        .await?;
    assert_eq!(retained, 1);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_scope_and_foreign_objects_never_grant_access() -> R {
    let (repo, _, command) = fixture().await?;
    enable(&repo, &command).await?;
    let accepted = repo.accept(&command, &key("request")?).await?;
    for change in 0..3 {
        let mut foreign = command.scope.clone();
        match change {
            0 => foreign.project = ProjectId::new(),
            1 => foreign.repository = RepositoryId::parse("foreign/source")?,
            _ => foreign.actor = GitActorId::parse(JobId::new().to_string())?,
        }
        assert!(matches!(
            ControlCommandRepository::get(&repo, &foreign, accepted.id).await,
            Err(JobStoreError::Unauthorized)
        ));
    }
    assert!(matches!(
        ControlCommandRepository::get(&repo, &command.scope, ControlCommandId::new()).await,
        Err(JobStoreError::Unauthorized)
    ));

    let mut missing = command.clone();
    missing.action = ResolvedControlAction::CancelEligibleJob { job: JobId::new() };
    enable(&repo, &missing).await?;
    assert!(matches!(
        repo.accept(&missing, &key("cancel")?).await,
        Err(JobStoreError::Unauthorized)
    ));

    let mut wrong_source = command;
    if let ResolvedControlAction::RequestCertification { inputs, .. } = &mut wrong_source.action {
        inputs.source.snapshot_sha256 = digest_bytes(b"unregistered source");
    }
    assert!(matches!(
        repo.accept(&wrong_source, &key("source")?).await,
        Err(JobStoreError::Unauthorized)
    ));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_dispatch_race_fencing_and_terminal_receipt_are_durable() -> R {
    let (repo, pool, command) = fixture().await?;
    enable(&repo, &command).await?;
    let accepted = repo.accept(&command, &key("request")?).await?;
    let (a, b) = tokio::join!(
        ControlCommandRepository::claim(&repo, "dispatcher-a", 30),
        ControlCommandRepository::claim(&repo, "dispatcher-b", 30),
    );
    let (a, b) = (a?, b?);
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let assignment = a.or(b).ok_or("no dispatcher")?;
    assert_eq!(assignment.record.dispatches, 1);
    assert_eq!(assignment.record.state, ControlCommandState::Processing);
    let wrong = ControlCommandLease {
        command: accepted.id,
        dispatcher: assignment.lease.dispatcher.clone(),
        token: LeaseToken::new(),
    };
    let outcome = ControlCommandOutcome::Rejected {
        reason: CommandFailure::ReviewRequired,
    };
    assert!(
        ControlCommandRepository::renew(&repo, &wrong, 30)
            .await
            .is_err()
    );
    assert!(repo.finish(&wrong, &outcome).await.is_err());
    assert!(
        ControlCommandRepository::renew(&repo, &assignment.lease, 301)
            .await
            .is_err()
    );
    ControlCommandRepository::renew(&repo, &assignment.lease, 30).await?;
    repo.finish(&assignment.lease, &outcome).await?;

    let record = ControlCommandRepository::get(&repo, &command.scope, accepted.id).await?;
    assert_eq!(record.state, ControlCommandState::Rejected);
    assert!(matches!(
        record.outcome,
        Some(ControlCommandOutcome::Rejected {
            reason: CommandFailure::ReviewRequired
        })
    ));
    assert!(repo.finish(&assignment.lease, &outcome).await.is_err());
    assert!(
        ControlCommandRepository::claim(&repo, "another", 30)
            .await?
            .is_none()
    );
    assert_eq!(
        repo.accept(&command, &key("request")?).await?.id,
        accepted.id
    );
    let fresh = repo.accept(&command, &key("another-tab")?).await?;
    assert_ne!(fresh.id, accepted.id);
    assert_eq!(fresh.state, ControlCommandState::Requested);
    for query in [
        "UPDATE control_commands SET state='REQUESTED',outcome=NULL",
        "UPDATE control_commands SET request_sha256=repeat('a',64)",
        "DELETE FROM control_commands",
        "UPDATE control_command_keys SET idempotency_key='replacement'",
        "DELETE FROM control_command_keys",
        "UPDATE control_command_audit SET event='CommandRequested'",
        "DELETE FROM control_command_audit",
    ] {
        assert!(sqlx::query(query).execute(&pool).await.is_err());
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_expired_dispatch_cannot_publish_or_revive_ownership() -> R {
    let (repo, _, command) = fixture().await?;
    enable(&repo, &command).await?;
    repo.accept(&command, &key("request")?).await?;
    let first = ControlCommandRepository::claim(&repo, "lost", 5)
        .await?
        .ok_or("no claim")?;
    // Real database expiry, without changing production limits or disabling state guards.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let outcome = ControlCommandOutcome::Inconclusive {
        reason: CommandFailure::UncertainOutcome,
    };
    assert!(
        ControlCommandRepository::renew(&repo, &first.lease, 30)
            .await
            .is_err()
    );
    assert!(repo.finish(&first.lease, &outcome).await.is_err());
    let second = ControlCommandRepository::claim(&repo, "replacement", 30)
        .await?
        .ok_or("no replacement")?;
    assert_eq!(second.record.id, first.record.id);
    assert_eq!(second.record.dispatches, 2);
    assert_ne!(second.lease.token, first.lease.token);
    assert_eq!(
        second.record.command.bytes()?,
        first.record.command.bytes()?
    );
    assert!(repo.finish(&first.lease, &outcome).await.is_err());
    repo.finish(&second.lease, &outcome).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_receipt_requires_real_scoped_domain_object() -> R {
    let (repo, _, command) = fixture().await?;
    enable(&repo, &command).await?;
    repo.accept(&command, &key("request")?).await?;
    let assignment = ControlCommandRepository::claim(&repo, "dispatcher", 30)
        .await?
        .ok_or("no claim")?;
    let effect = |job| ControlCommandOutcome::Applied {
        effect: Box::new(CommandEffect::CertificationRequested {
            job: Some(job),
            session: None,
        }),
    };
    assert!(matches!(
        repo.finish(&assignment.lease, &effect(JobId::new())).await,
        Err(JobStoreError::Precondition)
    ));

    let ResolvedControlAction::RequestCertification { inputs, .. } = &command.action else {
        return Err("wrong fixture operation".into());
    };
    let job = JobRepository::create(
        &repo,
        CreateJob {
            inputs: inputs.as_ref().clone(),
            idempotency: key("internal")?,
        },
    )
    .await?;
    repo.finish(&assignment.lease, &effect(job.id)).await?;
    let record = ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
    assert_eq!(record.state, ControlCommandState::Applied);
    assert_eq!(
        JobRepository::get(&repo, job.id).await?.state,
        archcert_domain::jobs::JobState::Queued
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_revocation_blocks_inflight_publication_without_erasing_history() -> R {
    let (repo, pool, command) = fixture().await?;
    enable(&repo, &command).await?;
    let accepted = repo.accept(&command, &key("request")?).await?;
    let assignment = ControlCommandRepository::claim(&repo, "dispatcher", 30)
        .await?
        .ok_or("no claim")?;
    sqlx::query("DELETE FROM repository_grants")
        .execute(&pool)
        .await?;

    let outcome = ControlCommandOutcome::Rejected {
        reason: CommandFailure::DomainPrecondition,
    };
    assert!(matches!(
        repo.finish(&assignment.lease, &outcome).await,
        Err(JobStoreError::Unauthorized)
    ));
    assert!(matches!(
        ControlCommandRepository::renew(&repo, &assignment.lease, 30).await,
        Err(JobStoreError::Unauthorized)
    ));
    let retained: (String, Option<serde_json::Value>, i64) = sqlx::query_as(
        "SELECT state,outcome,(SELECT count(*) FROM control_command_audit) FROM control_commands WHERE id=$1",
    )
    .bind(accepted.id.to_string())
    .fetch_one(&pool).await?;
    assert_eq!(retained.0, "PROCESSING");
    assert!(retained.1.is_none());
    assert_eq!(retained.2, 3);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_grant_lock_contention_has_a_database_deadline() -> R {
    let (repo, pool, command) = fixture().await?;
    enable(&repo, &command).await?;
    let mut blocked = pool.begin().await?;
    sqlx::query("SELECT actor FROM repository_grants FOR UPDATE")
        .fetch_all(&mut *blocked)
        .await?;

    let retry_key = key("request")?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        repo.accept(&command, &retry_key),
    )
    .await?;
    assert!(matches!(result, Err(JobStoreError::Unavailable)));
    blocked.rollback().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM control_commands")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);

    // The original key is still usable: no partial acceptance or phantom alias survived.
    repo.accept(&command, &retry_key).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_certification_mutation_and_receipt_share_one_durable_result() -> R {
    let (repo, pool, command) = fixture().await?;
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;
    let ControlCommandOutcome::Applied { effect } = outcome else {
        return Err("certification command did not apply".into());
    };
    let CommandEffect::CertificationRequested {
        job: Some(job),
        session: None,
    } = *effect
    else {
        return Err("wrong command effect".into());
    };

    let replay = repo.accept(&command, &key("another-tab")?).await?;
    assert_eq!(replay.id, assignment.record.id);
    assert_eq!(replay.state, ControlCommandState::Applied);
    assert!(
        repo.apply_job_command(&assignment.lease, &command.authority_context)
            .await
            .is_err()
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM certification_jobs),(SELECT count(*) FROM audit_events)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 2));
    assert_eq!(
        JobRepository::get(&repo, job).await?.state,
        JobState::Queued
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_changed_authority_context_cannot_select_a_new_default() -> R {
    let (repo, pool, command) = fixture().await?;
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &digest_bytes(b"new default"))
        .await?;

    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::UnsupportedAuthorityContext,
        }
    ));
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(jobs, 0);
    assert_eq!(
        ControlCommandRepository::get(&repo, &command.scope, assignment.record.id)
            .await?
            .state,
        ControlCommandState::Rejected
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_cancellation_is_terminal_without_target_or_policy_failure() -> R {
    let (repo, pool, mut command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;
    let original = JobRepository::get(&repo, job).await?;
    command.action = ResolvedControlAction::CancelEligibleJob { job };
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;

    assert!(matches!(outcome, ControlCommandOutcome::Applied { effect }
        if matches!(*effect, CommandEffect::JobCanceled { job: affected } if affected == job)));
    let canceled = JobRepository::get(&repo, job).await?;
    assert_eq!(canceled.state, JobState::Inconclusive);
    assert_eq!(
        canceled.failure,
        Some(archcert_domain::jobs::FailureCategory::OperatorCancellation)
    );
    assert_eq!(canceled.inputs, original.inputs);
    assert!(canceled.attempts.is_empty());
    assert!(
        canceled.evaluation.is_none()
            && canceled.issuance.is_none()
            && canceled.certificate.is_none()
    );
    assert!(JobRepository::claim(&repo, "worker", 30).await?.is_none());
    let canceled_events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event='JobCanceled'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(canceled_events, 1);
    assert!(
        sqlx::query("UPDATE certification_jobs SET state='QUEUED',failure=NULL")
            .execute(&pool)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_cancellation_and_worker_claim_have_one_locked_winner() -> R {
    let (repo, _, mut command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;
    command.action = ResolvedControlAction::CancelEligibleJob { job };
    let assignment = assignment(&repo, &command).await?;
    let (outcome, worker) = tokio::join!(
        repo.apply_job_command(&assignment.lease, &command.authority_context),
        JobRepository::claim(&repo, "racing-worker", 30),
    );
    let (outcome, worker) = (outcome?, worker?);
    let state = JobRepository::get(&repo, job).await?;

    match outcome {
        ControlCommandOutcome::Applied { effect } => {
            assert!(
                matches!(*effect, CommandEffect::JobCanceled { job: affected } if affected == job)
            );
            assert!(worker.is_none());
            assert_eq!(state.state, JobState::Inconclusive);
            assert!(state.attempts.is_empty());
        }
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition,
        } => {
            assert_eq!(worker.ok_or("claim winner missing")?.job.id, job);
            assert_eq!(state.state, JobState::Running);
            assert_eq!(state.attempts.len(), 1);
        }
        _ => return Err("unexpected racing outcome".into()),
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_cancellation_never_changes_running_work_or_its_lease() -> R {
    let (repo, _, mut command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;
    let worker = JobRepository::claim(&repo, "active-worker", 30)
        .await?
        .ok_or("no worker")?;
    JobRepository::start(&repo, &worker.lease).await?;
    command.action = ResolvedControlAction::CancelEligibleJob { job };
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;

    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition
        }
    ));
    let retained = JobRepository::get(&repo, job).await?;
    assert_eq!(retained.state, JobState::Running);
    assert_eq!(retained.attempts.len(), 1);
    assert_eq!(
        retained.attempts[0].state,
        archcert_domain::jobs::AttemptState::Running
    );
    JobRepository::renew(&repo, &worker.lease, 30).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_recovery_receipt_retains_original_attempt_after_worker_advances() -> R {
    let (repo, pool, mut command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;
    let old = JobRepository::claim(&repo, "lost-before-start", 5)
        .await?
        .ok_or("no worker")?;
    // Same controlled clock fixture as the original lease regressions; runtime bounds stay intact.
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1")
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    command.action = ResolvedControlAction::RetryEligibleJob {
        job,
        attempt: old.lease.attempt,
    };
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;

    assert!(matches!(outcome, ControlCommandOutcome::Applied { effect }
        if matches!(*effect, CommandEffect::JobRecoveryRequested { job: affected, attempt }
            if affected == job && attempt == old.lease.attempt)));
    let replacement = JobRepository::claim(&repo, "replacement", 30)
        .await?
        .ok_or("no replacement")?;
    assert_ne!(old.lease.attempt, replacement.lease.attempt);
    let replay = repo.accept(&command, &key("another-tab")?).await?;
    assert_eq!(replay.id, assignment.record.id);
    assert!(
        matches!(replay.outcome, Some(ControlCommandOutcome::Applied { effect })
        if matches!(*effect, CommandEffect::JobRecoveryRequested { attempt, .. } if attempt == old.lease.attempt))
    );
    let retained = JobRepository::get(&repo, job).await?;
    assert_eq!(retained.state, JobState::Running);
    assert_eq!(retained.attempts.len(), 2);
    assert!(JobRepository::renew(&repo, &old.lease, 30).await.is_err());

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_receipt_failure_rolls_back_both_admission_and_domain_audit() -> R {
    let (repo, pool, command) = fixture().await?;
    let assignment = assignment(&repo, &command).await?;
    sqlx::query(
        "CREATE FUNCTION fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.state='APPLIED' THEN RAISE EXCEPTION 'injected receipt failure'; END IF;
           RETURN NEW;
         END $$",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER fail_receipt BEFORE UPDATE ON control_commands
         FOR EACH ROW EXECUTE FUNCTION fail_receipt()",
    )
    .execute(&pool)
    .await?;

    assert!(matches!(
        repo.apply_job_command(&assignment.lease, &command.authority_context)
            .await,
        Err(JobStoreError::Unavailable)
    ));
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM certification_jobs),(SELECT count(*) FROM audit_events)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (0, 0));
    let retained =
        ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
    assert_eq!(retained.state, ControlCommandState::Processing);
    assert!(retained.outcome.is_none());

    sqlx::query("DROP TRIGGER fail_receipt ON control_commands")
        .execute(&pool)
        .await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;
    assert!(matches!(outcome, ControlCommandOutcome::Applied { .. }));
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(jobs, 1);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_retry_requires_confirmed_cleanup_after_started_attempt() -> R {
    let (repo, pool, mut command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;
    let worker = JobRepository::claim(&repo, "uncertain-worker", 5)
        .await?
        .ok_or("no worker")?;
    JobRepository::start(&repo, &worker.lease).await?;
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1")
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    command.action = ResolvedControlAction::RetryEligibleJob {
        job,
        attempt: worker.lease.attempt,
    };
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;

    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition
        }
    ));
    let retained = JobRepository::get(&repo, job).await?;
    assert_eq!(retained.state, JobState::Running);
    assert_eq!(retained.attempts.len(), 1);
    assert_eq!(
        retained.attempts[0].state,
        archcert_domain::jobs::AttemptState::Running
    );
    assert!(retained.attempts[0].runtime.is_none());
    assert!(
        JobRepository::claim(&repo, "replacement", 30)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_retry_cannot_expand_original_attempt_budget() -> R {
    let (repo, pool, mut command) = fixture().await?;
    if let ResolvedControlAction::RequestCertification { inputs, .. } = &mut command.action {
        inputs.maximum_attempts = 1;
    }
    command.authority_context = digest_bytes(b"explicit one-attempt fixture authority");
    let job = admitted_job(&repo, &command).await?;
    let worker = JobRepository::claim(&repo, "only-attempt", 5)
        .await?
        .ok_or("no worker")?;
    sqlx::query("UPDATE certification_attempts SET lease_until=leased_at+1")
        .execute(&pool)
        .await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    command.action = ResolvedControlAction::RetryEligibleJob {
        job,
        attempt: worker.lease.attempt,
    };
    let assignment = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&assignment.lease, &command.authority_context)
        .await?;

    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition
        }
    ));
    let retained = JobRepository::get(&repo, job).await?;
    assert_eq!(retained.state, JobState::Running);
    assert_eq!(retained.inputs.maximum_attempts, 1);
    assert_eq!(retained.attempts.len(), 1);
    assert!(
        JobRepository::claim(&repo, "replacement", 30)
            .await?
            .is_none()
    );

    // Existing authority recovery can close uncertainty, without granting another attempt.
    JobRepository::recover(&repo, job, worker.lease.attempt).await?;
    assert_eq!(
        JobRepository::get(&repo, job).await?.state,
        JobState::Inconclusive
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_cancellation_guard_rejects_missing_or_wrong_reason() -> R {
    let (repo, pool, command) = fixture().await?;
    let job = admitted_job(&repo, &command).await?;

    for reason in [
        None,
        Some("TARGET_FAILURE"),
        Some("POLICY_FAILURE"),
        Some("WORKER_LOSS"),
    ] {
        let result = sqlx::query(
            "UPDATE certification_jobs SET state='INCONCLUSIVE',failure=$2 WHERE id=$1",
        )
        .bind(job.to_string())
        .bind(reason)
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "missing or unrelated reason must not enable queued cancellation"
        );
        let retained = JobRepository::get(&repo, job).await?;
        assert_eq!(retained.state, JobState::Queued);
        assert!(retained.failure.is_none());
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_known_rejection_retains_old_key_and_coalesces_a_fresh_action() -> R {
    let (repo, pool, command) = fixture().await?;
    let original = assignment(&repo, &command).await?;
    repo.finish(
        &original.lease,
        &ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition,
        },
    )
    .await?;
    let original_key = key("request")?;
    let second_key = key("explicit-fresh-action")?;
    let third_key = key("duplicate-fresh-action")?;

    let (old, fresh, duplicate) = tokio::join!(
        repo.accept(&command, &original_key),
        repo.accept(&command, &second_key),
        repo.accept(&command, &third_key),
    );
    let (old, fresh, duplicate) = (old?, fresh?, duplicate?);
    assert_eq!(old.id, original.record.id);
    assert_eq!(old.state, ControlCommandState::Rejected);
    assert_ne!(fresh.id, old.id);
    assert_eq!(fresh.id, duplicate.id);

    let current = ControlCommandRepository::claim(&repo, "fresh-dispatcher", 30)
        .await?
        .ok_or("no fresh claim")?;
    assert_eq!(current.record.id, fresh.id);
    let result = repo
        .apply_job_command(&current.lease, &command.authority_context)
        .await?;
    assert!(matches!(result, ControlCommandOutcome::Applied { .. }));
    assert_eq!(
        repo.accept(&command, &key("fourth-tab")?).await?.id,
        fresh.id
    );
    assert_eq!(repo.accept(&command, &original_key).await?.id, old.id);
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM certification_jobs)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (2, 1));

    let mut substituted = command.clone();
    if let ResolvedControlAction::RequestCertification { inputs, .. } = &mut substituted.action {
        inputs.plan_sha256 = digest_bytes(b"changed original request");
    }
    assert!(matches!(
        repo.accept(&substituted, &original_key).await,
        Err(JobStoreError::Conflict)
    ));
    let retained = ControlCommandRepository::get(&repo, &command.scope, old.id).await?;
    assert_eq!(retained.state, ControlCommandState::Rejected);
    assert!(matches!(
        retained.outcome,
        Some(ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition,
        })
    ));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_uncertain_outcome_never_authorizes_repetition_with_a_new_key() -> R {
    let (repo, pool, command) = fixture().await?;
    let original = assignment(&repo, &command).await?;
    repo.finish(
        &original.lease,
        &ControlCommandOutcome::Inconclusive {
            reason: CommandFailure::UncertainOutcome,
        },
    )
    .await?;

    let first_key = key("new-key-one")?;
    let second_key = key("new-key-two")?;
    let (first, second) = tokio::join!(
        repo.accept(&command, &first_key),
        repo.accept(&command, &second_key)
    );
    assert_eq!(first?.id, original.record.id);
    assert_eq!(second?.id, original.record.id);
    assert!(
        ControlCommandRepository::claim(&repo, "new-dispatcher", 30)
            .await?
            .is_none()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM control_commands")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_applied_request_with_policy_failure_cannot_create_another_workflow() -> R {
    let (repo, pool, command) = fixture().await?;
    let original = assignment(&repo, &command).await?;
    let outcome = repo
        .apply_job_command(&original.lease, &command.authority_context)
        .await?;
    let ControlCommandOutcome::Applied { effect } = outcome else {
        return Err("wrong fixture outcome".into());
    };
    let CommandEffect::CertificationRequested { job: Some(job), .. } = *effect else {
        return Err("wrong fixture effect".into());
    };

    // Metadata-only negative lifecycle fixture; it establishes no runtime or positive evidence proof.
    let worker = JobRepository::claim(&repo, "denial-fixture", 30)
        .await?
        .ok_or("no worker")?;
    JobRepository::start(&repo, &worker.lease).await?;
    let execution = archcert_application::release::release_reference(b"negative execution fixture");
    repo.stage_artifact(job, Some(worker.lease.attempt), "EXECUTION", &execution)
        .await?;
    repo.artifact_available(job, Some(worker.lease.attempt), "EXECUTION", &execution)
        .await?;
    JobRepository::accept_evidence(&repo, &worker.lease, &execution).await?;
    let evaluation = archcert_application::release::release_reference(b"negative policy fixture");
    repo.stage_artifact(job, None, "EVALUATION", &evaluation)
        .await?;
    repo.artifact_available(job, None, "EVALUATION", &evaluation)
        .await?;
    JobRepository::record_evaluation(&repo, job, &evaluation, EvaluationDecision::NotEligible)
        .await?;

    let replay = repo
        .accept(&command, &key("new-key-after-policy-failure")?)
        .await?;
    assert_eq!(replay.id, original.record.id);
    assert_eq!(replay.state, ControlCommandState::Applied);
    let retained = JobRepository::get(&repo, job).await?;
    assert_eq!(retained.state, JobState::NotEligible);
    assert_eq!(retained.attempts.len(), 1);
    assert!(retained.certificate.is_none());
    assert!(
        JobRepository::claim(&repo, "forbidden-rerun", 30)
            .await?
            .is_none()
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM certification_jobs)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 1));

    Ok(())
}
