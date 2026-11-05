//! Real PostgreSQL command coordination; no browser or target execution is simulated.

use archcert_application::{glassmere::commands::*, jobs::*};
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{ControlCommandId, IdempotencyKey, JobId, JobInputs, LeaseToken, PolicyPin},
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
        repo.accept(&command, &key("another-tab")?).await?.id,
        accepted.id
    );
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
