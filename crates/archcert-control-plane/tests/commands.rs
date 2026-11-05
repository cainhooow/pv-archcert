//! Real PostgreSQL command authentication, object scope and durable acceptance.
//! Metadata fixtures establish no target execution or certificate issuance.

use archcert_application::{glassmere::commands::*, jobs::*};
use archcert_control_plane::{
    AuthorityGrant, ControlPlane, ControlPlaneConfiguration, commands::CommandCredentials,
};
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    jobs::{IdempotencyKey, JobId, JobState},
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};
use archcert_gateway::{DevelopmentSubmissionStore, IngressEvidence, SubmissionStore};
use archcert_source::{GitObjectFormat, PackLimits};
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{os::unix::fs::PermissionsExt, sync::Arc};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const COMMAND_TOKEN: &str = "public-regression-command-token-00000001";

struct Fixture {
    state: ControlPlane,
    pool: PgPool,
    credentials: CommandCredentials,
    submission: SourceSubmissionId,
    _directory: tempfile::TempDir,
}

async fn fixture(reviewed: bool) -> Result<Fixture> {
    let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&url).await?;
    let schema = format!("command_auth_{}", JobId::new().to_string().replace('-', ""));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |connection, _| {
            let schema = schema.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(schema)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let repository = PostgresJobRepository::from_pool(pool.clone());
    repository.migrate().await?;

    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = directory.path().canonicalize()?;
    let source_store = root.join("sources");
    let artifact_root = root.join("artifacts");
    std::fs::create_dir(&source_store)?;
    std::fs::create_dir(&artifact_root)?;
    std::fs::set_permissions(&source_store, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&artifact_root, std::fs::Permissions::from_mode(0o700))?;
    let grant = AuthorityGrant {
        project: ProjectId::new(),
        repository: RepositoryId::parse("fixture/commands")?,
        actor: GitActorId::parse(JobId::new().to_string())?,
        token_sha256: digest_bytes(b"public-regression-legacy-token-00000001"),
        profile: "python".into(),
        image: format!("python@sha256:{}", "a".repeat(64)),
        authority_toml: include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml").into(),
        maximum_attempts: 2,
        ironcrest: reviewed,
        greywatch: false,
        semantic_request_bytes: None,
        ironcrest_baseline: None,
    };
    let submission = SourceSubmissionId::new();
    let source = SourceSnapshot::seal(
        grant.project,
        grant.repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1_700_000_000,
    )?;
    let evidence = IngressEvidence {
        submission: submission.clone(),
        actor: grant.actor.clone(),
        device: DeviceKeyId::parse("c".repeat(64))?,
        project: grant.project,
        repository: grant.repository.clone(),
        transport: "SSH_PUBLIC_KEY".into(),
        received_refs: vec!["refs/heads/main".into()],
        requested_commit: Some(source.identity().commit.clone()),
        source: Some(source.identity().clone()),
        object_format: GitObjectFormat::Sha1,
        pack_sha256: None,
        pack_bytes: 0,
        pack_objects: 0,
        pack_limits: PackLimits::default(),
        git_adapter: None,
        lfs_unresolved: 0,
        submodules_unresolved: 0,
        external_sources: vec![],
        source_schema: 1,
        resolution: None,
        completeness: Some(source.status()),
        status: "ACCEPTED".into(),
        received_at: 1_700_000_000,
        accepted_at: Some(1_700_000_000),
        events: vec![],
        candidate: format!("candidate/{submission}"),
    };
    let mut store = DevelopmentSubmissionStore::open(&source_store, 10)?;
    store.accept(&source, &evidence)?;
    drop(store);

    let credential_path = root.join("commands.json");
    std::fs::write(
        &credential_path,
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "principals": [{
                "scope": {"project": grant.project, "repository": grant.repository, "actor": grant.actor},
                "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
                "operations": ["REQUEST_CERTIFICATION", "CANCEL_ELIGIBLE_JOB", "RETRY_ELIGIBLE_JOB"],
            }],
        }))?,
    )?;
    std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))?;
    let configuration = ControlPlaneConfiguration {
        source_store,
        artifact_root: artifact_root.clone(),
        grants: vec![grant],
    };
    let credentials = CommandCredentials::load(&credential_path, &configuration)?;
    let state = ControlPlane {
        repository,
        artifacts: Arc::new(FilesystemArtifactStore::open_unencrypted_development(
            &artifact_root,
        )?),
        configuration,
    };

    Ok(Fixture {
        state,
        pool,
        credentials,
        submission,
        _directory: directory,
    })
}

fn authorization(
    fixture: &Fixture,
    operation: ControlOperation,
) -> Result<archcert_control_plane::commands::CommandAuthorization> {
    let grant = &fixture.state.configuration.grants[0];
    Ok(fixture.credentials.authorize(
        &fixture.state.configuration,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        operation,
        Some(&grant.command_context()?),
    )?)
}

fn key(value: &str) -> Result<IdempotencyKey> {
    Ok(IdempotencyKey::parse(value.into())?)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn authenticated_certification_coalesces_before_creating_a_job() -> Result {
    let fixture = fixture(false).await?;

    assert!(matches!(
        fixture.state.provision_commands(&fixture.credentials).await,
        Err(JobStoreError::Unauthorized)
    ));
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM repository_grants")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(grants, 0);

    let auth = authorization(&fixture, ControlOperation::RequestCertification)?;
    let first_key = key("first-tab")?;

    assert!(matches!(
        fixture
            .state
            .request_certification(&auth, fixture.submission.clone(), None, &first_key)
            .await,
        Err(JobStoreError::Unauthorized)
    ));

    fixture.state.provision().await?;
    fixture
        .state
        .provision_commands(&fixture.credentials)
        .await?;
    let second_key = key("second-tab")?;

    let (first, duplicate) = tokio::join!(
        fixture
            .state
            .request_certification(&auth, fixture.submission.clone(), None, &first_key),
        fixture
            .state
            .request_certification(&auth, fixture.submission.clone(), None, &second_key),
    );
    let first = first.map_err(|error| format!("first certification acceptance: {error}"))?;
    assert_eq!(
        first.id,
        duplicate
            .map_err(|error| format!("duplicate certification acceptance: {error}"))?
            .id
    );
    assert_eq!(first.state, ControlCommandState::Requested);
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM certification_jobs)",
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (1, 0));

    let assignment =
        ControlCommandRepository::claim(&fixture.state.repository, "authority-dispatcher", 30)
            .await?
            .ok_or("no command")?;
    fixture
        .state
        .repository
        .apply_job_command(&assignment.lease, auth.context())
        .await?;
    let replay = fixture
        .state
        .request_certification(&auth, fixture.submission.clone(), None, &key("third-tab")?)
        .await?;
    assert_eq!(replay.id, first.id);
    assert_eq!(replay.state, ControlCommandState::Applied);
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(jobs, 1);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn authenticated_cancellation_rejects_wrong_operation_foreign_actor_and_revoked_grant()
-> Result {
    let fixture = fixture(false).await?;
    fixture.state.provision().await?;
    fixture
        .state
        .provision_commands(&fixture.credentials)
        .await?;
    let grant = &fixture.state.configuration.grants[0];
    let job = fixture
        .state
        .submit(
            grant.actor.clone(),
            grant.project,
            grant.repository.clone(),
            fixture.submission.clone(),
            key("legacy-fixture")?,
        )
        .await?;
    let cert_auth = authorization(&fixture, ControlOperation::RequestCertification)?;

    assert!(matches!(
        fixture
            .state
            .request_cancellation(&cert_auth, job.id, &key("wrong-operation")?)
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    let cancel_auth = authorization(&fixture, ControlOperation::CancelEligibleJob)?;

    assert!(matches!(
        fixture
            .state
            .request_cancellation(&cancel_auth, JobId::new(), &key("foreign-id")?)
            .await,
        Err(JobStoreError::Unauthorized)
    ));

    // A project grant permits reading shared history, not mutating another actor's work.
    let foreign_actor = GitActorId::parse(JobId::new().to_string())?;
    fixture
        .state
        .repository
        .grant(grant.project, &grant.repository, &foreign_actor)
        .await?;
    let mut foreign_inputs = job.inputs.clone();
    foreign_inputs.actor = foreign_actor;
    let foreign_job = JobRepository::create(
        &fixture.state.repository,
        CreateJob {
            inputs: foreign_inputs,
            idempotency: key("foreign-job")?,
        },
    )
    .await?;
    assert!(matches!(
        fixture
            .state
            .request_cancellation(&cancel_auth, foreign_job.id, &key("foreign-actor")?)
            .await,
        Err(JobStoreError::Unauthorized)
    ));

    let accepted = fixture
        .state
        .request_cancellation(&cancel_auth, job.id, &key("cancel")?)
        .await?;
    assert!(matches!(
        fixture.state.command_status(&cert_auth, accepted.id).await,
        Err(JobStoreError::Unauthorized)
    ));
    let assignment =
        ControlCommandRepository::claim(&fixture.state.repository, "authority-dispatcher", 30)
            .await?
            .ok_or("no cancellation")?;
    fixture
        .state
        .repository
        .apply_job_command(&assignment.lease, cancel_auth.context())
        .await?;
    assert_eq!(
        JobRepository::get(&fixture.state.repository, job.id)
            .await?
            .state,
        JobState::Inconclusive
    );
    assert_eq!(
        fixture
            .state
            .command_status(&cancel_auth, accepted.id)
            .await?
            .state,
        ControlCommandState::Applied
    );

    sqlx::query("DELETE FROM control_command_grants")
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .state
            .command_status(&cancel_auth, accepted.id)
            .await,
        Err(JobStoreError::Unauthorized)
    ));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn certification_cannot_downgrade_review_or_reinterpret_changed_context() -> Result {
    let mut fixture = fixture(true).await?;
    fixture.state.provision().await?;
    fixture
        .state
        .provision_commands(&fixture.credentials)
        .await?;
    let auth = authorization(&fixture, ControlOperation::RequestCertification)?;
    assert!(matches!(
        fixture
            .state
            .request_certification(
                &auth,
                fixture.submission.clone(),
                None,
                &key("omit-review")?
            )
            .await,
        Err(JobStoreError::Precondition)
    ));
    let grant = &fixture.state.configuration.grants[0];
    let session = fixture
        .state
        .open_ironcrest(
            grant.actor.clone(),
            grant.project,
            grant.repository.clone(),
            fixture.submission.clone(),
            JobId::new(),
        )
        .await?;
    let accepted = fixture
        .state
        .request_certification(
            &auth,
            fixture.submission.clone(),
            Some(session.id),
            &key("reviewed")?,
        )
        .await?;
    assert_eq!(accepted.state, ControlCommandState::Requested);
    fixture.state.configuration.grants[0].maximum_attempts = 1;
    assert!(matches!(
        fixture
            .state
            .request_certification(
                &auth,
                fixture.submission.clone(),
                Some(session.id),
                &key("reviewed")?
            )
            .await,
        Err(JobStoreError::Precondition)
    ));
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(jobs, 0);

    Ok(())
}
