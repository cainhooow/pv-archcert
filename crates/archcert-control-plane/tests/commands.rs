//! Real PostgreSQL command authentication, object scope and durable acceptance.
//! Metadata fixtures establish no target execution or certificate issuance.

#[path = "commands/release_build.rs"]
mod release_build;

use archcert_application::release::*;
use archcert_application::{glassmere::commands::*, jobs::*};
use archcert_control_plane::{
    AuthorityGrant, ControlPlane, ControlPlaneConfiguration, commands::CommandCredentials,
};
use archcert_domain::release::CertifiedSourceIdentity;
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

// These rows establish scoped request admission only. No certificate, permit or
// runtime evidence is manufactured or accepted by a verifier in this fixture.
async fn readiness_invocation(
    fixture: &Fixture,
) -> Result<archcert_domain::release::BuildInvocationIdentity> {
    let grant = &fixture.state.configuration.grants[0];
    let job = fixture
        .state
        .submit(
            grant.actor.clone(),
            grant.project,
            grant.repository.clone(),
            fixture.submission.clone(),
            IdempotencyKey::parse("readiness-source-metadata".into())?,
        )
        .await?;
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"metadata dependencies"),
            toolchain_sha256: digest_bytes(b"metadata toolchain"),
        },
        "fixture",
    )?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: CertifiedSourceIdentity {
            project: grant.project,
            repository: grant.repository.clone(),
            source: job.inputs.source,
            certificate_sha256: digest_bytes(b"metadata certificate identity"),
        },
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: job.inputs.policy.sha256,
        source_authority_key_sha256: digest_bytes(b"metadata source key"),
        release_authority_key_sha256: digest_bytes(b"metadata release key"),
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };
    let admission = ReleaseAdmission {
        input_reference: release_reference(&release_bytes(&input)?),
        input,
        submission: fixture.submission.clone(),
        actor: grant.actor.clone(),
    };
    ReleaseRepository::open(&fixture.state.repository, &admission).await?;

    Ok(admission.input.identity()?)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn authenticated_readiness_requests_keep_original_keys_and_scope_fresh_observations() -> Result
{
    let fixture = fixture(false).await?;
    fixture.state.provision().await?;
    let grant = &fixture.state.configuration.grants[0];
    let path = fixture
        .state
        .configuration
        .artifact_root
        .parent()
        .ok_or("fixture root")?
        .join("readiness-credentials.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "principals": [{
                "scope": {
                    "project": grant.project,
                    "repository": grant.repository,
                    "actor": grant.actor,
                },
                "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
                "operations": ["REQUEST_RELEASE_READINESS_EVALUATION"],
            }],
        }))?,
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let credentials = CommandCredentials::load(&path, &fixture.state.configuration)?;
    fixture.state.provision_commands(&credentials).await?;
    let readiness_authorization = credentials.authorize(
        &fixture.state.configuration,
        COMMAND_TOKEN,
        grant.project,
        &grant.repository,
        ControlOperation::RequestReleaseReadinessEvaluation,
        Some(&grant.command_context()?),
    )?;
    let invocation = readiness_invocation(&fixture).await?;
    let first_key = IdempotencyKey::parse("first-observation".into())?;

    let first = fixture
        .state
        .request_readiness(&readiness_authorization, invocation.clone(), &first_key)
        .await?;
    let retry = fixture
        .state
        .request_readiness(&readiness_authorization, invocation.clone(), &first_key)
        .await?;
    let fresh = fixture
        .state
        .request_readiness(
            &readiness_authorization,
            invocation.clone(),
            &IdempotencyKey::parse("explicit-fresh-observation".into())?,
        )
        .await?;
    assert_eq!(first.id, retry.id);
    assert_ne!(first.id, fresh.id);
    assert_eq!(first.state, ControlCommandState::Requested);

    let wrong_operation = authorization(&fixture, ControlOperation::CancelEligibleJob)?;
    assert!(matches!(
        fixture
            .state
            .request_readiness(
                &wrong_operation,
                invocation.clone(),
                &IdempotencyKey::parse("wrong-operation".into())?
            )
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    assert!(matches!(
        fixture
            .state
            .request_readiness(
                &readiness_authorization,
                archcert_domain::release::BuildInvocationIdentity(digest_bytes(
                    b"absent invocation"
                )),
                &IdempotencyKey::parse("wrong-object".into())?
            )
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    sqlx::query(
        "DELETE FROM control_command_grants WHERE operation='REQUEST_RELEASE_READINESS_EVALUATION'",
    )
    .execute(&fixture.pool)
    .await?;
    assert!(matches!(
        fixture
            .state
            .request_readiness(
                &readiness_authorization,
                invocation,
                &IdempotencyKey::parse("revoked".into())?
            )
            .await,
        Err(JobStoreError::Unauthorized)
    ));

    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_keys),
                (SELECT count(*) FROM release_invocations)",
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (2, 2, 1));

    Ok(())
}

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
        release_build: None,
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
        diagnostics: Default::default(),
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
        Some(&grant.command_context_for(operation)?),
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
