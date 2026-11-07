#[path = "tests/readiness.rs"]
mod readiness;

#[path = "tests/build_dispatch.rs"]
mod build_dispatch;

#[path = "tests/build_http.rs"]
mod build_http;

use super::*;
use archcert_application::{glassmere::commands::*, jobs::*};
use archcert_control_plane::{AuthorityGrant, ControlPlane, ControlPlaneConfiguration};
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{JobId, JobInputs, JobState, PolicyPin},
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request as HttpRequest},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use tokio::io::AsyncBufReadExt;
use tower::ServiceExt;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const COMMAND_TOKEN: &str = "public-regression-command-token-00000001";
const LEGACY_TOKEN: &str = "public-regression-legacy-token-000000001";

struct Fixture {
    state: ApiState,
    pool: PgPool,
    job: JobId,
    body: serde_json::Value,
    credential_path: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

async fn fixture(real: bool) -> Result<Fixture> {
    let pool = if real {
        let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
        let admin = PgPool::connect(&url).await?;
        let schema = format!("command_http_{}", JobId::new().to_string().replace('-', ""));
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await?;
        PgPoolOptions::new()
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
            .await?
    } else {
        PgPoolOptions::new().connect_lazy("postgres://unreachable@127.0.0.1:1/no_database")?
    };
    let repository = PostgresJobRepository::from_pool(pool.clone());
    if real {
        repository.migrate().await?;
    }

    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = directory.path().canonicalize()?;
    let artifacts = Arc::new(FilesystemArtifactStore::open_unencrypted_development(
        &root,
    )?);
    let grant = AuthorityGrant {
        project: ProjectId::new(),
        repository: RepositoryId::parse("fixture/commands")?,
        actor: GitActorId::parse(JobId::new().to_string())?,
        token_sha256: digest_bytes(LEGACY_TOKEN.as_bytes()),
        profile: "python".into(),
        image: format!("python@sha256:{}", "a".repeat(64)),
        authority_toml: include_str!("../../../../docs/policy/CONTROLLED_AUTHORITY.toml").into(),
        maximum_attempts: 2,
        ironcrest: false,
        greywatch: false,
        semantic_request_bytes: None,
        ironcrest_baseline: None,
        release_build: None,
    };
    let scope = CommandScope {
        project: grant.project,
        repository: grant.repository.clone(),
        actor: grant.actor.clone(),
    };
    let context = grant.command_context()?;
    let credential_path = root.join("commands.json");
    std::fs::write(
        &credential_path,
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "principals": [{
                "scope": scope,
                "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
                "operations": ["CANCEL_ELIGIBLE_JOB"]
            }],
        }))?,
    )?;
    std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))?;
    let control = Arc::new(ControlPlane {
        repository,
        artifacts,
        configuration: ControlPlaneConfiguration {
            source_store: "/unused".into(),
            artifact_root: root,
            grants: vec![grant],
        },
    });

    let job = if real {
        control.provision().await?;
        let credentials = CommandCredentials::load(&credential_path, &control.configuration)?;
        control.provision_commands(&credentials).await?;
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
        control
            .repository
            .register_source(&submission, &source)
            .await?;
        JobRepository::create(
            &control.repository,
            CreateJob {
                inputs: JobInputs {
                    project: scope.project,
                    repository: scope.repository.clone(),
                    actor: scope.actor,
                    submission,
                    source: source.identity().clone(),
                    policy: PolicyPin {
                        id: "development".into(),
                        version: "1.0.0".into(),
                        sha256: digest_bytes(b"metadata fixture"),
                    },
                    profile: "python".into(),
                    image: format!("python@sha256:{}", "a".repeat(64)),
                    plan_sha256: digest_bytes(b"metadata fixture plan"),
                    authority_toml: "PRIVATE_RECIPE_CANARY".into(),
                    maximum_attempts: 2,
                },
                idempotency: IdempotencyKey::parse("fixture".into())?,
            },
        )
        .await?
        .id
    } else {
        JobId::new()
    };
    let body = serde_json::json!({
        "schema": 1,
        "project": scope.project,
        "repository": scope.repository,
        "authority_context": context,
        "action": {
            "kind": "CANCEL_ELIGIBLE_JOB",
            "job": job
        },
    });

    Ok(Fixture {
        state: ApiState {
            control,
            command_credentials: Some(credential_path.clone()),
            command_slots: Arc::new(tokio::sync::Semaphore::new(8)),
            platform: None,
        },
        pool,
        job,
        body,
        credential_path,
        _directory: directory,
    })
}

fn post(body: &serde_json::Value, token: Option<&str>, key: &str) -> Result<HttpRequest<Body>> {
    let mut request = HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v2/commands")
        .header("content-type", "application/json")
        .header("idempotency-key", key);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }

    Ok(request.body(Body::from(serde_json::to_vec(body)?))?)
}

async fn json(response: Response) -> Result<serde_json::Value> {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let bytes = to_bytes(response.into_body(), 128 * 1024).await?;
    let text = std::str::from_utf8(&bytes)?;
    for excluded in [
        COMMAND_TOKEN,
        LEGACY_TOKEN,
        "PRIVATE_RECIPE_CANARY",
        "authority_toml",
        "lease",
    ] {
        assert!(!text.contains(excluded), "private value leaked: {excluded}");
    }

    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::test]
async fn command_http_denies_missing_legacy_ambiguous_and_wrong_operation_credentials() -> Result {
    let fixture = fixture(false).await?;
    let app = crate::router(fixture.state.clone());

    for token in [
        None,
        Some(LEGACY_TOKEN),
        Some("unknown-public-regression-token-00000001"),
    ] {
        let response = app
            .clone()
            .oneshot(post(&fixture.body, token, "deny")?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    let mut ambiguous = post(&fixture.body, Some(COMMAND_TOKEN), "deny")?;
    ambiguous.headers_mut().append(
        header::AUTHORIZATION,
        header::HeaderValue::from_static("Bearer second-public-regression-token-00000001"),
    );
    assert_eq!(
        app.clone().oneshot(ambiguous).await?.status(),
        StatusCode::UNAUTHORIZED
    );

    let mut wrong_operation = fixture.body.clone();
    wrong_operation["action"] = serde_json::json!({
        "kind": "REQUEST_CERTIFICATION",
        "source_submission": SourceSubmissionId::new()
    });
    assert_eq!(
        app.clone()
            .oneshot(post(&wrong_operation, Some(COMMAND_TOKEN), "deny")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let legacy_request = HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/certifications")
        .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
        .header("idempotency-key", "deny")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "project": fixture.body["project"],
            "repository": fixture.body["repository"],
            "source_submission": SourceSubmissionId::new()
        }))?))?;
    assert_eq!(
        app.oneshot(legacy_request).await?.status(),
        StatusCode::UNAUTHORIZED
    );

    Ok(())
}

#[tokio::test]
async fn command_http_enforces_bounds_private_reload_and_explicit_opt_in() -> Result {
    let fixture = fixture(false).await?;
    let app = crate::router(fixture.state.clone());
    let mut forged = fixture.body.clone();
    forged["role"] = serde_json::json!("Administrator");
    assert_eq!(
        app.clone()
            .oneshot(post(&forged, Some(COMMAND_TOKEN), "deny")?)
            .await?
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut oversized = fixture.body.clone();
    oversized["padding"] = serde_json::json!("a".repeat(5000));
    assert_eq!(
        app.clone()
            .oneshot(post(&oversized, Some(COMMAND_TOKEN), "deny")?)
            .await?
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let uri = format!("/api/v2/command-context?padding={}", "a".repeat(800));
    assert_eq!(
        app.clone()
            .oneshot(HttpRequest::builder().uri(uri).body(Body::empty())?)
            .await?
            .status(),
        StatusCode::URI_TOO_LONG
    );
    let slots = fixture
        .state
        .command_slots
        .clone()
        .acquire_many_owned(8)
        .await?;
    assert_eq!(
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "busy")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(slots);

    std::fs::set_permissions(
        &fixture.credential_path,
        std::fs::Permissions::from_mode(0o644),
    )?;
    assert_eq!(
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "public-file")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!ready(&fixture.state).await);
    std::fs::remove_file(&fixture.credential_path)?;
    assert_eq!(
        app.oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "missing-file")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let mut disabled = fixture.state.clone();
    disabled.command_credentials = None;
    assert_eq!(
        crate::router(disabled)
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "disabled")?)
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn command_http_duplicates_scope_and_durable_receipts_use_real_postgres() -> Result {
    let fixture = fixture(true).await?;
    fixture
        .state
        .control
        .repository
        .check_command_readiness()
        .await?;
    let app = crate::router(fixture.state.clone());
    let (first, same_key, another_tab) = tokio::join!(
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "first-tab")?),
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "first-tab")?),
        app.clone()
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "second-tab")?),
    );
    let mut receipts = Vec::new();
    for response in [first?, same_key?, another_tab?] {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        receipts.push(json(response).await?);
    }
    assert_eq!(receipts[0]["command_id"], receipts[1]["command_id"]);
    assert_eq!(receipts[0]["command_id"], receipts[2]["command_id"]);
    assert_eq!(receipts[0]["state"], "REQUESTED");
    let assignment = ControlCommandRepository::claim(
        &fixture.state.control.repository,
        "authority-dispatcher",
        30,
    )
    .await?
    .ok_or("no command")?;
    fixture
        .state
        .control
        .repository
        .apply_job_command(
            &assignment.lease,
            &assignment.record.command.authority_context,
        )
        .await?;

    let query = format!(
        "project={}&repository=fixture/commands&operation=CANCEL_ELIGIBLE_JOB&authority_context={}",
        fixture.body["project"].as_str().ok_or("project")?,
        fixture.body["authority_context"]
            .as_str()
            .ok_or("context")?
    );
    let uri = format!(
        "/api/v2/commands/{}?{query}",
        receipts[0]["command_id"].as_str().ok_or("id")?
    );
    let response = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri(&uri)
                .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt = json(response).await?;
    assert_eq!(receipt["state"], "APPLIED");
    assert_eq!(receipt["outcome"]["effect"]["kind"], "JOB_CANCELED");
    assert_eq!(
        JobRepository::get(&fixture.state.control.repository, fixture.job)
            .await?
            .state,
        JobState::Inconclusive
    );

    let mut foreign = fixture.body.clone();
    foreign["action"]["job"] = serde_json::to_value(JobId::new())?;
    assert_eq!(
        app.clone()
            .oneshot(post(&foreign, Some(COMMAND_TOKEN), "foreign-object")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    foreign["project"] = serde_json::to_value(ProjectId::new())?;
    assert_eq!(
        app.clone()
            .oneshot(post(&foreign, Some(COMMAND_TOKEN), "foreign-project")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM audit_events WHERE event='JobCanceled')")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(counts, (1, 1));

    // A daemon restart may select new authority for future requests. Inspection
    // still binds the original receipt, without making its old selection current.
    let mut configuration = fixture.state.control.configuration.clone();
    configuration.grants[0].maximum_attempts = 1;
    let current_context = configuration.grants[0].command_context()?;
    let restarted = crate::router(ApiState {
        control: Arc::new(ControlPlane {
            repository: fixture.state.control.repository.clone(),
            artifacts: fixture.state.control.artifacts.clone(),
            configuration,
        }),
        ..fixture.state.clone()
    });
    let historical = restarted
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri(&uri)
                .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(historical.status(), StatusCode::OK);
    assert_eq!(json(historical).await?, receipt);
    let substituted = uri.replace(
        fixture.body["authority_context"]
            .as_str()
            .ok_or("context")?,
        current_context.as_str(),
    );
    assert_eq!(
        restarted
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(substituted)
                    .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        restarted
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "old-selection")?)
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );

    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.credential_path)?)?;
    value["principals"][0]["operations"] = serde_json::json!(["REQUEST_CERTIFICATION"]);
    std::fs::write(&fixture.credential_path, serde_json::to_vec(&value)?)?;
    assert_eq!(
        app.oneshot(
            HttpRequest::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {COMMAND_TOKEN}"))
                .body(Body::empty())?
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and the built controller; scripts/test-ravenport"]
async fn command_dispatcher_sigkill_recovers_claim_and_preserves_published_receipt() -> Result {
    use std::os::unix::process::ExitStatusExt;

    let executable = std::path::PathBuf::from(std::env::var("ARCHCERT_TEST_CONTROLLER_BINARY")?)
        .canonicalize()?;
    assert!(executable.is_file());
    let database_url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    // The child must use only this test's schema, never an inherited options value.
    if database_url.contains('?') {
        return Err("process regression requires a PostgreSQL URL without query options".into());
    }

    for stage in ["claimed", "published"] {
        let fixture = fixture(true).await?;
        let app = crate::router(fixture.state.clone());
        let response = app
            .oneshot(post(&fixture.body, Some(COMMAND_TOKEN), "process-crash")?)
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted = json(response).await?;
        let id = ControlCommandId::parse(accepted["command_id"].as_str().ok_or("command id")?)?;
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&fixture.pool)
            .await?;
        assert!(
            schema.starts_with("command_http_")
                && schema
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        let child_url = format!("{database_url}?options=-csearch_path%3D{schema}");

        let grant = &fixture.state.control.configuration.grants[0];
        let configuration = serde_json::json!({
            "source_store": fixture.state.control.configuration.source_store,
            "artifact_root": fixture.state.control.configuration.artifact_root,
            "grants": [{
                "project": grant.project,
                "repository": grant.repository,
                "actor": grant.actor,
                "token_sha256": grant.token_sha256,
                "profile": grant.profile,
                "image": grant.image,
                "authority_toml": grant.authority_toml,
                "maximum_attempts": grant.maximum_attempts,
            }],
        });
        let config_path = fixture.credential_path.with_file_name("authority.json");
        std::fs::write(&config_path, serde_json::to_vec(&configuration)?)?;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
        let arguments = [
            "dispatch-command",
            "--dispatcher",
            "process-regression",
            "--lease-seconds",
            "5",
        ];
        let mut process = tokio::process::Command::new(&executable)
            .arg("--config")
            .arg(&config_path)
            .args(arguments)
            .args(["--stop-after", stage, "--hold-checkpoint"])
            .env_clear()
            .env("ARCHCERT_DATABASE_URL", &child_url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stderr = process.stderr.take().ok_or("missing child stderr")?;
        let bounded_stderr = tokio::io::AsyncReadExt::take(stderr, 4096);
        let mut lines = tokio::io::BufReader::new(bounded_stderr).lines();
        let marker = format!("Controlled Glassmere command interruption after {stage}");
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            while let Some(line) = lines.next_line().await? {
                if line == marker {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
            }
            Err("controller exited before its crash checkpoint".into())
        })
        .await??;

        process.kill().await?;
        assert_eq!(
            process.wait().await?.signal(),
            Some(9),
            "test must send actual SIGKILL"
        );
        let stopped_job =
            JobRepository::get(&fixture.state.control.repository, fixture.job).await?;
        assert_eq!(
            stopped_job.state,
            if stage == "claimed" {
                JobState::Queued
            } else {
                JobState::Inconclusive
            }
        );

        if stage == "claimed" {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        }
        let recovered = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tokio::process::Command::new(&executable)
                .arg("--config")
                .arg(&config_path)
                .args(arguments)
                .env_clear()
                .env("ARCHCERT_DATABASE_URL", &child_url)
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        assert!(recovered.status.success(), "controller recovery failed");
        let public: serde_json::Value = serde_json::from_slice(&recovered.stdout)?;
        if stage == "claimed" {
            assert_eq!(public["command_id"], accepted["command_id"]);
            assert_eq!(public["state"], "APPLIED");
        } else {
            assert_eq!(public["status"], "IDLE");
        }

        let scope = CommandScope {
            project: grant.project,
            repository: grant.repository.clone(),
            actor: grant.actor.clone(),
        };
        let retained =
            ControlCommandRepository::get(&fixture.state.control.repository, &scope, id).await?;
        assert_eq!(retained.state, ControlCommandState::Applied);
        assert_eq!(retained.dispatches, if stage == "claimed" { 2 } else { 1 });
        assert_eq!(
            serde_json::to_value(&retained.request_sha256)?,
            accepted["request_sha256"]
        );
        let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM control_commands),(SELECT count(*) FROM audit_events WHERE event='JobCanceled')")
            .fetch_one(&fixture.pool).await?;
        assert_eq!(counts, (1, 1));
        println!(
            "Actual SIGKILL recovered {stage}; one original request and one cancellation audit retained"
        );
    }

    Ok(())
}
