//! Authenticated durable ArchCert admission/status API. No execution or signing.

mod commands;

use archcert_application::{artifacts::ImmutableArtifactStore, jobs::JobStoreError};
use archcert_control_plane::{ControlPlane, ControlPlaneConfiguration};
use archcert_domain::jobs::{IdempotencyKey, JobId};
use archcert_protocol::jobs::{CertificationJobResponse, CreateCertificationRequest};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::trace::TraceLayer;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    /// Optional strict private command-only credentials; never legacy submission tokens.
    #[arg(long)]
    command_credentials: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[derive(Clone)]
struct ApiState {
    control: Arc<ControlPlane>,
    command_credentials: Option<PathBuf>,
    command_slots: Arc<tokio::sync::Semaphore>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "archcertd=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();

    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "development authority API must bind loopback"
    );

    let config = ControlPlaneConfiguration::load(&args.config)?;
    let database_url = std::env::var("ARCHCERT_DATABASE_URL")?;
    let state = Arc::new(ControlPlane::connect(&database_url, config).await?);

    // Verify migrations were applied explicitly; do not mutate schema at startup.
    state.repository.check_readiness().await?;

    if let Some(path) = &args.command_credentials {
        archcert_control_plane::commands::CommandCredentials::load(path, &state.configuration)?;
        state.repository.check_command_readiness().await?;
    }

    let app = router(ApiState {
        control: state,
        command_credentials: args.command_credentials,
        command_slots: Arc::new(tokio::sync::Semaphore::new(8)),
    });

    tracing::info!(address=%args.listen,"ArchCert durable API listening");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn router(state: ApiState) -> Router {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readiness))
        .route("/api/v1/certifications", post(submit))
        .route("/api/v1/certifications/{id}", get(status))
        .route("/api/v1/certifications/{id}/certificate", get(certificate));
    let app = if state.command_credentials.is_some() {
        app.merge(commands::router())
    } else {
        app
    };

    app.layer(DefaultBodyLimit::max(4096))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn readiness(State(state): State<ApiState>) -> Response {
    let commands_ready = commands::ready(&state).await;
    let state = state.control;
    if commands_ready
        && state.repository.check_readiness().await.is_ok()
        && state.artifacts.check_readiness().is_ok()
    {
        (StatusCode::OK, "ready").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "authority dependencies unavailable",
        )
            .into_response()
    }
}

fn actor(
    state: &ControlPlane,
    headers: &HeaderMap,
) -> Result<archcert_domain::ingress::GitActorId, JobStoreError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(JobStoreError::Unauthorized)?;

    state.configuration.authenticate(token)
}

fn error(e: JobStoreError) -> Response {
    let status = match e {
        JobStoreError::Unauthorized => StatusCode::UNAUTHORIZED,
        JobStoreError::Conflict => StatusCode::CONFLICT,
        JobStoreError::Invalid => StatusCode::BAD_REQUEST,
        JobStoreError::Precondition => StatusCode::NOT_FOUND,
        JobStoreError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        JobStoreError::SemanticContextLimit => StatusCode::PAYLOAD_TOO_LARGE,
    };
    (status, e.to_string()).into_response()
}

async fn submit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateCertificationRequest>,
) -> Response {
    let result = async {
        let actor = actor(&state.control, &headers)?;
        let key = headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(JobStoreError::Invalid)?;
        state
            .control
            .submit(
                actor,
                request.project,
                request.repository,
                request.source_submission,
                IdempotencyKey::parse(key.into())?,
            )
            .await
    }
    .await;

    match result {
        Ok(job) => (
            StatusCode::ACCEPTED,
            Json(CertificationJobResponse::from(job)),
        )
            .into_response(),
        Err(e) => error(e),
    }
}

async fn status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let actor = actor(&state.control, &headers)?;
        state.control.status(&actor, JobId::parse(&id)?).await
    }
    .await;

    match result {
        Ok(job) => Json(CertificationJobResponse::from(job)).into_response(),
        Err(e) => error(e),
    }
}

async fn certificate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let result = async {
        let actor = actor(&state.control, &headers)?;
        let job = state.control.status(&actor, JobId::parse(&id)?).await?;

        let cert = job.certificate.ok_or(JobStoreError::Precondition)?;

        state
            .control
            .artifacts
            .get(job.inputs.project, &cert.artifact)
            .await
    }
    .await;

    match result {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(e) => error(e),
    }
}
