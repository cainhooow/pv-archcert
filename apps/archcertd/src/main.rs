//! Authenticated durable ArchCert admission/status API. No execution or signing.

use archcert_application::{
    artifacts::ImmutableArtifactStore,
    jobs::{JobRepository, JobStoreError},
};
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

mod commands;
mod platform;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    /// Optional strict private command-only credentials; never legacy submission tokens.
    #[arg(long)]
    command_credentials: Option<PathBuf>,
    /// Product accounts use this API and the existing Glassmere sessions.
    #[arg(long)]
    platform_config: Option<PathBuf>,
    /// Explicit host administration; ordinary startup never initializes accounts.
    #[command(subcommand)]
    administration: Option<platform::Command>,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[derive(Clone)]
struct ApiState {
    control: Arc<ControlPlane>,
    command_credentials: Option<PathBuf>,
    command_slots: Arc<tokio::sync::Semaphore>,
    platform: Option<Arc<platform::Service>>,
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

    let platform = if let Some(path) = &args.platform_config {
        Some(platform::Service::open(path).await?)
    } else {
        None
    };

    if let Some(command) = args.administration {
        let service = platform
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("product account configuration required"))?;
        return service.administer(command).await;
    }

    let database_url = std::env::var("ARCHCERT_DATABASE_URL")?;
    let state = Arc::new(if let Some(service) = &platform {
        service.control().await?
    } else {
        ControlPlane::connect(
            &database_url,
            ControlPlaneConfiguration::load(&args.config)?,
        )
        .await?
    });

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
        platform,
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

    let app = if state.platform.is_some() {
        app.merge(
            Router::new()
                .route("/api/v1/platform", post(platform::call))
                .layer(DefaultBodyLimit::max(8192)),
        )
    } else {
        app
    };
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

fn has_account_identity(headers: &HeaderMap) -> bool {
    headers.contains_key("x-archcert-principal") || headers.contains_key("x-archcert-generation")
}

async fn authorized_control(
    state: &ApiState,
    headers: &HeaderMap,
    project: archcert_domain::ProjectId,
    repository: &archcert_domain::source::RepositoryId,
    write: bool,
) -> Result<(archcert_domain::ingress::GitActorId, Arc<ControlPlane>), JobStoreError> {
    if !has_account_identity(headers) {
        return Ok((actor(&state.control, headers)?, Arc::clone(&state.control)));
    }

    let service = state.platform.as_ref().ok_or(JobStoreError::Unauthorized)?;
    let identity = service
        .identity_from_headers(headers)
        .map_err(platform::store_error)?;
    let grant = service
        .grant_for_account(&identity, project, repository, write)
        .await
        .map_err(platform::store_error)?;
    let actor = grant.actor.clone();

    // Narrow the existing control plane to the authenticated project. Reuse its
    // metadata pool, artifact adapter and unchanged admission/verification logic.
    let control = ControlPlane {
        repository: state.control.repository.clone(),
        artifacts: Arc::clone(&state.control.artifacts),
        configuration: ControlPlaneConfiguration {
            source_store: state.control.configuration.source_store.clone(),
            artifact_root: state.control.configuration.artifact_root.clone(),
            grants: vec![grant],
        },
    };
    Ok((actor, Arc::new(control)))
}

async fn control_for_job(
    state: &ApiState,
    headers: &HeaderMap,
    id: JobId,
) -> Result<(archcert_domain::ingress::GitActorId, Arc<ControlPlane>), JobStoreError> {
    if !has_account_identity(headers) {
        return Ok((actor(&state.control, headers)?, Arc::clone(&state.control)));
    }

    // Authenticate the private broker before reading even internal job metadata.
    state
        .platform
        .as_ref()
        .ok_or(JobStoreError::Unauthorized)?
        .identity_from_headers(headers)
        .map_err(platform::store_error)?;
    let job = state.control.repository.get(id).await?;
    authorized_control(
        state,
        headers,
        job.inputs.project,
        &job.inputs.repository,
        false,
    )
    .await
}

async fn submit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateCertificationRequest>,
) -> Response {
    let result = async {
        let (actor, control) =
            authorized_control(&state, &headers, request.project, &request.repository, true)
                .await?;
        let key = headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(JobStoreError::Invalid)?;
        control
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
        let id = JobId::parse(&id)?;
        let (actor, control) = control_for_job(&state, &headers, id).await?;
        control.status(&actor, id).await
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
        let id = JobId::parse(&id)?;
        let (actor, control) = control_for_job(&state, &headers, id).await?;
        let job = control.status(&actor, id).await?;

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
