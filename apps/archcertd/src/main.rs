//! Bootstrap ArchCert control-plane API.

use archcert_application::{BootstrapSubmitCertification, SubmitCertification};
use archcert_protocol::{CertificationResponse, SubmitCertificationRequest};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::{net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
struct AppState {
    submitter: Arc<dyn SubmitCertification>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "archcertd=info,tower_http=info".into()),
        )
        .init();

    let state = AppState {
        submitter: Arc::new(BootstrapSubmitCertification),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/certifications", post(submit_certification))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "ArchCert API listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn submit_certification(
    State(state): State<AppState>,
    Json(request): Json<SubmitCertificationRequest>,
) -> Response {
    match state.submitter.submit(request.into()) {
        Ok(response) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(CertificationResponse::from(response)),
        )
            .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bootstrap_does_not_claim_a_persisted_job() -> anyhow::Result<()> {
        let request = SubmitCertificationRequest {
            project_id: "project".into(),
            commit: archcert_domain::GitObjectId::parse("a".repeat(40))?,
            profile: "node".into(),
        };
        let response = submit_certification(
            State(AppState {
                submitter: Arc::new(BootstrapSubmitCertification),
            }),
            Json(request),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = axum::body::to_bytes(response.into_body(), 1024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"status":"UNAVAILABLE"})
        );
        Ok(())
    }
}
