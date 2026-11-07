//! Private local identity/provisioning adapter. No runtime or signing dependency.

use anyhow::{Result, ensure};
use archcert_application::local::*;
use archcert_control_plane::read_private;
use archcert_domain::source::digest_bytes;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

mod identity;
mod projects;
mod publication;

#[cfg(test)]
mod tests;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Host-only initial setup; refuses an existing installation row.
    Init,
    /// Host-only renewal of an unconsumed bootstrap secret.
    RenewSetup,
    /// Reconstruct private projections from durable records.
    Publish,
    /// Audited recovery; password is read from a private file, never argv.
    RecoverPassword {
        email: String,
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Disable or change a local role, invalidating previous sessions.
    SetRole { email: String, role: String },
    /// Serve the independently authenticated loopback broker.
    Serve,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    instance: String,
    root: PathBuf,
    origin: String,
    listen: SocketAddr,
    token_sha256: String,
    gateway_binary: PathBuf,
    ssh_user: String,
    ssh_port: u16,
    image: Option<String>,
    authority_toml: String,
}

struct Service {
    config: Configuration,
    pool: PgPool,
    publication: Mutex<()>,
    password_slots: tokio::sync::Semaphore,
    request_slots: tokio::sync::Semaphore,
    dummy_password_hash: String,
}

fn entropy() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok(hex::encode(bytes))
}

fn invalid() -> anyhow::Error {
    anyhow::anyhow!("INVALID_REQUEST")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config: Configuration = serde_json::from_slice(&read_private(&args.config, 65536)?)?;
    ensure!(
        config.listen.ip().is_loopback() && config.origin.starts_with("http://127.0.0.1:"),
        "local loopback configuration required"
    );
    ensure!(
        config.root.is_absolute() && config.root.canonicalize()? == config.root,
        "canonical private root required"
    );
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&std::env::var("ARCHCERT_DATABASE_URL")?)
        .await?;
    if let Some(image) = &config.image {
        archcert_application::worker::resolve_authority_plan(
            "python",
            image,
            &config.authority_toml,
        )?;
    }
    let service = Arc::new(Service {
        config,
        pool,
        publication: Mutex::new(()),
        password_slots: tokio::sync::Semaphore::new(2),
        request_slots: tokio::sync::Semaphore::new(8),
        dummy_password_hash: identity::password_hash(&entropy()?)?,
    });

    match args.command {
        Command::Init => service.initialize(false).await?,
        Command::RenewSetup => service.initialize(true).await?,
        Command::Publish => service.publish().await?,
        Command::RecoverPassword {
            email,
            password_file,
        } => service.recover_password(&email, &password_file).await?,
        Command::SetRole { email, role } => service.set_role(&email, &role).await?,
        Command::Serve => {
            // Startup never migrates or reopens initialization.
            service.instance_state().await?;
            let listener = tokio::net::TcpListener::bind(service.config.listen).await?;
            let router = Router::new()
                .route("/local", post(call))
                .layer(DefaultBodyLimit::max(8192))
                .with_state(service);
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    event: &str,
    entity: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO local_audit(actor,event,entity) VALUES ($1,$2,$3)")
        .bind(actor)
        .bind(event)
        .bind(entity)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn call(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    Json(request): Json<LocalRequest>,
) -> Response {
    let authorized = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|token| {
            token.len() == 64
                && digest_bytes(token.as_bytes()).as_str() == service.config.token_sha256
        });
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Ok(_slot) = service.request_slots.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };

    match service.call(request).await {
        Ok(reply) => Json(reply).into_response(),
        Err(error) => {
            if let Some(sqlx::Error::Database(database)) = error.downcast_ref::<sqlx::Error>() {
                eprintln!(
                    "Local operation rejected: database SQLSTATE {}",
                    database.code().as_deref().unwrap_or("UNKNOWN")
                );
            }
            let code = error.to_string();
            let (status, message) = match code.as_str() {
                "INVALID_REQUEST" => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                "UNAUTHORIZED" => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
                "CONFLICT" => (StatusCode::CONFLICT, "CONFLICT"),
                "RATE_LIMITED" => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
                "CONFIGURATION_REQUIRED" => {
                    (StatusCode::PRECONDITION_FAILED, "CONFIGURATION_REQUIRED")
                }
                _ => (StatusCode::SERVICE_UNAVAILABLE, "RECOVERY_REQUIRED"),
            };
            (status, message).into_response()
        }
    }
}

impl Service {
    async fn call(&self, request: LocalRequest) -> Result<LocalReply> {
        let mut reply = LocalReply {
            state: "ACKNOWLEDGED".into(),
            details: json!({}),
            credential: None,
        };
        match request {
            LocalRequest::Status => {
                reply.state = self.instance_state().await?;
                let observed = read_private(&self.config.root.join("health/readiness.json"), 16384)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
                let now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                )
                .fetch_one(&self.pool)
                .await?;
                let readiness = observed.filter(|value| value["observed_at_unix"].as_i64().is_some_and(|time| (0..=45).contains(&(now-time))))
                    .unwrap_or_else(|| json!({"state":"UNAVAILABLE","reason":"No recent host dependency observation"}));
                let policy = archcert_policy::development_bundle()?;
                let plan = self
                    .config
                    .image
                    .as_ref()
                    .map(|image| {
                        archcert_application::worker::resolve_authority_plan(
                            "python",
                            image,
                            &self.config.authority_toml,
                        )
                    })
                    .transpose()?;
                let plan_digest = plan.as_ref().map(|plan| plan.digest()).transpose()?;
                reply.details = json!({
                    "authority": {
                        "policy": policy.identity(),
                        "image": self.config.image,
                        "plan_sha256": plan_digest,
                    },
                    "classification": "LOCAL SELF-HOSTED PILOT — DEVELOPMENT CERTIFICATION AUTHORITY",
                    "profile": if self.config.image.is_some() { "python-controlled-local-v1" } else { "CONFIGURATION_REQUIRED" },
                    "m6": "UNSUPPORTED in local onboarding",
                    "postgres": "READY",
                    "git_ssh_port": self.config.ssh_port,
                    "observed_health": readiness,
                });
            }
            LocalRequest::Validate { identity } => {
                self.validate(&identity).await?;
            }
            LocalRequest::Setup {
                secret,
                display_name,
                email,
                password,
                confirmation,
            } => {
                self.setup(secret, display_name, email, password, confirmation)
                    .await?;
                reply.state = "INITIALIZED".into();
            }
            LocalRequest::Login { email, password } => {
                reply.credential = Some(self.login(email, password).await?);
            }
            LocalRequest::Projects { identity } => {
                self.validate(&identity).await?;
                reply.details = self.projects(&identity).await?;
            }
            LocalRequest::CreateProject {
                identity,
                name,
                description,
                repository,
                public_key,
                request_key,
            } => {
                reply.details = self
                    .create_project(
                        identity,
                        projects::ProjectRegistration {
                            name,
                            description,
                            repository,
                            public_key,
                            request_key,
                        },
                    )
                    .await?;
            }
            LocalRequest::Certify {
                identity,
                project,
                submission,
                request_key,
            } => {
                reply.details = self
                    .certify(identity, project, submission, request_key)
                    .await?;
                reply.state = "REQUEST_ACCEPTED".into();
            }
        }
        Ok(reply)
    }
}
