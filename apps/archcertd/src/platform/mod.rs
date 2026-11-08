//! Product accounts and project provisioning inside the existing durable API.
//! Execution, signing and certification admission retain their existing boundaries.

use anyhow::{Result, ensure};
use archcert_application::platform::*;
use archcert_control_plane::{ControlPlane, ControlPlaneConfiguration, read_private};
use archcert_domain::source::digest_bytes;
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

mod identity;
mod projects;
mod publication;

#[cfg(test)]
mod tests;

#[derive(Subcommand)]
pub(super) enum Command {
    /// Host-only initial setup; refuses an existing installation row.
    Initialize,
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
    /// Disable or change an account role, invalidating previous sessions.
    SetRole { email: String, role: String },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    instance: String,
    root: PathBuf,
    origin: String,
    #[serde(default)]
    development_http: bool,
    token_sha256: String,
    gateway_binary: PathBuf,
    #[serde(default)]
    ingress: archcert_gateway::IngressCapacity,
    ssh_user: String,
    ssh_port: u16,
    image: Option<String>,
    authority_toml: String,
}

pub(super) struct Service {
    config: Configuration,
    pub(super) pool: PgPool,
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

pub(super) fn store_error(error: anyhow::Error) -> archcert_application::jobs::JobStoreError {
    use archcert_application::jobs::JobStoreError;

    match error.to_string().as_str() {
        "UNAUTHORIZED" => JobStoreError::Unauthorized,
        "INVALID_REQUEST" => JobStoreError::Invalid,
        "CONFLICT" => JobStoreError::Conflict,
        _ => JobStoreError::Unavailable,
    }
}

impl Service {
    pub(super) async fn open(path: &Path) -> Result<Arc<Self>> {
        let config: Configuration = serde_json::from_slice(&read_private(path, 65536)?)?;
        config.ingress.validate()?;
        let origin: axum::http::Uri = config.origin.parse()?;
        ensure!(
            origin.authority().is_some() && origin.path() == "/" && origin.query().is_none(),
            "invalid trusted origin"
        );
        ensure!(
            origin.scheme_str() == Some("https")
                || (config.development_http
                    && origin.scheme_str() == Some("http")
                    && origin.host() == Some("127.0.0.1")),
            "HTTPS origin or explicit loopback development HTTP required"
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

        Ok(Arc::new(Self {
            config,
            pool,
            publication: Mutex::new(()),
            password_slots: tokio::sync::Semaphore::new(2),
            request_slots: tokio::sync::Semaphore::new(8),
            dummy_password_hash: identity::password_hash(&entropy()?)?,
        }))
    }

    pub(super) async fn administer(&self, command: Command) -> Result<()> {
        match command {
            Command::Initialize => self.initialize(false).await,
            Command::RenewSetup => self.initialize(true).await,
            Command::Publish => self.publish().await,
            Command::RecoverPassword {
                email,
                password_file,
            } => self.recover_password(&email, &password_file).await,
            Command::SetRole { email, role } => self.set_role(&email, &role).await,
        }
    }

    pub(super) async fn control(&self) -> Result<ControlPlane> {
        self.instance_state().await?;
        let rows = sqlx::query("SELECT * FROM project_registry ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let grants = rows
            .iter()
            .map(|row| self.grant(row))
            .collect::<Result<Vec<_>>>()?;
        let configuration = ControlPlaneConfiguration {
            source_store: self.config.root.join("sources"),
            artifact_root: self.config.root.join("artifacts"),
            grants,
        };

        // One metadata pool and artifact adapter for the existing API/control plane.
        Ok(ControlPlane {
            repository: PostgresJobRepository::from_pool(self.pool.clone()),
            artifacts: Arc::new(FilesystemArtifactStore::open_unencrypted_development(
                &configuration.artifact_root,
            )?),
            configuration,
        })
    }

    fn broker_authorized(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all("authorization").iter();
        let token = values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        values.next().is_none()
            && token.is_some_and(|token| {
                token.len() == 64
                    && digest_bytes(token.as_bytes()).as_str() == self.config.token_sha256
            })
    }

    pub(super) fn identity_from_headers(&self, headers: &HeaderMap) -> Result<AccountIdentity> {
        ensure!(self.broker_authorized(headers), "UNAUTHORIZED");
        let read = |name: &str| -> Result<String> {
            let mut values = headers.get_all(name).iter();
            let value = values
                .next()
                .and_then(|value| value.to_str().ok())
                .ok_or_else(invalid)?;
            ensure!(
                values.next().is_none() && value.len() <= 128,
                "INVALID_REQUEST"
            );
            Ok(value.into())
        };
        Ok(AccountIdentity {
            principal: read("x-archcert-principal")?,
            generation: read("x-archcert-generation")?,
        })
    }
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    event: &str,
    entity: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO provisioning_audit(actor,event,entity) VALUES ($1,$2,$3)")
        .bind(actor)
        .bind(event)
        .bind(entity)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn call(
    State(state): State<crate::ApiState>,
    headers: HeaderMap,
    Json(request): Json<PlatformRequest>,
) -> Response {
    let Some(service) = state.platform else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !service.broker_authorized(&headers) {
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
                    "Product operation rejected: database SQLSTATE {}",
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
    async fn call(&self, request: PlatformRequest) -> Result<PlatformReply> {
        let mut reply = PlatformReply {
            state: "ACKNOWLEDGED".into(),
            details: json!({}),
            credential: None,
        };

        match request {
            PlatformRequest::Status => {
                reply.state = self.instance_state().await?;

                let artifacts_ready = FilesystemArtifactStore::open_unencrypted_development(
                    &self.config.root.join("artifacts"),
                )
                .and_then(|store| store.check_readiness())
                .is_ok();
                let sources_ready = archcert_gateway::AcceptedSubmissionReader::open(
                    &self.config.root.join("sources"),
                )
                .is_ok();

                let observed = read_private(&self.config.root.join("health/readiness.json"), 16384)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let readiness = observed
                    .filter(|value| {
                        value["observed_at_unix"]
                            .as_u64()
                            .is_some_and(|time| now.checked_sub(time).is_some_and(|age| age <= 45))
                    })
                    .unwrap_or_else(|| {
                        json!({
                            "state": "UNAVAILABLE",
                            "reason": "No recent host dependency observation",
                        })
                    });

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
                    "classification": "DEVELOPMENT CERTIFICATION AUTHORITY",
                    "profile": if self.config.image.is_some() { "python" } else { "CONFIGURATION_REQUIRED" },
                    "m6": "UNSUPPORTED in project onboarding",
                    "postgres": "READY",
                    "migrations": "READY — required schema 0012",
                    "artifact_store": if artifacts_ready { "READY" } else { "ERROR" },
                    "source_catalog": if sources_ready { "READY" } else { "ERROR" },
                    "git_ssh_port": self.config.ssh_port,
                    "observed_health": readiness,
                });
            }
            PlatformRequest::Validate { identity } => {
                self.validate(&identity).await?;
            }
            PlatformRequest::Setup {
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
            PlatformRequest::Login { email, password } => {
                reply.credential = Some(self.login(email, password).await?);
            }
            PlatformRequest::Projects { identity } => {
                self.validate(&identity).await?;
                reply.details = self.projects(&identity).await?;
            }
            PlatformRequest::CreateProject {
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
            // Certification is admitted only by the existing certification route.
            PlatformRequest::Certify { .. } => return Err(invalid()),
        }
        Ok(reply)
    }
}
