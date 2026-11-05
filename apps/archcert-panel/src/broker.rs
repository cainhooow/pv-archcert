//! Fixed loopback command client. No write database, runtime or signing capability.

use archcert_application::{glassmere::commands::*, jobs::JobStoreError};
use archcert_domain::{
    ProjectId,
    jobs::IdempotencyKey,
    source::{RepositoryId, digest_bytes},
};
use archcert_glassmere::auth::PanelConfiguration;
use archcert_protocol::commands::{
    ControlActionRequest, ControlCommandContextResponse, ControlCommandResponse,
    CreateControlCommandRequest,
};
use async_trait::async_trait;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, body::Bytes, header};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, JobStoreError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    endpoint: SocketAddr,
    mappings: Vec<Mapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    principal: String,
    project: ProjectId,
    repository: RepositoryId,
    operations: Vec<ControlOperation>,
    token: String,
}

fn supported(operation: ControlOperation) -> bool {
    matches!(
        operation,
        ControlOperation::RequestCertification
            | ControlOperation::CancelEligibleJob
            | ControlOperation::RetryEligibleJob
    )
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute()
        || path
            .canonicalize()
            .map_err(|_| JobStoreError::Unavailable)?
            != path
    {
        return Err(JobStoreError::Unavailable);
    }
    let parent = std::fs::metadata(path.parent().ok_or(JobStoreError::Unavailable)?)
        .map_err(|_| JobStoreError::Unavailable)?;
    if parent.uid() != rustix::process::geteuid().as_raw() || parent.mode() & 0o077 != 0 {
        return Err(JobStoreError::Unavailable);
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| JobStoreError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| JobStoreError::Unavailable)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 128 * 1024
    {
        return Err(JobStoreError::Unavailable);
    }

    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JobStoreError::Unavailable)?;
    if bytes.len() > 128 * 1024 {
        return Err(JobStoreError::Unavailable);
    }

    Ok(bytes)
}

impl Configuration {
    fn load(path: &Path, panel: &Path) -> Result<Self> {
        let configuration: Self =
            serde_json::from_slice(&read_private(path)?).map_err(|_| JobStoreError::Unavailable)?;
        let panel = PanelConfiguration::load(panel).map_err(|_| JobStoreError::Unavailable)?;
        if configuration.schema != 1
            || !configuration.endpoint.ip().is_loopback()
            || configuration.endpoint.port() == 0
            || configuration.mappings.is_empty()
            || configuration.mappings.len() > 128
        {
            return Err(JobStoreError::Unavailable);
        }

        for (index, mapping) in configuration.mappings.iter().enumerate() {
            let hash = digest_bytes(mapping.token.as_bytes());
            if mapping.principal.is_empty()
                || mapping.principal.len() > 64
                || !mapping
                    .principal
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                || !(32..=256).contains(&mapping.token.len())
                || !mapping.token.bytes().all(|byte| byte.is_ascii_graphic())
                || mapping.operations.is_empty()
                || mapping.operations.len() > 3
                || mapping
                    .operations
                    .iter()
                    .enumerate()
                    .any(|(index, operation)| {
                        !supported(*operation) || mapping.operations[..index].contains(operation)
                    })
                || panel
                    .principals
                    .iter()
                    .any(|principal| principal.token_sha256 == hash.as_str())
                || configuration.mappings[..index].iter().any(|previous| {
                    (previous.principal == mapping.principal
                        && previous.project == mapping.project
                        && previous.repository == mapping.repository)
                        || (previous.token == mapping.token
                            && previous.principal != mapping.principal)
                })
            {
                return Err(JobStoreError::Unavailable);
            }
        }

        Ok(configuration)
    }

    fn mapping(
        &self,
        principal: &str,
        project: ProjectId,
        repository: &RepositoryId,
        operation: ControlOperation,
    ) -> Result<&Mapping> {
        self.mappings
            .iter()
            .find(|mapping| {
                mapping.principal == principal
                    && mapping.project == project
                    && mapping.repository == *repository
                    && mapping.operations.contains(&operation)
            })
            .ok_or(JobStoreError::Unauthorized)
    }
}

/// Independently provisioned command client. Configuration secrets have no serializer/debugger.
pub(super) struct CommandBroker {
    path: PathBuf,
    panel_path: PathBuf,
    endpoint: SocketAddr,
    client: Client<HttpConnector, Full<Bytes>>,
    slots: tokio::sync::Semaphore,
}

impl CommandBroker {
    /// Validate private configuration before listening; endpoint changes require restart.
    pub(super) fn open(path: PathBuf, panel_path: PathBuf) -> Result<Self> {
        let configuration = Configuration::load(&path, &panel_path)?;
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_connect_timeout(Some(Duration::from_secs(2)));
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .retry_canceled_requests(false)
            .pool_max_idle_per_host(0);

        Ok(Self {
            path,
            panel_path,
            endpoint: configuration.endpoint,
            client: builder.build(connector),
            slots: tokio::sync::Semaphore::new(4),
        })
    }

    fn configuration(&self) -> Result<Configuration> {
        let configuration = Configuration::load(&self.path, &self.panel_path)?;
        if configuration.endpoint != self.endpoint {
            return Err(JobStoreError::Unavailable);
        }

        Ok(configuration)
    }

    async fn request<T: DeserializeOwned>(
        &self,
        mapping: &Mapping,
        method: Method,
        path: &str,
        body: Vec<u8>,
        key: Option<&IdempotencyKey>,
        expected: StatusCode,
    ) -> Result<T> {
        if body.len() > 4096 {
            return Err(JobStoreError::Invalid);
        }
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| JobStoreError::Unavailable)?;
        let request = async {
            let mut authorization =
                header::HeaderValue::from_str(&format!("Bearer {}", mapping.token))
                    .map_err(|_| JobStoreError::Unavailable)?;
            authorization.set_sensitive(true);
            let mut request = Request::builder()
                .method(method)
                .uri(format!("http://{}{path}", self.endpoint))
                .header(header::AUTHORIZATION, authorization)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(key) = key {
                request = request.header("idempotency-key", key.as_str());
            }
            let request = request
                .body(Full::new(Bytes::from(body)))
                .map_err(|_| JobStoreError::Invalid)?;
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| JobStoreError::Unavailable)?;

            if response.status() != expected {
                return Err(match response.status() {
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                        JobStoreError::Unauthorized
                    }
                    StatusCode::CONFLICT => JobStoreError::Conflict,
                    StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                        JobStoreError::Invalid
                    }
                    StatusCode::PAYLOAD_TOO_LARGE => JobStoreError::SemanticContextLimit,
                    _ => JobStoreError::Unavailable,
                });
            }
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next());
            if content_type != Some("application/json") {
                return Err(JobStoreError::Unavailable);
            }
            let body = Limited::new(response.into_body(), MAX_CONTROL_COMMAND_BYTES)
                .collect()
                .await
                .map_err(|_| JobStoreError::Unavailable)?
                .to_bytes();

            serde_json::from_slice(&body).map_err(|_| JobStoreError::Unavailable)
        };

        tokio::time::timeout(Duration::from_secs(10), request)
            .await
            .map_err(|_| JobStoreError::Unavailable)?
    }
}

fn receipt(
    value: ControlCommandResponse,
    project: ProjectId,
    repository: &RepositoryId,
    operation: ControlOperation,
    context: &archcert_domain::Sha256Digest,
    id: Option<archcert_domain::jobs::ControlCommandId>,
) -> Result<CommandReceiptObservation> {
    let terminal = matches!(
        value.state,
        ControlCommandState::Applied
            | ControlCommandState::Rejected
            | ControlCommandState::Inconclusive
    );
    if value.schema != 1
        || value.project != project
        || value.repository != *repository
        || value.operation != operation
        || value.authority_context != *context
        || id.is_some_and(|id| value.command_id != id)
        || terminal != value.outcome.is_some()
        || value
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.state() != value.state)
    {
        return Err(JobStoreError::Unavailable);
    }

    if let Some(ControlCommandOutcome::Applied { effect }) = &value.outcome {
        let valid = match (operation, effect.as_ref()) {
            (
                ControlOperation::RequestCertification,
                CommandEffect::CertificationRequested { job, session },
            ) => {
                (job.is_some() || session.is_some())
                    && session.is_none_or(|session| job.is_none_or(|job| job == session))
            }
            (ControlOperation::CancelEligibleJob, CommandEffect::JobCanceled { .. })
            | (ControlOperation::RetryEligibleJob, CommandEffect::JobRecoveryRequested { .. }) => {
                true
            }
            _ => false,
        };
        if !valid {
            return Err(JobStoreError::Unavailable);
        }
    }

    Ok(CommandReceiptObservation {
        id: value.command_id,
        project: value.project,
        repository: value.repository,
        operation: value.operation,
        authority_context: value.authority_context,
        request_sha256: value.request_sha256,
        state: value.state,
        created_at: value.created_at,
        outcome: value.outcome,
    })
}

#[async_trait]
impl GlassmereCommandBroker for CommandBroker {
    async fn context(
        &self,
        principal: &str,
        project: ProjectId,
        repository: &RepositoryId,
        operation: ControlOperation,
    ) -> Result<CommandContextObservation> {
        let configuration = self.configuration()?;
        let mapping = configuration.mapping(principal, project, repository, operation)?;
        let path = format!(
            "/api/v2/command-context?project={project}&repository={}&operation={}",
            repository.as_str(),
            operation.name()
        );
        let value: ControlCommandContextResponse = self
            .request(
                mapping,
                Method::GET,
                &path,
                Vec::new(),
                None,
                StatusCode::OK,
            )
            .await?;
        if value.schema != 1
            || value.project != project
            || value.repository != *repository
            || value.operation != operation
        {
            return Err(JobStoreError::Unavailable);
        }

        Ok(CommandContextObservation {
            project: value.project,
            repository: value.repository,
            operation: value.operation,
            authority_context: value.authority_context,
            requires_reviewed_session: value.requires_reviewed_session,
        })
    }

    async fn submit(
        &self,
        principal: &str,
        request: &RequestedJobCommand,
        key: &IdempotencyKey,
    ) -> Result<CommandReceiptObservation> {
        let configuration = self.configuration()?;
        let operation = request.action.operation();
        let mapping =
            configuration.mapping(principal, request.project, &request.repository, operation)?;
        let action = match &request.action {
            RequestedJobAction::RequestCertification {
                submission,
                reviewed_session,
            } => ControlActionRequest::RequestCertification {
                source_submission: submission.clone(),
                reviewed_session: *reviewed_session,
            },
            RequestedJobAction::CancelEligibleJob { job } => {
                ControlActionRequest::CancelEligibleJob { job: *job }
            }
            RequestedJobAction::RetryEligibleJob { job, attempt } => {
                ControlActionRequest::RetryEligibleJob {
                    job: *job,
                    attempt: *attempt,
                }
            }
        };
        let body = serde_json::to_vec(&CreateControlCommandRequest {
            schema: 1,
            project: request.project,
            repository: request.repository.clone(),
            authority_context: request.authority_context.clone(),
            action,
        })
        .map_err(|_| JobStoreError::Invalid)?;
        let value = self
            .request(
                mapping,
                Method::POST,
                "/api/v2/commands",
                body,
                Some(key),
                StatusCode::ACCEPTED,
            )
            .await?;

        let receipt = receipt(
            value,
            request.project,
            &request.repository,
            operation,
            &request.authority_context,
            None,
        )?;
        if let Some(ControlCommandOutcome::Applied { effect }) = &receipt.outcome {
            let matches = match (&request.action, effect.as_ref()) {
                (
                    RequestedJobAction::RequestCertification {
                        reviewed_session, ..
                    },
                    CommandEffect::CertificationRequested { job, session },
                ) => {
                    reviewed_session == session
                        && (job.is_some() || session.is_some())
                        && session.is_none_or(|session| job.is_none_or(|job| job == session))
                }
                (
                    RequestedJobAction::CancelEligibleJob { job },
                    CommandEffect::JobCanceled { job: affected },
                ) => job == affected,
                (
                    RequestedJobAction::RetryEligibleJob { job, attempt },
                    CommandEffect::JobRecoveryRequested {
                        job: affected,
                        attempt: generation,
                    },
                ) => job == affected && attempt == generation,
                _ => false,
            };
            if !matches {
                return Err(JobStoreError::Unavailable);
            }
        }

        Ok(receipt)
    }

    async fn receipt(
        &self,
        principal: &str,
        selection: &CommandReceiptSelection,
    ) -> Result<CommandReceiptObservation> {
        let configuration = self.configuration()?;
        let mapping = configuration.mapping(
            principal,
            selection.project,
            &selection.repository,
            selection.operation,
        )?;
        let path = format!(
            "/api/v2/commands/{}?project={}&repository={}&operation={}&authority_context={}",
            selection.id,
            selection.project,
            selection.repository.as_str(),
            selection.operation.name(),
            selection.authority_context.as_str()
        );
        let value = self
            .request(
                mapping,
                Method::GET,
                &path,
                Vec::new(),
                None,
                StatusCode::OK,
            )
            .await?;

        receipt(
            value,
            selection.project,
            &selection.repository,
            selection.operation,
            &selection.authority_context,
            Some(selection.id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::jobs::{ControlCommandId, JobId};
    use archcert_glassmere::auth::{Principal, Role};
    use axum::{
        Json, Router,
        extract::State,
        response::{IntoResponse, Response},
        routing::any,
    };
    use std::{
        convert::Infallible,
        os::unix::fs::PermissionsExt,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    const LOGIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RECEIPT: &str = "10000000-0000-4000-8000-000000000010";
    const JOB: &str = "10000000-0000-4000-8000-000000000011";

    struct Backend {
        project: ProjectId,
        mode: AtomicUsize,
        calls: AtomicUsize,
        authorization: Mutex<Vec<String>>,
        bodies: Mutex<Vec<serde_json::Value>>,
        redirect: Mutex<String>,
    }

    struct UnknownSizeBody(Option<Bytes>);

    impl hyper::body::Body for UnknownSizeBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, Infallible>>> {
            Poll::Ready(
                self.0
                    .take()
                    .map(|bytes| Ok(hyper::body::Frame::data(bytes))),
            )
        }
    }

    async fn backend(
        State(state): State<Arc<Backend>>,
        request: axum::extract::Request,
    ) -> std::result::Result<Response, StatusCode> {
        state.calls.fetch_add(1, Ordering::Relaxed);
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        state
            .authorization
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .push(authorization);
        let method = request.method().clone();
        let context_request = request.uri().path() == "/api/v2/command-context";
        let bytes = axum::body::to_bytes(request.into_body(), 4096)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        if !bytes.is_empty() {
            state
                .bodies
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .push(serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?);
        }
        let mode = state.mode.load(Ordering::Relaxed);
        if mode == 3 {
            let location = state
                .redirect
                .lock()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .clone();
            return Ok((
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, location)],
            )
                .into_response());
        }
        if mode == 7 {
            return Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                "{",
            )
                .into_response());
        }

        let project = if mode == 1 {
            ProjectId::new()
        } else {
            state.project
        };
        let context = digest_bytes(b"broker fixture authority");
        let value = if context_request {
            serde_json::json!({
                "schema": if mode == 2 { 99 } else { 1 },
                "project": project,
                "repository": "broker/fixture",
                "operation": "CANCEL_ELIGIBLE_JOB",
                "authority_context": context,
                "requires_reviewed_session": false,
            })
        } else {
            serde_json::json!({
                "schema": 1,
                "command_id": RECEIPT,
                "project": project,
                "repository": "broker/fixture",
                "operation": "CANCEL_ELIGIBLE_JOB",
                "authority_context": context,
                "request_sha256": digest_bytes(b"broker fixture request"),
                "state": if mode == 6 { "APPLIED" } else { "REQUESTED" },
                "created_at": 1_700_000_000,
                "outcome": if mode == 6 { serde_json::json!({
                    "state": "APPLIED",
                    "effect": { "kind": "JOB_CANCELED", "job": JobId::new() },
                }) } else { serde_json::Value::Null },
            })
        };
        if mode == 4 {
            let mut bytes =
                serde_json::to_vec(&value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            // Valid JSON with legal trailing whitespace: without a byte bound the
            // typed response would be accepted. Unknown size forces streamed limiting.
            bytes.extend(vec![b' '; MAX_CONTROL_COMMAND_BYTES + 1]);
            return Ok((
                [(header::CONTENT_TYPE, "application/json")],
                axum::body::Body::new(UnknownSizeBody(Some(Bytes::from(bytes)))),
            )
                .into_response());
        }

        let status = if method == Method::POST {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        Ok((status, Json(value)).into_response())
    }

    struct Server {
        address: SocketAddr,
        state: Arc<Backend>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Server {
        async fn start() -> TestResult<Self> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let state = Arc::new(Backend {
                project: ProjectId::new(),
                mode: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                authorization: Mutex::new(Vec::new()),
                bodies: Mutex::new(Vec::new()),
                redirect: Mutex::new(String::new()),
            });
            let app = Router::new()
                .fallback(any(backend))
                .with_state(state.clone());
            let task = tokio::spawn(async move { axum::serve(listener, app).await });

            Ok(Self {
                address,
                state,
                task,
            })
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    struct Files {
        _root: tempfile::TempDir,
        configuration: PathBuf,
        panel: PathBuf,
    }

    impl Files {
        fn new(server: &Server) -> TestResult<Self> {
            let root = tempfile::tempdir()?;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
            let path = root.path().canonicalize()?;
            let panel = path.join("panel.json");
            let panel_value = PanelConfiguration {
                schema: 1,
                origin: "http://127.0.0.1:8090".into(),
                development_http: true,
                demonstration_data: true,
                audit_path: path.join("audit.jsonl"),
                principals: vec![Principal {
                    id: "operator".into(),
                    token_sha256: digest_bytes(LOGIN.as_bytes()).as_str().into(),
                    role: Role::Operator,
                    projects: vec![server.state.project],
                    grant_generation: Some("c".repeat(64)),
                }],
            };
            std::fs::write(&panel, serde_json::to_vec(&panel_value)?)?;
            std::fs::set_permissions(&panel, std::fs::Permissions::from_mode(0o600))?;
            let configuration = path.join("broker.json");
            let value = serde_json::json!({
                "schema": 1,
                "endpoint": server.address,
                "mappings": [{
                    "principal": "operator",
                    "project": server.state.project,
                    "repository": "broker/fixture",
                    "operations": ["CANCEL_ELIGIBLE_JOB"],
                    "token": TOKEN,
                }],
            });
            std::fs::write(&configuration, serde_json::to_vec(&value)?)?;
            std::fs::set_permissions(&configuration, std::fs::Permissions::from_mode(0o600))?;

            Ok(Self {
                _root: root,
                configuration,
                panel,
            })
        }

        fn change(&self, change: impl FnOnce(&mut serde_json::Value)) -> TestResult {
            let mut value = serde_json::from_slice(&std::fs::read(&self.configuration)?)?;
            change(&mut value);
            std::fs::write(&self.configuration, serde_json::to_vec(&value)?)?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn broker_uses_exact_scope_separate_credentials_and_identifier_only_requests()
    -> TestResult {
        let server = Server::start().await?;
        let files = Files::new(&server)?;
        let broker = CommandBroker::open(files.configuration.clone(), files.panel.clone())?;
        let repository = RepositoryId::parse("broker/fixture")?;
        let context = broker
            .context(
                "operator",
                server.state.project,
                &repository,
                ControlOperation::CancelEligibleJob,
            )
            .await?;
        let request = RequestedJobCommand {
            project: server.state.project,
            repository: repository.clone(),
            authority_context: context.authority_context.clone(),
            action: RequestedJobAction::CancelEligibleJob {
                job: JobId::parse(JOB)?,
            },
        };
        let receipt = broker
            .submit(
                "operator",
                &request,
                &IdempotencyKey::parse("browser-retry-key".into())?,
            )
            .await?;
        assert_eq!(receipt.state, ControlCommandState::Requested);
        assert_eq!(receipt.id, ControlCommandId::parse(RECEIPT)?);

        let calls = server.state.calls.load(Ordering::Relaxed);
        for (principal, project, repository, operation) in [
            (
                "viewer",
                server.state.project,
                repository.clone(),
                ControlOperation::CancelEligibleJob,
            ),
            (
                "operator",
                ProjectId::new(),
                repository.clone(),
                ControlOperation::CancelEligibleJob,
            ),
            (
                "operator",
                server.state.project,
                RepositoryId::parse("other/repository")?,
                ControlOperation::CancelEligibleJob,
            ),
            (
                "operator",
                server.state.project,
                repository.clone(),
                ControlOperation::RequestCertification,
            ),
        ] {
            assert!(matches!(
                broker
                    .context(principal, project, &repository, operation)
                    .await,
                Err(JobStoreError::Unauthorized)
            ));
        }
        assert_eq!(server.state.calls.load(Ordering::Relaxed), calls);
        let authorization = server
            .state
            .authorization
            .lock()
            .map_err(|_| "test mutex")?;
        assert!(
            authorization
                .iter()
                .all(|value| value == &format!("Bearer {TOKEN}"))
        );
        let bodies = server.state.bodies.lock().map_err(|_| "test mutex")?;
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["action"]["job"], JOB);
        for excluded in [
            "token",
            "actor",
            "role",
            "authority_toml",
            "command",
            "limits",
        ] {
            assert!(bodies[0].get(excluded).is_none());
        }

        Ok(())
    }

    #[tokio::test]
    async fn broker_rejects_misbinding_unknown_schema_malformed_json_and_streamed_oversize()
    -> TestResult {
        let server = Server::start().await?;
        let files = Files::new(&server)?;
        let broker = CommandBroker::open(files.configuration.clone(), files.panel.clone())?;
        let repository = RepositoryId::parse("broker/fixture")?;
        for mode in [1, 2, 4, 7] {
            server.state.mode.store(mode, Ordering::Relaxed);
            assert!(
                matches!(
                    broker
                        .context(
                            "operator",
                            server.state.project,
                            &repository,
                            ControlOperation::CancelEligibleJob
                        )
                        .await,
                    Err(JobStoreError::Unavailable)
                ),
                "mode {mode}"
            );
        }
        server.state.mode.store(6, Ordering::Relaxed);
        let request = RequestedJobCommand {
            project: server.state.project,
            repository,
            authority_context: digest_bytes(b"broker fixture authority"),
            action: RequestedJobAction::CancelEligibleJob {
                job: JobId::parse(JOB)?,
            },
        };
        assert!(matches!(
            broker
                .submit(
                    "operator",
                    &request,
                    &IdempotencyKey::parse("effect-binding".into())?
                )
                .await,
            Err(JobStoreError::Unavailable)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn broker_never_follows_redirects_or_sends_credentials_to_a_changed_endpoint()
    -> TestResult {
        let server = Server::start().await?;
        let other = Server::start().await?;
        let files = Files::new(&server)?;
        let broker = CommandBroker::open(files.configuration.clone(), files.panel.clone())?;
        server.state.mode.store(3, Ordering::Relaxed);
        *server.state.redirect.lock().map_err(|_| "test mutex")? =
            format!("http://{}/capture", other.address);
        let repository = RepositoryId::parse("broker/fixture")?;
        assert!(matches!(
            broker
                .context(
                    "operator",
                    server.state.project,
                    &repository,
                    ControlOperation::CancelEligibleJob
                )
                .await,
            Err(JobStoreError::Unavailable)
        ));
        assert_eq!(other.state.calls.load(Ordering::Relaxed), 0);

        files.change(|value| value["endpoint"] = serde_json::json!(other.address))?;
        assert!(matches!(
            broker
                .context(
                    "operator",
                    server.state.project,
                    &repository,
                    ControlOperation::CancelEligibleJob
                )
                .await,
            Err(JobStoreError::Unavailable)
        ));
        assert_eq!(other.state.calls.load(Ordering::Relaxed), 0);

        Ok(())
    }

    #[tokio::test]
    async fn broker_reload_denies_login_secret_reuse_public_files_symlinks_and_external_endpoints()
    -> TestResult {
        let server = Server::start().await?;
        let files = Files::new(&server)?;
        let broker = CommandBroker::open(files.configuration.clone(), files.panel.clone())?;
        let repository = RepositoryId::parse("broker/fixture")?;
        files.change(|value| value["mappings"][0]["token"] = serde_json::json!(LOGIN))?;
        assert!(matches!(
            broker
                .context(
                    "operator",
                    server.state.project,
                    &repository,
                    ControlOperation::CancelEligibleJob
                )
                .await,
            Err(JobStoreError::Unavailable)
        ));
        files.change(|value| value["mappings"][0]["token"] = serde_json::json!(TOKEN))?;
        let link = files.configuration.with_file_name("broker-link.json");
        std::os::unix::fs::symlink(&files.configuration, &link)?;
        assert!(CommandBroker::open(link, files.panel.clone()).is_err());
        files.change(|value| value["endpoint"] = serde_json::json!("192.0.2.1:8080"))?;
        assert!(CommandBroker::open(files.configuration.clone(), files.panel.clone()).is_err());
        files.change(|value| value["endpoint"] = serde_json::json!(server.address))?;
        std::fs::set_permissions(&files.configuration, std::fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            broker
                .context(
                    "operator",
                    server.state.project,
                    &repository,
                    ControlOperation::CancelEligibleJob
                )
                .await,
            Err(JobStoreError::Unavailable)
        ));
        assert_eq!(server.state.calls.load(Ordering::Relaxed), 0);

        Ok(())
    }
}
