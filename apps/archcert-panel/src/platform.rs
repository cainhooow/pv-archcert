//! Private client of the existing ArchCert API; no authority adapters.

use archcert_application::{jobs::JobStoreError, platform::*};
use async_trait::async_trait;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    endpoint: SocketAddr,
    token: String,
}

pub(super) struct PlatformClient {
    path: PathBuf,
    endpoint: SocketAddr,
    client: Client<HttpConnector, Full<Bytes>>,
    slots: tokio::sync::Semaphore,
}

impl PlatformClient {
    pub(super) fn open(path: PathBuf) -> Result<Self, JobStoreError> {
        let config: Configuration = serde_json::from_slice(&super::broker::read_private(&path)?)
            .map_err(|_| JobStoreError::Invalid)?;
        if !config.endpoint.ip().is_loopback() || config.token.len() != 64 {
            return Err(JobStoreError::Invalid);
        }
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_connect_timeout(Some(Duration::from_secs(2)));
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .retry_canceled_requests(false)
            .pool_max_idle_per_host(0);
        Ok(Self {
            path,
            endpoint: config.endpoint,
            client: builder.build(connector),
            slots: tokio::sync::Semaphore::new(4),
        })
    }
}

#[async_trait]
impl Platform for PlatformClient {
    async fn call(&self, request: PlatformRequest) -> Result<PlatformReply, JobStoreError> {
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| JobStoreError::Unavailable)?;
        let config: Configuration =
            serde_json::from_slice(&super::broker::read_private(&self.path)?)
                .map_err(|_| JobStoreError::Unavailable)?;
        if config.endpoint != self.endpoint || config.token.len() != 64 {
            return Err(JobStoreError::Unavailable);
        }
        let mut identity = None;
        let (path, bytes) = match request {
            PlatformRequest::Certify {
                identity: current,
                project,
                repository,
                submission,
                request_key,
            } => {
                identity = Some((current, request_key));
                (
                    "/api/v1/certifications",
                    serde_json::to_vec(&serde_json::json!({
                        "project": project,
                        "repository": repository,
                        "source_submission": submission,
                    })),
                )
            }
            operation => ("/api/v1/platform", serde_json::to_vec(&operation)),
        };
        let bytes = bytes.map_err(|_| JobStoreError::Invalid)?;
        let mut request = Request::post(format!("http://{}{path}", self.endpoint))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", config.token));
        if let Some((current, key)) = &identity {
            request = request
                .header("x-archcert-principal", &current.principal)
                .header("x-archcert-generation", &current.generation)
                .header("idempotency-key", key);
        }
        let request = request
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|_| JobStoreError::Invalid)?;
        tokio::time::timeout(Duration::from_secs(40), async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| JobStoreError::Unavailable)?;
            if identity.is_some() && response.status().as_u16() != 202 {
                return Err(match response.status().as_u16() {
                    400 => JobStoreError::Invalid,
                    401 | 403 => JobStoreError::Unauthorized,
                    409 => JobStoreError::Conflict,
                    _ => JobStoreError::Unavailable,
                });
            }
            if !response.status().is_success() {
                return Err(match response.status().as_u16() {
                    400 => JobStoreError::Invalid,
                    401 | 403 => JobStoreError::Unauthorized,
                    409 => JobStoreError::Conflict,
                    _ => JobStoreError::Unavailable,
                });
            }
            let bytes = Limited::new(response.into_body(), 128 * 1024)
                .collect()
                .await
                .map_err(|_| JobStoreError::Unavailable)?
                .to_bytes();
            if identity.is_some() {
                let admission: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| JobStoreError::Unavailable)?;
                let job = admission["job_id"]
                    .as_str()
                    .ok_or(JobStoreError::Unavailable)?;
                archcert_domain::jobs::JobId::parse(job).map_err(|_| JobStoreError::Unavailable)?;
                Ok(PlatformReply {
                    state: "REQUEST_ACCEPTED".into(),
                    details: serde_json::json!({"job":job}),
                    credential: None,
                })
            } else {
                serde_json::from_slice(&bytes).map_err(|_| JobStoreError::Unavailable)
            }
        })
        .await
        .map_err(|_| JobStoreError::Unavailable)?
    }
}
