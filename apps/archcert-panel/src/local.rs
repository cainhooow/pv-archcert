//! Independently authenticated loopback local-identity client; no authority adapters.

use archcert_application::{jobs::JobStoreError, local::*};
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

pub(super) struct LocalClient {
    path: PathBuf,
    endpoint: SocketAddr,
    client: Client<HttpConnector, Full<Bytes>>,
    slots: tokio::sync::Semaphore,
}

impl LocalClient {
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
impl LocalPlatform for LocalClient {
    async fn call(&self, request: LocalRequest) -> Result<LocalReply, JobStoreError> {
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
        let bytes = serde_json::to_vec(&request).map_err(|_| JobStoreError::Invalid)?;
        let request = Request::post(format!("http://{}/local", self.endpoint))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", config.token))
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|_| JobStoreError::Invalid)?;
        tokio::time::timeout(Duration::from_secs(40), async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| JobStoreError::Unavailable)?;
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
            serde_json::from_slice(&bytes).map_err(|_| JobStoreError::Unavailable)
        })
        .await
        .map_err(|_| JobStoreError::Unavailable)?
    }
}
