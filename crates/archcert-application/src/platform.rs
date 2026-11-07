//! Product account and project operations, separate from execution and signing.

use crate::jobs::JobStoreError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Exact current account revision, rechecked before every panel request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountIdentity {
    /// Authority-generated account identifier.
    pub principal: String,
    /// Non-revivable assignment generation.
    pub generation: String,
}

/// Closed product operations; no runtime, key, policy or arbitrary command selector.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PlatformRequest {
    /// Observe durable initialization and infrastructure status.
    Status,
    /// Consume the host-delivered setup secret exactly once.
    Setup {
        /// Host-delivered single-use bootstrap secret.
        secret: String,
        /// Bounded display name.
        display_name: String,
        /// Account address normalized by the identity adapter.
        email: String,
        /// Human secret, never audited or stored in plaintext.
        password: String,
        /// Repeated password; checked by the server.
        confirmation: String,
    },
    /// Exchange a human password through the existing application's identity boundary.
    Login {
        /// Normalized account address.
        email: String,
        /// Human secret, never audited.
        password: String,
    },
    /// Recheck account enablement and assignment generation.
    Validate {
        /// Current exact account revision.
        identity: AccountIdentity,
    },
    /// Read only the account's own registered projects and accepted sources.
    Projects {
        /// Current exact account revision.
        identity: AccountIdentity,
    },
    /// Request a new owned project under the host's single delegated profile.
    CreateProject {
        /// Current exact account revision.
        identity: AccountIdentity,
        /// Bounded project display name.
        name: String,
        /// Bounded inert project description.
        description: String,
        /// Requested repository identifier, independently validated.
        repository: String,
        /// Ed25519 public authentication key; no private material.
        public_key: String,
        /// Exact retained idempotency identity.
        request_key: String,
    },
    /// Admit an exact accepted source using existing durable admission semantics.
    Certify {
        /// Current exact account revision.
        identity: AccountIdentity,
        /// Exact owned project identifier.
        project: String,
        /// Exact repository registered for that project.
        repository: String,
        /// Exact accepted Northgate source submission.
        submission: String,
        /// Exact retained idempotency identity.
        request_key: String,
    },
}

/// Public onboarding projection. Secret exchanges remain internal to the broker.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformReply {
    /// Durable state or acknowledged operation, never a manufactured verdict.
    pub state: String,
    /// Bounded display fields; presentation must escape all strings.
    pub details: serde_json::Value,
    /// Private random panel credential, returned only by successful account login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Existing API's private product interface, mediated by Glassmere's sessions.
#[async_trait]
pub trait Platform: Send + Sync {
    /// Execute a bounded product operation; certification uses existing admission.
    async fn call(&self, request: PlatformRequest) -> Result<PlatformReply, JobStoreError>;
}
