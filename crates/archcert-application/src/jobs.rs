//! Durable control-plane ports. Database, wire and runtime capabilities stay outside.
use archcert_domain::{Sha256Digest, jobs::*};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fixed public persistence errors; never expose credentials or database diagnostics.
#[derive(Debug, Error)]
pub enum JobStoreError {
    /// Metadata service unavailable; inspect durable state before retrying writes.
    #[error("durable control plane unavailable")]
    Unavailable,
    /// Input or retained metadata violates a structural invariant.
    #[error("invalid durable input")]
    Invalid,
    /// Authorization failed; existence is not disclosed.
    #[error("not authorized")]
    Unauthorized,
    /// Scoped key was already bound to different inputs.
    #[error("idempotency conflict")]
    Conflict,
    /// Missing record or rejected state/lease precondition.
    #[error("state or ownership precondition failed")]
    Precondition,
}
impl From<JobError> for JobStoreError {
    fn from(_: JobError) -> Self {
        Self::Invalid
    }
}

/// Submission after authentication and immutable source/authority resolution.
#[derive(Debug, Clone)]
pub struct CreateJob {
    /// All pinned inputs.
    pub inputs: JobInputs,
    /// Scoped client retry key.
    pub idempotency: IdempotencyKey,
}
/// Lease proof; never serialize into target input or status responses.
#[derive(Clone)]
pub struct Lease {
    /// Exact job.
    pub job: JobId,
    /// Exact attempt, never reused.
    pub attempt: AttemptId,
    /// Authenticated worker identity.
    pub worker: String,
    /// Secret fencing capability.
    pub token: LeaseToken,
}
/// Immutable metadata for an exact artifact. Availability requires verified stored bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    /// Exact artifact bytes SHA-256.
    pub sha256: Sha256Digest,
    /// Exact byte count.
    pub size: u64,
    /// Artifact schema, independent of canonical certificate/source schema.
    pub schema: u32,
    /// Authority producer implementation.
    pub producer: String,
}
/// Attempt status view; deliberately omits its fencing capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationAttempt {
    /// Immutable attempt identity.
    pub id: AttemptId,
    /// One-based authority attempt ordinal.
    pub ordinal: u16,
    /// Execution worker identity.
    pub worker: String,
    /// Explicit attempt state.
    pub state: AttemptState,
    /// Original lease creation UTC seconds.
    pub leased_at: i64,
    /// Last bounded lease deadline UTC seconds.
    pub lease_until: i64,
    /// Optional end UTC seconds.
    pub ended_at: Option<i64>,
    /// Structured uncertainty or failure.
    pub failure: Option<FailureCategory>,
    /// Exact accepted evidence artifact, if any.
    pub evidence: Option<ArtifactReference>,
}
/// Frozen issuance binding, created before calling the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedIssuance {
    /// Canonical payload SHA-256, not envelope artifact digest.
    pub certificate_sha256: Sha256Digest,
    /// Exact authority-selected key ID.
    pub signing_key_id: String,
    /// Frozen certificate instance time.
    pub issued_at: u64,
}
/// Durable verified certificate metadata; storage must retain the cryptographic envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedCertificate {
    /// The same immutable prepared payload binding.
    pub issuance: PreparedIssuance,
    /// Immutable independently verified envelope bytes.
    pub artifact: ArtifactReference,
    /// Detached Ed25519 signature encoded as lowercase hex.
    pub signature: String,
    /// True only after independent verification; never sufficient on its own.
    pub verified: bool,
}
/// Transport-independent durable read model. Does not construct a certification capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationJob {
    /// Stable job identity.
    pub id: JobId,
    /// All pinned authority inputs.
    pub inputs: JobInputs,
    /// Creation time, UTC seconds from database.
    pub created_at: i64,
    /// Durable evaluation phase entry time from PostgreSQL.
    pub evaluation_at: Option<i64>,
    /// Structured terminal failure/uncertainty category.
    pub failure: Option<FailureCategory>,
    /// Durable state.
    pub state: JobState,
    /// Full attempt history in ordinal order.
    pub attempts: Vec<CertificationAttempt>,
    /// Bound immutable evaluation summary artifact.
    pub evaluation: Option<ArtifactReference>,
    /// Prepared issuance persists through crashes before/after signing.
    pub issuance: Option<PreparedIssuance>,
    /// Verified certificate metadata on completion.
    pub certificate: Option<PersistedCertificate>,
}
/// Claimed work, consumed by a trusted execution adapter.
pub struct Assignment {
    /// Durable pinned job.
    pub job: CertificationJob,
    /// Current ownership proof.
    pub lease: Lease,
}
/// Authority evaluation disposition, independent of transport/policy adapter types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDecision {
    /// All required evidence establishes eligibility; signing still required.
    Eligible,
    /// Definite target/policy rejection; never automatically retried.
    NotEligible,
    /// Infrastructure or evidence uncertainty; no positive authority claim.
    Inconclusive,
}
/// Transactional application port. Implementations must lock and fence all mutations.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// Atomically admit an authorized request or return its identical prior job.
    async fn create(&self, request: CreateJob) -> Result<CertificationJob, JobStoreError>;
    /// Internal authority read; HTTP must separately check authenticated scope.
    async fn get(&self, id: JobId) -> Result<CertificationJob, JobStoreError>;
    /// Atomically select/claim one queued job and create a new attempt.
    async fn claim(
        &self,
        worker: &str,
        lease_seconds: u32,
    ) -> Result<Option<Assignment>, JobStoreError>;
    /// Begin target execution only under a valid current lease.
    async fn start(&self, lease: &Lease) -> Result<(), JobStoreError>;
    /// Renew an unexpired lease under bounded lifetime.
    async fn renew(&self, lease: &Lease, lease_seconds: u32) -> Result<(), JobStoreError>;
    /// Expire a lost attempt; requeue only after an authority has confirmed cleanup.
    async fn recover(&self, id: JobId, cleanup_confirmed: bool) -> Result<(), JobStoreError>;
    /// Accept only a validated AVAILABLE bound evidence reference under the current lease.
    async fn accept_evidence(
        &self,
        lease: &Lease,
        artifact: &ArtifactReference,
    ) -> Result<(), JobStoreError>;
    /// Persist evaluation once. Eligibility alone does not create a certificate.
    async fn record_evaluation(
        &self,
        id: JobId,
        artifact: &ArtifactReference,
        decision: EvaluationDecision,
    ) -> Result<(), JobStoreError>;
    /// Bind a single payload/key/time after durable eligibility, before sign().
    async fn prepare_issuance(
        &self,
        id: JobId,
        issuance: &PreparedIssuance,
    ) -> Result<PreparedIssuance, JobStoreError>;
    /// Atomically complete an exact prepared issuance backed by AVAILABLE verified bytes.
    async fn complete(
        &self,
        id: JobId,
        certificate: &PersistedCertificate,
    ) -> Result<(), JobStoreError>;
}
