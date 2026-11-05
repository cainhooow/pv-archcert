//! Authority-owned observation models. Presentation cannot submit readiness facts.

pub mod search;

use crate::jobs::JobStoreError;
use archcert_domain::{ProjectId, SourceIdentity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Version of the additive Glassmere query contract.
pub const PROJECTION_SCHEMA: u32 = 1;

/// All public collection pages are bounded independently of browser parameters.
pub const MAX_PAGE_SIZE: usize = 50;

/// Maximum inert evidence preview, distinct from original immutable downloads.
pub const MAX_PREVIEW_BYTES: usize = 8192;

/// Exact categorical release result; never a score or a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseState {
    /// All selected authoritative prerequisites verified for this exact tuple.
    ReleaseAllowed,
    /// One or more exact prerequisites failed or remain uncertain.
    ReleaseDenied,
}

/// Stable blockers preserve the difference between missing, failed and uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockerCode {
    /// No source certificate bytes are available.
    NoSourceCertificate,
    /// Existing selected-key verifier rejected the certificate.
    CertificateInvalid,
    /// Certificate is valid for a different certification scope.
    CertificateScopeMismatch,
    /// Two independent complete builds do not establish reproducibility.
    BuildNotReproducible,
    /// Actual bytes differ from the selected artifact.
    ArtifactMismatch,
    /// No permit has been accepted.
    ReleasePermitMissing,
    /// Existing verifier or exact canonical permit binding rejected.
    ReleasePermitInvalid,
    /// An authoritative mandatory deterministic policy failed.
    PolicyFailed,
    /// A mandatory prerequisite is missing or NOT_PROVEN.
    MandatoryEvidenceMissing,
    /// Supplemental review vetoes continuation.
    SemanticVeto,
    /// Required review remains INCONCLUSIVE.
    ReviewInconclusive,
    /// Source identities disagree.
    SourceIdentityMismatch,
    /// Artifact identities disagree.
    ArtifactIdentityMismatch,
    /// Environment does not match the selected authority requirement.
    EnvironmentNotQualified,
    /// Requested projection revision is no longer current.
    StaleProjection,
    /// A dependency or mandatory observation is unavailable.
    InfrastructureUncertain,
}

/// An explanation produced below the frontend, tied to the affected identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBlocker {
    /// Stable machine reason.
    pub code: BlockerCode,
    /// Fixed authority explanation, never a frontend inference.
    pub summary: String,
    /// Exact selected entity or digest affected.
    pub affected_identity: String,
    /// Immutable backing artifact, where available.
    pub evidence_reference: Option<String>,
    /// Bounded operational category, not an automatic repair operation.
    pub remediation_category: String,
}

/// Exact object tuple being observed. Branch names are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSubject {
    /// Project UUID.
    pub project: ProjectId,
    /// Exact registered repository.
    pub repository: String,
    /// Commit, tree and snapshot digest.
    pub source: SourceIdentity,
    /// Canonical certificate payload identity, if selected.
    pub certificate: Option<String>,
    /// Exact invocation, binding recipe and environment.
    pub invocation: String,
    /// Digest of the actual selected release artifact.
    pub artifact: Option<String>,
    /// Canonical permit payload identity, if selected.
    pub permit: Option<String>,
}

/// Backend readiness observation. It does not grant a new release capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseReadiness {
    /// Explicit compatibility version.
    pub schema: u32,
    /// Exact source/artifact tuple.
    pub subject: ReleaseSubject,
    /// Binary headline with structured denial reasons.
    pub state: ReleaseState,
    /// Empty only when all mandatory checks established their result.
    pub blockers: Vec<ReleaseBlocker>,
    /// Canonical content revision, not a wall-clock ordering surrogate.
    pub revision: String,
    /// UTC Unix seconds for observation age, never authority ordering.
    pub evaluated_at: i64,
    /// Explicit provenance and development scope.
    pub provenance: String,
}

/// Results established by a trusted query/verifier adapter, never browser input.
/// These are not accepted by any HTTP command or deserialization endpoint.
pub struct ReadinessChecks {
    /// Exact subject selected before checking evidence.
    pub subject: ReleaseSubject,
    /// Certificate verification and exact source/scope binding.
    pub certificate: Result<(), BlockerCode>,
    /// Independent A/B completion, cleanup and exact comparison.
    pub reproducibility: Result<(), BlockerCode>,
    /// Rehashed bytes and exact artifact binding.
    pub artifact: Result<(), BlockerCode>,
    /// Selected-key signature plus exact canonical M6 payload binding.
    pub permit: Result<(), BlockerCode>,
    /// Deterministic source policy, verified through its certificate/evidence scope.
    pub policy: Result<(), BlockerCode>,
    /// Required supplemental gate; CLEAR creates no deterministic proof.
    pub review: Result<(), BlockerCode>,
    /// Explicitly selected recipe/environment scope, never target selection.
    pub environment: Result<(), BlockerCode>,
    /// Snapshot availability and revision agreement.
    pub freshness: Result<(), BlockerCode>,
}

impl ReadinessChecks {
    /// Aggregate exact checked requirements, preserving every distinct blocker.
    pub fn evaluate(self, revision: String, evaluated_at: i64) -> ReleaseReadiness {
        let mut blockers = Vec::new();

        for check in [
            self.certificate,
            self.reproducibility,
            self.artifact,
            self.permit,
            self.policy,
            self.review,
            self.environment,
            self.freshness,
        ] {
            if let Err(code) = check
                && !blockers.iter().any(|b: &ReleaseBlocker| b.code == code)
            {
                blockers.push(ReleaseBlocker {
                    code,
                    summary: blocker_summary(code).into(),
                    affected_identity: self.subject.invocation.clone(),
                    evidence_reference: None,
                    remediation_category: "AUTHORITY_EVIDENCE_REQUIRED".into(),
                });
            }
        }

        ReleaseReadiness {
            schema: PROJECTION_SCHEMA,
            subject: self.subject,
            state: if blockers.is_empty() {
                ReleaseState::ReleaseAllowed
            } else {
                ReleaseState::ReleaseDenied
            },
            blockers,
            revision,
            evaluated_at,
            provenance: "Existing certificate and M6 verifiers; DEVELOPMENT authority scope".into(),
        }
    }
}

/// Stable bounded explanations. Unknown backend versions must not default green.
pub fn blocker_summary(code: BlockerCode) -> &'static str {
    match code {
        BlockerCode::NoSourceCertificate => "Source certificate bytes are missing.",
        BlockerCode::CertificateInvalid => {
            "Source certificate verification failed or is unsupported."
        }
        BlockerCode::CertificateScopeMismatch => "Certificate scope does not match this release.",
        BlockerCode::BuildNotReproducible => {
            "Independent complete builds do not establish reproducibility."
        }
        BlockerCode::ArtifactMismatch => "Actual artifact bytes differ from the selected binding.",
        BlockerCode::ReleasePermitMissing => "An accepted Release Permit is missing.",
        BlockerCode::ReleasePermitInvalid => {
            "Release Permit verification or canonical binding failed."
        }
        BlockerCode::PolicyFailed => "A mandatory deterministic policy failed.",
        BlockerCode::MandatoryEvidenceMissing => "Mandatory evidence is missing or NOT_PROVEN.",
        BlockerCode::SemanticVeto => "Supplemental review vetoes continuation.",
        BlockerCode::ReviewInconclusive => "Required review remains INCONCLUSIVE.",
        BlockerCode::SourceIdentityMismatch => "Source commit, tree or snapshot binding differs.",
        BlockerCode::ArtifactIdentityMismatch => {
            "Selected artifact identity differs from the permit/build."
        }
        BlockerCode::EnvironmentNotQualified => {
            "Build environment does not meet the selected authority scope."
        }
        BlockerCode::StaleProjection => {
            "This projection revision is stale; refresh authoritative state."
        }
        BlockerCode::InfrastructureUncertain => {
            "A required dependency or observation is unavailable."
        }
    }
}

/// Explicit public fact with provenance. No internal authority struct is serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationField {
    /// Human-readable label.
    pub label: String,
    /// Escaped inert text at the presentation boundary.
    pub value: String,
    /// Producer or durable record supplying this value.
    pub provenance: String,
}

/// Bounded operational entity, distinct from accepted immutable evidence bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityObservation {
    /// Non-secret job/session/invocation identity.
    pub id: String,
    /// Explicit entity vocabulary.
    pub kind: String,
    /// Exact underlying state; unsupported states stay visible.
    pub state: String,
    /// Selected public fields only.
    pub fields: Vec<ObservationField>,
}

/// One project/repository scope. No repository credential or remote URL is exposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectObservation {
    /// Project UUID.
    pub project: ProjectId,
    /// Registry label; multiple repositories require exact entity selection.
    pub repository: String,
}

/// Immutable reference metadata; acceptance is separate from byte availability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObservation {
    /// Owning durable entity.
    pub entity: String,
    /// Fixed role name.
    pub role: String,
    /// Digest of exact bytes, never mutable row identity.
    pub sha256: String,
    /// Byte size.
    pub size: u64,
    /// Producer schema.
    pub schema: u32,
    /// Producer identity.
    pub producer: String,
    /// Retained STAGING/AVAILABLE state.
    pub state: String,
    /// Explicit selected-key verification observations, separate from record existence.
    #[serde(default)]
    pub verification: Vec<ObservationField>,
}

/// A durable event retains its own stream ordering; independent streams do not merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineObservation {
    /// Certification or release stream.
    pub stream: String,
    /// Durable sequence within that stream.
    pub sequence: i64,
    /// Backing job/session/invocation.
    pub entity: String,
    /// Exact recorded event.
    pub event: String,
    /// UTC Unix seconds, for display only.
    pub timestamp: i64,
}

/// Coherent bounded read. Deleting this value cannot delete certification truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSnapshot {
    /// Projection contract.
    pub schema: u32,
    /// Exact project/repository registry identity.
    pub project: ProjectObservation,
    /// Content revision excluding evaluation wall time.
    pub revision: String,
    /// Database read snapshot, not a certificate or lease.
    pub database_snapshot: String,
    /// UTC Unix seconds.
    pub evaluated_at: i64,
    /// Explicit page offset for each independently bounded collection.
    pub offset: u32,
    /// Page size fixed by authority.
    pub page_size: usize,
    /// At least one collection has a following page.
    pub has_more: bool,
    /// Exact accepted source records; no invented current-source ordering.
    pub sources: Vec<EntityObservation>,
    /// Jobs without fences, tokens, environment values or credentials.
    pub jobs: Vec<EntityObservation>,
    /// Semantic sessions, including blocked pre-admission sessions.
    pub sessions: Vec<EntityObservation>,
    /// Exact release invocation metadata.
    pub releases: Vec<EntityObservation>,
    /// Accepted or staged immutable reference metadata.
    pub evidence: Vec<EvidenceObservation>,
    /// Durable timeline, bounded independently by stream.
    pub timeline: Vec<TimelineObservation>,
    /// Outages, unsupported dimensions and explicit selection limitations.
    pub limitations: Vec<String>,
}

/// Query-only port: no arbitrary SQL, write, runtime, signing or object publication.
#[async_trait]
pub trait GlassmereQuery: Send + Sync {
    /// Bounded exact operational search within a separately authorized project.
    async fn search(
        &self,
        project: ProjectId,
        query: &search::SearchQuery,
    ) -> Result<search::SearchPage, JobStoreError>;

    /// List only explicitly authorized project scopes; bounded keyset cursor.
    async fn projects(
        &self,
        allowed: &[ProjectId],
        after: Option<ProjectId>,
    ) -> Result<Vec<ProjectObservation>, JobStoreError>;

    /// Read one coherent project/repository aggregate; scope is checked by the caller.
    async fn snapshot(
        &self,
        project: ProjectId,
        offset: u32,
    ) -> Result<ProjectSnapshot, JobStoreError>;

    /// Read an exact registered job/session without requiring its history-page offset.
    /// Child evidence and audit collections remain independently bounded.
    async fn entity(
        &self,
        project: ProjectId,
        entity: &str,
        offset: u32,
    ) -> Result<ProjectSnapshot, JobStoreError>;

    /// Verify one exact release, never a heuristic latest release.
    async fn readiness(
        &self,
        project: ProjectId,
        invocation: &str,
    ) -> Result<ReleaseReadiness, JobStoreError>;

    /// Resolve and read only a project-bound registered immutable object.
    async fn evidence(
        &self,
        project: ProjectId,
        entity: &str,
        digest: &str,
    ) -> Result<(EvidenceObservation, Vec<u8>), JobStoreError>;

    /// Separate process/dependency health from release authorization.
    async fn healthy(&self) -> bool;
}
