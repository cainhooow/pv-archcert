//! Versioned identities for the canonical M6 artifact pipeline.

use crate::{ProjectId, Sha256Digest, SourceIdentity, source::RepositoryId};
use serde::{Deserialize, Serialize};

macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Sha256Digest);
    };
}

identity!(
    BuildRecipeIdentity,
    "SHA-256 of the complete canonical authority recipe."
);
identity!(
    BuildEnvironmentIdentity,
    "SHA-256 of the pinned authority build environment."
);
identity!(
    BuildInvocationIdentity,
    "SHA-256 of the admitted immutable build input manifest."
);
identity!(
    BuildResultIdentity,
    "SHA-256 of one canonical independently collected build result."
);
identity!(
    ReproducibilityIdentity,
    "SHA-256 of the canonical comparison evidence."
);
identity!(
    ReleasePermitIdentity,
    "SHA-256 of the canonical signed permit payload, not its signature."
);

/// Exact scoped source and source certificate. Neither identifies a deployable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedSourceIdentity {
    /// Registered project scope.
    pub project: ProjectId,
    /// Registered repository scope.
    pub repository: RepositoryId,
    /// Exact immutable source bytes and Git provenance.
    pub source: SourceIdentity,
    /// Canonical source certificate payload identity, separately verified.
    pub certificate_sha256: Sha256Digest,
}

/// Content identity of the initial single-file deployable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifactIdentity {
    /// Schema-1 kind is REGULAR_FILE.
    pub kind: String,
    /// Schema-1 algorithm is SHA-256.
    pub algorithm: String,
    /// Digest of the actual immutable bytes, never of a filename.
    pub sha256: Sha256Digest,
    /// Exact nonzero byte count.
    pub size: u64,
    /// Schema-1 media type is application/octet-stream.
    pub media_type: String,
    /// Schema-1 production role is RUST_EXECUTABLE.
    pub role: String,
}

/// Independently executed repetitions of the same admitted build contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildOrdinal {
    /// First fresh execution instance.
    A,
    /// Second fresh execution instance; never a copy of A.
    B,
}

/// Reliability of the build operation, separate from reproducibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BuildCompletion {
    /// Runtime exit zero, collected output and confirmed sandbox/source cleanup.
    Complete,
    /// Observed normal nonzero exit; no eligible artifact.
    TargetFailed,
    /// Infrastructure, cleanup, collection or observation could not complete.
    Inconclusive,
}

/// Deterministic comparison result. Missing output is never a byte difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReproducibilityVerdict {
    /// Independently collected output size and SHA-256 match exactly.
    Reproducible,
    /// Both outputs completed but their bytes differ.
    NonReproducible,
    /// Two successful independent outputs could not be established.
    Inconclusive,
}
