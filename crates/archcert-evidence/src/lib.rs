//! Inactive future evidence-payload reference scaffold.
//!
//! Payload retention is separate from authority interpretation. This crate is not
//! linked into the development execution/evaluation path and cannot create verdicts.
use archcert_domain::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Reference to a future retained observation payload, with no property verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Content identity of the complete typed observation.
    pub observation_sha256: Sha256Digest,
    /// Digest of the separately retained detailed payload.
    pub payload_sha256: Sha256Digest,
}
