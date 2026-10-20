//! Cryptographic boundaries used by ArchCert.
//!
//! Cryptographic primitives and canonicalization formats must be selected by an
//! approved ADR before production signing is implemented. The runner must never
//! possess a production signing key.

use async_trait::async_trait;
use thiserror::Error;

/// Errors raised by the signing boundary.
#[derive(Debug, Error)]
pub enum SigningError {
    /// The signing service rejected the request.
    #[error("signing service rejected the request")]
    Rejected,
    /// The signer is intentionally unavailable in the current environment.
    #[error("signer unavailable")]
    Unavailable,
}

/// Detached signature returned by a certificate signing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature(pub Vec<u8>);

/// Isolated certificate-signing boundary.
#[async_trait]
pub trait CertificateSigner: Send + Sync {
    /// Signs an already canonicalized certificate payload.
    async fn sign(&self, canonical_payload: &[u8]) -> Result<DetachedSignature, SigningError>;
}
