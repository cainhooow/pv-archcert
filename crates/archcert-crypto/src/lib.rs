//! Ed25519 authority port and offline verification primitives.
//!
//! No runner, source, project configuration or execution adapter can depend on this
//! crate. The optional local adapter is DEVELOPMENT ONLY, NOT PRODUCTION KEY MANAGEMENT.
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(all(feature = "local-development", unix))]
pub mod local;

/// Stable SHA-256 identity of exactly the 32 raw Ed25519 public-key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyId(String);
impl SigningKeyId {
    /// Lowercase SHA-256, independent of paths or filenames.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Public Ed25519 verification material; never a signing capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);
impl PublicKey {
    /// Rejects malformed encodings and small-order keys before use.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak()
            || !key.to_edwards().is_torsion_free()
            || key.to_edwards().compress().to_bytes() != bytes
        {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(bytes))
    }
    /// Strict lowercase raw-key hexadecimal; not a private-key encoding.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let bytes = decode_hex::<32>(value).map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_bytes(bytes)
    }
    /// Canonical public representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    /// Stable public signing-key identity.
    pub fn key_id(&self) -> SigningKeyId {
        SigningKeyId(hex::encode(Sha256::digest(self.0)))
    }
    /// Strict Ed25519 verification of the exact supplied message, with no fallback.
    pub fn verify(&self, message: &[u8], signature: &DetachedSignature) -> Result<(), CryptoError> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|_| CryptoError::InvalidPublicKey)?
            .verify_strict(message, &Signature::from_bytes(&signature.0))
            .map_err(|_| CryptoError::VerificationFailed)
    }
}
/// Detached Ed25519 signature, distinct from any certificate digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature([u8; 64]);
impl DetachedSignature {
    /// Fixed-length output from a signer adapter.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
    /// Strict lowercase hexadecimal signature decoding.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        Ok(Self(
            decode_hex(value).map_err(|_| CryptoError::InvalidSignature)?,
        ))
    }
    /// Public detached signature representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], hex::FromHexError> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(s, &mut bytes)?;
    Ok(bytes)
}
/// Fixed public failures; messages never include key input or adapter diagnostics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Public key encoding or group element is invalid.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// Signature encoding has the wrong length or alphabet.
    #[error("invalid Ed25519 signature encoding")]
    InvalidSignature,
    /// The exact message did not verify under the selected public key.
    #[error("Ed25519 verification failed")]
    VerificationFailed,
}
/// Errors across the isolated signing boundary; no secret diagnostics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningFailure {
    /// Private key could not be safely obtained or decoded.
    #[error("signing key unavailable")]
    SigningKeyUnavailable,
    /// The signer failed to produce a signature.
    #[error("signing failed")]
    SigningFailed,
}
/// Narrow authority port. Only canonical certificate bytes reach this interface.
/// Filesystem, environment, KMS, HSM and PKCS#11 details belong to adapters.
pub trait CertificateSigner {
    /// Stable public-key identity; never a filename.
    fn key_id(&self) -> SigningKeyId;
    /// Signs exactly the canonical payload supplied by the issuance component.
    fn sign(&self, message: &[u8]) -> Result<DetachedSignature, SigningFailure>;
}
