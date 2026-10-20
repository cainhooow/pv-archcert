//! Immutable scoped bulk storage and future envelope encryption boundaries.
use crate::jobs::{ArtifactReference, JobStoreError};
use archcert_domain::ProjectId;
use async_trait::async_trait;

/// S3-compatible immutable object semantics. No vendor-specific object identity.
#[async_trait]
pub trait ImmutableArtifactStore: Send + Sync {
    /// Create-only upload. Existing identical bytes may succeed; replacement must fail.
    /// Verify digest and size before publication, and never infer identity from location.
    async fn put(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
        bytes: &[u8],
    ) -> Result<(), JobStoreError>;
    /// Bounded read which independently verifies exact digest and size before return.
    async fn get(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
    ) -> Result<Vec<u8>, JobStoreError>;
}
/// Future provider-owned envelope, opaque to domain and target execution.
pub struct SealedArtifact {
    /// Authenticated encrypted object bytes produced by a maintained crypto provider.
    pub ciphertext: Vec<u8>,
    /// Provider-defined wrapped DEK and algorithm/version metadata; never a plaintext key.
    pub key_envelope: Vec<u8>,
}
/// Narrow future encryption boundary. No custom encryption algorithm is implemented.
/// Intended hierarchy: root KEK -> organization/project KEK -> per-artifact DEK.
#[async_trait]
pub trait ArtifactCipher: Send + Sync {
    /// Authenticated encryption bound to the authority project and immutable metadata.
    async fn seal(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
        plaintext: &[u8],
    ) -> Result<SealedArtifact, JobStoreError>;
    /// Decrypt/authenticate, then reverify plaintext digest/size before returning.
    async fn open(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
        sealed: &SealedArtifact,
    ) -> Result<Vec<u8>, JobStoreError>;
}
