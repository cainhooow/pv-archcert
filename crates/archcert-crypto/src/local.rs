//! DEVELOPMENT ONLY. NOT PRODUCTION KEY MANAGEMENT.
//!
//! Keys are created in an explicit private authority directory, never discovered
//! from an environment variable. The caller must keep that directory outside all
//! repositories/materialization roots and load only after target cleanup finishes.
use crate::{CertificateSigner, DetachedSignature, PublicKey, SigningFailure, SigningKeyId};
use ed25519_dalek::{
    Signer, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

/// Private local development signer. Deliberately has no Debug, Display, Clone,
/// serialization or private-byte export implementation. Dalek zeroizes on drop.
pub struct LocalDevelopmentSigner(SigningKey);
fn safe_parent(path: &Path) -> Result<(), SigningFailure> {
    let parent = path.parent().ok_or(SigningFailure::SigningKeyUnavailable)?;
    let metadata =
        std::fs::symlink_metadata(parent).map_err(|_| SigningFailure::SigningKeyUnavailable)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(SigningFailure::SigningKeyUnavailable);
    }
    Ok(())
}
impl LocalDevelopmentSigner {
    /// Generates PKCS#8 DER using OS cryptographic randomness, exclusive no-follow
    /// creation and mode 0600. Refuses an existing path or an unsafe parent.
    /// Returns only public material. Never prints private bytes.
    pub fn generate(path: &Path) -> Result<PublicKey, SigningFailure> {
        safe_parent(path)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        let key = SigningKey::from_bytes(&seed);
        let encoded = key
            .to_pkcs8_der()
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        file.write_all(encoded.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        PublicKey::from_bytes(key.verifying_key().to_bytes())
            .map_err(|_| SigningFailure::SigningKeyUnavailable)
    }
    /// Loads bounded PKCS#8 DER from an explicit private, owned, no-follow file.
    /// Must be called after execution has ended; never pass this object to a runner.
    pub fn load(path: &Path) -> Result<Self, SigningFailure> {
        safe_parent(path)?;
        let file: File = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        if !metadata.is_file()
            || metadata.len() > 4096
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(SigningFailure::SigningKeyUnavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        if bytes.len() > 4096 {
            return Err(SigningFailure::SigningKeyUnavailable);
        }
        let key = SigningKey::from_pkcs8_der(&bytes)
            .map_err(|_| SigningFailure::SigningKeyUnavailable)?;
        Ok(Self(key))
    }
    /// Public verification material only.
    pub fn public_key(&self) -> Result<PublicKey, SigningFailure> {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
            .map_err(|_| SigningFailure::SigningKeyUnavailable)
    }
}
impl CertificateSigner for LocalDevelopmentSigner {
    fn key_id(&self) -> SigningKeyId {
        // A generated Dalek public key is valid by construction.
        PublicKey(self.0.verifying_key().to_bytes()).key_id()
    }
    fn sign(&self, message: &[u8]) -> Result<DetachedSignature, SigningFailure> {
        Ok(DetachedSignature::from_bytes(
            self.0.sign(message).to_bytes(),
        ))
    }
}
