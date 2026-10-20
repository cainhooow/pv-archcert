//! Local development key isolation, permissions and secret diagnostic regression.
#![cfg(all(feature = "local-development", unix))]
use archcert_crypto::{CertificateSigner, SigningFailure, local::LocalDevelopmentSigner};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
type R = Result<(), Box<dyn std::error::Error>>;
#[test]
fn temporary_os_random_keys_sign_round_trip_and_never_export_secrets_in_diagnostics() -> R {
    let dir = tempfile::tempdir()?;
    let key_path = dir.path().join("key.der");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let public =
        LocalDevelopmentSigner::generate(&key_path).map_err(|e| format!("generation: {e}"))?;
    assert_eq!(fs::metadata(&key_path)?.permissions().mode() & 0o777, 0o600);
    let signer = LocalDevelopmentSigner::load(&key_path).map_err(|e| format!("load: {e}"))?;
    assert_eq!(signer.key_id(), public.key_id());
    assert_eq!(signer.public_key()?, public);
    let signature = signer.sign(b"canonical test payload")?;
    public.verify(b"canonical test payload", &signature)?;
    assert!(public.verify(b"altered payload", &signature).is_err());
    let encoded = fs::read(&key_path)?;
    let observable = format!(
        "{public:?} {signature:?} {} {:?}",
        SigningFailure::SigningKeyUnavailable,
        SigningFailure::SigningFailed
    );
    assert!(!observable.contains(&hex::encode(&encoded)));
    assert!(!observable.contains(&hex::encode(&encoded[encoded.len() - 32..])));
    let second = LocalDevelopmentSigner::generate(&dir.path().join("second.der"))?;
    assert_ne!(public, second);
    assert!(LocalDevelopmentSigner::generate(&key_path).is_err());
    Ok(())
}
#[test]
fn unsafe_permissions_symlinks_hardlinks_bad_lengths_and_canary_errors_reject() -> R {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("key.der");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    LocalDevelopmentSigner::generate(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(LocalDevelopmentSigner::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let link = dir.path().join("link");
    symlink(&path, &link)?;
    assert!(LocalDevelopmentSigner::load(&link).is_err());
    let hard = dir.path().join("hard");
    fs::hard_link(&path, &hard)?;
    assert!(LocalDevelopmentSigner::load(&path).is_err());
    fs::remove_file(hard)?;
    let canary = "CANARY_PRIVATE_KEY_BYTES_NOT_FOR_LOGS";
    fs::write(&path, canary)?;
    let failure = match LocalDevelopmentSigner::load(&path) {
        Ok(_) => return Err("accepted canary key".into()),
        Err(e) => e,
    };
    assert_eq!(failure, SigningFailure::SigningKeyUnavailable);
    assert!(!format!("{failure} {failure:?}").contains(canary));
    fs::write(&path, vec![0; 4097])?;
    assert!(LocalDevelopmentSigner::load(&path).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
    assert!(LocalDevelopmentSigner::generate(&dir.path().join("unsafe.der")).is_err());
    Ok(())
}
