//! Public-verifier selection conformance; the retained OpenSSL vector is synthetic.

use super::*;
use archcert_certificate::{CertificateEnvelope, release::certified_source};
use archcert_domain::Sha256Digest;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const CERTIFICATE: &[u8] =
    include_bytes!("../../archcert-certificate/tests/fixtures/openssl-vector.json");

fn fixture() -> TestResult<(BuildInputManifest, RustReleaseRecipe, PublicKey)> {
    let certificate = CertificateEnvelope::read(CERTIFICATE)?;
    let key =
        PublicKey::from_hex("81bc9f78e8d161faf8ca4ef3e44524210da1fee99f665afd891eeece20200ca0")?;
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"test public dependencies"),
            toolchain_sha256: digest_bytes(b"test public toolchain"),
        },
        "test-binary",
    )?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: certified_source(&certificate, &key)?,
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: Sha256Digest::parse(
            "e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae",
        )?,
        source_authority_key_sha256: Sha256Digest::parse(key.key_id().as_str())?,
        // Test-only public selection; no key custody or signature operation is involved.
        release_authority_key_sha256: Sha256Digest::parse(key.key_id().as_str())?,
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };

    Ok((input, recipe, key))
}

#[test]
fn selected_m6_verifier_accepts_the_exact_public_conformance_vector() -> TestResult {
    let (input, recipe, key) = fixture()?;

    verify_release_source(
        &input,
        CERTIFICATE,
        std::slice::from_ref(&key),
        std::slice::from_ref(&key),
        &[recipe],
    )?;

    Ok(())
}

#[test]
fn missing_trust_selection_or_frozen_binding_substitution_fails_closed() -> TestResult {
    let (input, recipe, key) = fixture()?;
    let keys = std::slice::from_ref(&key);
    let recipes = std::slice::from_ref(&recipe);
    for (source_keys, release_keys, recipes) in [
        (&[][..], keys, recipes),
        (keys, &[][..], recipes),
        (keys, keys, &[][..]),
    ] {
        assert!(matches!(
            verify_release_source(&input, CERTIFICATE, source_keys, release_keys, recipes),
            Err(JobStoreError::Precondition)
        ));
    }

    for change in 0..9 {
        let mut other = input.clone();
        match change {
            0 => other.certified_source.project = ProjectId::new(),
            1 => other.certified_source.source.snapshot_sha256 = digest_bytes(b"other source"),
            2 => other.certified_source.certificate_sha256 = digest_bytes(b"other certificate"),
            3 => other.source_policy_sha256 = digest_bytes(b"other policy"),
            4 => other.source_authority_key_sha256 = digest_bytes(b"other source key"),
            5 => other.release_authority_key_sha256 = digest_bytes(b"other release key"),
            6 => other.recipe_identity.0 = digest_bytes(b"other recipe"),
            7 => other.recipe.version = "0.0.0".into(),
            _ => other.environment_identity.0 = digest_bytes(b"other environment"),
        }

        assert!(matches!(
            verify_release_source(&other, CERTIFICATE, keys, keys, recipes),
            Err(JobStoreError::Precondition)
        ));
    }

    Ok(())
}

#[test]
fn damaged_or_oversized_certificate_never_becomes_verified_source() -> TestResult {
    let (input, recipe, key) = fixture()?;
    let keys = std::slice::from_ref(&key);
    let recipes = std::slice::from_ref(&recipe);
    let mut value: serde_json::Value = serde_json::from_slice(CERTIFICATE)?;
    value["signature"] = serde_json::Value::String("0".repeat(128));
    let damaged = serde_json::to_vec(&value)?;
    for bytes in [b"{}".as_slice(), damaged.as_slice(), &vec![b' '; 65_537]] {
        assert!(matches!(
            verify_release_source(&input, bytes, keys, keys, recipes),
            Err(JobStoreError::Precondition)
        ));
    }

    Ok(())
}
