//! Release conformance and hostile-input tests; synthetic source is not certification.

#[path = "../../archcert-application/tests/support/release.rs"]
mod fixtures;

use archcert_application::release::*;
use archcert_certificate::{CertificateEnvelope, release::*};
use archcert_crypto::PublicKey;
use archcert_domain::{release::*, source::digest_bytes};
use ed25519_dalek::{Signer, SigningKey};
use fixtures::*;
use serde_json::{Value, json};

struct Fixture {
    input: BuildInputManifest,
    recipe: RustReleaseRecipe,
    certificate: CertificateEnvelope,
    source_key: PublicKey,
    release_key: PublicKey,
    signing: SigningKey,
    a: BuildResult,
    b: BuildResult,
    comparison: ReproducibilityEvidence,
}

impl Fixture {
    fn new() -> R<Self> {
        let certificate =
            CertificateEnvelope::read(include_bytes!("fixtures/openssl-vector.json").as_slice())?;
        let source_key = PublicKey::from_hex(
            "81bc9f78e8d161faf8ca4ef3e44524210da1fee99f665afd891eeece20200ca0",
        )?;
        let signing = SigningKey::from_bytes(&[42; 32]);
        let release_key = PublicKey::from_bytes(signing.verifying_key().to_bytes())?;
        let mut input = input()?;
        input.certified_source = certified_source(&certificate, &source_key)?;
        input.source_policy_sha256 = archcert_domain::Sha256Digest::parse(
            "e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae",
        )?;
        input.source_authority_key_sha256 =
            archcert_domain::Sha256Digest::parse(source_key.key_id().as_str())?;
        input.release_authority_key_sha256 =
            archcert_domain::Sha256Digest::parse(release_key.key_id().as_str())?;
        let a = result(&input, BuildOrdinal::A, b"deployable")?;
        let b = result(&input, BuildOrdinal::B, b"deployable")?;
        let comparison = compare_builds(&input, &a, &b)?;

        Ok(Self {
            input,
            recipe: recipe()?,
            certificate,
            source_key,
            release_key,
            signing,
            a,
            b,
            comparison,
        })
    }

    fn draft(&self) -> R<ReleasePermitDraft> {
        Ok(ReleasePermitDraft::prepare(ReleasePermitContext {
            input: &self.input,
            recipe: &self.recipe,
            source_certificate: &self.certificate,
            source_key: &self.source_key,
            release_key: &self.release_key,
            a: &self.a,
            b: &self.b,
            reproducibility: &self.comparison,
            artifact: b"deployable",
        })?)
    }

    // Conformance signature only: application issuance additionally requires the
    // unconstructible durable payload capability. This helper tests offline parsing.
    fn envelope(&self) -> R<Value> {
        let draft = self.draft()?;
        let signature = self.signing.sign(draft.bytes());
        Ok(json!({
            "payload": serde_json::from_slice::<Value>(draft.bytes())?,
            "permit_sha256": draft.identity().0,
            "signature": signature.to_string().to_lowercase(),
            "public_key": self.release_key.to_hex(),
        }))
    }
}

#[test]
fn offline_gate_verifies_exact_deployable_bytes_scope_and_separate_trust_key() -> R {
    let f = Fixture::new()?;
    let json = serde_json::to_vec(&f.envelope()?)?;
    let envelope = ReleasePermitEnvelope::read(json.as_slice())?;
    let scope = &f.input.certified_source;

    envelope.authorize_artifact(
        &f.release_key,
        scope.project,
        &scope.repository,
        b"deployable",
    )?;
    assert!(
        envelope
            .authorize_artifact(
                &f.release_key,
                scope.project,
                &scope.repository,
                b"replacement"
            )
            .is_err()
    );
    assert!(
        envelope
            .authorize_artifact(
                &f.release_key,
                archcert_domain::ProjectId::new(),
                &scope.repository,
                b"deployable"
            )
            .is_err()
    );
    assert!(envelope.verify(&f.source_key).is_err());
    assert!(
        ReleasePermitEnvelope::read(include_bytes!("fixtures/openssl-vector.json").as_slice())
            .is_err()
    );

    Ok(())
}

#[test]
fn source_substitution_policy_downgrade_nonreproducibility_and_missing_build_never_prepare() -> R {
    let mut f = Fixture::new()?;
    f.input.certified_source.source.snapshot_sha256 = digest_bytes(b"another source");
    assert!(f.draft().is_err());

    f = Fixture::new()?;
    f.input.source_policy_sha256 = digest_bytes(b"different policy");
    assert!(f.draft().is_err());

    f = Fixture::new()?;
    f.b.artifact = Some(artifact_identity(b"different output")?);
    f.comparison = compare_builds(&f.input, &f.a, &f.b)?;
    assert!(f.draft().is_err());

    f = Fixture::new()?;
    f.b.completion = BuildCompletion::Inconclusive;
    f.b.artifact = None;
    f.b.execution = None;
    f.comparison = compare_builds(&f.input, &f.a, &f.b)?;
    assert!(f.draft().is_err());

    Ok(())
}

#[test]
fn every_payload_binding_is_signed_and_unknown_duplicate_and_oversized_objects_reject() -> R {
    let f = Fixture::new()?;
    let original = f.envelope()?;
    for field in [
        "invocation",
        "recipe",
        "environment",
        "reproducibility",
        "policy_sha256",
    ] {
        let mut changed = original.clone();
        changed["payload"][field] = json!(digest_bytes(b"substitution"));
        changed["permit_sha256"] = json!(digest_bytes(&release_bytes(&changed["payload"])?));
        let bytes = serde_json::to_vec(&changed)?;
        assert!(
            ReleasePermitEnvelope::read(bytes.as_slice())
                .and_then(|e| e.verify(&f.release_key))
                .is_err()
        );
    }

    let bytes = serde_json::to_vec(&original)?;
    let text = std::str::from_utf8(&bytes)?;
    let duplicate = text.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
    assert!(ReleasePermitEnvelope::read(duplicate.as_bytes()).is_err());
    assert!(ReleasePermitEnvelope::read(&vec![b' '; 65_537][..]).is_err());
    let mut unknown = original;
    unknown["payload"]["allow_override"] = json!(true);
    assert!(ReleasePermitEnvelope::read(serde_json::to_vec(&unknown)?.as_slice()).is_err());

    Ok(())
}
