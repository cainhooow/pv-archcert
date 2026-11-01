//! Read-only reuse of M6 verification. No issuance or private-key operation.

use crate::{CertificateEnvelope, release::*};
use archcert_application::{glassmere::*, release::*};
use archcert_crypto::PublicKey;
use archcert_domain::{release::*, source::digest_bytes};

/// Authority-selected public verification context. Raw target data selects none
/// of these keys, recipe semantics or required scope.
pub struct ReleaseObservationContext<'a> {
    /// Exact immutable admitted input, loaded in a coherent metadata snapshot.
    pub input: &'a BuildInputManifest,
    /// Explicitly provisioned recipe capability.
    pub recipe: &'a RustReleaseRecipe,
    /// Separately trusted source verification key.
    pub source_key: &'a PublicKey,
    /// Separately trusted release verification key.
    pub release_key: &'a PublicKey,
    /// Rehashed AVAILABLE object bytes from this invocation and project only.
    pub evidence: &'a [(ReleaseRole, Vec<u8>)],
}

fn bytes<'a>(context: &'a ReleaseObservationContext<'_>, role: ReleaseRole) -> Option<&'a [u8]> {
    context
        .evidence
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, b)| b.as_slice())
}

/// Recheck existing certificate/build/permit authority for one exact artifact.
/// The resulting facts may be aggregated by application, never submitted by a browser.
pub fn observe_release(context: ReleaseObservationContext<'_>) -> ReadinessChecks {
    use BlockerCode::*;

    let input = context.input;
    let source = &input.certified_source;
    let certificate = bytes(&context, ReleaseRole::SourceCertificate)
        .map(CertificateEnvelope::read)
        .transpose();
    let certificate_check = match &certificate {
        Ok(Some(certificate)) => {
            if certificate.verify(context.source_key).is_err() {
                Err(CertificateInvalid)
            } else if certificate.payload.project != source.project.to_string()
                || certificate.payload.repository != source.repository.as_str()
            {
                Err(CertificateScopeMismatch)
            } else if certificate.payload.source.commit != source.source.commit.as_str()
                || certificate.payload.source.tree != source.source.tree.as_str()
                || certificate.payload.source.snapshot_sha256
                    != source.source.snapshot_sha256.as_str()
            {
                Err(SourceIdentityMismatch)
            } else {
                verify_source(
                    input,
                    context.recipe,
                    certificate,
                    context.source_key,
                    context.release_key,
                )
                .map_err(|_| CertificateScopeMismatch)
            }
        }
        Ok(None) => Err(NoSourceCertificate),
        Err(_) => Err(CertificateInvalid),
    };

    let a = bytes(&context, ReleaseRole::ResultA)
        .and_then(|b| serde_json::from_slice::<BuildResult>(b).ok());
    let b = bytes(&context, ReleaseRole::ResultB)
        .and_then(|b| serde_json::from_slice::<BuildResult>(b).ok());
    let comparison = bytes(&context, ReleaseRole::Reproducibility)
        .and_then(|b| serde_json::from_slice::<ReproducibilityEvidence>(b).ok());
    let reproducibility = match (&a, &b, &comparison) {
        (Some(a), Some(b), Some(comparison)) => match compare_builds(input, a, b) {
            Ok(actual) if actual == *comparison => {
                if actual.verdict == ReproducibilityVerdict::Reproducible {
                    Ok(())
                } else {
                    Err(BuildNotReproducible)
                }
            }
            _ => Err(BuildNotReproducible),
        },
        _ => Err(MandatoryEvidenceMissing),
    };

    let artifact_a = bytes(&context, ReleaseRole::ArtifactA);
    let artifact_b = bytes(&context, ReleaseRole::ArtifactB);
    let artifact = match (artifact_a, artifact_b, &a, &b) {
        (Some(aa), Some(bb), Some(a), Some(b)) => match artifact_identity(aa) {
            Ok(identity)
                if aa == bb
                    && a.artifact.as_ref() == Some(&identity)
                    && b.artifact.as_ref() == Some(&identity) =>
            {
                Ok(())
            }
            _ => Err(ArtifactMismatch),
        },
        _ => Err(MandatoryEvidenceMissing),
    };

    let permit = bytes(&context, ReleaseRole::PermitEnvelope)
        .map(ReleasePermitEnvelope::read)
        .transpose();
    let verified_permit = match &permit {
        Ok(Some(permit)) => permit.verify(context.release_key).ok(),
        _ => None,
    };
    let permit_check = match (&permit, &certificate, &a, &b, &comparison, artifact_a) {
        (Ok(None), _, _, _, _, _) => Err(ReleasePermitMissing),
        (
            Ok(Some(permit)),
            Ok(Some(certificate)),
            Some(a),
            Some(b),
            Some(comparison),
            Some(artifact),
        ) => {
            // The existing M6 constructor independently validates the complete
            // canonical payload. Comparing its identity detects valid foreign
            // permits without adding a second cryptographic implementation.
            let draft = ReleasePermitDraft::prepare(ReleasePermitContext {
                input,
                recipe: context.recipe,
                source_certificate: certificate,
                source_key: context.source_key,
                release_key: context.release_key,
                a,
                b,
                reproducibility: comparison,
                artifact,
            });

            match draft {
                Ok(draft)
                    if verified_permit.as_ref() == Some(draft.identity())
                        && bytes(&context, ReleaseRole::PermitPayload) == Some(draft.bytes())
                        && permit
                            .authorize_artifact(
                                context.release_key,
                                source.project,
                                &source.repository,
                                artifact,
                            )
                            .is_ok() =>
                {
                    Ok(())
                }
                _ => Err(ReleasePermitInvalid),
            }
        }
        _ => Err(ReleasePermitInvalid),
    };

    ReadinessChecks {
        subject: ReleaseSubject {
            project: source.project,
            repository: source.repository.as_str().into(),
            source: source.source.clone(),
            certificate: Some(source.certificate_sha256.as_str().into()),
            invocation: input
                .identity()
                .map(|id| id.0.as_str().into())
                .unwrap_or_default(),
            artifact: artifact_a.map(|b| digest_bytes(b).as_str().into()),
            permit: verified_permit.map(|id| id.0.as_str().into()),
        },
        certificate: certificate_check,
        reproducibility,
        artifact,
        permit: permit_check,
        // Selected-key verification authenticates the original authority policy
        // and required-review issuance claims; it does not rerun those checks.
        // Supplemental CLEAR text is never consulted as a success flag.
        policy: certificate_check.map_err(|_| MandatoryEvidenceMissing),
        review: certificate_check.map_err(|_| ReviewInconclusive),
        environment: input
            .validate(context.recipe)
            .map_err(|_| EnvironmentNotQualified),
        freshness: if bytes(&context, ReleaseRole::Input) == release_bytes(input).ok().as_deref() {
            Ok(())
        } else {
            Err(MandatoryEvidenceMissing)
        },
    }
}
