//! Readiness invariants live below the browser and retain exact blocker codes.

use archcert_application::glassmere::*;
use archcert_domain::{GitObjectId, ProjectId, Sha256Digest, SourceIdentity};

type R = Result<(), Box<dyn std::error::Error>>;

fn eligible() -> Result<ReadinessChecks, Box<dyn std::error::Error>> {
    Ok(ReadinessChecks {
        subject: ReleaseSubject {
            project: ProjectId::new(),
            repository: "fixture/project".into(),
            source: SourceIdentity {
                commit: GitObjectId::parse("a".repeat(40))?,
                tree: GitObjectId::parse("b".repeat(40))?,
                snapshot_sha256: Sha256Digest::parse("c".repeat(64))?,
            },
            certificate: Some("d".repeat(64)),
            invocation: "e".repeat(64),
            artifact: Some("f".repeat(64)),
            permit: Some("1".repeat(64)),
        },
        certificate: Ok(()),
        reproducibility: Ok(()),
        artifact: Ok(()),
        permit: Ok(()),
        policy: Ok(()),
        review: Ok(()),
        environment: Ok(()),
        freshness: Ok(()),
    })
}

#[test]
fn fully_verified_development_scope_allows_exact_subject() -> R {
    let checks = eligible()?;
    let subject = checks.subject.clone();

    let readiness = checks.evaluate("revision".into(), 1700000000);

    assert_eq!(readiness.state, ReleaseState::ReleaseAllowed);
    assert_eq!(readiness.subject, subject);
    assert!(readiness.blockers.is_empty());

    Ok(())
}

#[test]
fn qualification_corpus_preserves_every_denial_reason() -> R {
    use BlockerCode::*;

    for code in [
        NoSourceCertificate,
        CertificateInvalid,
        CertificateScopeMismatch,
        SourceIdentityMismatch,
        MandatoryEvidenceMissing,
        ArtifactMismatch,
        ArtifactIdentityMismatch,
        BuildNotReproducible,
        ReleasePermitMissing,
        ReleasePermitInvalid,
        PolicyFailed,
        ReviewInconclusive,
        SemanticVeto,
        EnvironmentNotQualified,
        StaleProjection,
        InfrastructureUncertain,
    ] {
        let mut checks = eligible()?;
        checks.freshness = Err(code);

        let readiness = checks.evaluate("revision".into(), 1700000000);

        assert_eq!(readiness.state, ReleaseState::ReleaseDenied, "{code:?}");
        assert_eq!(readiness.blockers.len(), 1);
        assert_eq!(readiness.blockers[0].code, code);
        assert!(!readiness.blockers[0].summary.is_empty());
    }

    Ok(())
}

#[test]
fn every_mandatory_check_independently_denies_and_clear_cannot_override() -> R {
    for index in 0..8 {
        let mut checks = eligible()?;
        let requirement = match index {
            0 => &mut checks.certificate,
            1 => &mut checks.reproducibility,
            2 => &mut checks.artifact,
            3 => &mut checks.permit,
            4 => &mut checks.policy,
            5 => &mut checks.review,
            6 => &mut checks.environment,
            _ => &mut checks.freshness,
        };
        *requirement = Err(BlockerCode::MandatoryEvidenceMissing);

        let readiness = checks.evaluate("revision".into(), 1700000000);

        assert_eq!(readiness.state, ReleaseState::ReleaseDenied);
    }

    let mut checks = eligible()?;
    checks.policy = Err(BlockerCode::PolicyFailed);
    checks.review = Ok(()); // Authority-accepted supplemental CLEAR adds no proof.

    assert_eq!(
        checks.evaluate("revision".into(), 1700000000).state,
        ReleaseState::ReleaseDenied,
    );

    Ok(())
}

#[test]
fn partial_knowledge_does_not_manufacture_full_coverage_or_new_blockers() -> R {
    // M7 bounded PARTIAL_ACCEPTABLE coverage is not itself an M6 policy veto.
    // Its exact scope remains evidence; readiness has no coverage-success flag.
    let readiness = eligible()?.evaluate("revision".into(), 1700000000);
    let value = serde_json::to_value(readiness)?;

    assert!(value.get("score").is_none());
    assert!(value.get("knowledge_complete").is_none());
    assert_eq!(value["schema"], PROJECTION_SCHEMA);

    Ok(())
}
