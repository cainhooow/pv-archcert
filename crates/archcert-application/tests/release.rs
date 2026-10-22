//! Exact M6 input identity, comparison and negative release evidence specifications.

#[path = "support/release.rs"]
mod fixtures;

use archcert_application::release::*;
use archcert_domain::{release::*, source::digest_bytes};
use fixtures::*;

#[test]
fn recipe_and_invocation_pin_source_certificate_environment_and_output() -> R {
    let original = input()?;
    original.validate(&recipe()?)?;
    let identity = original.identity()?;

    for field in 0..9 {
        let mut changed = original.clone();
        match field {
            0 => changed.certified_source.source.snapshot_sha256 = digest_bytes(b"other source"),
            1 => changed.certified_source.certificate_sha256 = digest_bytes(b"other certificate"),
            2 => changed.recipe.environment.image = format!("other@sha256:{}", "f".repeat(64)),
            3 => {
                changed.recipe.environment.dependency_bundle_sha256 =
                    digest_bytes(b"other dependencies")
            }
            4 => changed.recipe.environment.toolchain_sha256 = digest_bytes(b"other toolchain"),
            5 => changed.recipe.output = "/work/elsewhere".into(),
            6 => changed.release_authority_key_sha256 = digest_bytes(b"other authority"),
            7 => changed.recipe.normalization = "STRIP-DIFFERENCES".into(),
            _ => changed.recipe.collector_sha256 = digest_bytes(b"substituted collector"),
        }

        assert_ne!(changed.identity()?, identity);
        if (2..=5).contains(&field) || field >= 7 {
            assert!(changed.validate(&recipe()?).is_err());
        }
    }

    assert!(RustReleaseRecipe::new(original.recipe.environment, "../escape").is_err());

    Ok(())
}

#[test]
fn exact_equal_bytes_different_bytes_and_missing_build_have_distinct_verdicts() -> R {
    let input = input()?;
    let a = result(&input, BuildOrdinal::A, b"exact deployable")?;
    let mut b = result(&input, BuildOrdinal::B, b"exact deployable")?;

    assert_eq!(
        compare_builds(&input, &a, &b)?.verdict,
        ReproducibilityVerdict::Reproducible
    );

    b.artifact = Some(artifact_identity(b"nondeterministic second build")?);
    assert_eq!(
        compare_builds(&input, &a, &b)?.verdict,
        ReproducibilityVerdict::NonReproducible
    );

    b.completion = BuildCompletion::Inconclusive;
    b.execution = None;
    b.cleanup_complete = false;
    b.artifact = None;
    assert_eq!(
        compare_builds(&input, &a, &b)?.verdict,
        ReproducibilityVerdict::Inconclusive
    );

    Ok(())
}

#[test]
fn copies_replayed_executions_foreign_sources_and_failed_cleanup_cannot_prove_reproducibility() -> R
{
    let input = input()?;
    let a = result(&input, BuildOrdinal::A, b"same")?;
    let mut b = a.clone();
    b.ordinal = BuildOrdinal::B;

    assert_eq!(
        compare_builds(&input, &a, &b)?.verdict,
        ReproducibilityVerdict::Inconclusive
    );

    b = result(&input, BuildOrdinal::B, b"same")?;
    b.cleanup_complete = false;
    assert!(compare_builds(&input, &a, &b).is_err());

    b.cleanup_complete = true;
    b.source.source.snapshot_sha256 = digest_bytes(b"foreign");
    assert!(compare_builds(&input, &a, &b).is_err());

    assert!(artifact_identity(b"").is_err());

    Ok(())
}
