//! Real PostgreSQL atomic admission and fencing; synthetic certificate metadata
//! and a test verifier establish no cryptographic, execution or signing qualification.

use super::*;
use archcert_application::{artifacts::ImmutableArtifactStore, release::*};
use archcert_domain::release::*;
use archcert_storage::artifacts::FilesystemArtifactStore;
use async_trait::async_trait;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};

const CERTIFICATE: &[u8] = b"metadata fixture original certificate / not a signed envelope";

async fn release_fixture() -> R<(
    PostgresJobRepository,
    PgPool,
    ResolvedControlCommand,
    tempfile::TempDir,
    FilesystemArtifactStore,
)> {
    release_fixture_with_certificate(CERTIFICATE).await
}

async fn release_fixture_with_certificate(
    certificate: &[u8],
) -> R<(
    PostgresJobRepository,
    PgPool,
    ResolvedControlCommand,
    tempfile::TempDir,
    FilesystemArtifactStore,
)> {
    let (repo, pool, mut command) = fixture().await?;
    let ResolvedControlAction::RequestCertification { inputs, .. } = &command.action else {
        return Err("source fixture".into());
    };
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"metadata dependencies"),
            toolchain_sha256: digest_bytes(b"metadata toolchain"),
        },
        "fixture",
    )?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: CertifiedSourceIdentity {
            project: command.scope.project,
            repository: command.scope.repository.clone(),
            source: inputs.source.clone(),
            certificate_sha256: digest_bytes(b"metadata source certificate payload"),
        },
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: inputs.policy.sha256.clone(),
        source_authority_key_sha256: digest_bytes(b"metadata source key"),
        release_authority_key_sha256: digest_bytes(b"metadata release key"),
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };
    let reference = ArtifactReference {
        sha256: digest_bytes(certificate),
        size: certificate.len() as u64,
        schema: 1,
        producer: "metadata-certifier-fixture".into(),
    };

    // Explicit migration-owner fixture: this row is not an issued certificate.
    // Exercise object-scope SQL without using a fake signature as positive crypto evidence.
    sqlx::query(
        "INSERT INTO certification_jobs(
           id,project,repository,actor,idempotency_key,inputs,state,
           evaluation,eligible,issuance,certificate
         ) VALUES ($1,$2,$3,$4,'metadata-source',$5,'COMPLETED','{}',true,'{}',$6)",
    )
    .bind(JobId::new().to_string())
    .bind(command.scope.project.to_string())
    .bind(command.scope.repository.as_str())
    .bind(command.scope.actor.as_str())
    .bind(serde_json::to_value(inputs)?)
    .bind(serde_json::json!({
        "artifact": reference,
        "issuance": {
            "certificate_sha256": input.certified_source.certificate_sha256,
        },
    }))
    .execute(&pool)
    .await?;
    let admission = ReleaseAdmission {
        input_reference: release_reference(&release_bytes(&input)?),
        input,
        submission: inputs.submission.clone(),
        actor: command.scope.actor.clone(),
    };
    command.action = ResolvedControlAction::RequestReleaseBuild {
        admission: Box::new(admission),
        source_certificate: reference.clone(),
    };
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let store =
        FilesystemArtifactStore::open_unencrypted_development(&directory.path().canonicalize()?)?;
    store
        .put(command.scope.project, &reference, certificate)
        .await?;

    Ok((repo, pool, command, directory, store))
}

struct Verifier {
    fail: bool,
    calls: AtomicUsize,
}

impl Verifier {
    fn new(fail: bool) -> Self {
        Self {
            fail,
            calls: AtomicUsize::new(0),
        }
    }
}

impl ReleaseBuildSourceVerifier for Verifier {
    fn verify(&self, _: &BuildInputManifest, certificate: &[u8]) -> Result<(), JobStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail || certificate != CERTIFICATE {
            return Err(JobStoreError::Precondition);
        }

        Ok(())
    }
}

struct Reads<'a> {
    store: &'a FilesystemArtifactStore,
    calls: AtomicUsize,
    corrupt: bool,
}

#[async_trait]
impl ImmutableArtifactStore for Reads<'_> {
    async fn put(
        &self,
        _: ProjectId,
        _: &ArtifactReference,
        _: &[u8],
    ) -> Result<(), JobStoreError> {
        Err(JobStoreError::Unauthorized)
    }

    async fn get(
        &self,
        project: ProjectId,
        reference: &ArtifactReference,
    ) -> Result<Vec<u8>, JobStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut bytes = self.store.get(project, reference).await?;
        if self.corrupt {
            bytes.reverse();
        }

        Ok(bytes)
    }
}

async fn assert_no_admission(pool: &PgPool) -> R {
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM release_invocations),
                (SELECT count(*) FROM release_audit),
                (SELECT count(*) FROM release_evidence),
                (SELECT count(*) FROM control_command_audit WHERE event='CommandApplied')",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(counts, (0, 0, 0, 0));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_command_coalesces_keys_and_admits_once_without_execution_claims() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    enable(&repo, &command).await?;
    let one = key("tab-one")?;
    let two = key("tab-two")?;
    let (first, second) = tokio::join!(repo.accept(&command, &one), repo.accept(&command, &two));
    let first = first?;
    assert_eq!(first.id, second?.id);
    let assignment = ControlCommandRepository::claim(&repo, "release-dispatcher", 30)
        .await?
        .ok_or("no claim")?;
    let verifier = Verifier::new(false);
    let prepared = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &store,
        verifier: &verifier,
    }
    .prepare(&assignment, &command.authority_context)
    .await?;

    let (a, b) = tokio::join!(
        repo.apply_release_build(&assignment.lease, &command.authority_context, &prepared),
        repo.apply_release_build(&assignment.lease, &command.authority_context, &prepared),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(JobStoreError::Precondition)
    ));
    let replay = repo.accept(&command, &key("refresh-or-new-tab")?).await?;
    assert_eq!(first.id, replay.id);
    assert_eq!(replay.state, ControlCommandState::Applied);
    let ControlCommandOutcome::Applied { effect } = replay.outcome.ok_or("receipt")? else {
        return Err("not applied".into());
    };
    let CommandEffect::ReleaseBuildRequested { invocation } = *effect else {
        return Err("wrong effect".into());
    };
    let record = ReleaseRepository::get(&repo, command.scope.project, &invocation).await?;
    assert!(!record.claimed_a && !record.claimed_b && record.references.is_empty());
    for ordinal in [BuildOrdinal::A, BuildOrdinal::B] {
        assert!(matches!(
            ReleaseRepository::claim(&repo, command.scope.project, &invocation, ordinal).await,
            Err(JobStoreError::Precondition)
        ));
    }
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM release_invocations),
                (SELECT count(*) FROM release_audit WHERE event='BUILD_ADMITTED'),
                (SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'),
                (SELECT count(*) FROM control_command_keys)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 1, 1, 3));
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_command_receipt_failure_rolls_back_invocation_and_both_audits() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    let assignment = assignment(&repo, &command).await?;
    let prepared = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &store,
        verifier: &Verifier::new(false),
    }
    .prepare(&assignment, &command.authority_context)
    .await?;
    sqlx::query(
        "CREATE FUNCTION fail_release_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.state='APPLIED' THEN RAISE EXCEPTION 'injected receipt failure'; END IF;
           RETURN NEW;
         END $$",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER fail_release_receipt BEFORE UPDATE ON control_commands
         FOR EACH ROW EXECUTE FUNCTION fail_release_receipt()",
    )
    .execute(&pool)
    .await?;

    assert!(matches!(
        repo.apply_release_build(&assignment.lease, &command.authority_context, &prepared)
            .await,
        Err(JobStoreError::Unavailable)
    ));
    assert_no_admission(&pool).await?;
    let pending =
        ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
    assert_eq!(pending.state, ControlCommandState::Processing);
    assert!(pending.outcome.is_none());

    sqlx::query("DROP TRIGGER fail_release_receipt ON control_commands")
        .execute(&pool)
        .await?;
    repo.apply_release_build(&assignment.lease, &command.authority_context, &prepared)
        .await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_preparation_requires_current_grants_exact_context_and_verified_bytes() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    let assignment = assignment(&repo, &command).await?;
    let reads = Reads {
        store: &store,
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let verifier = Verifier::new(true);
    let preparer = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &reads,
        verifier: &verifier,
    };

    assert!(matches!(
        preparer
            .prepare(&assignment, &digest_bytes(b"wrong authority context"))
            .await,
        Err(JobStoreError::Precondition)
    ));
    assert_eq!(reads.calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        preparer
            .prepare(&assignment, &command.authority_context)
            .await,
        Err(JobStoreError::Precondition)
    ));
    assert_eq!(reads.calls.load(Ordering::Relaxed), 1);
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
    assert_no_admission(&pool).await?;

    sqlx::query("DELETE FROM control_command_grants")
        .execute(&pool)
        .await?;
    assert!(matches!(
        preparer
            .prepare(&assignment, &command.authority_context)
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    assert_eq!(reads.calls.load(Ordering::Relaxed), 1);
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
    assert_no_admission(&pool).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_prepared_capability_cannot_survive_takeover_or_grant_revocation() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    enable(&repo, &command).await?;
    repo.accept(&command, &key("expired-release")?).await?;
    let old = ControlCommandRepository::claim(&repo, "old-release-dispatcher", 5)
        .await?
        .ok_or("original claim")?;
    let verifier = Verifier::new(false);
    let preparer = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &store,
        verifier: &verifier,
    };
    let prepared = preparer.prepare(&old, &command.authority_context).await?;
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert!(matches!(
        repo.apply_release_build(&old.lease, &command.authority_context, &prepared)
            .await,
        Err(JobStoreError::Precondition)
    ));
    let current = ControlCommandRepository::claim(&repo, "new-dispatcher", 30)
        .await?
        .ok_or("new generation")?;
    assert!(matches!(
        repo.apply_release_build(&current.lease, &command.authority_context, &prepared)
            .await,
        Err(JobStoreError::Precondition)
    ));
    assert!(matches!(
        preparer.prepare(&old, &command.authority_context).await,
        Err(JobStoreError::Precondition)
    ));
    let current_prepared = preparer
        .prepare(&current, &command.authority_context)
        .await?;

    sqlx::query("DELETE FROM control_command_grants")
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.apply_release_build(
            &current.lease,
            &command.authority_context,
            &current_prepared
        )
        .await,
        Err(JobStoreError::Unauthorized)
    ));
    assert_no_admission(&pool).await?;
    enable(&repo, &command).await?;
    let outcome = repo
        .apply_release_build(
            &current.lease,
            &digest_bytes(b"unsupported selected authority"),
            &current_prepared,
        )
        .await?;
    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::UnsupportedAuthorityContext,
        }
    ));
    assert_no_admission(&pool).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_request_rejects_certificate_or_source_substitution_before_acceptance() -> R {
    let (repo, pool, command, _directory, _store) = release_fixture().await?;
    for change in 0..5 {
        let mut substituted = command.clone();
        let ResolvedControlAction::RequestReleaseBuild {
            admission,
            source_certificate,
        } = &mut substituted.action
        else {
            return Err("wrong fixture action".into());
        };
        match change {
            0 => source_certificate.sha256 = digest_bytes(b"different certificate envelope"),
            1 => {
                admission.input.certified_source.certificate_sha256 =
                    digest_bytes(b"different payload")
            }
            2 => {
                admission.input.certified_source.source.snapshot_sha256 =
                    digest_bytes(b"foreign source")
            }
            3 => admission.submission = SourceSubmissionId::new(),
            _ => {
                substituted.scope.actor = GitActorId::parse(JobId::new().to_string())?;
                admission.actor = substituted.scope.actor.clone();
            }
        }
        admission.input_reference = release_reference(&release_bytes(&admission.input)?);
        repo.grant(
            substituted.scope.project,
            &substituted.scope.repository,
            &substituted.scope.actor,
        )
        .await?;
        enable(&repo, &substituted).await?;

        assert!(
            repo.accept(&substituted, &key(&format!("foreign-{change}"))?)
                .await
                .is_err()
        );
    }
    let requests: i64 = sqlx::query_scalar("SELECT count(*) FROM control_commands")
        .fetch_one(&pool)
        .await?;
    assert_eq!(requests, 0);
    assert_no_admission(&pool).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_preparation_bounds_reads_and_independently_rechecks_returned_bytes() -> R {
    for oversized in [true, false] {
        let large = vec![b'x'; 65_537];
        let certificate = if oversized {
            large.as_slice()
        } else {
            CERTIFICATE
        };
        let (repo, pool, command, _directory, store) =
            release_fixture_with_certificate(certificate).await?;
        let assignment = assignment(&repo, &command).await?;
        let reads = Reads {
            store: &store,
            calls: AtomicUsize::new(0),
            corrupt: !oversized,
        };
        let verifier = Verifier::new(false);
        let preparer = ReleaseBuildRequestPreparer {
            commands: &repo,
            artifacts: &reads,
            verifier: &verifier,
        };

        let result = preparer
            .prepare(&assignment, &command.authority_context)
            .await;
        if oversized {
            assert!(matches!(result, Err(JobStoreError::Invalid)));
            assert_eq!(reads.calls.load(Ordering::Relaxed), 0);
        } else {
            assert!(matches!(result, Err(JobStoreError::Precondition)));
            assert_eq!(reads.calls.load(Ordering::Relaxed), 1);
        }
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
        assert_no_admission(&pool).await?;
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_prepared_capability_cannot_substitute_another_frozen_request() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    let original = assignment(&repo, &command).await?;
    let verifier = Verifier::new(false);
    let prepared = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &store,
        verifier: &verifier,
    }
    .prepare(&original, &command.authority_context)
    .await?;
    let mut other = command.clone();
    other.authority_context = digest_bytes(b"another explicitly selected authority context");
    enable(&repo, &other).await?;
    repo.accept(&other, &key("different-context")?).await?;
    let other_assignment = ControlCommandRepository::claim(&repo, "other-dispatcher", 30)
        .await?
        .ok_or("other claim")?;
    assert_ne!(original.record.id, other_assignment.record.id);

    assert!(matches!(
        repo.apply_release_build(&other_assignment.lease, &other.authority_context, &prepared)
            .await,
        Err(JobStoreError::Precondition)
    ));
    assert_no_admission(&pool).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn release_command_preserves_existing_non_expiring_m6_claim_and_evidence() -> R {
    let (repo, pool, command, _directory, store) = release_fixture().await?;
    let ResolvedControlAction::RequestReleaseBuild { admission, .. } = &command.action else {
        return Err("wrong fixture action".into());
    };
    let recipe = RustReleaseRecipe::new(admission.input.recipe.environment.clone(), "fixture")?;
    let workflow = ReleaseWorkflow {
        repository: &repo,
        artifacts: &store,
    };
    workflow.admit(admission, &recipe, CERTIFICATE).await?;
    let invocation = admission.input.identity()?;
    let project = command.scope.project;
    let original_claim = ReleaseRepository::claim(&repo, project, &invocation, BuildOrdinal::A)
        .await?
        .ok_or("original independent M6 claim")?;
    let original = ReleaseRepository::get(&repo, project, &invocation).await?;
    assert!(original.claimed_a && !original.claimed_b);
    let assignment = assignment(&repo, &command).await?;
    let prepared = ReleaseBuildRequestPreparer {
        commands: &repo,
        artifacts: &store,
        verifier: &Verifier::new(false),
    }
    .prepare(&assignment, &command.authority_context)
    .await?;

    repo.apply_release_build(&assignment.lease, &command.authority_context, &prepared)
        .await?;

    let retained = ReleaseRepository::get(&repo, project, &invocation).await?;
    assert_eq!(release_bytes(&original)?, release_bytes(&retained)?);
    let stored_token: Option<String> = sqlx::query_scalar(
        "SELECT claim_a FROM release_invocations WHERE project=$1 AND invocation=$2",
    )
    .bind(project.to_string())
    .bind(invocation.0.as_str())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        stored_token.as_deref(),
        Some(original_claim.token.to_string().as_str())
    );
    assert!(
        ReleaseRepository::claim(&repo, project, &invocation, BuildOrdinal::A)
            .await?
            .is_none()
    );
    assert!(matches!(
        ReleaseRepository::claim(&repo, project, &invocation, BuildOrdinal::B).await,
        Err(JobStoreError::Precondition)
    ));
    let admitted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM release_audit WHERE event='BUILD_ADMITTED'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(admitted, 1);

    Ok(())
}
