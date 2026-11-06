//! Real PostgreSQL native request resolution. Synthetic completed-job metadata
//! is not certificate issuance and cannot pass independent M6 envelope verification.

use super::*;
use archcert_control_plane::commands::ReleaseBuildAuthority;

const CERTIFICATE: &[u8] = b"native request metadata fixture / not a signed envelope";

fn write_build_credentials(fixture: &mut Fixture) -> Result {
    let grant = &fixture.state.configuration.grants[0];
    let operations = [
        "REQUEST_CERTIFICATION",
        "CANCEL_ELIGIBLE_JOB",
        "RETRY_ELIGIBLE_JOB",
        "REQUEST_RELEASE_BUILD",
    ];
    let path = fixture
        ._directory
        .path()
        .canonicalize()?
        .join("commands.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "principals": [{
                "scope": {
                    "project": grant.project,
                    "repository": grant.repository,
                    "actor": grant.actor,
                },
                "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
                "operations": operations,
            }],
        }))?,
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    fixture.credentials = CommandCredentials::load(&path, &fixture.state.configuration)?;

    Ok(())
}

async fn insert_certificate_metadata(
    fixture: &Fixture,
    inputs: &archcert_domain::jobs::JobInputs,
    certificate: &PersistedCertificate,
) -> Result<JobId> {
    let id = JobId::new();
    let evaluation = ArtifactReference {
        sha256: digest_bytes(b"metadata evaluation"),
        size: 19,
        schema: 1,
        producer: "metadata-only-fixture".into(),
    };
    // Migration-owner fixture, without running the certification or signer path.
    sqlx::query(
        "INSERT INTO certification_jobs(
            id,project,repository,actor,idempotency_key,inputs,state,
            evaluation,eligible,issuance,certificate
         ) VALUES ($1,$2,$3,$4,$1,$5,'COMPLETED',$6,true,$7,$8)",
    )
    .bind(id.to_string())
    .bind(inputs.project.to_string())
    .bind(inputs.repository.as_str())
    .bind(inputs.actor.as_str())
    .bind(serde_json::to_value(inputs)?)
    .bind(serde_json::to_value(evaluation)?)
    .bind(serde_json::to_value(&certificate.issuance)?)
    .bind(serde_json::to_value(certificate)?)
    .execute(&fixture.pool)
    .await?;

    Ok(id)
}

async fn release_fixture() -> Result<(Fixture, JobId, CertificationJob, PersistedCertificate)> {
    let mut fixture = fixture(false).await?;
    fixture.state.provision().await?;
    let grant = &fixture.state.configuration.grants[0];
    let source_job = fixture
        .state
        .submit(
            grant.actor.clone(),
            grant.project,
            grant.repository.clone(),
            fixture.submission.clone(),
            key("source-template-only")?,
        )
        .await?;
    let source_key = digest_bytes(b"metadata source public key");
    let certificate = PersistedCertificate {
        issuance: PreparedIssuance {
            certificate_sha256: digest_bytes(b"metadata source certificate payload"),
            signing_key_id: source_key.as_str().into(),
            issued_at: 1_700_000_000,
        },
        artifact: ArtifactReference {
            sha256: digest_bytes(CERTIFICATE),
            size: CERTIFICATE.len() as u64,
            schema: 1,
            producer: "metadata-only-fixture".into(),
        },
        signature: "0".repeat(128),
        verified: true,
    };
    let id = insert_certificate_metadata(&fixture, &source_job.inputs, &certificate).await?;
    archcert_application::artifacts::ImmutableArtifactStore::put(
        fixture.state.artifacts.as_ref(),
        grant.project,
        &certificate.artifact,
        CERTIFICATE,
    )
    .await?;
    fixture.state.configuration.grants[0].release_build = Some(ReleaseBuildAuthority {
        schema: 1,
        recipe_version: "1.0.2".into(),
        environment: BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"metadata dependencies"),
            toolchain_sha256: digest_bytes(b"metadata toolchain"),
        },
        binary: "fixture".into(),
        source_policy_sha256: source_job.inputs.policy.sha256.clone(),
        source_authority_key_sha256: source_key,
        release_authority_key_sha256: digest_bytes(b"metadata release public key"),
    });
    write_build_credentials(&mut fixture)?;
    fixture
        .state
        .provision_commands(&fixture.credentials)
        .await?;

    Ok((fixture, id, source_job, certificate))
}

async fn assert_no_requests(fixture: &Fixture) -> Result {
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_audit),
                (SELECT count(*) FROM release_invocations)",
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (0, 0, 0));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn native_build_request_freezes_private_selection_and_coalesces_client_keys() -> Result {
    let (fixture, id, source_job, certificate) = release_fixture().await?;
    let authorization = authorization(&fixture, ControlOperation::RequestReleaseBuild)?;
    let one = key("first-tab")?;
    let two = key("second-tab")?;

    let (first, second, retry) = tokio::join!(
        fixture
            .state
            .request_release_build(&authorization, id, &one),
        fixture
            .state
            .request_release_build(&authorization, id, &two),
        fixture
            .state
            .request_release_build(&authorization, id, &one),
    );
    let first = first?;
    assert_eq!(first.id, second?.id);
    assert_eq!(first.id, retry?.id);
    assert_eq!(first.state, ControlCommandState::Requested);
    assert!(first.outcome.is_none());
    let ResolvedControlAction::RequestReleaseBuild {
        admission,
        source_certificate,
    } = first.command.action
    else {
        return Err("wrong resolved action".into());
    };
    let grant = &fixture.state.configuration.grants[0];
    let selection = grant.release_build.as_ref().ok_or("selection")?;
    admission.input.validate(&selection.recipe()?)?;
    assert_eq!(source_certificate, certificate.artifact);
    assert_eq!(admission.submission, fixture.submission);
    assert_eq!(admission.actor, grant.actor);
    assert_eq!(
        admission.input.certified_source.source,
        source_job.inputs.source
    );
    assert_eq!(
        admission.input.certified_source.certificate_sha256,
        certificate.issuance.certificate_sha256
    );
    assert_eq!(
        admission.input.source_policy_sha256,
        selection.source_policy_sha256
    );
    assert_eq!(
        admission.input.source_authority_key_sha256,
        selection.source_authority_key_sha256
    );
    assert_eq!(
        admission.input.release_authority_key_sha256,
        selection.release_authority_key_sha256
    );
    assert_ne!(first.command.authority_context, grant.command_context()?);
    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_keys),
                (SELECT count(*) FROM release_invocations),
                (SELECT count(*) FROM certification_attempts),
                (SELECT count(*) FROM certification_jobs)",
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (1, 2, 0, 0, 2));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn native_build_authorizes_operation_and_each_object_scope_before_source_access() -> Result {
    let (fixture, id, source_job, certificate) = release_fixture().await?;
    let authorization = authorization(&fixture, ControlOperation::RequestReleaseBuild)?;
    let wrong_operation = super::authorization(&fixture, ControlOperation::RequestCertification)?;
    let offline = fixture
        .state
        .configuration
        .source_store
        .with_extension("offline");
    std::fs::rename(&fixture.state.configuration.source_store, &offline)?;

    assert!(matches!(
        fixture
            .state
            .request_release_build(&wrong_operation, id, &key("wrong-op")?)
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    for change in 0..3 {
        let mut inputs = source_job.inputs.clone();
        match change {
            0 => inputs.project = ProjectId::new(),
            1 => inputs.repository = RepositoryId::parse("foreign/repository")?,
            _ => inputs.actor = GitActorId::parse(JobId::new().to_string())?,
        }
        let foreign = insert_certificate_metadata(&fixture, &inputs, &certificate).await?;

        assert!(matches!(
            fixture
                .state
                .request_release_build(&authorization, foreign, &key(&format!("foreign-{change}"))?)
                .await,
            Err(JobStoreError::Unauthorized)
        ));
    }
    sqlx::query("DELETE FROM control_command_grants")
        .execute(&fixture.pool)
        .await?;
    assert!(matches!(
        fixture
            .state
            .request_release_build(&authorization, id, &key("revoked")?)
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    assert_no_requests(&fixture).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn native_build_rejects_policy_key_mismatch_and_missing_complete_source() -> Result {
    let (mut fixture, id, _, _) = release_fixture().await?;
    let original = fixture.state.configuration.grants[0]
        .release_build
        .clone()
        .ok_or("selection")?;
    let offline = fixture
        .state
        .configuration
        .source_store
        .with_extension("offline");
    std::fs::rename(&fixture.state.configuration.source_store, &offline)?;
    for change in 0..2 {
        let mut other = original.clone();
        if change == 0 {
            other.source_policy_sha256 = digest_bytes(b"different approved source policy");
        } else {
            other.source_authority_key_sha256 = digest_bytes(b"different approved source key");
        }
        fixture.state.configuration.grants[0].release_build = Some(other);
        fixture
            .state
            .provision_commands(&fixture.credentials)
            .await?;
        let authorization = authorization(&fixture, ControlOperation::RequestReleaseBuild)?;

        assert!(matches!(
            fixture
                .state
                .request_release_build(&authorization, id, &key(&format!("mismatch-{change}"))?)
                .await,
            Err(JobStoreError::Precondition)
        ));
    }
    fixture.state.configuration.grants[0].release_build = Some(original);
    let authorization = authorization(&fixture, ControlOperation::RequestReleaseBuild)?;
    assert!(matches!(
        fixture
            .state
            .request_release_build(&authorization, id, &key("missing-source")?)
            .await,
        Err(JobStoreError::Unavailable)
    ));
    assert_no_requests(&fixture).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn unsupported_build_provisioning_cannot_partially_publish_new_context_grants() -> Result {
    let mut fixture = fixture(false).await?;
    fixture.state.provision().await?;
    fixture
        .state
        .provision_commands(&fixture.credentials)
        .await?;
    fixture.state.configuration.grants[0].maximum_attempts = 1;
    write_build_credentials(&mut fixture)?;

    assert!(matches!(
        fixture.state.provision_commands(&fixture.credentials).await,
        Err(JobStoreError::Precondition)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM control_command_grants")
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(count, 3);
    assert_no_requests(&fixture).await?;

    Ok(())
}
