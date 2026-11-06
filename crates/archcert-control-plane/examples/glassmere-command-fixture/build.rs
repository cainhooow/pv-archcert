//! Re-ingest explicitly selected historical source without executing it. Imported
//! certification metadata is a fixture, not issuance; dispatch verifies original bytes.

use super::*;
use archcert_application::{
    artifacts::ImmutableArtifactStore,
    release::{BuildEnvironment, ReleaseAdmission},
    source::{SourceSubmission, ingest_source},
};
use archcert_control_plane::commands::ReleaseBuildAuthority;
use archcert_domain::{jobs::JobInputs, source::SourceLimits};
use archcert_source::{MemorySourceStore, PackedGitGateway};
use archcert_storage::artifacts::ReadOnlyFilesystemArtifactStore;
use std::{path::PathBuf, time::Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    project: ProjectId,
    invocation: Sha256Digest,
    query_config: PathBuf,
    source_pack: PathBuf,
    legacy_token_sha256: Sha256Digest,
    command_token_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    environment: BuildEnvironment,
    binary: String,
}

async fn pool(root: &Path) -> Result<PgPool> {
    let database: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("database.json"), 8192)?,
    )?;
    let pool = PgPool::connect(database["authority_url"].as_str().ok_or("authority URL")?).await?;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await?;
    let resources: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("resources.json"), 8192)?,
    )?;
    if schema == "public" || resources["schema"].as_str() != Some(schema.as_str()) {
        return Err("Build fixture requires its exact isolated schema".into());
    }

    Ok(pool)
}

async fn historical_fingerprint(pool: &PgPool, selection: &Import) -> Result<Sha256Digest> {
    let value: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('invocation',to_jsonb(r),'evidence',
            (SELECT jsonb_agg(to_jsonb(e) ORDER BY role) FROM public.release_evidence e
             WHERE e.project=r.project AND e.invocation=r.invocation),'audit',
            (SELECT jsonb_agg(to_jsonb(a) ORDER BY sequence) FROM public.release_audit a
             WHERE a.project=r.project AND a.invocation=r.invocation))
         FROM public.release_invocations r WHERE project=$1 AND invocation=$2",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .fetch_one(pool)
    .await?;

    Ok(archcert_domain::source::digest_bytes(&serde_json::to_vec(
        &value,
    )?))
}

pub(super) async fn import(root: &Path) -> Result {
    let selection: Import = serde_json::from_slice(&archcert_control_plane::read_private(
        &root.join("build-import.json"),
        8192,
    )?)?;
    let pool = pool(root).await?;
    let original = historical_fingerprint(&pool, &selection).await?;
    let value: serde_json::Value = sqlx::query_scalar(
        "SELECT admission FROM public.release_invocations WHERE project=$1 AND invocation=$2",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .fetch_one(&pool)
    .await?;
    let historical: ReleaseAdmission = serde_json::from_value(value)?;
    let input = &historical.input;
    let source = &input.certified_source;
    if input.identity()?.0 != selection.invocation || source.project != selection.project {
        return Err("Historical build selection does not bind its invocation/project".into());
    }

    let mut query: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&selection.query_config, 256 * 1024)?,
    )?;
    let mut selected = Vec::new();
    for value in query["recipes"].as_array().ok_or("approved recipes")? {
        let provision: Recipe = serde_json::from_value(value.clone())?;
        let authority = ReleaseBuildAuthority {
            schema: 1,
            recipe_version: input.recipe.version.clone(),
            environment: provision.environment,
            binary: provision.binary,
            source_policy_sha256: input.source_policy_sha256.clone(),
            source_authority_key_sha256: input.source_authority_key_sha256.clone(),
            release_authority_key_sha256: input.release_authority_key_sha256.clone(),
        };
        let recipe = authority.recipe()?;
        if recipe.identity()? == input.recipe_identity
            && recipe.environment_identity()? == input.environment_identity
            && serde_json::to_value(recipe.description())? == serde_json::to_value(&input.recipe)?
        {
            selected.push(authority);
        }
    }
    if selected.len() != 1 {
        return Err("Select exactly one approved historical recipe; no newer default".into());
    }
    let authority = selected.pop().ok_or("approved recipe")?;
    let reference: serde_json::Value = sqlx::query_scalar(
        "SELECT reference FROM public.release_evidence
         WHERE project=$1 AND invocation=$2 AND role='SOURCE_CERTIFICATE' AND available",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .fetch_one(&pool)
    .await?;
    let reference: ArtifactReference = serde_json::from_value(reference)?;
    if reference.schema != 1 || reference.size == 0 || reference.size > 65_536 {
        return Err("Historical certificate exceeds the existing admission boundary".into());
    }
    let original_artifacts =
        ReadOnlyFilesystemArtifactStore::open_unencrypted_development(Path::new(
            query["artifact_root"]
                .as_str()
                .ok_or("original artifact root")?,
        ))?;
    let bytes = original_artifacts.get(selection.project, &reference)?;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    let payload = &envelope["payload"];
    if payload["source"] != serde_json::to_value(&source.source)?
        || payload["project"] != json!(source.project)
        || payload["repository"] != json!(source.repository)
        || envelope["certificate_sha256"] != json!(source.certificate_sha256)
        || payload["policy"]["sha256"] != json!(input.source_policy_sha256)
        || payload["signing_key_id"] != json!(input.source_authority_key_sha256)
    {
        return Err("Historical envelope metadata does not bind the selected source".into());
    }

    // Owned bounded transport bytes enter the existing maintained decoder. No
    // checkout, hooks, repository configuration, target commands or network access.
    let limits = PackLimits::default();
    let pack = archcert_control_plane::read_private(&selection.source_pack, limits.max_pack_bytes)?;
    let started = Instant::now();
    let gateway = PackedGitGateway::new(
        source.repository.clone(),
        &pack,
        GitObjectFormat::Sha1,
        limits,
    )?;
    let ingestion = ingest_source(
        &gateway,
        &mut MemorySourceStore::default(),
        SourceSubmission {
            project: source.project,
            repository: source.repository.clone(),
            requested_commit: source.source.commit.clone(),
        },
        SourceLimits::default(),
    )?;
    let elapsed = started.elapsed().as_millis();
    ingestion.snapshot.require_complete()?;
    if ingestion.snapshot.identity() != &source.source {
        return Err("Freshly ingested source differs from the historical certificate".into());
    }

    let source_root = root.join("build-sources");
    let artifact_root = root.join("build-artifacts");
    for path in [&source_root, &artifact_root] {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let submission = SourceSubmissionId::new();
    let evidence = IngressEvidence {
        submission: submission.clone(),
        actor: historical.actor.clone(),
        device: DeviceKeyId::parse(
            archcert_domain::source::digest_bytes(
                b"local historical fixture; no device authentication",
            )
            .as_str()
            .into(),
        )?,
        project: source.project,
        repository: source.repository.clone(),
        transport: "DEVELOPMENT_LOCAL_PACK_IMPORT_NO_SSH_AUTHENTICATION".into(),
        received_refs: vec![],
        requested_commit: Some(source.source.commit.clone()),
        source: Some(source.source.clone()),
        object_format: GitObjectFormat::Sha1,
        // No network receive transaction occurred. Actual validated pack identity,
        // bytes and selected object visits are retained separately below.
        pack_sha256: None,
        pack_bytes: 0,
        pack_objects: 0,
        pack_limits: limits,
        git_adapter: None,
        lfs_unresolved: 0,
        submodules_unresolved: 0,
        external_sources: vec![],
        source_schema: 1,
        resolution: None,
        completeness: Some(ingestion.snapshot.status()),
        status: "ACCEPTED".into(),
        received_at: ingestion.evidence.created_at,
        accepted_at: Some(ingestion.evidence.created_at),
        events: vec![],
        candidate: format!("development-local-import/{submission}"),
    };
    DevelopmentSubmissionStore::open(&source_root, 10)?.accept(&ingestion.snapshot, &evidence)?;
    let artifacts = FilesystemArtifactStore::open_unencrypted_development(&artifact_root)?;
    artifacts.put(selection.project, &reference, &bytes).await?;

    let mut configuration: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("authority.json"), 256 * 1024)?,
    )?;
    let mut grant = configuration["grants"][0].clone();
    grant["project"] = json!(source.project);
    grant["repository"] = json!(source.repository);
    grant["actor"] = json!(historical.actor);
    grant["token_sha256"] = json!(selection.legacy_token_sha256);
    grant["release_build"] = json!(authority);
    configuration["grants"] = json!([grant]);
    configuration["source_store"] = json!(source_root);
    configuration["artifact_root"] = json!(artifact_root);
    let authority_path = root.join("build-authority.json");
    private_json(&authority_path, &configuration)?;
    let credentials_path = root.join("build-credentials.json");
    private_json(
        &credentials_path,
        &json!({
            "schema": 1,
            "principals": [{
                "scope": {
                    "project": source.project,
                    "repository": source.repository,
                    "actor": historical.actor,
                },
                "token_sha256": selection.command_token_sha256,
                "operations": ["REQUEST_RELEASE_BUILD"],
            }],
        }),
    )?;
    query["artifact_root"] = json!(artifact_root);
    private_json(&root.join("build-query.json"), &query)?;
    let state = ControlPlane {
        repository: PostgresJobRepository::from_pool(pool.clone()),
        artifacts: Arc::new(artifacts),
        configuration: ControlPlaneConfiguration::load(&authority_path)?,
    };
    state.provision().await?;
    let credentials = CommandCredentials::load(&credentials_path, &state.configuration)?;
    state.provision_commands(&credentials).await?;
    let grant = &state.configuration.grants[0];
    let inputs = JobInputs {
        project: source.project,
        repository: source.repository.clone(),
        actor: historical.actor.clone(),
        submission: submission.clone(),
        source: source.source.clone(),
        policy: serde_json::from_value(payload["policy"].clone())?,
        profile: grant.profile.clone(),
        image: grant.image.clone(),
        plan_sha256: archcert_domain::source::digest_bytes(
            b"historical import metadata; not a new certification plan",
        ),
        authority_toml: grant.authority_toml.clone(),
        maximum_attempts: grant.maximum_attempts,
    };
    let issuance = PreparedIssuance {
        certificate_sha256: source.certificate_sha256.clone(),
        signing_key_id: input.source_authority_key_sha256.as_str().into(),
        issued_at: payload["issued_at"]
            .as_u64()
            .ok_or("historical issue time")?,
    };
    let certificate = PersistedCertificate {
        issuance: issuance.clone(),
        artifact: reference.clone(),
        signature: envelope["signature"]
            .as_str()
            .ok_or("historical signature")?
            .into(),
        // This imported flag is no proof: dispatch must independently verify bytes.
        verified: true,
    };
    let metadata = serde_json::to_vec(&json!({
        "purpose": "Development historical certificate metadata import; no new evaluation or issuance",
        "certificate_artifact": reference,
    }))?;
    let evaluation = ArtifactReference {
        sha256: archcert_domain::source::digest_bytes(&metadata),
        size: metadata.len() as u64,
        schema: 1,
        producer: "development-historical-import-metadata".into(),
    };
    state
        .artifacts
        .put(source.project, &evaluation, &metadata)
        .await?;
    let job = JobId::new();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO accepted_sources(submission,project,repository,source) VALUES($1,$2,$3,$4)",
    )
    .bind(submission.to_string())
    .bind(source.project.to_string())
    .bind(source.repository.as_str())
    .bind(serde_json::to_value(&source.source)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO certification_jobs(id,project,repository,actor,idempotency_key,
            inputs,state,evaluation,eligible,issuance,certificate)
         VALUES($1,$2,$3,$4,$1,$5,'COMPLETED',$6,true,$7,$8)",
    )
    .bind(job.to_string())
    .bind(source.project.to_string())
    .bind(source.repository.as_str())
    .bind(historical.actor.as_str())
    .bind(serde_json::to_value(inputs)?)
    .bind(serde_json::to_value(evaluation)?)
    .bind(serde_json::to_value(issuance)?)
    .bind(serde_json::to_value(certificate)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO audit_events(job,event) VALUES($1,'DevelopmentHistoricalSourceCertificateFixtureImport')")
        .bind(job.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    private_json(
        &root.join("build-fixture.json"),
        &json!({
            "schema": 1,
            "purpose": "Fresh passive source ingestion with retained historical certificate; no new certification, build or signature",
            "project": source.project,
            "repository": source.repository,
            "actor": historical.actor,
            "source": source.source,
            "certificate_artifact": reference,
            "job": job,
            "submission": submission,
            "invocation": selection.invocation,
            "authority_context": grant.command_context_for(archcert_application::glassmere::commands::ControlOperation::RequestReleaseBuild)?,
            "pack_sha256": archcert_domain::source::digest_bytes(&pack),
            "pack_bytes": pack.len(),
            "source_validation_milliseconds": elapsed,
            "source_evidence": ingestion.evidence,
            "source_events": ingestion.events,
            "original_release_record_sha256": original,
        }),
    )?;
    pool.close().await;
    println!("Historical source re-ingested into an isolated development build fixture");

    Ok(())
}

pub(super) async fn inspect(root: &Path) -> Result {
    let selection: Import = serde_json::from_slice(&archcert_control_plane::read_private(
        &root.join("build-import.json"),
        8192,
    )?)?;
    let fixture: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("build-fixture.json"), 256 * 1024)?,
    )?;
    let pool = pool(root).await?;
    let job: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(j) FROM certification_jobs j WHERE id=$1")
            .bind(fixture["job"].as_str().ok_or("imported job")?)
            .fetch_one(&pool)
            .await?;
    let authority = ControlPlaneConfiguration::load(&root.join("build-authority.json"))?;
    let accepted = archcert_gateway::AcceptedSubmissionReader::open(&authority.source_store)?
        .load(&SourceSubmissionId::parse(
            fixture["submission"].as_str().ok_or("submission")?,
        )?)?;
    if serde_json::to_value(accepted.snapshot.identity())? != fixture["source"] {
        return Err("Retained fixture source changed".into());
    }
    let reference: ArtifactReference =
        serde_json::from_value(fixture["certificate_artifact"].clone())?;
    let artifacts =
        ReadOnlyFilesystemArtifactStore::open_unencrypted_development(&authority.artifact_root)?;
    let certificate = artifacts.get(selection.project, &reference)?;

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM release_invocations),
            (SELECT count(*) FROM release_invocations WHERE claim_a IS NOT NULL OR claim_b IS NOT NULL),
            (SELECT count(*) FROM release_evidence),
            (SELECT count(*) FROM audit_events WHERE event='CertificateIssued')",
    ).fetch_one(&pool).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "invocations": counts.0,
            "claimed_invocations": counts.1,
            "release_evidence": counts.2,
            "issued_certificates": counts.3,
            "retained_source": accepted.snapshot.identity(),
            "certificate_artifact_sha256": archcert_domain::source::digest_bytes(&certificate),
            "imported_job_sha256": archcert_domain::source::digest_bytes(&serde_json::to_vec(&job)?),
            "original_release_record_sha256": historical_fingerprint(&pool, &selection).await?,
        }))?
    );
    pool.close().await;

    Ok(())
}
