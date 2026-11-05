//! Explicit historical development import into the already isolated fixture schema.
//! Original signed bytes and authority rows remain untouched. No runtime or key is loaded.

use super::*;
use archcert_application::{artifacts::ImmutableArtifactStore, release::ReleaseAdmission};
use archcert_storage::artifacts::ReadOnlyFilesystemArtifactStore;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    project: ProjectId,
    invocation: Sha256Digest,
    query_config: PathBuf,
    legacy_token_sha256: Sha256Digest,
    command_token_sha256: Sha256Digest,
}

pub(super) async fn import_readiness(root: &Path) -> Result {
    let selection: Import = serde_json::from_slice(&archcert_control_plane::read_private(
        &root.join("import.json"),
        8192,
    )?)?;
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
    if resources["schema"].as_str() != Some(schema.as_str()) || schema == "public" {
        return Err("Historical fixture import requires its exact isolated schema".into());
    }

    let mut query: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&selection.query_config, 256 * 1024)?,
    )?;
    let original_artifacts = ReadOnlyFilesystemArtifactStore::open_unencrypted_development(
        Path::new(query["artifact_root"].as_str().ok_or("artifact root")?),
    )?;
    let artifact_root = root.join("readiness-artifacts");
    std::fs::create_dir(&artifact_root)?;
    std::fs::set_permissions(&artifact_root, std::fs::Permissions::from_mode(0o700))?;
    let artifacts = FilesystemArtifactStore::open_unencrypted_development(&artifact_root)?;

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let admission_json: serde_json::Value = sqlx::query_scalar(
        "INSERT INTO release_invocations(project,invocation,admission,claim_a,claim_b)
         SELECT project,invocation,admission,claim_a,claim_b FROM public.release_invocations
         WHERE project=$1 AND invocation=$2 RETURNING admission",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .fetch_one(&mut *tx)
    .await?;
    let admission: ReleaseAdmission = serde_json::from_value(admission_json)?;
    if admission.input.identity()?.0 != selection.invocation
        || admission.input.certified_source.project != selection.project
    {
        return Err("Historical import source/invocation binding mismatch".into());
    }

    let references: Vec<(String, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT role,reference,available FROM public.release_evidence
         WHERE project=$1 AND invocation=$2 ORDER BY role",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .fetch_all(&mut *tx)
    .await?;

    for (_, value, available) in &references {
        if *available {
            let reference: ArtifactReference = serde_json::from_value(value.clone())?;
            let bytes = original_artifacts.get(selection.project, &reference)?;
            artifacts.put(selection.project, &reference, &bytes).await?;
        }
    }

    sqlx::query(
        "INSERT INTO release_evidence(project,invocation,role,reference,available)
         SELECT project,invocation,role,reference,available FROM public.release_evidence
         WHERE project=$1 AND invocation=$2",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO release_audit(project,invocation,event)
         VALUES($1,$2,'DevelopmentHistoricalReadinessFixtureImport')",
    )
    .bind(selection.project.to_string())
    .bind(selection.invocation.as_str())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let authority_path = root.join("readiness-authority.json");
    let mut authority: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("authority.json"), 256 * 1024)?,
    )?;
    // This profile scopes permission to request an observation. M6 verification
    // independently uses the imported immutable input and explicit public query selection.
    let mut grant = authority["grants"][0].clone();
    grant["project"] = json!(selection.project);
    grant["repository"] = json!(admission.input.certified_source.repository);
    grant["actor"] = json!(admission.actor);
    grant["token_sha256"] = json!(selection.legacy_token_sha256);
    authority["grants"] = json!([grant]);
    authority["artifact_root"] = json!(artifact_root);
    private_json(&authority_path, &authority)?;
    let credential_path = root.join("readiness-credentials.json");
    private_json(
        &credential_path,
        &json!({
            "schema": 1,
            "principals": [{
                "scope": {
                    "project": selection.project,
                    "repository": admission.input.certified_source.repository,
                    "actor": admission.actor,
                },
                "token_sha256": selection.command_token_sha256,
                "operations": ["REQUEST_RELEASE_READINESS_EVALUATION"],
            }],
        }),
    )?;
    query["artifact_root"] = json!(artifact_root);
    private_json(&root.join("readiness-query.json"), &query)?;
    let configuration = ControlPlaneConfiguration::load(&authority_path)?;
    let state = ControlPlane {
        repository: PostgresJobRepository::from_pool(pool.clone()),
        artifacts: Arc::new(artifacts),
        configuration,
    };
    state.provision().await?;
    let credentials = CommandCredentials::load(&credential_path, &state.configuration)?;
    state.provision_commands(&credentials).await?;
    private_json(
        &root.join("readiness-fixture.json"),
        &json!({
            "schema": 1,
            "purpose": "Historical development fixture import; no new execution, claims or signatures",
            "project": selection.project,
            "invocation": selection.invocation,
            "admission": admission,
            "references": references,
            "authority_context": state.configuration.grants[0].command_context()?,
        }),
    )?;
    pool.close().await;
    println!(
        "Historical readiness fixture copied into the isolated schema and private artifact store"
    );

    Ok(())
}
