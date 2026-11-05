//! Isolated browser qualification metadata. Creates no target result or certificate.
//! Supply a new private fixture directory and a development PostgreSQL administrator URL.

use archcert_application::jobs::*;
use archcert_control_plane::{
    ControlPlane, ControlPlaneConfiguration, commands::CommandCredentials,
};
use archcert_domain::{
    GitObjectId, ProjectId, Sha256Digest,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    jobs::{IdempotencyKey, JobId},
    source::{RepositoryId, SourceSnapshot},
};
use archcert_gateway::{DevelopmentSubmissionStore, IngressEvidence, SubmissionStore};
use archcert_source::{GitObjectFormat, PackLimits};
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
    sync::Arc,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

async fn inspect(root: &Path) -> Result {
    let database: serde_json::Value = serde_json::from_slice(
        &archcert_control_plane::read_private(&root.join("database.json"), 8192)?,
    )?;
    let pool = PgPool::connect(database["authority_url"].as_str().ok_or("authority URL")?).await?;
    let totals: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM certification_jobs),
                (SELECT count(*) FROM certification_attempts),
                (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_keys),
                (SELECT count(*) FROM certification_jobs WHERE certificate IS NOT NULL)",
    )
    .fetch_one(&pool)
    .await?;
    let expired: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM certification_attempts WHERE lease_until<=floor(extract(epoch FROM clock_timestamp()))",
    ).fetch_one(&pool).await?;
    let commands: serde_json::Value = sqlx::query_scalar(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'operation',operation,'state',state) ORDER BY id),'[]'::jsonb) FROM control_commands",
    ).fetch_one(&pool).await?;
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT coalesce(jsonb_object_agg(event,n),'{}'::jsonb) FROM (SELECT event,count(*) AS n FROM audit_events GROUP BY event) counts",
    ).fetch_one(&pool).await?;
    let command_audit: serde_json::Value = sqlx::query_scalar(
        "SELECT coalesce(jsonb_object_agg(event,n),'{}'::jsonb) FROM (SELECT event,count(*) AS n FROM control_command_audit GROUP BY event) counts",
    ).fetch_one(&pool).await?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "jobs": totals.0,
            "attempts": totals.1,
            "commands_count": totals.2,
            "keys": totals.3,
            "certificates": totals.4,
            "expired_attempts": expired,
            "commands": commands,
            "audit": audit,
            "command_audit": command_audit,
        }))?
    );

    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    reader_password: String,
    principals: BTreeMap<String, CredentialHashes>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialHashes {
    legacy: Sha256Digest,
    command: Sha256Digest,
}

fn private_json(path: &Path, value: &impl Serialize) -> Result {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    Ok(())
}

fn retain_source(
    root: &Path,
    project: ProjectId,
    repository: &RepositoryId,
    actor: &GitActorId,
    marker: char,
) -> Result<SourceSubmissionId> {
    let submission = SourceSubmissionId::new();
    let source = SourceSnapshot::seal(
        project,
        repository.clone(),
        GitObjectId::parse(marker.to_string().repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1_700_000_000,
    )?;
    let evidence = IngressEvidence {
        submission: submission.clone(),
        actor: actor.clone(),
        device: DeviceKeyId::parse("c".repeat(64))?,
        project,
        repository: repository.clone(),
        transport: "SSH_PUBLIC_KEY".into(),
        received_refs: vec!["refs/heads/main".into()],
        requested_commit: Some(source.identity().commit.clone()),
        source: Some(source.identity().clone()),
        object_format: GitObjectFormat::Sha1,
        pack_sha256: None,
        pack_bytes: 0,
        pack_objects: 0,
        pack_limits: PackLimits::default(),
        git_adapter: None,
        lfs_unresolved: 0,
        submodules_unresolved: 0,
        external_sources: vec![],
        source_schema: 1,
        resolution: None,
        completeness: Some(source.status()),
        status: "ACCEPTED".into(),
        received_at: 1_700_000_000,
        accepted_at: Some(1_700_000_000),
        events: vec![],
        candidate: format!("browser-fixture/{submission}"),
    };

    let mut store = DevelopmentSubmissionStore::open(root, 10)?;
    store.accept(&source, &evidence)?;

    Ok(submission)
}

#[tokio::main]
async fn main() -> Result {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--inspect" {
        return inspect(&Path::new(&args[2]).canonicalize()?).await;
    }

    if args.len() != 2 {
        return Err(
            "Supply one existing private qualification directory containing seed.json".into(),
        );
    }

    let root = Path::new(&args[1]).canonicalize()?;
    let seed: Seed = serde_json::from_slice(&archcert_control_plane::read_private(
        &root.join("seed.json"),
        4096,
    )?)?;
    if seed
        .principals
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != ["administrator", "operator"]
        || seed.reader_password.len() != 64
        || !seed
            .reader_password
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Invalid explicit fixture principals or reader credential".into());
    }

    let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&url).await?;
    let suffix = JobId::new().to_string().replace('-', "");
    let schema = format!("glassmere_commands_{suffix}");
    let role = format!("glassmere_commands_reader_{suffix}");
    // Retain names before setup, including failures. Cleanup must target only this fixture.
    private_json(
        &root.join("resources.json"),
        &json!({
            "schema": schema,
            "reader_role": role,
        }),
    )?;
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await?;
    let selected_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |connection, _| {
            let schema = selected_schema.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(schema)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let repository = PostgresJobRepository::from_pool(pool.clone());
    repository.migrate().await?;

    let source_root = root.join("sources");
    let artifact_root = root.join("artifacts");
    for directory in [&source_root, &artifact_root] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let project = ProjectId::new();
    let repository_id = RepositoryId::parse("qualification/glassmere-commands")?;
    let mut grants = Vec::new();
    let mut credentials = Vec::new();
    let mut subjects = BTreeMap::new();
    for (ordinal, (principal, hashes)) in seed.principals.iter().enumerate() {
        let actor = GitActorId::parse(JobId::new().to_string())?;
        let submission = retain_source(
            &source_root,
            project,
            &repository_id,
            &actor,
            if ordinal == 0 { 'a' } else { 'c' },
        )?;
        grants.push(json!({
            "project": project,
            "repository": repository_id,
            "actor": actor,
            "token_sha256": hashes.legacy,
            "profile": "python",
            "image": format!("python@sha256:{}", "a".repeat(64)),
            "authority_toml": include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml"),
            "maximum_attempts": 2,
            "ironcrest": false,
            "greywatch": false,
        }));
        credentials.push(json!({
            "scope": {
                "project": project,
                "repository": repository_id,
                "actor": actor,
            },
            "token_sha256": hashes.command,
            "operations": [
                "REQUEST_CERTIFICATION",
                "CANCEL_ELIGIBLE_JOB",
                "RETRY_ELIGIBLE_JOB",
            ],
        }));
        subjects.insert(
            principal.clone(),
            json!({
                "submission": submission,
                "actor": actor,
            }),
        );
    }
    let authority_path = root.join("authority.json");
    private_json(
        &authority_path,
        &json!({
            "source_store": source_root,
            "artifact_root": artifact_root,
            "grants": grants,
        }),
    )?;
    let credential_path = root.join("backend-credentials.json");
    private_json(
        &credential_path,
        &json!({
            "schema": 1,
            "principals": credentials,
        }),
    )?;
    let configuration = ControlPlaneConfiguration::load(&authority_path)?;
    let state = ControlPlane {
        repository,
        artifacts: Arc::new(FilesystemArtifactStore::open_unencrypted_development(
            &artifact_root,
        )?),
        configuration,
    };
    state.provision().await?;
    let credentials = CommandCredentials::load(&credential_path, &state.configuration)?;
    state.provision_commands(&credentials).await?;

    // Claimed but never started: no target or runtime resource exists. Expiry uses
    // the ordinary five-second lease; no SQL clock or timeout override is needed.
    for (principal, subject) in &mut subjects {
        let submission =
            SourceSubmissionId::parse(subject["submission"].as_str().ok_or("submission")?)?;
        let actor = GitActorId::parse(subject["actor"].as_str().ok_or("actor")?.into())?;
        let recovery = state
            .submit(
                actor,
                project,
                repository_id.clone(),
                submission,
                IdempotencyKey::parse(format!("{principal}-recovery-fixture"))?,
            )
            .await?;
        let assignment = JobRepository::claim(&state.repository, "fixture-never-started", 5)
            .await?
            .ok_or("fixture lease")?;
        if assignment.job.id != recovery.id {
            return Err("Fixture claimed an unexpected job".into());
        }
        subject["recovery_job"] = json!(recovery.id);
        subject["attempt"] = json!(assignment.lease.attempt);
        // Queue fixtures after all recovery claims to keep claim selection exact.
        subject["inputs"] = serde_json::to_value(recovery.inputs)?;
    }
    for (principal, subject) in &mut subjects {
        let inputs = serde_json::from_value(
            subject
                .as_object_mut()
                .ok_or("subject")?
                .remove("inputs")
                .ok_or("inputs")?,
        )?;
        let queued = JobRepository::create(
            &state.repository,
            CreateJob {
                inputs,
                idempotency: IdempotencyKey::parse(format!("{principal}-cancel-fixture"))?,
            },
        )
        .await?;
        subject["queued_job"] = json!(queued.id);
    }

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{}'",
        seed.reader_password
    )))
    .execute(&admin)
    .await?;
    for statement in [
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!("GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&admin)
            .await?;
    }

    let mut reader_url = PgConnectOptions::from_str(&url)?
        .username(&role)
        .password(&seed.reader_password)
        .to_url_lossy();
    let mut authority_url = PgConnectOptions::from_str(&url)?.to_url_lossy();
    // SQLx's lossy URL conversion omits its in-memory options. Set the encoded
    // startup option on the exported URLs themselves, then verify both services.
    for exported in [&mut reader_url, &mut authority_url] {
        exported
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let connection = PgPool::connect(exported.as_str()).await?;
        let actual: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&connection)
            .await?;
        if actual != schema {
            return Err("Exported fixture connection escaped its isolated schema".into());
        }
        let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM certification_jobs")
            .fetch_one(&connection)
            .await?;
        if jobs != 4 {
            return Err(
                "Exported fixture connection did not retain exactly four fixture jobs".into(),
            );
        }
        connection.close().await;
    }
    private_json(
        &root.join("database.json"),
        &json!({
            "authority_url": authority_url.as_str(),
            "reader_url": reader_url.as_str(),
        }),
    )?;
    private_json(
        &root.join("query.json"),
        &json!({
            "schema": 1,
            "artifact_root": artifact_root,
            "source_public_keys": [],
            "release_public_keys": [],
            "recipes": [],
        }),
    )?;
    private_json(
        &root.join("fixture.json"),
        &json!({
            "schema": 1,
            "purpose": "Metadata-only workflow/browser qualification; no runtime, signing or target proof",
            "project": project,
            "repository": repository_id,
            "subjects": subjects,
            "initial_jobs": 4,
        }),
    )?;
    pool.close().await;
    println!(
        "Isolated command browser fixture created; private configuration retained in its explicit directory"
    );

    Ok(())
}
