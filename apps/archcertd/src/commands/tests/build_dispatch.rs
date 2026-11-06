//! Actual native controller / PostgreSQL / public-verifier composition. Synthetic
//! source/job metadata is not source acquisition, target execution or certification.

use super::*;
use archcert_application::release::*;
use archcert_control_plane::commands::ReleaseBuildAuthority;
use archcert_domain::{Sha256Digest, SourceIdentity, release::*};
use sqlx::ConnectOptions;
use std::{path::PathBuf, process::Stdio, time::Duration};

const SOURCE_PUBLIC_KEY: &str = "81bc9f78e8d161faf8ca4ef3e44524210da1fee99f665afd891eeece20200ca0";
const OTHER_PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const CERTIFICATE: &[u8] =
    include_bytes!("../../../../../crates/archcert-certificate/tests/fixtures/openssl-vector.json");

struct NativeFixture {
    control: ControlPlane,
    command: ResolvedControlCommand,
    configuration: PathBuf,
    observation: PathBuf,
    writer_url: String,
    reader_url: String,
    source_job: JobId,
    source_fingerprint: Sha256Digest,
    base: Fixture,
}

fn private_json(path: &std::path::Path, value: &serde_json::Value) -> Result {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

async fn native_fixture(tampered: bool) -> Result<NativeFixture> {
    let base = fixture(true).await?;
    let root = base._directory.path().canonicalize()?;
    let envelope: serde_json::Value = serde_json::from_slice(CERTIFICATE)?;
    let payload = &envelope["payload"];
    let source: SourceIdentity = serde_json::from_value(payload["source"].clone())?;
    let project: ProjectId = serde_json::from_value(payload["project"].clone())?;
    let repository: RepositoryId = serde_json::from_value(payload["repository"].clone())?;
    let source_key = Sha256Digest::parse(payload["signing_key_id"].as_str().ok_or("source key")?)?;
    let source_policy = Sha256Digest::parse(payload["policy"]["sha256"].as_str().ok_or("policy")?)?;
    let certificate_sha256 = Sha256Digest::parse(
        envelope["certificate_sha256"]
            .as_str()
            .ok_or("certificate id")?,
    )?;
    let scope = CommandScope {
        project,
        repository,
        actor: GitActorId::parse(JobId::new().to_string())?,
    };
    let selection = ReleaseBuildAuthority {
        schema: 1,
        recipe_version: "1.0.2".into(),
        environment: BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"public vector fixture dependencies"),
            toolchain_sha256: digest_bytes(b"public vector fixture toolchain"),
        },
        binary: "fixture".into(),
        source_policy_sha256: source_policy.clone(),
        source_authority_key_sha256: source_key.clone(),
        release_authority_key_sha256: source_key.clone(),
    };
    let grant = AuthorityGrant {
        project,
        repository: scope.repository.clone(),
        actor: scope.actor.clone(),
        token_sha256: digest_bytes(LEGACY_TOKEN.as_bytes()),
        profile: "python".into(),
        image: format!("python@sha256:{}", "a".repeat(64)),
        authority_toml: include_str!("../../../../../docs/policy/CONTROLLED_AUTHORITY.toml").into(),
        maximum_attempts: 2,
        ironcrest: false,
        greywatch: false,
        semantic_request_bytes: None,
        ironcrest_baseline: None,
        release_build: Some(selection.clone()),
    };
    let control = ControlPlane {
        repository: PostgresJobRepository::from_pool(base.pool.clone()),
        artifacts: base.state.control.artifacts.clone(),
        configuration: ControlPlaneConfiguration {
            source_store: root.join("unacquired-vector-source"),
            artifact_root: root.clone(),
            grants: vec![grant],
        },
    };
    control.provision().await?;
    let grant = &control.configuration.grants[0];
    private_json(
        &base.credential_path,
        &serde_json::json!({
            "schema": 1,
            "principals": [{
                "scope": scope,
                "token_sha256": digest_bytes(COMMAND_TOKEN.as_bytes()),
                "operations": ["REQUEST_RELEASE_BUILD"],
            }],
        }),
    )?;
    let credentials = CommandCredentials::load(&base.credential_path, &control.configuration)?;
    control.provision_commands(&credentials).await?;

    // The vector supplies only signed public bytes and immutable binding metadata.
    // Native dispatch must independently verify it; there is no acquired source here.
    let submission = SourceSubmissionId::new();
    sqlx::query(
        "INSERT INTO accepted_sources(submission,project,repository,source) VALUES ($1,$2,$3,$4)",
    )
    .bind(submission.to_string())
    .bind(project.to_string())
    .bind(scope.repository.as_str())
    .bind(serde_json::to_value(&source)?)
    .execute(&base.pool)
    .await?;
    let inputs = JobInputs {
        project,
        repository: scope.repository.clone(),
        actor: scope.actor.clone(),
        submission: submission.clone(),
        source: source.clone(),
        policy: PolicyPin {
            id: payload["policy"]["id"].as_str().ok_or("policy id")?.into(),
            version: payload["policy"]["version"]
                .as_str()
                .ok_or("policy version")?
                .into(),
            sha256: source_policy.clone(),
        },
        profile: grant.profile.clone(),
        image: grant.image.clone(),
        plan_sha256: digest_bytes(b"metadata source plan"),
        authority_toml: grant.authority_toml.clone(),
        maximum_attempts: 2,
    };
    let bytes = if tampered {
        let mut damaged = envelope.clone();
        damaged["signature"] = serde_json::json!("0".repeat(128));
        serde_json::to_vec(&damaged)?
    } else {
        CERTIFICATE.to_vec()
    };
    let reference = ArtifactReference {
        sha256: digest_bytes(&bytes),
        size: bytes.len() as u64,
        schema: 1,
        producer: "archcert-certifier".into(),
    };
    let issuance = PreparedIssuance {
        certificate_sha256: certificate_sha256.clone(),
        signing_key_id: source_key.as_str().into(),
        issued_at: payload["issued_at"].as_u64().ok_or("issued time")?,
    };
    let certificate = PersistedCertificate {
        issuance: issuance.clone(),
        artifact: reference.clone(),
        signature: envelope["signature"].as_str().ok_or("signature")?.into(),
        verified: true,
    };
    let source_job = JobId::new();
    let evaluation = ArtifactReference {
        sha256: digest_bytes(b"vector-source metadata evaluation"),
        size: 33,
        schema: 1,
        producer: "metadata-only-fixture".into(),
    };
    sqlx::query(
        "INSERT INTO certification_jobs(id,project,repository,actor,idempotency_key,
            inputs,state,evaluation,eligible,issuance,certificate)
         VALUES ($1,$2,$3,$4,$1,$5,'COMPLETED',$8,true,$6,$7)",
    )
    .bind(source_job.to_string())
    .bind(project.to_string())
    .bind(scope.repository.as_str())
    .bind(scope.actor.as_str())
    .bind(serde_json::to_value(inputs)?)
    .bind(serde_json::to_value(issuance)?)
    .bind(serde_json::to_value(certificate)?)
    .bind(serde_json::to_value(evaluation)?)
    .execute(&base.pool)
    .await?;
    archcert_application::artifacts::ImmutableArtifactStore::put(
        control.artifacts.as_ref(),
        project,
        &reference,
        &bytes,
    )
    .await?;

    let recipe = selection.recipe()?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: CertifiedSourceIdentity {
            project,
            repository: scope.repository.clone(),
            source,
            certificate_sha256,
        },
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: source_policy,
        source_authority_key_sha256: source_key.clone(),
        release_authority_key_sha256: source_key,
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };
    let admission = ReleaseAdmission {
        input_reference: release_reference(&release_bytes(&input)?),
        input,
        submission,
        actor: scope.actor.clone(),
    };
    let command = ResolvedControlCommand {
        schema: 1,
        scope,
        authority_context: grant.command_context_for(ControlOperation::RequestReleaseBuild)?,
        action: ResolvedControlAction::RequestReleaseBuild {
            admission: Box::new(admission),
            source_certificate: reference,
        },
    };
    let configuration = root.join("build-authority.json");
    private_json(
        &configuration,
        &serde_json::json!({
            "source_store": control.configuration.source_store,
            "artifact_root": control.configuration.artifact_root,
            "grants": [{
                "project": grant.project,
                "repository": grant.repository,
                "actor": grant.actor,
                "token_sha256": grant.token_sha256,
                "profile": grant.profile,
                "image": grant.image,
                "authority_toml": grant.authority_toml,
                "maximum_attempts": grant.maximum_attempts,
                "release_build": selection,
            }],
        }),
    )?;
    let observation = root.join("build-observer.json");
    private_json(
        &observation,
        &serde_json::json!({
            "schema": 1,
            "artifact_root": root,
            "source_public_keys": [SOURCE_PUBLIC_KEY],
            "release_public_keys": [SOURCE_PUBLIC_KEY],
            "recipes": [{
                "environment": selection.environment,
                "binary": selection.binary,
            }],
        }),
    )?;

    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&base.pool)
        .await?;
    assert!(
        schema.starts_with("command_http_")
            && schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let mut url = base.pool.connect_options().to_url_lossy();
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let writer_url = url.to_string();
    let role = format!(
        "build_observer_{}",
        JobId::new().to_string().replace('-', "")
    );
    let password = JobId::new().to_string();
    // All interpolated DDL values are generated UUID identifiers/credentials, not input.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}'"
    )))
    .execute(&base.pool)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA {schema} TO {role}"
    )))
    .execute(&base.pool)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}"
    )))
    .execute(&base.pool)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE {role} SET default_transaction_read_only=on"
    )))
    .execute(&base.pool)
    .await?;
    url.set_username(&role).map_err(|_| "reader URL username")?;
    url.set_password(Some(&password))
        .map_err(|_| "reader URL password")?;
    let source_state = JobRepository::get(&control.repository, source_job).await?;
    let source_fingerprint = digest_bytes(&release_bytes(&source_state)?);

    Ok(NativeFixture {
        control,
        command,
        configuration,
        observation,
        writer_url,
        reader_url: url.to_string(),
        source_job,
        source_fingerprint,
        base,
    })
}

fn process(fixture: &NativeFixture, observer: bool) -> Result<tokio::process::Command> {
    let executable =
        PathBuf::from(std::env::var("ARCHCERT_TEST_CONTROLLER_BINARY")?).canonicalize()?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("--config")
        .arg(&fixture.configuration)
        .args([
            "dispatch-command",
            "--dispatcher",
            "native-build-regression",
            "--lease-seconds",
            "5",
        ])
        .env_clear()
        .env("ARCHCERT_DATABASE_URL", &fixture.writer_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if observer {
        command
            .arg("--observation-config")
            .arg(&fixture.observation)
            .env("ARCHCERT_OBSERVATION_DATABASE_URL", &fixture.reader_url);
    }

    Ok(command)
}

async fn dispatch(fixture: &NativeFixture, observer: bool) -> Result<serde_json::Value> {
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        process(fixture, observer)?.output(),
    )
    .await??;
    assert!(
        output.status.success(),
        "native controller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 128 * 1024);
    let text = std::str::from_utf8(&output.stdout)?;
    for private in [
        COMMAND_TOKEN,
        LEGACY_TOKEN,
        "authority_toml",
        "source_certificate",
        "lease",
        "PRIVATE_RECIPE_CANARY",
    ] {
        assert!(!text.contains(private), "private command data leaked");
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

async fn accept(fixture: &NativeFixture, key: &str) -> Result<ControlCommandRecord> {
    Ok(fixture
        .control
        .repository
        .accept(&fixture.command, &IdempotencyKey::parse(key.into())?)
        .await?)
}

async fn assert_admission(fixture: &NativeFixture, expected: i64) -> Result {
    let counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM release_invocations),
                (SELECT count(*) FROM release_audit WHERE event='BUILD_ADMITTED'),
                (SELECT count(*) FROM release_evidence),
                (SELECT count(*) FROM release_invocations WHERE claim_a IS NOT NULL OR claim_b IS NOT NULL),
                (SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'),
                (SELECT count(*) FROM certification_attempts),
                (SELECT count(*) FROM certification_jobs)",
    ).fetch_one(&fixture.base.pool).await?;
    assert_eq!(counts, (expected, expected, 0, 0, expected, 0, 2));
    let source = JobRepository::get(&fixture.control.repository, fixture.source_job).await?;
    assert_eq!(source.state, JobState::Completed);
    assert!(source.attempts.is_empty());
    assert_eq!(
        digest_bytes(&release_bytes(&source)?),
        fixture.source_fingerprint
    );
    let ResolvedControlAction::RequestReleaseBuild {
        source_certificate, ..
    } = &fixture.command.action
    else {
        return Err("source action".into());
    };
    let bytes = archcert_application::artifacts::ImmutableArtifactStore::get(
        fixture.control.artifacts.as_ref(),
        fixture.command.scope.project,
        source_certificate,
    )
    .await?;
    assert_eq!(digest_bytes(&bytes), source_certificate.sha256);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and the built controller; scripts/test-ravenport"]
async fn native_build_dispatch_verifies_public_source_and_publishes_only_admission() -> Result {
    let fixture = native_fixture(false).await?;
    let first = accept(&fixture, "first-tab").await?;
    assert_eq!(first.id, accept(&fixture, "second-tab").await?.id);

    let receipt = dispatch(&fixture, true).await?;

    assert_eq!(receipt["schema"], 3);
    assert_eq!(receipt["command_id"], first.id.to_string());
    assert_eq!(receipt["state"], "APPLIED");
    assert_eq!(
        receipt["outcome"]["effect"]["kind"],
        "RELEASE_BUILD_REQUESTED"
    );
    assert_eq!(
        accept(&fixture, "new-tab-after-applied").await?.id,
        first.id
    );
    assert_eq!(dispatch(&fixture, true).await?["status"], "IDLE");
    assert_admission(&fixture, 1).await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and the built controller; scripts/test-ravenport"]
async fn native_build_verification_failure_has_no_effect_and_known_rejection_can_retry() -> Result {
    for wrong_key in [false, true] {
        let fixture = native_fixture(!wrong_key).await?;
        if wrong_key {
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&fixture.observation)?)?;
            value["source_public_keys"] = serde_json::json!([OTHER_PUBLIC_KEY]);
            private_json(&fixture.observation, &value)?;
        }
        accept(&fixture, "invalid-source").await?;

        let receipt = dispatch(&fixture, true).await?;

        assert_eq!(receipt["state"], "REJECTED");
        assert_eq!(receipt["outcome"]["reason"], "IDENTITY_MISMATCH");
        assert_admission(&fixture, 0).await?;
    }

    let fixture = native_fixture(false).await?;
    let first = accept(&fixture, "same-key").await?;
    let rejected = dispatch(&fixture, false).await?;
    assert_eq!(rejected["state"], "REJECTED");
    assert_eq!(rejected["outcome"]["reason"], "INFRASTRUCTURE_UNAVAILABLE");
    assert_eq!(accept(&fixture, "same-key").await?.id, first.id);
    assert_admission(&fixture, 0).await?;
    let fresh = accept(&fixture, "explicit-fresh-key").await?;
    assert_ne!(fresh.id, first.id);

    let applied = dispatch(&fixture, true).await?;

    assert_eq!(applied["command_id"], fresh.id.to_string());
    assert_eq!(applied["state"], "APPLIED");
    assert_admission(&fixture, 1).await?;
    assert_eq!(accept(&fixture, "another-tab").await?.id, fresh.id);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and the built controller; scripts/test-ravenport"]
async fn native_build_dispatch_sigkill_recovers_claim_and_retains_published_admission() -> Result {
    use std::os::unix::process::ExitStatusExt;

    for stage in ["claimed", "published"] {
        let fixture = native_fixture(false).await?;
        let original = accept(&fixture, "process-crash").await?;
        let mut child = process(&fixture, true)?
            .args(["--stop-after", stage, "--hold-checkpoint"])
            .spawn()?;
        let stderr = child.stderr.take().ok_or("child stderr")?;
        let bounded = tokio::io::AsyncReadExt::take(stderr, 4096);
        let mut lines = tokio::io::BufReader::new(bounded).lines();
        let marker = format!("Controlled Glassmere command interruption after {stage}");
        tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(line) = lines.next_line().await? {
                if line == marker {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
            }
            Err("native build controller exited before crash checkpoint".into())
        })
        .await??;

        child.kill().await?;
        assert_eq!(child.wait().await?.signal(), Some(9));
        assert_admission(&fixture, if stage == "claimed" { 0 } else { 1 }).await?;
        if stage == "claimed" {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        let recovered = dispatch(&fixture, true).await?;
        assert_eq!(
            recovered[if stage == "claimed" {
                "state"
            } else {
                "status"
            }],
            if stage == "claimed" {
                "APPLIED"
            } else {
                "IDLE"
            }
        );
        let retained = ControlCommandRepository::get(
            &fixture.control.repository,
            &fixture.command.scope,
            original.id,
        )
        .await?;
        assert_eq!(retained.state, ControlCommandState::Applied);
        assert_eq!(retained.request_sha256, original.request_sha256);
        assert_eq!(retained.dispatches, if stage == "claimed" { 2 } else { 1 });
        assert_admission(&fixture, 1).await?;
        println!(
            "Actual SIGKILL recovered build {stage}; one admission, zero M6 execution claims/evidence retained"
        );
    }

    Ok(())
}
