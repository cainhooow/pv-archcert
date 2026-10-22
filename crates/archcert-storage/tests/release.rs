//! Real PostgreSQL M6 races, publication checkpoints and immutable recovery.

#[path = "../../archcert-application/tests/support/release.rs"]
mod fixtures;

use archcert_application::{jobs::JobStoreError, release::*};
use archcert_domain::{ingress::*, jobs::JobId, release::*, source::*};
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
use fixtures::*;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};

async fn database() -> R<PostgresJobRepository> {
    let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&url).await?;
    let schema = format!("release_{}", JobId::new().to_string().replace('-', ""));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |c, _| {
            let schema = schema.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(schema)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let repository = PostgresJobRepository::from_pool(pool);
    repository.migrate().await?;

    Ok(repository)
}

async fn admission(repo: &PostgresJobRepository) -> R<ReleaseAdmission> {
    let mut input = input()?;
    let s = &input.certified_source;
    let snapshot = SourceSnapshot::seal(
        s.project,
        s.repository.clone(),
        s.source.commit.clone(),
        s.source.tree.clone(),
        vec![],
        1,
        1,
    )?;
    input.certified_source.source = snapshot.identity().clone();
    let actor = GitActorId::parse(JobId::new().to_string())?;
    let submission = SourceSubmissionId::new();
    repo.grant(
        input.certified_source.project,
        &input.certified_source.repository,
        &actor,
    )
    .await?;
    repo.register_source(&submission, &snapshot).await?;

    Ok(ReleaseAdmission {
        input_reference: release_reference(&release_bytes(&input)?),
        input,
        submission,
        actor,
    })
}

struct Builder {
    calls: Cell<u32>,
    different: bool,
    unavailable_b: bool,
}

impl ReleaseBuilder for Builder {
    fn build(&self, input: &BuildInputManifest, ordinal: BuildOrdinal) -> BuildOutput {
        self.calls.set(self.calls.get() + 1);
        let bytes = if self.different && ordinal == BuildOrdinal::B {
            b"other".to_vec()
        } else {
            b"artifact".to_vec()
        };
        let mut result = fixtures::result(input, ordinal, &bytes)
            .unwrap_or_else(|e| panic!("fixture construction: {e}"));
        let mut artifact = Some(bytes);

        if self.unavailable_b && ordinal == BuildOrdinal::B {
            result.completion = BuildCompletion::Inconclusive;
            result.execution = None;
            result.cleanup_complete = false;
            result.artifact = None;
            artifact = None;
        }

        BuildOutput { result, artifact }
    }
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn concurrent_release_admission_claims_and_payloads_are_create_only() -> R {
    let repo = database().await?;
    let admission = admission(&repo).await?;
    let project = admission.input.certified_source.project;
    let id = admission.input.identity()?;
    let (a, b) = tokio::join!(repo.open(&admission), repo.open(&admission));
    a?;
    b?;
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let store =
        FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
    let workflow = ReleaseWorkflow {
        repository: &repo,
        artifacts: &store,
    };
    workflow
        .admit(&admission, &recipe()?, b"retained source certificate")
        .await?;
    let (a, b) = tokio::join!(
        repo.claim(project, &id, BuildOrdinal::A),
        repo.claim(project, &id, BuildOrdinal::A)
    );
    let a = a?;
    let b = b?;
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    assert!(repo.claim(project, &id, BuildOrdinal::A).await?.is_none());
    assert!(repo.claim(project, &id, BuildOrdinal::B).await.is_err());
    assert!(
        repo.get(archcert_domain::ProjectId::new(), &id)
            .await
            .is_err()
    );

    let builder = Builder {
        calls: Cell::new(0),
        different: false,
        unavailable_b: false,
    };
    assert!(
        workflow
            .run_build(&admission.input, BuildOrdinal::A, &builder)
            .await
            .is_err()
    );
    assert_eq!(
        builder.calls.get(),
        0,
        "unknown claimed execution must not be retried"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn accepted_builds_resume_without_execution_and_reject_permit_replacement() -> R {
    let repo = database().await?;
    let admission = admission(&repo).await?;
    let input = &admission.input;
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let store =
        FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
    let workflow = ReleaseWorkflow {
        repository: &repo,
        artifacts: &store,
    };
    workflow
        .admit(&admission, &recipe()?, b"retained source certificate")
        .await?;
    let builder = Builder {
        calls: Cell::new(0),
        different: false,
        unavailable_b: false,
    };
    workflow.run_build(input, BuildOrdinal::A, &builder).await?;
    workflow.run_build(input, BuildOrdinal::B, &builder).await?;
    assert_eq!(
        workflow.compare(input).await?.verdict,
        ReproducibilityVerdict::Reproducible
    );
    let prepared = workflow
        .prepare_payload(input, b"canonical message frozen by issuer")
        .await?;
    assert_eq!(
        prepared.digest(),
        &digest_bytes(b"canonical message frozen by issuer")
    );

    // A newly constructed workflow represents controller restart/reconnect.
    let resumed = ReleaseWorkflow {
        repository: &repo,
        artifacts: &store,
    };
    resumed.run_build(input, BuildOrdinal::A, &builder).await?;
    resumed.run_build(input, BuildOrdinal::B, &builder).await?;
    assert_eq!(builder.calls.get(), 2);
    assert!(matches!(
        resumed.prepare_payload(input, b"different message").await,
        Err(JobStoreError::Conflict)
    ));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn different_outputs_and_failed_second_build_never_prepare_a_payload() -> R {
    for unavailable_b in [false, true] {
        let repo = database().await?;
        let admission = admission(&repo).await?;
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let store =
            FilesystemArtifactStore::open_unencrypted_development(&root.path().canonicalize()?)?;
        let workflow = ReleaseWorkflow {
            repository: &repo,
            artifacts: &store,
        };
        workflow
            .admit(&admission, &recipe()?, b"retained source certificate")
            .await?;
        let builder = Builder {
            calls: Cell::new(0),
            different: true,
            unavailable_b,
        };
        workflow
            .run_build(&admission.input, BuildOrdinal::A, &builder)
            .await?;
        workflow
            .run_build(&admission.input, BuildOrdinal::B, &builder)
            .await?;
        let expected = if unavailable_b {
            ReproducibilityVerdict::Inconclusive
        } else {
            ReproducibilityVerdict::NonReproducible
        };
        assert_eq!(workflow.compare(&admission.input).await?.verdict, expected);
        assert!(
            workflow
                .prepare_payload(&admission.input, b"must never be accepted")
                .await
                .is_err()
        );
        let record = repo
            .get(
                admission.input.certified_source.project,
                &admission.input.identity()?,
            )
            .await?;
        assert!(record.references.iter().all(|r| !matches!(
            r.role,
            ReleaseRole::PermitPayload | ReleaseRole::PermitEnvelope
        )));
    }

    Ok(())
}
