//! Real PostgreSQL query isolation and least-privilege tests; no mock DB claims.

use archcert_application::{glassmere::*, jobs::*};
use archcert_domain::{GitObjectId, ProjectId, ingress::*, jobs::*, source::*};
use archcert_storage::{PostgresJobRepository, glassmere::ObservationRepository};
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::str::FromStr;

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Database {
    admin: PgPool,
    schema: String,
    role: String,
    repository: PostgresJobRepository,
    reader_url: String,
}

impl Database {
    async fn open() -> R<Self> {
        let url = std::env::var("ARCHCERT_TEST_DATABASE_URL")?;
        let admin = PgPool::connect(&url).await?;
        let suffix = JobId::new().to_string().replace('-', "");
        let schema = format!("glassmere_{suffix}");
        let role = format!("glassmere_reader_{suffix}");
        let password = JobId::new().to_string();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}'"
        )))
        .execute(&admin)
        .await?;
        let schema_for_pool = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |c, _| {
                let schema = schema_for_pool.clone();
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
        repository.migrate().await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA {schema} TO {role}"
        )))
        .execute(&admin)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}"
        )))
        .execute(&admin)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE {role} SET search_path TO {schema}"
        )))
        .execute(&admin)
        .await?;
        let reader_url = PgConnectOptions::from_str(&url)?
            .username(&role)
            .password(&password)
            .options([("search_path", schema.as_str())])
            .to_url_lossy()
            .to_string();

        Ok(Self {
            admin,
            schema,
            role,
            repository,
            reader_url,
        })
    }

    async fn close(self) -> R {
        // Read pool teardown precedes schema/role cleanup at each call site.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {}", self.role)))
            .execute(&self.admin)
            .await?;
        Ok(())
    }

    async fn request(&self) -> R<CreateJob> {
        let project = ProjectId::new();
        let repository = RepositoryId::parse("glassmere/fixture")?;
        let actor = GitActorId::parse(JobId::new().to_string())?;
        let submission = SourceSubmissionId::new();
        let source = SourceSnapshot::seal(
            project,
            repository.clone(),
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![],
            1,
            1700000000,
        )?;
        self.repository.grant(project, &repository, &actor).await?;
        self.repository
            .register_source(&submission, &source)
            .await?;

        Ok(CreateJob {
            inputs: JobInputs {
                project,
                repository,
                submission,
                source: source.identity().clone(),
                actor,
                policy: PolicyPin {
                    id: "development".into(),
                    version: "1.0.0".into(),
                    sha256: digest_bytes(b"policy"),
                },
                profile: "python".into(),
                image: format!("python@sha256:{}", "d".repeat(64)),
                plan_sha256: digest_bytes(b"plan"),
                authority_toml: "password = 'SENSITIVE_MUST_NOT_LEAK'".into(),
                maximum_attempts: 1,
            },
            idempotency: IdempotencyKey::parse("initial".into())?,
        })
    }
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and role provisioning"]
async fn readonly_queries_scope_objects_bound_pages_and_reconstruct_after_restart() -> R {
    let db = Database::open().await?;
    let request = db.request().await?;
    let other = db.request().await?;
    let project = request.inputs.project;
    let foreign = db.repository.create(other).await?;
    for ordinal in 0..55 {
        let mut request = request.clone();
        request.idempotency = IdempotencyKey::parse(format!("page-{ordinal}"))?;
        db.repository.create(request).await?;
    }
    let reader = ObservationRepository::connect(&db.reader_url).await?;

    let projects = reader.projects(&[project], None).await?;
    let first = reader.snapshot(project, 0).await?;
    let second = reader.snapshot(project, 50).await?;

    assert_eq!(projects.len(), 1);
    assert_eq!(first.jobs.len(), MAX_PAGE_SIZE);
    assert_eq!(second.jobs.len(), 5);
    assert!(first.has_more);
    // Admission writes CertificationRequested and JobCreated, so timeline
    // pagination continues after the final job page.
    assert!(second.has_more);
    assert!(!reader.snapshot(project, 100).await?.has_more);
    assert!(
        first
            .jobs
            .iter()
            .all(|job| job.id != foreign.id.to_string())
    );
    let json = serde_json::to_string(&first)?;
    assert!(!json.contains("SENSITIVE_MUST_NOT_LEAK"));
    assert!(!json.contains("authority_toml"));
    assert!(!json.contains("token"));
    assert!(
        reader
            .evidence(
                project,
                &foreign.id.to_string(),
                digest_bytes(b"foreign").as_str()
            )
            .await
            .is_err()
    );
    assert!(reader.snapshot(project, 100001).await.is_err());

    drop(reader);
    let reader = ObservationRepository::connect(&db.reader_url).await?;
    assert_eq!(reader.snapshot(project, 0).await?.revision, first.revision);
    let connection = PgPool::connect(&db.reader_url).await?;
    assert!(
        sqlx::query("DELETE FROM certification_jobs")
            .execute(&connection)
            .await
            .is_err()
    );
    connection.close().await;
    drop(reader);
    db.close().await
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and role provisioning"]
async fn writable_roles_are_rejected_and_concurrent_aggregate_reads_are_coherent() -> R {
    let db = Database::open().await?;
    let request = db.request().await?;
    let project = request.inputs.project;
    let reader = ObservationRepository::connect(&db.reader_url).await?;
    let writer = async {
        for ordinal in 0..20 {
            let mut request = request.clone();
            request.idempotency = IdempotencyKey::parse(format!("race-{ordinal}"))?;
            db.repository.create(request).await?;
        }
        R::Ok(())
    };
    let observer = async {
        for _ in 0..20 {
            let snapshot = reader.snapshot(project, 0).await?;
            assert_eq!(snapshot.jobs.len() * 2, snapshot.timeline.len());
            assert!(
                snapshot
                    .jobs
                    .iter()
                    .all(|job| snapshot.timeline.iter().any(|event| event.entity == job.id))
            );
        }
        R::Ok(())
    };
    let (written, observed) = tokio::join!(writer, observer);
    written?;
    observed?;

    drop(reader);
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT INSERT ON ALL TABLES IN SCHEMA {} TO {}",
        db.schema, db.role
    )))
    .execute(&db.admin)
    .await?;
    assert!(matches!(
        ObservationRepository::connect(&db.reader_url).await,
        Err(JobStoreError::Unauthorized)
    ));

    db.close().await
}
