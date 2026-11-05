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
async fn exact_source_selection_ignores_history_page_and_preserves_project_scope() -> R {
    let db = Database::open().await?;
    let request = db.request().await?;
    let foreign = db.request().await?;
    let project = request.inputs.project;
    let mut submissions = vec![request.inputs.submission.to_string()];

    for ordinal in 0..55 {
        let submission = SourceSubmissionId::new();
        let source = SourceSnapshot::seal(
            project,
            request.inputs.repository.clone(),
            GitObjectId::parse(format!("{ordinal:040x}"))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![],
            1,
            1700000000,
        )?;
        db.repository.register_source(&submission, &source).await?;
        submissions.push(submission.to_string());
    }
    submissions.sort();
    let selected = submissions.last().ok_or("source fixture")?;
    let reader = ObservationRepository::connect(&db.reader_url).await?;

    let first = reader.snapshot(project, 0).await?;
    assert_eq!(first.sources.len(), MAX_PAGE_SIZE);
    assert!(first.sources.iter().all(|source| &source.id != selected));

    for offset in [0, 50, 100_000] {
        let exact = reader.entity(project, selected, offset).await?;
        assert_eq!(exact.sources.len(), 1);
        assert_eq!(&exact.sources[0].id, selected);
        assert_eq!(exact.project.project, project);
        assert!(exact.sources[0].fields.iter().any(|field| {
            field.label == "Repository" && field.value == request.inputs.repository.as_str()
        }));
        assert!(exact.jobs.is_empty());
        assert!(exact.sessions.is_empty());
    }
    assert!(matches!(
        reader
            .entity(project, &foreign.inputs.submission.to_string(), 0)
            .await,
        Err(JobStoreError::Precondition)
    ));
    assert!(matches!(
        reader.entity(project, selected, 100_001).await,
        Err(JobStoreError::Invalid)
    ));

    drop(reader);
    db.close().await
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

    let second_repository = RepositoryId::parse("glassmere/second-repository")?;
    let second_submission = SourceSubmissionId::new();
    let second_source = SourceSnapshot::seal(
        project,
        second_repository.clone(),
        GitObjectId::parse("c".repeat(40))?,
        GitObjectId::parse("d".repeat(40))?,
        vec![],
        1,
        1700000000,
    )?;
    db.repository
        .grant(project, &second_repository, &request.inputs.actor)
        .await?;
    db.repository
        .register_source(&second_submission, &second_source)
        .await?;
    let mut second_request = request.clone();
    second_request.inputs.repository = second_repository.clone();
    second_request.inputs.submission = second_submission;
    second_request.inputs.source = second_source.identity().clone();
    db.repository.create(second_request).await?;

    let reader = ObservationRepository::connect(&db.reader_url).await?;

    let projects = reader.projects(&[project], None).await?;
    let first = reader.snapshot(project, 0).await?;
    let second = reader.snapshot(project, 50).await?;

    assert_eq!(projects.len(), 1);
    assert_eq!(first.jobs.len(), MAX_PAGE_SIZE);
    assert_eq!(second.jobs.len(), 6);

    let selected = &second.jobs[0].id;
    assert!(first.jobs.iter().all(|job| &job.id != selected));
    let exact = reader.entity(project, selected, 0).await?;
    let later = reader.entity(project, selected, 50).await?;
    assert_eq!(exact.jobs.len(), 1);
    assert_eq!(&exact.jobs[0].id, selected);
    assert_eq!(later.jobs.len(), 1);
    assert_eq!(&later.jobs[0].id, selected);
    assert!(exact.evidence.iter().all(|item| &item.entity == selected));
    assert!(exact.timeline.iter().all(|event| &event.entity == selected));
    assert_eq!(exact.timeline.len(), 2);
    assert!(later.timeline.is_empty());
    assert!(matches!(
        reader.entity(project, &foreign.id.to_string(), 0).await,
        Err(JobStoreError::Precondition)
    ));
    assert!(matches!(
        reader.entity(project, &JobId::new().to_string(), 0).await,
        Err(JobStoreError::Precondition)
    ));
    assert!(reader.entity(project, selected, 100_001).await.is_err());
    assert_eq!(
        projects[0].repository,
        "MULTIPLE_REPOSITORIES / SELECT EXACT ENTITY"
    );
    assert_eq!(first.project.repository, projects[0].repository);
    assert!(first.jobs.iter().chain(&second.jobs).any(|job| {
        job.fields
            .iter()
            .any(|field| field.label == "Repository" && field.value == second_repository.as_str())
    }));
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

#[tokio::test]
#[ignore = "requires real PostgreSQL and role provisioning"]
async fn job_inspection_preserves_attempt_phases_and_nested_certificate_identity_without_capabilities()
-> R {
    let db = Database::open().await?;
    let request = db.request().await?;
    let project = request.inputs.project;
    let id = db.repository.create(request).await?.id;
    let reference = ArtifactReference {
        sha256: digest_bytes(b"observation-only-test-metadata"),
        size: b"observation-only-test-metadata".len() as u64,
        schema: 1,
        producer: "observation-fixture".into(),
    };
    let reader = ObservationRepository::connect(&db.reader_url).await?;
    let queued = reader.snapshot(project, 0).await?;
    assert_eq!(queued.jobs[0].state, "QUEUED");
    assert!(queued.jobs[0].fields.iter().any(|field| {
        field.label == "Evaluation started UTC Unix seconds" && field.value == "NOT RECORDED"
    }));

    let assignment = db
        .repository
        .claim("named-fixture-worker", 30)
        .await?
        .ok_or("claim")?;
    db.repository.start(&assignment.lease).await?;
    let binding = RuntimeBinding {
        endpoint: "unix:///private/ENDPOINT_MUST_NOT_LEAK.sock".into(),
        daemon_id: "DAEMON_MUST_NOT_LEAK".into(),
        gate_root: "/private/GATE_MUST_NOT_LEAK".into(),
    };
    db.repository
        .bind_runtime(&assignment.lease, &binding)
        .await?;
    let running = reader.snapshot(project, 0).await?;
    assert!(
        running.jobs[0].fields.iter().any(|field| {
            field.label == "Attempt 1: runtime cleanup" && field.value == "PENDING"
        })
    );
    assert!(running.jobs[0].fields.iter().any(|field| {
        field.label == "Attempt 1: execution ended UTC Unix seconds"
            && field.value == "NOT RECORDED"
    }));

    // These are metadata fixtures, not cryptographic certificates or runtime proof.
    // The test exercises the existing repository transitions, then SELECT-only projection.
    db.repository
        .stage_artifact(id, Some(assignment.lease.attempt), "EXECUTION", &reference)
        .await?;
    db.repository
        .artifact_available(id, Some(assignment.lease.attempt), "EXECUTION", &reference)
        .await?;
    db.repository
        .accept_evidence(&assignment.lease, &reference)
        .await?;
    db.repository
        .fence_runtime(id, assignment.lease.attempt, &binding)
        .await?;
    db.repository
        .finish_cleanup(
            id,
            assignment.lease.attempt,
            &binding,
            RuntimeCleanupState::Succeeded,
        )
        .await?;

    for kind in ["EVALUATION", "CERTIFICATE"] {
        db.repository
            .stage_artifact(id, None, kind, &reference)
            .await?;
        db.repository
            .artifact_available(id, None, kind, &reference)
            .await?;
    }
    db.repository
        .record_evaluation(id, &reference, EvaluationDecision::Eligible)
        .await?;
    let issuance = PreparedIssuance {
        certificate_sha256: digest_bytes(b"canonical-payload-identity"),
        signing_key_id: "a".repeat(64),
        issued_at: 1700000000,
    };
    db.repository.prepare_issuance(id, &issuance).await?;
    db.repository
        .complete(
            id,
            &PersistedCertificate {
                issuance: issuance.clone(),
                artifact: reference.clone(),
                signature: "a".repeat(128),
                verified: true,
            },
        )
        .await?;

    let complete = reader.snapshot(project, 0).await?;
    let job = &complete.jobs[0];
    assert_eq!(job.state, "COMPLETED");
    for (label, expected) in [
        (
            "Certificate identity",
            issuance.certificate_sha256.as_str().to_string(),
        ),
        ("Attempt 1: identity", assignment.lease.attempt.to_string()),
        ("Attempt 1: worker", "named-fixture-worker".into()),
        ("Attempt 1: state", "COMPLETED".into()),
        ("Attempt 1: runtime cleanup", "SUCCEEDED".into()),
        ("Attempt 1: runtime fenced", "true".into()),
    ] {
        assert!(
            job.fields
                .iter()
                .any(|field| field.label == label && field.value == expected),
            "{label}"
        );
    }
    for label in [
        "Evaluation started UTC Unix seconds",
        "Attempt 1: leased UTC Unix seconds",
        "Attempt 1: execution ended UTC Unix seconds",
    ] {
        let field = job
            .fields
            .iter()
            .find(|field| field.label == label)
            .ok_or("timestamp")?;
        assert!(field.value.parse::<i64>()? > 0);
    }
    let json = serde_json::to_string(&complete)?;
    for (kind, value) in [
        (
            search::SearchKind::Certificate,
            issuance.certificate_sha256.as_str(),
        ),
        (search::SearchKind::Certificate, reference.sha256.as_str()),
        (search::SearchKind::Verdict, "ELIGIBLE"),
    ] {
        let page = reader
            .search(
                project,
                &search::SearchQuery {
                    kind,
                    value: value.into(),
                    after: None,
                },
            )
            .await?;
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].entity, id.to_string());
    }
    for excluded in [
        "ENDPOINT_MUST_NOT_LEAK",
        "DAEMON_MUST_NOT_LEAK",
        "GATE_MUST_NOT_LEAK",
        "token",
        "authority_toml",
        "SENSITIVE_MUST_NOT_LEAK",
    ] {
        assert!(!json.contains(excluded), "{excluded}");
    }
    assert!(
        job.fields
            .iter()
            .any(|field| field.label == "Recovery eligibility"
                && field.value.starts_with("NOT EVALUATED BY PANEL"))
    );

    drop(reader);
    db.close().await
}

async fn search_pages(
    reader: &ObservationRepository,
    project: ProjectId,
    mut query: search::SearchQuery,
) -> R<Vec<search::SearchPage>> {
    let mut pages = Vec::new();
    for _ in 0..8 {
        let page = reader.search(project, &query).await?;
        assert!(page.hits.len() <= MAX_PAGE_SIZE);
        let next = page.next.clone();
        pages.push(page);
        let Some(next) = next else {
            return Ok(pages);
        };
        query.after = Some(next);
    }

    Err("Search pagination did not terminate within this fixture's expected bound".into())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and role provisioning"]
async fn exact_search_scopes_metadata_and_paginates_without_duplicate_keys_during_inserts() -> R {
    use search::{SearchKind, SearchQuery};

    let db = Database::open().await?;
    let request = db.request().await?;
    let project = request.inputs.project;
    let reference = ArtifactReference {
        sha256: digest_bytes(b"search fixture"),
        size: b"search fixture".len() as u64,
        schema: 1,
        producer: "search-fixture".into(),
    };

    // Repository metadata transitions exercise recorded dispositions only. They
    // establish no cryptographic certificate or live runtime qualification.
    for (ordinal, decision) in [
        EvaluationDecision::NotEligible,
        EvaluationDecision::Inconclusive,
    ]
    .into_iter()
    .enumerate()
    {
        let mut failed = request.clone();
        failed.idempotency = IdempotencyKey::parse(format!("evaluation-{ordinal}"))?;
        let id = db.repository.create(failed).await?.id;
        let assignment = db
            .repository
            .claim("search-fixture-worker", 30)
            .await?
            .ok_or("claim")?;
        assert_eq!(assignment.job.id, id);
        db.repository.start(&assignment.lease).await?;
        db.repository
            .stage_artifact(id, Some(assignment.lease.attempt), "EXECUTION", &reference)
            .await?;
        db.repository
            .artifact_available(id, Some(assignment.lease.attempt), "EXECUTION", &reference)
            .await?;
        db.repository
            .accept_evidence(&assignment.lease, &reference)
            .await?;
        db.repository
            .stage_artifact(id, None, "EVALUATION", &reference)
            .await?;
        db.repository
            .artifact_available(id, None, "EVALUATION", &reference)
            .await?;
        db.repository
            .record_evaluation(id, &reference, decision)
            .await?;
    }

    let mut expected = std::collections::BTreeSet::new();
    for ordinal in 0..105 {
        let mut queued = request.clone();
        queued.idempotency = IdempotencyKey::parse(format!("search-{ordinal}"))?;
        let job = db.repository.create(queued).await?;
        db.repository
            .stage_artifact(job.id, None, "BUNDLE", &reference)
            .await?;
        expected.insert(job.id.to_string());
    }
    let foreign_request = db.request().await?;
    let foreign_project = foreign_request.inputs.project;
    let foreign = db.repository.create(foreign_request).await?;
    db.repository
        .stage_artifact(foreign.id, None, "BUNDLE", &reference)
        .await?;
    let reader = ObservationRepository::connect(&db.reader_url).await?;
    let query = SearchQuery {
        kind: SearchKind::Status,
        value: "QUEUED".into(),
        after: None,
    };

    let pages = search_pages(&reader, project, query.clone()).await?;
    assert_eq!(
        pages.iter().map(|page| page.hits.len()).collect::<Vec<_>>(),
        [50, 50, 5]
    );
    let found: std::collections::BTreeSet<_> = pages
        .iter()
        .flat_map(|page| &page.hits)
        .map(|hit| hit.entity.clone())
        .collect();
    assert_eq!(found, expected);
    assert!(
        pages
            .iter()
            .flat_map(|page| &page.hits)
            .all(|hit| hit.entity != foreign.id.to_string())
    );

    let first = reader.search(project, &query).await?;
    let mut inserted = request.clone();
    inserted.idempotency = IdempotencyKey::parse("concurrent-search-insert".into())?;
    let inserted = db.repository.create(inserted).await?;
    let mut continuation = query.clone();
    continuation.after = first.next.clone();
    let mut keys: Vec<_> = first.hits.iter().map(|hit| hit.key.clone()).collect();
    let mut entities: std::collections::BTreeSet<_> =
        first.hits.iter().map(|hit| hit.entity.clone()).collect();
    for page in search_pages(&reader, project, continuation).await? {
        for hit in page.hits {
            keys.push(hit.key);
            assert!(entities.insert(hit.entity));
        }
    }
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(expected.is_subset(&entities));
    assert!(
        entities.len() == 105
            || (entities.len() == 106 && entities.contains(&inserted.id.to_string()))
    );

    for (kind, value, count) in [
        (SearchKind::Project, project.to_string(), 1),
        (SearchKind::Project, foreign_project.to_string(), 0),
        (SearchKind::Job, foreign.id.to_string(), 0),
        (
            SearchKind::Job,
            expected.first().ok_or("fixture job")?.clone(),
            1,
        ),
        (
            SearchKind::Commit,
            request.inputs.source.commit.as_str().into(),
            109,
        ),
        (SearchKind::Verdict, "NOT_ELIGIBLE".into(), 1),
        (SearchKind::Verdict, "INCONCLUSIVE".into(), 1),
        (SearchKind::Verdict, "ELIGIBLE".into(), 0),
        (SearchKind::Artifact, reference.sha256.as_str().into(), 109),
    ] {
        let pages = search_pages(
            &reader,
            project,
            SearchQuery {
                kind,
                value,
                after: None,
            },
        )
        .await?;
        assert_eq!(
            pages.iter().map(|page| page.hits.len()).sum::<usize>(),
            count,
            "{kind:?}"
        );
        assert!(
            pages
                .iter()
                .flat_map(|page| &page.hits)
                .all(|hit| hit.entity != foreign.id.to_string())
        );
    }

    // Deliberately unsupported STAGING release metadata proves that lookup does
    // not claim a valid certificate/permit. No bytes, signature or eligibility
    // are manufactured, and the fixture cannot authorize a release.
    let envelope = digest_bytes(b"unverifiable metadata fixture");
    let certificate = digest_bytes(b"canonical certificate lookup fixture");
    let mut owned_invocation = String::new();
    for scope in [project, foreign_project] {
        let invocation = digest_bytes(scope.to_string().as_bytes());
        if scope == project {
            owned_invocation = invocation.as_str().into();
        }
        let admission = serde_json::json!({
            "input": {
                "schema": 999,
                "certified_source": {
                    "certificate_sha256": certificate,
                },
            },
        });
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {}.release_invocations(project,invocation,admission) VALUES($1,$2,$3)",
            db.schema
        )))
        .bind(scope.to_string())
        .bind(invocation.as_str())
        .bind(admission)
        .execute(&db.admin)
        .await?;
        for role in [
            "SOURCE_CERTIFICATE",
            "PERMIT_PAYLOAD",
            "PERMIT_ENVELOPE",
            "ARTIFACT_A",
        ] {
            let reference = serde_json::json!({
                "sha256": envelope,
                "size": 1,
                "schema": 999,
                "producer": "unsupported-search-fixture",
            });
            let statement = sqlx::AssertSqlSafe(format!(
                "INSERT INTO {}.release_evidence(project,invocation,role,reference) VALUES($1,$2,$3,$4)",
                db.schema
            ));
            sqlx::query(statement)
                .bind(scope.to_string())
                .bind(invocation.as_str())
                .bind(role)
                .bind(reference)
                .execute(&db.admin)
                .await?;
        }
    }
    for (kind, value, count) in [
        (SearchKind::Certificate, certificate.as_str(), 1),
        (SearchKind::Certificate, envelope.as_str(), 1),
        (SearchKind::Permit, envelope.as_str(), 2),
        (SearchKind::Artifact, envelope.as_str(), 4),
    ] {
        let page = reader
            .search(
                project,
                &SearchQuery {
                    kind,
                    value: value.into(),
                    after: None,
                },
            )
            .await?;
        assert_eq!(page.hits.len(), count, "{kind:?}");
        assert!(
            page.hits
                .iter()
                .all(|hit| hit.entity == owned_invocation && hit.state == "STAGING")
        );
    }
    let mut wrong_cursor = query;
    wrong_cursor.after = first.next;
    wrong_cursor.value = "RUNNING".into();
    assert!(matches!(
        reader.search(project, &wrong_cursor).await,
        Err(JobStoreError::Invalid)
    ));

    drop(reader);
    db.close().await
}
