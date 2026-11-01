//! Bounded read-only observation adapter. No workflow loaders or row locks.

use super::*;
use archcert_application::{glassmere::*, release::*};
use sqlx::{Postgres, Transaction, postgres::PgPoolOptions};

/// Separate SELECT-only connection pool, never shared with controller writes.
pub struct ObservationRepository {
    pool: PgPool,
}

/// Exact immutable release records observed within one database snapshot.
pub struct ReleaseObservationRecord {
    /// Frozen admission; not exposed directly to the browser.
    pub admission: ReleaseAdmission,
    /// Rehashable scoped references.
    pub references: Vec<ReleaseReference>,
    /// Snapshot token from the coherent read.
    pub snapshot: String,
    /// UTC evaluation timestamp.
    pub evaluated_at: i64,
}

fn field(label: &str, value: impl ToString, provenance: &str) -> ObservationField {
    ObservationField {
        label: label.into(),
        value: value.to_string(),
        provenance: provenance.into(),
    }
}

fn source_fields(value: &Value, provenance: &str) -> Vec<ObservationField> {
    ["commit", "tree", "snapshot_sha256"]
        .into_iter()
        .map(|name| {
            field(
                name,
                value[name].as_str().unwrap_or("UNKNOWN / UNSUPPORTED"),
                provenance,
            )
        })
        .collect()
}

fn evidence_row(row: PgRow) -> Result<EvidenceObservation> {
    let reference: ArtifactReference = decode(row.try_get("reference").map_err(db)?)?;

    Ok(EvidenceObservation {
        entity: row.try_get("entity").map_err(db)?,
        role: row.try_get("role").map_err(db)?,
        sha256: reference.sha256.as_str().into(),
        size: reference.size,
        schema: reference.schema,
        producer: reference.producer,
        state: row.try_get("state").map_err(db)?,
        verification: Vec::new(),
    })
}

impl ObservationRepository {
    /// Reject a role with inherited table mutation privileges. Explicit provisioning
    /// grants SELECT on required tables; migrations never run in the panel process.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .min_connections(2)
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET default_transaction_read_only = on")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET statement_timeout = '3s'")
                        .execute(connection)
                        .await?;

                    Ok(())
                })
            })
            .connect(url)
            .await
            .map_err(db)?;
        let writable: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN ('r','p') AND has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE')) OR (SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user)",
        ).fetch_one(&pool).await.map_err(db)?;

        if writable {
            pool.close().await;
            return Err(JobStoreError::Unauthorized);
        }

        Ok(Self { pool })
    }

    async fn begin(&self) -> Result<Transaction<'_, Postgres>> {
        let mut transaction = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(db)?;

        Ok(transaction)
    }

    /// Small dependency probe, independent of any release state.
    pub async fn healthy(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }

    /// Bounded keyset project list restricted by externally provisioned grants.
    pub async fn projects(
        &self,
        allowed: &[ProjectId],
        after: Option<ProjectId>,
    ) -> Result<Vec<ProjectObservation>> {
        if allowed.len() > 256 {
            return Err(JobStoreError::Invalid);
        }

        let rows = sqlx::query(
            "SELECT project,CASE WHEN count(DISTINCT repository)>1 THEN 'MULTIPLE_REPOSITORIES / SELECT EXACT ENTITY' ELSE min(repository) END AS repository FROM repository_grants WHERE project=ANY($1) AND ($2::text IS NULL OR project>$2) GROUP BY project ORDER BY project LIMIT 50",
        )
        .bind(allowed.iter().map(ToString::to_string).collect::<Vec<_>>())
        .bind(after.map(|p| p.to_string()))
        .fetch_all(&self.pool).await.map_err(db)?;

        rows.into_iter()
            .map(|r| {
                Ok(ProjectObservation {
                    project: r
                        .try_get::<String, _>("project")
                        .map_err(db)?
                        .parse()
                        .map_err(|_| JobStoreError::Invalid)?,
                    repository: r.try_get("repository").map_err(db)?,
                })
            })
            .collect()
    }

    /// Coherent independently paged collections. Multiple repositories in one
    /// project remain visible on each source/job; no branch is selected as current.
    pub async fn snapshot(&self, project: ProjectId, offset: u32) -> Result<ProjectSnapshot> {
        if offset > 100_000 {
            return Err(JobStoreError::Invalid);
        }

        let mut tx = self.begin().await?;
        let repository: Option<String> =
            sqlx::query_scalar("SELECT CASE WHEN count(DISTINCT repository)>1 THEN 'MULTIPLE_REPOSITORIES / SELECT EXACT ENTITY' ELSE min(repository) END FROM repository_grants WHERE project=$1")
                .bind(project.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let repository = repository.ok_or(JobStoreError::Precondition)?;
        let snapshot: String = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let evaluated_at = now(&mut tx).await?;
        let mut has_more = false;

        let rows = sqlx::query("SELECT submission,repository,source FROM accepted_sources WHERE project=$1 ORDER BY submission LIMIT 51 OFFSET $2")
            .bind(project.to_string()).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db)?;
        has_more |= rows.len() > MAX_PAGE_SIZE;
        let mut sources = Vec::new();

        for row in rows.into_iter().take(MAX_PAGE_SIZE) {
            let source: Value = row.try_get("source").map_err(db)?;
            let mut fields = source_fields(&source, "Accepted source registry");
            fields.push(field(
                "Repository",
                row.try_get::<String, _>("repository").map_err(db)?,
                "Accepted source registry",
            ));
            sources.push(EntityObservation {
                id: row.try_get("submission").map_err(db)?,
                kind: "SOURCE".into(),
                state: "ACCEPTED IMMUTABLE SOURCE".into(),
                fields,
            });
        }

        let rows = sqlx::query("SELECT id,state,inputs->>'repository' AS repository,inputs->'source' AS source,inputs->'policy' AS policy,inputs->>'profile' AS profile,created_at,evaluation_at,failure,evaluation,certificate FROM certification_jobs WHERE project=$1 ORDER BY id LIMIT 51 OFFSET $2")
            .bind(project.to_string()).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db)?;
        has_more |= rows.len() > MAX_PAGE_SIZE;
        let mut jobs = Vec::new();
        let job_ids = rows
            .iter()
            .take(MAX_PAGE_SIZE)
            .map(|row| row.try_get::<String, _>("id").map_err(db))
            .collect::<Result<Vec<_>>>()?;
        let attempt_rows = sqlx::query(
            "SELECT job,ordinal,state,leased_at,lease_until,ended_at,failure FROM certification_attempts WHERE job=ANY($1) ORDER BY job,ordinal LIMIT 150",
        ).bind(&job_ids).fetch_all(&mut *tx).await.map_err(db)?;
        let mut attempts_by_job = std::collections::BTreeMap::<String, Vec<PgRow>>::new();
        for attempt in attempt_rows {
            let job = attempt.try_get::<String, _>("job").map_err(db)?;
            attempts_by_job.entry(job).or_default().push(attempt);
        }

        for row in rows.into_iter().take(MAX_PAGE_SIZE) {
            let id: String = row.try_get("id").map_err(db)?;
            let source: Value = row.try_get("source").map_err(db)?;
            let mut fields = source_fields(&source, "Durable job source binding");
            fields.push(field(
                "Repository",
                row.try_get::<String, _>("repository").map_err(db)?,
                "Durable job source binding",
            ));
            fields.extend([
                field(
                    "Policy",
                    row.try_get::<Value, _>("policy").map_err(db)?,
                    "Authority policy pin",
                ),
                field(
                    "Profile",
                    row.try_get::<String, _>("profile").map_err(db)?,
                    "Authority execution profile",
                ),
                field(
                    "Created UTC Unix seconds",
                    row.try_get::<i64, _>("created_at").map_err(db)?,
                    "Durable job",
                ),
                field(
                    "Failure category",
                    row.try_get::<Option<String>, _>("failure")
                        .map_err(db)?
                        .unwrap_or_else(|| "NONE RECORDED".into()),
                    "Durable job",
                ),
            ]);

            // Evaluation/certificate internals are deliberately not copied. Only
            // fixed public references and canonical verdict text are selected.
            let evaluation: Option<Value> = row.try_get("evaluation").map_err(db)?;
            if let Some(evaluation) = evaluation {
                fields.push(field(
                    "Evaluation evidence reference",
                    evaluation,
                    "Durable evaluation reference; not a verifier result",
                ));
            }
            let certificate: Option<Value> = row.try_get("certificate").map_err(db)?;
            if let Some(certificate) = certificate
                && let Some(identity) = certificate
                    .get("certificate_sha256")
                    .and_then(Value::as_str)
            {
                fields.push(field(
                    "Certificate identity",
                    identity,
                    "Durable metadata; verify original bytes",
                ));
            }

            let attempts = attempts_by_job.remove(&id).unwrap_or_default();
            for attempt in attempts {
                fields.push(field(
                    &format!(
                        "Attempt {}",
                        attempt.try_get::<i16, _>("ordinal").map_err(db)?
                    ),
                    format!(
                        "{}; lease until {} UTC Unix seconds; failure {}",
                        attempt.try_get::<String, _>("state").map_err(db)?,
                        attempt.try_get::<i64, _>("lease_until").map_err(db)?,
                        attempt
                            .try_get::<Option<String>, _>("failure")
                            .map_err(db)?
                            .unwrap_or_else(|| "NONE RECORDED".into())
                    ),
                    "Durable attempt; fencing credentials excluded",
                ));
            }

            jobs.push(EntityObservation {
                id,
                kind: "CERTIFICATION".into(),
                state: row.try_get("state").map_err(db)?,
                fields,
            });
        }

        let rows = sqlx::query("SELECT id,pin->>'repository' AS repository,pin->'source' AS source,pin->>'knowledge_mode' AS knowledge_mode,created_at,review_timestamp,invocation IS NOT NULL AS invoked FROM ironcrest_sessions WHERE project=$1 ORDER BY id LIMIT 51 OFFSET $2")
            .bind(project.to_string()).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db)?;
        has_more |= rows.len() > MAX_PAGE_SIZE;
        let mut sessions = Vec::new();
        for row in rows.into_iter().take(MAX_PAGE_SIZE) {
            let source: Value = row.try_get("source").map_err(db)?;
            let mut fields = source_fields(&source, "Frozen review session");
            fields.push(field(
                "Repository",
                row.try_get::<String, _>("repository").map_err(db)?,
                "Frozen review session",
            ));
            fields.push(field(
                "Authority",
                "SUPPLEMENTAL / NON-AUTHORITATIVE",
                "ADR 0050",
            ));
            fields.push(field(
                "Provider invocation",
                if row.try_get::<bool, _>("invoked").map_err(db)? {
                    "CLAIMED; outcome requires retained evidence"
                } else {
                    "NOT INVOKED"
                },
                "Durable invocation claim",
            ));
            sessions.push(EntityObservation {
                id: row.try_get("id").map_err(db)?,
                kind: "SEMANTIC_SESSION".into(),
                state: "INSPECT ACCEPTED GATE / REVIEW EVIDENCE".into(),
                fields,
            });
        }

        let rows = sqlx::query("SELECT invocation,admission->'input'->'certified_source'->>'repository' AS repository,admission->'input'->'certified_source'->'source' AS source,admission->'input'->'recipe_identity' AS recipe,admission->'input'->'environment_identity' AS environment,claim_a IS NOT NULL AS a,claim_b IS NOT NULL AS b FROM release_invocations WHERE project=$1 ORDER BY invocation LIMIT 51 OFFSET $2")
            .bind(project.to_string()).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db)?;
        has_more |= rows.len() > MAX_PAGE_SIZE;
        let mut releases = Vec::new();
        for row in rows.into_iter().take(MAX_PAGE_SIZE) {
            let source: Value = row.try_get("source").map_err(db)?;
            let mut fields = source_fields(&source, "M6 frozen input manifest");
            fields.push(field(
                "Repository",
                row.try_get::<String, _>("repository").map_err(db)?,
                "M6 frozen input manifest",
            ));
            fields.extend([
                field(
                    "Recipe",
                    row.try_get::<Value, _>("recipe").map_err(db)?,
                    "Authority recipe binding",
                ),
                field(
                    "Environment",
                    row.try_get::<Value, _>("environment").map_err(db)?,
                    "Authority environment binding",
                ),
                field(
                    "Runtime qualification",
                    "NOT_PROVEN for this observation host; retained M6 scope is separate",
                    "ADR 0048 exact qualification boundary",
                ),
            ]);
            releases.push(EntityObservation {
                id: row.try_get("invocation").map_err(db)?,
                kind: "RELEASE".into(),
                state: "VERIFY EXACT RELEASE READINESS".into(),
                fields,
            });
        }

        let rows = sqlx::query(
            "SELECT entity,role,reference,state FROM (SELECT a.job AS entity,a.kind AS role,a.reference,a.state FROM artifacts a JOIN certification_jobs j ON j.id=a.job WHERE j.project=$1 UNION ALL SELECT e.session,e.role,e.reference,e.state FROM ironcrest_evidence e JOIN ironcrest_sessions s ON s.id=e.session WHERE s.project=$1 UNION ALL SELECT invocation,role,reference,CASE WHEN available THEN 'AVAILABLE' ELSE 'STAGING' END FROM release_evidence WHERE project=$1) e ORDER BY entity,role LIMIT 51 OFFSET $2",
        ).bind(project.to_string()).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db)?;
        has_more |= rows.len() > MAX_PAGE_SIZE;
        let evidence = rows
            .into_iter()
            .take(MAX_PAGE_SIZE)
            .map(evidence_row)
            .collect::<Result<Vec<_>>>()?;

        let mut timeline = Vec::new();
        for stream in ["CERTIFICATION", "RELEASE"] {
            let query = if stream == "CERTIFICATION" {
                "SELECT a.sequence,a.job AS entity,a.event,a.created_at AS timestamp FROM audit_events a JOIN certification_jobs j ON j.id=a.job WHERE j.project=$1 ORDER BY a.sequence LIMIT 51 OFFSET $2"
            } else {
                "SELECT sequence,invocation AS entity,event,floor(extract(epoch FROM created_at))::bigint AS timestamp FROM release_audit WHERE project=$1 ORDER BY sequence LIMIT 51 OFFSET $2"
            };
            let rows = sqlx::query(query)
                .bind(project.to_string())
                .bind(i64::from(offset))
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?;
            has_more |= rows.len() > MAX_PAGE_SIZE;
            for row in rows.into_iter().take(MAX_PAGE_SIZE) {
                timeline.push(TimelineObservation {
                    stream: stream.into(),
                    sequence: row.try_get("sequence").map_err(db)?,
                    entity: row.try_get("entity").map_err(db)?,
                    event: row.try_get("event").map_err(db)?,
                    timestamp: row.try_get("timestamp").map_err(db)?,
                });
            }
        }

        tx.commit().await.map_err(db)?;
        let mut result = ProjectSnapshot {
            schema: PROJECTION_SCHEMA,
            project: ProjectObservation { project, repository },
            revision: String::new(),
            database_snapshot: snapshot,
            evaluated_at,
            offset,
            page_size: MAX_PAGE_SIZE,
            has_more,
            sources,
            jobs,
            sessions,
            releases,
            evidence,
            timeline,
            limitations: vec![
                "No authoritative current-source pointer exists. These are exact selected records, never a certified branch head.".into(),
                "Collections paginate independently in deterministic identity/stream order; no latest-source inference or global event ordering.".into(),
                "Runtime qualification is not established by a panel host or development fixture.".into(),
                "M9 INCOMPLETE — DEVELOPMENT PREVIEW. Workflow commands are unsupported.".into(),
            ],
        };
        // Operational observation time and MVCC allocation do not change semantic
        // content identity. They remain explicit fields in the returned snapshot.
        let time = result.evaluated_at;
        let database_snapshot = std::mem::take(&mut result.database_snapshot);
        result.evaluated_at = 0;
        result.revision = archcert_domain::source::digest_bytes(
            &serde_json::to_vec(&result).map_err(|_| JobStoreError::Invalid)?,
        )
        .as_str()
        .into();
        result.evaluated_at = time;
        result.database_snapshot = database_snapshot;

        Ok(result)
    }

    /// One fixed invocation and all its reference metadata share the same snapshot.
    pub async fn release(
        &self,
        project: ProjectId,
        invocation: &str,
    ) -> Result<ReleaseObservationRecord> {
        archcert_domain::Sha256Digest::parse(invocation).map_err(|_| JobStoreError::Invalid)?;
        let mut tx = self.begin().await?;
        let admission: Value = sqlx::query_scalar(
            "SELECT admission FROM release_invocations WHERE project=$1 AND invocation=$2",
        )
        .bind(project.to_string())
        .bind(invocation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(JobStoreError::Precondition)?;
        let admission: ReleaseAdmission = decode(admission)?;

        if admission.input.certified_source.project != project
            || admission.input.identity()?.0.as_str() != invocation
        {
            return Err(JobStoreError::Invalid);
        }

        let rows = sqlx::query("SELECT role,reference,available FROM release_evidence WHERE project=$1 AND invocation=$2 ORDER BY role")
            .bind(project.to_string()).bind(invocation).fetch_all(&mut *tx).await.map_err(db)?;
        let mut references = Vec::new();
        for row in rows {
            references.push(ReleaseReference {
                role: state(&row, "role")?,
                artifact: decode(row.try_get("reference").map_err(db)?)?,
                available: row.try_get("available").map_err(db)?,
            });
        }
        let snapshot = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let evaluated_at = now(&mut tx).await?;
        tx.commit().await.map_err(db)?;

        Ok(ReleaseObservationRecord {
            admission,
            references,
            snapshot,
            evaluated_at,
        })
    }

    /// Exact object-level binding lookup; an arbitrary digest cannot authorize a read.
    pub async fn evidence(
        &self,
        project: ProjectId,
        entity: &str,
        digest: &str,
    ) -> Result<EvidenceObservation> {
        if entity.len() > 64 {
            return Err(JobStoreError::Invalid);
        }
        archcert_domain::Sha256Digest::parse(digest).map_err(|_| JobStoreError::Invalid)?;
        let rows = sqlx::query(
            "SELECT entity,role,reference,state FROM (SELECT a.job AS entity,a.kind AS role,a.reference,a.state FROM artifacts a JOIN certification_jobs j ON j.id=a.job WHERE j.project=$1 AND j.id=$2 UNION ALL SELECT e.session,e.role,e.reference,e.state FROM ironcrest_evidence e JOIN ironcrest_sessions s ON s.id=e.session WHERE s.project=$1 AND s.id=$2 UNION ALL SELECT invocation,role,reference,CASE WHEN available THEN 'AVAILABLE' ELSE 'STAGING' END FROM release_evidence WHERE project=$1 AND invocation=$2) e WHERE reference->>'sha256'=$3 LIMIT 1",
        ).bind(project.to_string()).bind(entity).bind(digest).fetch_optional(&self.pool).await.map_err(db)?;

        evidence_row(rows.ok_or(JobStoreError::Precondition)?)
    }
}
