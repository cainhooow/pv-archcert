//! PostgreSQL transactional control-plane adapter. No target execution or signing.
pub mod artifacts;
mod ironcrest;
mod runtime;
use archcert_application::jobs::*;
use archcert_domain::{
    ProjectId,
    ingress::GitActorId,
    jobs::*,
    source::{RepositoryId, SourceSnapshot},
};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Row, postgres::PgRow};

type Result<T> = std::result::Result<T, JobStoreError>;
fn db(_: sqlx::Error) -> JobStoreError {
    JobStoreError::Unavailable
}
fn json(value: &impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| JobStoreError::Invalid)
}
fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| JobStoreError::Invalid)
}
fn optional<T: DeserializeOwned>(row: &PgRow, col: &str) -> Result<Option<T>> {
    row.try_get::<Option<Value>, _>(col)
        .map_err(db)?
        .map(decode)
        .transpose()
}
fn state<T: DeserializeOwned>(row: &PgRow, col: &str) -> Result<T> {
    decode(Value::String(row.try_get(col).map_err(db)?))
}
fn valid_lease(seconds: u32) -> Result<()> {
    if !(5..=300).contains(&seconds) {
        Err(JobStoreError::Invalid)
    } else {
        Ok(())
    }
}
async fn now(c: &mut PgConnection) -> Result<i64> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await
        .map_err(db)
}
async fn audit(
    c: &mut PgConnection,
    job: JobId,
    attempt: Option<AttemptId>,
    event: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO audit_events(job,attempt,event) VALUES ($1,$2,$3)")
        .bind(job.to_string())
        .bind(attempt.map(|x| x.to_string()))
        .bind(event)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
async fn load(c: &mut PgConnection, id: JobId) -> Result<CertificationJob> {
    let row = sqlx::query("SELECT * FROM certification_jobs WHERE id=$1 FOR UPDATE")
        .bind(id.to_string())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(JobStoreError::Precondition)?;
    let inputs: JobInputs = decode(row.try_get("inputs").map_err(db)?)?;
    inputs.validate()?;
    let rows = sqlx::query("SELECT a.*,r.binding AS runtime_binding,r.fenced AS runtime_fenced,r.cleanup AS runtime_cleanup FROM certification_attempts a LEFT JOIN attempt_runtime r ON r.attempt=a.id WHERE a.job=$1 ORDER BY a.ordinal")
        .bind(id.to_string())
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut attempts = Vec::new();
    for r in rows {
        attempts.push(CertificationAttempt {
            id: AttemptId::parse(r.try_get::<&str, _>("id").map_err(db)?)?,
            ordinal: u16::try_from(r.try_get::<i16, _>("ordinal").map_err(db)?)
                .map_err(|_| JobStoreError::Invalid)?,
            worker: r.try_get("worker").map_err(db)?,
            state: state(&r, "state")?,
            leased_at: r.try_get("leased_at").map_err(db)?,
            lease_until: r.try_get("lease_until").map_err(db)?,
            ended_at: r.try_get("ended_at").map_err(db)?,
            failure: r
                .try_get::<Option<String>, _>("failure")
                .map_err(db)?
                .map(|v| decode(Value::String(v)))
                .transpose()?,
            evidence: optional(&r, "evidence")?,
            runtime: optional::<RuntimeBinding>(&r, "runtime_binding")?
                .map(|binding| -> Result<AttemptRuntime> {
                    Ok(AttemptRuntime {
                        binding,
                        fenced: r.try_get("runtime_fenced").map_err(db)?,
                        cleanup: state(&r, "runtime_cleanup")?,
                    })
                })
                .transpose()?,
        });
    }
    Ok(CertificationJob {
        id,
        inputs,
        created_at: row.try_get("created_at").map_err(db)?,
        evaluation_at: row.try_get("evaluation_at").map_err(db)?,
        failure: row
            .try_get::<Option<String>, _>("failure")
            .map_err(db)?
            .map(|v| decode(Value::String(v)))
            .transpose()?,
        state: state(&row, "state")?,
        attempts,
        evaluation: optional(&row, "evaluation")?,
        issuance: optional(&row, "issuance")?,
        certificate: optional(&row, "certificate")?,
    })
}
async fn fenced(c: &mut PgConnection, lease: &Lease) -> Result<CertificationJob> {
    let job = load(c, lease.job).await?;
    if job.state != JobState::Running {
        return Err(JobStoreError::Precondition);
    }
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM certification_attempts a WHERE id=$1 AND job=$2 AND worker=$3 AND token=$4 AND state IN ('LEASED','RUNNING') AND lease_until > floor(extract(epoch FROM clock_timestamp())) AND NOT EXISTS(SELECT 1 FROM attempt_runtime r WHERE r.attempt=a.id AND r.fenced))")
        .bind(lease.attempt.to_string()).bind(lease.job.to_string()).bind(&lease.worker).bind(lease.token.to_string()).fetch_one(c).await.map_err(db)?;
    if !valid {
        return Err(JobStoreError::Precondition);
    }
    Ok(job)
}
async fn available(
    c: &mut PgConnection,
    id: JobId,
    attempt: &str,
    kind: &str,
    reference: &ArtifactReference,
) -> Result<()> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE job=$1 AND attempt=$2 AND kind=$3 AND reference=$4 AND state='AVAILABLE')").bind(id.to_string()).bind(attempt).bind(kind).bind(json(reference)?).fetch_one(c).await.map_err(db)?;
    if valid {
        Ok(())
    } else {
        Err(JobStoreError::Precondition)
    }
}

/// Cloneable database pool; contains no signing or execution capability.
#[derive(Clone)]
pub struct PostgresJobRepository {
    pool: PgPool,
}
impl PostgresJobRepository {
    /// Read-only readiness: required reviewed migrations must already be applied.
    pub async fn check_readiness(&self) -> Result<()> {
        let ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=3 AND success)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        if !ready {
            return Err(JobStoreError::Unavailable);
        }
        Ok(())
    }
    /// Connects with bounded pool/acquisition. Never creates or migrates tables.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(url)
            .await
            .map_err(db)?;
        Ok(Self { pool })
    }
    /// Wraps an already configured authority pool, useful for isolated integration schemas.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
    /// Applies reviewed migrations explicitly with separately provisioned migration authority.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate::Migrator::new(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations"
        )))
        .await
        .map_err(|_| JobStoreError::Unavailable)?
        .run(&self.pool)
        .await
        .map_err(|_| JobStoreError::Unavailable)
    }
    /// Authority provisioning, not a target/worker operation.
    pub async fn grant(
        &self,
        project: ProjectId,
        repository: &RepositoryId,
        actor: &GitActorId,
    ) -> Result<()> {
        sqlx::query("INSERT INTO repository_grants VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(project.to_string())
            .bind(repository.as_str())
            .bind(actor.as_str())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }
    /// Registers only an independently verified complete Northgate snapshot.
    pub async fn register_source(
        &self,
        submission: &archcert_domain::ingress::SourceSubmissionId,
        source: &SourceSnapshot,
    ) -> Result<()> {
        source
            .verify(&source.identity().snapshot_sha256)
            .map_err(|_| JobStoreError::Invalid)?;
        source
            .require_complete()
            .map_err(|_| JobStoreError::Invalid)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("INSERT INTO accepted_sources VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(submission.to_string())
            .bind(source.project().to_string())
            .bind(source.repository().as_str())
            .bind(json(source.identity())?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let r = sqlx::query("SELECT * FROM accepted_sources WHERE submission=$1")
            .bind(submission.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if r.try_get::<String, _>("project").map_err(db)? != source.project().to_string()
            || r.try_get::<String, _>("repository").map_err(db)? != source.repository().as_str()
            || r.try_get::<Value, _>("source").map_err(db)? != json(source.identity())?
        {
            return Err(JobStoreError::Conflict);
        }
        tx.commit().await.map_err(db)
    }
    /// Authorizes a scope without leaking source/job existence.
    pub async fn authorized(
        &self,
        project: ProjectId,
        repository: &RepositoryId,
        actor: &GitActorId,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3)").bind(project.to_string()).bind(repository.as_str()).bind(actor.as_str()).fetch_one(&self.pool).await.map_err(db)
    }
    /// Registers immutable staging metadata. A conflicting retry cannot overwrite it.
    pub async fn stage_artifact(
        &self,
        id: JobId,
        attempt: Option<AttemptId>,
        kind: &str,
        reference: &ArtifactReference,
    ) -> Result<()> {
        if reference.size == 0
            || reference.size > 64 * 1024 * 1024
            || reference.schema != 1
            || reference.producer.is_empty()
            || reference.producer.len() > 128
        {
            return Err(JobStoreError::Invalid);
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        if job.state.terminal() {
            return Err(JobStoreError::Precondition);
        }
        if let Some(a) = attempt
            && !job.attempts.iter().any(|v| v.id == a)
        {
            return Err(JobStoreError::Precondition);
        }
        let a = attempt.map(|x| x.to_string()).unwrap_or_default();
        sqlx::query("INSERT INTO artifacts(job,attempt,kind,reference,state) VALUES ($1,$2,$3,$4,'STAGING') ON CONFLICT DO NOTHING").bind(id.to_string()).bind(&a).bind(kind).bind(json(reference)?).execute(&mut *tx).await.map_err(db)?;
        let r: Value = sqlx::query_scalar(
            "SELECT reference FROM artifacts WHERE job=$1 AND attempt=$2 AND kind=$3",
        )
        .bind(id.to_string())
        .bind(a)
        .bind(kind)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if r != json(reference)? {
            return Err(JobStoreError::Conflict);
        }
        tx.commit().await.map_err(db)
    }
    /// Called only after independent object read/rehash/size verification.
    pub async fn artifact_available(
        &self,
        id: JobId,
        attempt: Option<AttemptId>,
        kind: &str,
        reference: &ArtifactReference,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        load(&mut tx, id).await?;
        let a = attempt.map(|x| x.to_string()).unwrap_or_default();
        sqlx::query("UPDATE artifacts SET state='AVAILABLE' WHERE job=$1 AND attempt=$2 AND kind=$3 AND reference=$4 AND state='STAGING'").bind(id.to_string()).bind(&a).bind(kind).bind(json(reference)?).execute(&mut *tx).await.map_err(db)?;
        available(&mut tx, id, &a, kind, reference).await?;
        tx.commit().await.map_err(db)
    }
    /// Appends a classified continuation failure while preserving recoverable issuance state.
    pub async fn note_failure(&self, id: JobId, category: FailureCategory) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        if !matches!(job.state, JobState::Evaluating | JobState::Signing) {
            return Err(JobStoreError::Precondition);
        }
        let event = match category {
            FailureCategory::SigningFailure => "SigningFailed",
            FailureCategory::VerificationFailure => "CertificateVerificationFailed",
            FailureCategory::PersistenceFailure => "PersistenceFailed",
            _ => return Err(JobStoreError::Invalid),
        };
        sqlx::query("UPDATE certification_jobs SET failure=$2 WHERE id=$1")
            .bind(id.to_string())
            .bind(json(&category)?.as_str().ok_or(JobStoreError::Invalid)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(&mut tx, id, None, event).await?;
        tx.commit().await.map_err(db)
    }
    /// Lists controller continuation work; claims remain transactionally checked.
    pub async fn continuations(&self) -> Result<Vec<JobId>> {
        let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM certification_jobs WHERE state IN ('EVALUATING','SIGNING') ORDER BY created_at,id LIMIT 100").fetch_all(&self.pool).await.map_err(db)?;
        ids.iter()
            .map(|x| JobId::parse(x).map_err(Into::into))
            .collect()
    }
    /// Lists expired execution jobs. Cleanup and recover perform separate conservative checks.
    pub async fn expired(&self) -> Result<Vec<JobId>> {
        let ids:Vec<String>=sqlx::query_scalar("SELECT job FROM certification_attempts WHERE state IN ('LEASED','RUNNING') AND lease_until <= floor(extract(epoch FROM clock_timestamp())) ORDER BY job LIMIT 100").fetch_all(&self.pool).await.map_err(db)?;
        ids.iter()
            .map(|x| JobId::parse(x).map_err(Into::into))
            .collect()
    }
}
#[async_trait]
impl JobRepository for PostgresJobRepository {
    async fn create(&self, request: CreateJob) -> Result<CertificationJob> {
        let i = &request.inputs;
        i.validate()?;
        if archcert_application::ironcrest::requires_reviewed_chain(&i.policy.id) {
            return Err(JobStoreError::Precondition);
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        // A grant row lock serializes revocation against authorized admission.
        let grant=sqlx::query("SELECT actor FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3 FOR SHARE").bind(i.project.to_string()).bind(i.repository.as_str()).bind(i.actor.as_str()).fetch_optional(&mut *tx).await.map_err(db)?;
        if grant.is_none() {
            return Err(JobStoreError::Unauthorized);
        }
        let source:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accepted_sources WHERE submission=$1 AND project=$2 AND repository=$3 AND source=$4)").bind(i.submission.to_string()).bind(i.project.to_string()).bind(i.repository.as_str()).bind(json(&i.source)?).fetch_one(&mut *tx).await.map_err(db)?;
        if !source {
            return Err(JobStoreError::Unauthorized);
        }
        let proposed = JobId::new();
        let inserted=sqlx::query("INSERT INTO certification_jobs(id,project,repository,actor,idempotency_key,inputs,state) VALUES ($1,$2,$3,$4,$5,$6,'QUEUED') ON CONFLICT(project,repository,actor,idempotency_key) DO NOTHING").bind(proposed.to_string()).bind(i.project.to_string()).bind(i.repository.as_str()).bind(i.actor.as_str()).bind(request.idempotency.as_str()).bind(json(i)?).execute(&mut *tx).await.map_err(db)?.rows_affected()==1;
        let id:String=sqlx::query_scalar("SELECT id FROM certification_jobs WHERE project=$1 AND repository=$2 AND actor=$3 AND idempotency_key=$4").bind(i.project.to_string()).bind(i.repository.as_str()).bind(i.actor.as_str()).bind(request.idempotency.as_str()).fetch_one(&mut *tx).await.map_err(db)?;
        let id = JobId::parse(&id)?;
        let job = load(&mut tx, id).await?;
        if job.inputs != *i {
            return Err(JobStoreError::Conflict);
        }
        if inserted {
            audit(&mut tx, id, None, "CertificationRequested").await?;
            audit(&mut tx, id, None, "JobCreated").await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(job)
    }
    async fn get(&self, id: JobId) -> Result<CertificationJob> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(job)
    }
    async fn claim(&self, worker: &str, seconds: u32) -> Result<Option<Assignment>> {
        valid_lease(seconds)?;
        if worker.is_empty()
            || worker.len() > 128
            || !worker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(JobStoreError::Invalid);
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let id:Option<String>=sqlx::query_scalar("SELECT id FROM certification_jobs WHERE state='QUEUED' ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(id) = id else { return Ok(None) };
        let id = JobId::parse(&id)?;
        let job = load(&mut tx, id).await?;
        if job.attempts.len() >= usize::from(job.inputs.maximum_attempts) {
            return Err(JobStoreError::Precondition);
        }
        job.state.transition(JobState::Running)?;
        let lease = Lease {
            job: id,
            attempt: AttemptId::new(),
            worker: worker.into(),
            token: LeaseToken::new(),
        };
        let time = now(&mut tx).await?;
        sqlx::query("INSERT INTO certification_attempts(id,job,ordinal,worker,token,state,leased_at,lease_until) VALUES ($1,$2,$3,$4,$5,'LEASED',$6,$7)").bind(lease.attempt.to_string()).bind(id.to_string()).bind(i16::try_from(job.attempts.len()+1).map_err(|_|JobStoreError::Invalid)?).bind(worker).bind(lease.token.to_string()).bind(time).bind(time+i64::from(seconds)).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE certification_jobs SET state='RUNNING' WHERE id=$1")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(&mut tx, id, Some(lease.attempt), "JobLeased").await?;
        let job = load(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(Some(Assignment { job, lease }))
    }
    async fn start(&self, lease: &Lease) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        fenced(&mut tx, lease).await?;
        let r = sqlx::query(
            "UPDATE certification_attempts SET state='RUNNING' WHERE id=$1 AND state='LEASED'",
        )
        .bind(lease.attempt.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Err(JobStoreError::Precondition);
        }
        audit(&mut tx, lease.job, Some(lease.attempt), "AttemptStarted").await?;
        tx.commit().await.map_err(db)
    }
    async fn renew(&self, lease: &Lease, seconds: u32) -> Result<()> {
        valid_lease(seconds)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        fenced(&mut tx, lease).await?;
        let time = now(&mut tx).await?;
        let r=sqlx::query("UPDATE certification_attempts SET lease_until=GREATEST(lease_until,$2) WHERE id=$1 AND $2 <= leased_at+3600").bind(lease.attempt.to_string()).bind(time+i64::from(seconds)).execute(&mut *tx).await.map_err(db)?;
        if r.rows_affected() != 1 {
            return Err(JobStoreError::Precondition);
        }
        tx.commit().await.map_err(db)
    }
    async fn recover(&self, id: JobId, expected: AttemptId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        if job.state != JobState::Running {
            return Err(JobStoreError::Precondition);
        }
        let a = job.attempts.last().ok_or(JobStoreError::Precondition)?;
        if a.id != expected || a.lease_until > now(&mut tx).await? {
            return Err(JobStoreError::Precondition);
        }
        // A caller assertion cannot substitute for durable exact-attempt cleanup.
        if a.state == AttemptState::Running
            && a.runtime
                .as_ref()
                .is_none_or(|r| !r.fenced || r.cleanup != RuntimeCleanupState::Succeeded)
        {
            return Err(JobStoreError::Precondition);
        }
        let committed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifacts WHERE job=$1 AND attempt=$2 AND kind='EXECUTION' AND state='AVAILABLE')")
            .bind(id.to_string()).bind(expected.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if committed {
            // Committed evidence must be validated/adopted, never discarded for a rerun.
            return Err(JobStoreError::Precondition);
        }
        let next = if job.attempts.len() < usize::from(job.inputs.maximum_attempts) {
            JobState::Queued
        } else {
            JobState::Inconclusive
        };
        job.state.transition(next)?;
        sqlx::query("UPDATE certification_attempts SET state='LOST',failure='WORKER_LOSS',ended_at=$2 WHERE id=$1 AND state IN ('LEASED','RUNNING')").bind(a.id.to_string()).bind(now(&mut tx).await?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE certification_jobs SET state=$2,failure=CASE WHEN $2='INCONCLUSIVE' THEN 'WORKER_LOSS' ELSE NULL END WHERE id=$1")
            .bind(id.to_string())
            .bind(json(&next)?.as_str().ok_or(JobStoreError::Invalid)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(&mut tx, id, Some(a.id), "AttemptRecovered").await?;
        tx.commit().await.map_err(db)
    }
    async fn accept_evidence(&self, lease: &Lease, reference: &ArtifactReference) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = fenced(&mut tx, lease).await?;
        if job
            .attempts
            .last()
            .is_none_or(|a| a.id != lease.attempt || a.state != AttemptState::Running)
        {
            return Err(JobStoreError::Precondition);
        }
        available(
            &mut tx,
            lease.job,
            &lease.attempt.to_string(),
            "EXECUTION",
            reference,
        )
        .await?;
        job.state.transition(JobState::Evaluating)?;
        sqlx::query("UPDATE attempt_runtime SET fenced=true WHERE job=$1 AND attempt=$2")
            .bind(lease.job.to_string())
            .bind(lease.attempt.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE certification_attempts SET state='EVIDENCE_READY',evidence=$2,ended_at=$3 WHERE id=$1").bind(lease.attempt.to_string()).bind(json(reference)?).bind(now(&mut tx).await?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE certification_jobs SET state='EVALUATING',evaluation_at=floor(extract(epoch FROM clock_timestamp())) WHERE id=$1")
            .bind(lease.job.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(
            &mut tx,
            lease.job,
            Some(lease.attempt),
            "ExecutionEvidenceAccepted",
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    async fn record_evaluation(
        &self,
        id: JobId,
        reference: &ArtifactReference,
        decision: EvaluationDecision,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        if job.evaluation.as_ref() == Some(reference) {
            let eligible: Option<bool> =
                sqlx::query_scalar("SELECT eligible FROM certification_jobs WHERE id=$1")
                    .bind(id.to_string())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?;
            if eligible != Some(decision == EvaluationDecision::Eligible)
                || (decision == EvaluationDecision::Inconclusive)
                    != (job.state == JobState::Inconclusive)
            {
                return Err(JobStoreError::Conflict);
            }
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        if job.state != JobState::Evaluating || job.evaluation.is_some() {
            return Err(JobStoreError::Precondition);
        }
        available(&mut tx, id, "", "EVALUATION", reference).await?;
        let next = match decision {
            EvaluationDecision::Eligible => "EVALUATING",
            EvaluationDecision::NotEligible => "NOT_ELIGIBLE",
            EvaluationDecision::Inconclusive => "INCONCLUSIVE",
        };
        let failure = match decision {
            EvaluationDecision::Eligible => None,
            EvaluationDecision::NotEligible => Some("POLICY_FAILURE"),
            EvaluationDecision::Inconclusive => Some("INFRASTRUCTURE_FAILURE"),
        };
        sqlx::query("UPDATE certification_jobs SET evaluation=$2,eligible=$3,state=$4,failure=$5 WHERE id=$1").bind(id.to_string()).bind(json(reference)?).bind(decision==EvaluationDecision::Eligible).bind(next).bind(failure).execute(&mut *tx).await.map_err(db)?;
        audit(&mut tx, id, None, "EvaluationCompleted").await?;
        tx.commit().await.map_err(db)
    }
    async fn prepare_issuance(
        &self,
        id: JobId,
        issuance: &PreparedIssuance,
    ) -> Result<PreparedIssuance> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        ironcrest::require_reviewed_issuance(&mut tx, &job).await?;
        if let Some(old) = job.issuance {
            if &old != issuance {
                return Err(JobStoreError::Conflict);
            }
            return Ok(old);
        }
        if job.state != JobState::Evaluating
            || job.evaluation.is_none()
            || issuance.issued_at == 0
            || issuance.signing_key_id.len() != 64
        {
            return Err(JobStoreError::Precondition);
        }
        job.state.transition(JobState::Signing)?;
        sqlx::query("UPDATE certification_jobs SET issuance=$2,state='SIGNING' WHERE id=$1 AND eligible IS TRUE").bind(id.to_string()).bind(json(issuance)?).execute(&mut *tx).await.map_err(db)?;
        audit(&mut tx, id, None, "SigningStarted").await?;
        tx.commit().await.map_err(db)?;
        Ok(issuance.clone())
    }
    async fn complete(&self, id: JobId, certificate: &PersistedCertificate) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = load(&mut tx, id).await?;
        ironcrest::require_reviewed_issuance(&mut tx, &job).await?;
        if job.certificate.as_ref() == Some(certificate) {
            return Ok(());
        }
        if job.state != JobState::Signing
            || job.issuance.as_ref() != Some(&certificate.issuance)
            || !certificate.verified
            || certificate.signature.len() != 128
            || !certificate.signature.bytes().all(|x| x.is_ascii_hexdigit())
        {
            return Err(JobStoreError::Precondition);
        }
        available(&mut tx, id, "", "CERTIFICATE", &certificate.artifact).await?;
        job.state.transition(JobState::Completed)?;
        sqlx::query("UPDATE certification_jobs SET certificate=$2,state='COMPLETED',failure=NULL WHERE id=$1")
            .bind(id.to_string())
            .bind(json(certificate)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let a = job.attempts.last().ok_or(JobStoreError::Precondition)?;
        sqlx::query("UPDATE certification_attempts SET state='COMPLETED' WHERE id=$1 AND state='EVIDENCE_READY'").bind(a.id.to_string()).execute(&mut *tx).await.map_err(db)?;
        audit(&mut tx, id, Some(a.id), "CertificateIssued").await?;
        tx.commit().await.map_err(db)
    }
}
