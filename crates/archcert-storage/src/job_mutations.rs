//! Shared locked job mutations. Callers own the surrounding transaction.

use super::{Result, audit, db, json, load, now};
use archcert_application::{
    glassmere::commands::{queued_cancellation_state, require_retry_capacity},
    jobs::{CertificationJob, CreateJob, JobStoreError, RuntimeCleanupState},
};
use archcert_domain::jobs::{AttemptId, AttemptState, JobId, JobState};
use sqlx::PgConnection;

/// Original non-reviewed admission, retaining every source/grant and immutable-input check.
pub(super) async fn create(c: &mut PgConnection, request: &CreateJob) -> Result<CertificationJob> {
    let i = &request.inputs;
    i.validate()?;

    if archcert_application::ironcrest::requires_reviewed_chain(&i.policy.id) {
        return Err(JobStoreError::Precondition);
    }

    // A grant row lock serializes revocation against authorized admission.
    let grant = sqlx::query(
        "SELECT actor FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3 FOR SHARE",
    )
        .bind(i.project.to_string())
        .bind(i.repository.as_str())
        .bind(i.actor.as_str())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?;

    if grant.is_none() {
        return Err(JobStoreError::Unauthorized);
    }

    let source: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accepted_sources WHERE submission=$1 AND project=$2 AND repository=$3 AND source=$4)",
    )
        .bind(i.submission.to_string())
        .bind(i.project.to_string())
        .bind(i.repository.as_str())
        .bind(json(&i.source)?)
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;

    if !source {
        return Err(JobStoreError::Unauthorized);
    }

    let proposed = JobId::new();
    let inserted = sqlx::query(
        "INSERT INTO certification_jobs(id,project,repository,actor,idempotency_key,inputs,state) VALUES ($1,$2,$3,$4,$5,$6,'QUEUED') ON CONFLICT(project,repository,actor,idempotency_key) DO NOTHING",
    )
        .bind(proposed.to_string())
        .bind(i.project.to_string())
        .bind(i.repository.as_str())
        .bind(i.actor.as_str())
        .bind(request.idempotency.as_str())
        .bind(json(i)?)
        .execute(&mut *c)
        .await
        .map_err(db)?
        .rows_affected() == 1;
    let id: String = sqlx::query_scalar(
        "SELECT id FROM certification_jobs WHERE project=$1 AND repository=$2 AND actor=$3 AND idempotency_key=$4",
    )
        .bind(i.project.to_string())
        .bind(i.repository.as_str())
        .bind(i.actor.as_str())
        .bind(request.idempotency.as_str())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let id = JobId::parse(&id)?;

    let job = load(&mut *c, id).await?;

    if job.inputs != *i {
        return Err(JobStoreError::Conflict);
    }

    if inserted {
        audit(&mut *c, id, None, "CertificationRequested").await?;

        audit(&mut *c, id, None, "JobCreated").await?;
    }

    Ok(job)
}

/// Original infrastructure-only recovery; lease expiry never substitutes for cleanup.
pub(super) async fn recover(c: &mut PgConnection, id: JobId, expected: AttemptId) -> Result<()> {
    let job = load(&mut *c, id).await?;

    if job.state != JobState::Running {
        return Err(JobStoreError::Precondition);
    }

    let a = job.attempts.last().ok_or(JobStoreError::Precondition)?;

    if a.id != expected || a.lease_until > now(&mut *c).await? {
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

    let committed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE job=$1 AND attempt=$2 AND kind='EXECUTION' AND state='AVAILABLE')",
    )
        .bind(id.to_string())
        .bind(expected.to_string())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;

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
    sqlx::query(
        "UPDATE certification_attempts SET state='LOST',failure='WORKER_LOSS',ended_at=$2 WHERE id=$1 AND state IN ('LEASED','RUNNING')",
    )
        .bind(a.id.to_string())
        .bind(now(&mut *c).await?)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(
        "UPDATE certification_jobs SET state=$2,failure=CASE WHEN $2='INCONCLUSIVE' THEN 'WORKER_LOSS' ELSE NULL END WHERE id=$1",
    )
        .bind(id.to_string())
        .bind(json(&next)?.as_str().ok_or(JobStoreError::Invalid)?)
        .execute(&mut *c)
        .await
        .map_err(db)?;

    audit(&mut *c, id, Some(a.id), "AttemptRecovered").await?;

    Ok(())
}

/// Eligible queued cancellation under the same row lock as worker claiming.
pub(super) async fn cancel(c: &mut PgConnection, id: JobId) -> Result<()> {
    let job = load(&mut *c, id).await?;
    let next = queued_cancellation_state(&job)?;

    sqlx::query(
        "UPDATE certification_jobs SET state=$2,failure='OPERATOR_CANCELLATION' WHERE id=$1",
    )
    .bind(id.to_string())
    .bind(json(&next)?.as_str().ok_or(JobStoreError::Invalid)?)
    .execute(&mut *c)
    .await
    .map_err(db)?;
    audit(&mut *c, id, None, "JobCanceled").await?;

    Ok(())
}

/// User retry is narrower than controller recovery: exhausted work cannot request a rerun.
pub(super) async fn retry(c: &mut PgConnection, id: JobId, expected: AttemptId) -> Result<()> {
    let job = load(&mut *c, id).await?;
    require_retry_capacity(&job)?;

    recover(c, id, expected).await
}
