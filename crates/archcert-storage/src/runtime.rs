//! Exact-attempt runtime fencing and cleanup metadata. Workers have no DB access.
use super::*;
impl PostgresJobRepository {
    /// Binds runtime authority under the current lease before any worker dispatch.
    pub async fn bind_runtime(&self, lease: &Lease, binding: &RuntimeBinding) -> Result<()> {
        binding.validate()?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let job = fenced(&mut tx, lease).await?;
        if job
            .attempts
            .last()
            .is_none_or(|a| a.id != lease.attempt || a.state != AttemptState::Running)
        {
            return Err(JobStoreError::Precondition);
        }
        sqlx::query("INSERT INTO attempt_runtime(attempt,job,binding) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(lease.attempt.to_string()).bind(lease.job.to_string()).bind(json(binding)?)
            .execute(&mut *tx).await.map_err(db)?;
        let bound: Value = sqlx::query_scalar(
            "SELECT binding FROM attempt_runtime WHERE attempt=$1 AND NOT fenced",
        )
        .bind(lease.attempt.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if bound != json(binding)? {
            return Err(JobStoreError::Precondition);
        }
        audit(&mut tx, lease.job, Some(lease.attempt), "RuntimeBound").await?;
        tx.commit().await.map_err(db)
    }
    /// Uses database time to establish irreversible expiry or closed attempt authority.
    /// Read before acquiring/revoking the local gate; recheck again before mutation.
    pub async fn cleanup_candidate(
        &self,
        job: JobId,
        attempt: AttemptId,
    ) -> Result<AttemptRuntime> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let view = load(&mut tx, job).await?;
        let a = view
            .attempts
            .iter()
            .find(|a| a.id == attempt)
            .ok_or(JobStoreError::Precondition)?;
        if matches!(a.state, AttemptState::Leased | AttemptState::Running)
            && a.lease_until > now(&mut tx).await?
        {
            return Err(JobStoreError::Precondition);
        }
        let runtime = a.runtime.clone().ok_or(JobStoreError::Precondition)?;
        tx.commit().await.map_err(db)?;
        Ok(runtime)
    }
    /// Records revocation only after the exclusive local gate was durably revoked.
    /// The trusted reconciler must retain that gate through runtime cleanup.
    pub async fn fence_runtime(
        &self,
        job: JobId,
        attempt: AttemptId,
        binding: &RuntimeBinding,
    ) -> Result<()> {
        self.change_cleanup(job, attempt, binding, RuntimeCleanupState::InProgress, true)
            .await
    }
    /// Reports inability to acquire a live execution gate without fabricating revocation.
    pub async fn block_cleanup(
        &self,
        job: JobId,
        attempt: AttemptId,
        binding: &RuntimeBinding,
    ) -> Result<()> {
        self.change_cleanup(job, attempt, binding, RuntimeCleanupState::Blocked, false)
            .await
    }
    /// Persists a bounded operational result. Success requires prior durable revocation.
    pub async fn finish_cleanup(
        &self,
        job: JobId,
        attempt: AttemptId,
        binding: &RuntimeBinding,
        outcome: RuntimeCleanupState,
    ) -> Result<()> {
        if !matches!(
            outcome,
            RuntimeCleanupState::Succeeded
                | RuntimeCleanupState::Failed
                | RuntimeCleanupState::Blocked
        ) {
            return Err(JobStoreError::Invalid);
        }
        self.change_cleanup(job, attempt, binding, outcome, false)
            .await
    }
    async fn change_cleanup(
        &self,
        job: JobId,
        attempt: AttemptId,
        binding: &RuntimeBinding,
        outcome: RuntimeCleanupState,
        revoke: bool,
    ) -> Result<()> {
        binding.validate()?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let view = load(&mut tx, job).await?;
        let a = view
            .attempts
            .iter()
            .find(|a| a.id == attempt)
            .ok_or(JobStoreError::Precondition)?;
        let r = a.runtime.as_ref().ok_or(JobStoreError::Precondition)?;
        if r.binding != *binding
            || (matches!(a.state, AttemptState::Leased | AttemptState::Running)
                && a.lease_until > now(&mut tx).await?)
            || (outcome == RuntimeCleanupState::Succeeded && !(r.fenced || revoke))
        {
            return Err(JobStoreError::Precondition);
        }
        if r.cleanup == RuntimeCleanupState::Succeeded {
            if outcome == RuntimeCleanupState::Succeeded {
                return Ok(());
            }
            return Err(JobStoreError::Precondition);
        }
        sqlx::query(
            "UPDATE attempt_runtime SET fenced=fenced OR $3,cleanup=$4 WHERE job=$1 AND attempt=$2",
        )
        .bind(job.to_string())
        .bind(attempt.to_string())
        .bind(revoke)
        .bind(json(&outcome)?.as_str().ok_or(JobStoreError::Invalid)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if revoke {
            audit(&mut tx, job, Some(attempt), "ExecutionFenced").await?;
        }
        let event = match outcome {
            RuntimeCleanupState::InProgress => "CleanupStarted",
            RuntimeCleanupState::Succeeded => "CleanupSucceeded",
            RuntimeCleanupState::Failed => "CleanupFailed",
            RuntimeCleanupState::Blocked => "CleanupBlocked",
            _ => return Err(JobStoreError::Invalid),
        };
        audit(&mut tx, job, Some(attempt), event).await?;
        tx.commit().await.map_err(db)
    }
}
