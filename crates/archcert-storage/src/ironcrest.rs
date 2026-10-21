//! Row-locked immutable review journal, separate from execution leases and jobs.

use super::*;
use archcert_application::{ironcrest::*, semantic::ReviewBinding};

fn valid_reference(reference: &ArtifactReference) -> Result<()> {
    if ![1, 2].contains(&reference.schema)
        || reference.size == 0
        || reference.size > 32 * 1024 * 1024
        || reference.producer != "archcert-ironcrest-v1/0.1.0"
    {
        return Err(JobStoreError::Invalid);
    }

    Ok(())
}

async fn load_session(
    c: &mut PgConnection,
    project: ProjectId,
    id: JobId,
) -> Result<IroncrestSession> {
    let row = sqlx::query("SELECT * FROM ironcrest_sessions WHERE id=$1 AND project=$2 FOR UPDATE")
        .bind(id.to_string())
        .bind(project.to_string())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(JobStoreError::Precondition)?;
    let pin: IroncrestSessionPin = decode(row.try_get("pin").map_err(db)?)?;
    pin.validate()?;
    let rows = sqlx::query("SELECT * FROM ironcrest_evidence WHERE session=$1 ORDER BY role")
        .bind(id.to_string())
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut evidence = Vec::new();

    for row in rows {
        evidence.push(IroncrestEvidenceReference {
            role: state(&row, "role")?,
            artifact: decode(row.try_get("reference").map_err(db)?)?,
            available: row.try_get::<&str, _>("state").map_err(db)? == "AVAILABLE",
        });
    }

    Ok(IroncrestSession {
        id,
        pin,
        created_at: u64::try_from(row.try_get::<i64, _>("created_at").map_err(db)?)
            .map_err(|_| JobStoreError::Invalid)?,
        review_claimed: row
            .try_get::<Option<String>, _>("invocation")
            .map_err(db)?
            .is_some(),
        review_timestamp: row
            .try_get::<Option<i64>, _>("review_timestamp")
            .map_err(db)?
            .map(|n| u64::try_from(n).map_err(|_| JobStoreError::Invalid))
            .transpose()?,
        evidence,
    })
}

async fn source_exists(
    c: &mut PgConnection,
    pin: &IroncrestSessionPin,
    submission: &archcert_domain::ingress::SourceSubmissionId,
    source: &archcert_domain::SourceIdentity,
) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM accepted_sources WHERE submission=$1 AND project=$2 AND repository=$3 AND source=$4)",
    )
        .bind(submission.to_string())
        .bind(pin.project.to_string())
        .bind(pin.repository.as_str())
        .bind(json(source)?)
        .fetch_one(c)
        .await
        .map_err(db)?;

    if !valid {
        return Err(JobStoreError::Unauthorized);
    }

    Ok(())
}

fn available_role(
    session: &IroncrestSession,
    role: IroncrestEvidenceRole,
) -> Result<&ArtifactReference> {
    session
        .evidence
        .iter()
        .find(|e| e.role == role && e.available)
        .map(|e| &e.artifact)
        .ok_or(JobStoreError::Precondition)
}

impl PostgresJobRepository {
    /// Separate readiness for the optional Ironcrest journal; historical readiness
    /// continues to require the historical migration only.
    pub async fn check_ironcrest_readiness(&self) -> Result<()> {
        let ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=4 AND success)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;

        if !ready {
            return Err(JobStoreError::Unavailable);
        }

        Ok(())
    }
}

#[async_trait]
impl IroncrestRepository for PostgresJobRepository {
    async fn admit_reviewed(
        &self,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<CertificationJob> {
        let id = admission.id();
        let i = admission.inputs();
        i.validate()?;

        let mut tx = self.pool.begin().await.map_err(db)?;

        let session = load_session(&mut tx, i.project, id).await?;

        if session.pin != *admission.pin() || !session.review_claimed {
            return Err(JobStoreError::Precondition);
        }

        // Serialize revocation against admission under the same grant-row lock
        // used by historical Ravenport. Recheck accepted target and baseline.
        let allowed = sqlx::query(
            "SELECT actor FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3 FOR SHARE",
        )
            .bind(i.project.to_string())
            .bind(i.repository.as_str())
            .bind(i.actor.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;

        if allowed.is_none() {
            return Err(JobStoreError::Unauthorized);
        }

        source_exists(
            &mut tx,
            &session.pin,
            &session.pin.submission,
            &session.pin.source,
        )
        .await?;

        if let Some(base) = &session.pin.baseline {
            source_exists(&mut tx, &session.pin, &base.submission, &base.source).await?;
        }

        for (role, reference) in admission.evidence() {
            if available_role(&session, *role)? != reference {
                return Err(JobStoreError::Precondition);
            }
        }

        let stored: Option<Value> =
            sqlx::query_scalar("SELECT binding FROM ironcrest_admissions WHERE session=$1")
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;

        if let Some(stored) = stored {
            if stored != json(admission)? {
                return Err(JobStoreError::Conflict);
            }

            let job = load(&mut tx, id).await?;

            if job.inputs != *i {
                return Err(JobStoreError::Conflict);
            }

            tx.commit().await.map_err(db)?;
            return Ok(job);
        }

        let occupied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM certification_jobs WHERE id=$1)")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;

        if occupied {
            return Err(JobStoreError::Conflict);
        }

        // The reserved identity is also the internal scoped idempotency key.
        // Job creation and complete immutable linkage commit in one transaction.
        sqlx::query(
            "INSERT INTO certification_jobs(id,project,repository,actor,idempotency_key,inputs,state) VALUES ($1,$2,$3,$4,$1,$5,'QUEUED')",
        )
            .bind(id.to_string())
            .bind(i.project.to_string())
            .bind(i.repository.as_str())
            .bind(i.actor.as_str())
            .bind(json(i)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("INSERT INTO ironcrest_admissions(session,job,binding) VALUES ($1,$1,$2)")
            .bind(id.to_string())
            .bind(json(admission)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        audit(&mut tx, id, None, "IroncrestReviewedAdmission").await?;

        audit(&mut tx, id, None, "JobCreated").await?;

        let job = load(&mut tx, id).await?;

        tx.commit().await.map_err(db)?;

        Ok(job)
    }

    async fn admitted_review(
        &self,
        admission: &ReviewedIroncrestAdmission,
    ) -> Result<CertificationJob> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let stored: Option<Value> = sqlx::query_scalar(
            "SELECT binding FROM ironcrest_admissions WHERE session=$1 AND job=$1",
        )
        .bind(admission.id().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;

        if stored.as_ref() != Some(&json(admission)?) {
            return Err(JobStoreError::Precondition);
        }

        let job = load(&mut tx, admission.id()).await?;

        if job.inputs != *admission.inputs() {
            return Err(JobStoreError::Precondition);
        }

        tx.commit().await.map_err(db)?;

        Ok(job)
    }

    async fn open_session(&self, id: JobId, pin: &IroncrestSessionPin) -> Result<IroncrestSession> {
        pin.validate()?;

        let mut tx = self.pool.begin().await.map_err(db)?;
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3)",
        )
            .bind(pin.project.to_string())
            .bind(pin.repository.as_str())
            .bind(pin.actor.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;

        if !allowed {
            return Err(JobStoreError::Unauthorized);
        }

        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM certification_jobs WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM ironcrest_sessions WHERE id=$1)",
        )
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;

        if occupied {
            return Err(JobStoreError::Precondition);
        }

        source_exists(&mut tx, pin, &pin.submission, &pin.source).await?;

        if let Some(base) = &pin.baseline {
            source_exists(&mut tx, pin, &base.submission, &base.source).await?;
        }

        sqlx::query(
            "INSERT INTO ironcrest_sessions(id,project,pin) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
            .bind(id.to_string())
            .bind(pin.project.to_string())
            .bind(json(pin)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        let session = load_session(&mut tx, pin.project, id).await?;

        if session.pin != *pin {
            return Err(JobStoreError::Conflict);
        }

        tx.commit().await.map_err(db)?;

        Ok(session)
    }

    async fn review_session(&self, project: ProjectId, id: JobId) -> Result<IroncrestSession> {
        let mut tx = self.pool.begin().await.map_err(db)?;

        let session = load_session(&mut tx, project, id).await?;

        tx.commit().await.map_err(db)?;

        Ok(session)
    }

    async fn stage_review_evidence(
        &self,
        project: ProjectId,
        id: JobId,
        role: IroncrestEvidenceRole,
        reference: &ArtifactReference,
        invocation: Option<&ReviewInvocation>,
    ) -> Result<()> {
        valid_reference(reference)?;

        let mut tx = self.pool.begin().await.map_err(db)?;

        let session = load_session(&mut tx, project, id).await?;

        match role {
            IroncrestEvidenceRole::AuthorityProfile => {
                if reference.sha256 != session.pin.authority_profile_sha256 {
                    return Err(JobStoreError::Precondition);
                }
            }
            IroncrestEvidenceRole::Knowledge => {
                available_role(&session, IroncrestEvidenceRole::AuthorityProfile)?;
            }
            IroncrestEvidenceRole::Impact => {
                available_role(&session, IroncrestEvidenceRole::Knowledge)?;
            }
            IroncrestEvidenceRole::Request => {
                available_role(&session, IroncrestEvidenceRole::Knowledge)?;
                available_role(&session, IroncrestEvidenceRole::Impact)?;
            }
            IroncrestEvidenceRole::Review => {
                let invocation = invocation.ok_or(JobStoreError::Precondition)?;
                let matches: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM ironcrest_sessions WHERE id=$1 AND invocation=$2 AND review_timestamp=$3)",
                )
                    .bind(id.to_string())
                    .bind(invocation.token.to_string())
                    .bind(i64::try_from(invocation.timestamp).map_err(|_| JobStoreError::Invalid)?)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?;

                if !matches {
                    return Err(JobStoreError::Precondition);
                }
            }
            IroncrestEvidenceRole::Gate => {
                available_role(&session, IroncrestEvidenceRole::Review)?;
            }
            IroncrestEvidenceRole::ChallengePlan => {
                available_role(&session, IroncrestEvidenceRole::Gate)?;
            }
            IroncrestEvidenceRole::ChallengeResult => {
                available_role(&session, IroncrestEvidenceRole::ChallengePlan)?;
            }
        }

        sqlx::query(
            "INSERT INTO ironcrest_evidence(session,role,reference,state) VALUES ($1,$2,$3,'STAGING') ON CONFLICT DO NOTHING",
        )
            .bind(id.to_string())
            .bind(role.as_str())
            .bind(json(reference)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let stored: Value = sqlx::query_scalar(
            "SELECT reference FROM ironcrest_evidence WHERE session=$1 AND role=$2",
        )
        .bind(id.to_string())
        .bind(role.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;

        if stored != json(reference)? {
            return Err(JobStoreError::Conflict);
        }

        tx.commit().await.map_err(db)
    }

    async fn review_evidence_available(
        &self,
        project: ProjectId,
        id: JobId,
        role: IroncrestEvidenceRole,
        reference: &ArtifactReference,
    ) -> Result<()> {
        valid_reference(reference)?;

        let mut tx = self.pool.begin().await.map_err(db)?;
        load_session(&mut tx, project, id).await?;
        sqlx::query(
            "UPDATE ironcrest_evidence SET state='AVAILABLE' WHERE session=$1 AND role=$2 AND reference=$3 AND state='STAGING'",
        )
            .bind(id.to_string())
            .bind(role.as_str())
            .bind(json(reference)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ironcrest_evidence WHERE session=$1 AND role=$2 AND reference=$3 AND state='AVAILABLE')",
        )
            .bind(id.to_string())
            .bind(role.as_str())
            .bind(json(reference)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;

        if !ready {
            return Err(JobStoreError::Precondition);
        }

        tx.commit().await.map_err(db)
    }

    async fn claim_review(
        &self,
        project: ProjectId,
        id: JobId,
        binding: &ReviewBinding,
        request: &ArtifactReference,
    ) -> Result<Option<ReviewInvocation>> {
        valid_reference(request)?;

        let mut tx = self.pool.begin().await.map_err(db)?;

        let session = load_session(&mut tx, project, id).await?;

        if !session.pin.matches_review(id, binding)
            || available_role(&session, IroncrestEvidenceRole::AuthorityProfile)?.sha256
                != binding.authority_profile_sha256
            || available_role(&session, IroncrestEvidenceRole::Knowledge)?.sha256
                != binding.knowledge_sha256
            || available_role(&session, IroncrestEvidenceRole::Impact)?.sha256
                != binding.impact_sha256
            || available_role(&session, IroncrestEvidenceRole::Request)? != request
        {
            return Err(JobStoreError::Precondition);
        }

        if session.review_claimed {
            tx.commit().await.map_err(db)?;
            return Ok(None);
        }

        let invocation = ReviewInvocation {
            token: JobId::new(),
            timestamp: u64::try_from(now(&mut tx).await?).map_err(|_| JobStoreError::Invalid)?,
        };
        sqlx::query("UPDATE ironcrest_sessions SET invocation=$2,review_timestamp=$3 WHERE id=$1")
            .bind(id.to_string())
            .bind(invocation.token.to_string())
            .bind(i64::try_from(invocation.timestamp).map_err(|_| JobStoreError::Invalid)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        tx.commit().await.map_err(db)?;

        Ok(Some(invocation))
    }
}

/// Additional control-plane issuance guard. Read immutable review metadata without
/// taking a session lock after the job lock, preserving admission lock ordering.
pub(super) async fn require_reviewed_issuance(
    c: &mut PgConnection,
    job: &CertificationJob,
) -> Result<()> {
    let present: bool = sqlx::query_scalar(
        "SELECT to_regclass(current_schema() || '.ironcrest_admissions') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;

    if !present {
        return if archcert_application::ironcrest::requires_reviewed_chain(&job.inputs.policy.id) {
            Err(JobStoreError::Precondition)
        } else {
            Ok(())
        };
    }

    let binding: Option<Value> =
        sqlx::query_scalar("SELECT binding FROM ironcrest_admissions WHERE job=$1 AND session=$1")
            .bind(job.id.to_string())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;
    let Some(binding) = binding else {
        return if archcert_application::ironcrest::requires_reviewed_chain(&job.inputs.policy.id) {
            Err(JobStoreError::Precondition)
        } else {
            Ok(())
        };
    };

    if binding["inputs"] != json(&job.inputs)? {
        return Err(JobStoreError::Precondition);
    }

    let pin: Value =
        sqlx::query_scalar("SELECT pin FROM ironcrest_sessions WHERE id=$1 AND project=$2")
            .bind(job.id.to_string())
            .bind(job.inputs.project.to_string())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;

    if binding["pin"] != pin {
        return Err(JobStoreError::Precondition);
    }

    let evidence: Vec<(IroncrestEvidenceRole, ArtifactReference)> =
        decode(binding["evidence"].clone())?;

    if evidence.len() != 7 {
        return Err(JobStoreError::Precondition);
    }

    for (role, reference) in evidence {
        let available: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ironcrest_evidence WHERE session=$1 AND role=$2 AND reference=$3 AND state='AVAILABLE')",
        )
            .bind(job.id.to_string())
            .bind(role.as_str())
            .bind(json(&reference)?)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;

        if !available {
            return Err(JobStoreError::Precondition);
        }
    }

    let challenge_ready: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ironcrest_evidence WHERE session=$1 AND role='CHALLENGE_RESULT' AND state='AVAILABLE')",
    )
        .bind(job.id.to_string())
        .fetch_one(c)
        .await
        .map_err(db)?;

    if !challenge_ready {
        return Err(JobStoreError::Precondition);
    }

    Ok(())
}
