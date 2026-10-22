//! Short row-locked M6 transactions, independent of historical certification jobs.

use super::*;
use archcert_application::release::*;
use archcert_domain::release::*;

fn role_name(role: ReleaseRole) -> Result<String> {
    serde_json::to_value(role)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(JobStoreError::Invalid)
}

async fn release_load(
    c: &mut PgConnection,
    project: ProjectId,
    id: &BuildInvocationIdentity,
) -> Result<ReleaseRecord> {
    let row = sqlx::query(
        "SELECT * FROM release_invocations WHERE project=$1 AND invocation=$2 FOR UPDATE",
    )
    .bind(project.to_string())
    .bind(id.0.as_str())
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .ok_or(JobStoreError::Precondition)?;
    let admission: ReleaseAdmission = decode(row.try_get("admission").map_err(db)?)?;

    if admission.input.identity()? != *id || admission.input.certified_source.project != project {
        return Err(JobStoreError::Precondition);
    }

    let rows = sqlx::query("SELECT role,reference,available FROM release_evidence WHERE project=$1 AND invocation=$2 ORDER BY role")
        .bind(project.to_string())
        .bind(id.0.as_str())
        .fetch_all(c).await.map_err(db)?;
    let mut references = Vec::new();

    for row in rows {
        references.push(ReleaseReference {
            role: state(&row, "role")?,
            artifact: decode(row.try_get("reference").map_err(db)?)?,
            available: row.try_get("available").map_err(db)?,
        });
    }

    Ok(ReleaseRecord {
        admission,
        claimed_a: row
            .try_get::<Option<String>, _>("claim_a")
            .map_err(db)?
            .is_some(),
        claimed_b: row
            .try_get::<Option<String>, _>("claim_b")
            .map_err(db)?
            .is_some(),
        references,
    })
}

async fn release_audit(
    c: &mut PgConnection,
    project: ProjectId,
    id: &BuildInvocationIdentity,
    event: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO release_audit(project,invocation,event) VALUES ($1,$2,$3)")
        .bind(project.to_string())
        .bind(id.0.as_str())
        .bind(event)
        .execute(c)
        .await
        .map_err(db)?;

    Ok(())
}

fn has(record: &ReleaseRecord, role: ReleaseRole) -> bool {
    record
        .references
        .iter()
        .any(|r| r.role == role && r.available)
}

fn prerequisites(record: &ReleaseRecord, role: ReleaseRole) -> Result<()> {
    let valid = match role {
        ReleaseRole::Input => true,
        ReleaseRole::SourceCertificate => has(record, ReleaseRole::Input),
        ReleaseRole::ArtifactA | ReleaseRole::ResultA => record.claimed_a,
        ReleaseRole::ArtifactB | ReleaseRole::ResultB => record.claimed_b,
        ReleaseRole::Reproducibility => {
            has(record, ReleaseRole::ResultA) && has(record, ReleaseRole::ResultB)
        }
        ReleaseRole::PermitPayload => {
            has(record, ReleaseRole::Reproducibility)
                && has(record, ReleaseRole::ArtifactA)
                && has(record, ReleaseRole::ArtifactB)
        }
        ReleaseRole::PermitEnvelope => has(record, ReleaseRole::PermitPayload),
    };

    if !valid {
        return Err(JobStoreError::Precondition);
    }

    Ok(())
}

#[async_trait]
impl ReleaseRepository for PostgresJobRepository {
    async fn open(&self, admission: &ReleaseAdmission) -> Result<ReleaseRecord> {
        let input = &admission.input;
        let source = &input.certified_source;
        let id = input.identity()?;

        if admission.input_reference != release_reference(&release_bytes(input)?) {
            return Err(JobStoreError::Invalid);
        }

        let mut tx = self.pool.begin().await.map_err(db)?;
        let allowed = sqlx::query("SELECT actor FROM repository_grants WHERE project=$1 AND repository=$2 AND actor=$3 FOR SHARE")
            .bind(source.project.to_string()).bind(source.repository.as_str()).bind(admission.actor.as_str())
            .fetch_optional(&mut *tx).await.map_err(db)?.is_some();
        let accepted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accepted_sources WHERE submission=$1 AND project=$2 AND repository=$3 AND source=$4)")
            .bind(admission.submission.to_string()).bind(source.project.to_string())
            .bind(source.repository.as_str()).bind(json(&source.source)?)
            .fetch_one(&mut *tx).await.map_err(db)?;

        if !allowed || !accepted {
            return Err(JobStoreError::Unauthorized);
        }

        let inserted = sqlx::query("INSERT INTO release_invocations(project,invocation,admission) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(source.project.to_string()).bind(id.0.as_str()).bind(json(admission)?)
            .execute(&mut *tx).await.map_err(db)?.rows_affected() == 1;
        let record = release_load(&mut tx, source.project, &id).await?;

        if json(&record.admission)? != json(admission)? {
            return Err(JobStoreError::Conflict);
        }

        if inserted {
            release_audit(&mut tx, source.project, &id, "BUILD_ADMITTED").await?;
        }

        tx.commit().await.map_err(db)?;

        Ok(record)
    }

    async fn get(&self, project: ProjectId, id: &BuildInvocationIdentity) -> Result<ReleaseRecord> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let record = release_load(&mut tx, project, id).await?;
        tx.commit().await.map_err(db)?;

        Ok(record)
    }

    async fn claim(
        &self,
        project: ProjectId,
        id: &BuildInvocationIdentity,
        ordinal: BuildOrdinal,
    ) -> Result<Option<BuildClaim>> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let record = release_load(&mut tx, project, id).await?;

        if !has(&record, ReleaseRole::Input)
            || !has(&record, ReleaseRole::SourceCertificate)
            || (ordinal == BuildOrdinal::B && !has(&record, ReleaseRole::ResultA))
        {
            return Err(JobStoreError::Precondition);
        }

        let claimed = match ordinal {
            BuildOrdinal::A => record.claimed_a,
            BuildOrdinal::B => record.claimed_b,
        };

        if claimed {
            tx.commit().await.map_err(db)?;
            return Ok(None);
        }

        let token = JobId::new();
        let query = match ordinal {
            BuildOrdinal::A => {
                "UPDATE release_invocations SET claim_a=$3 WHERE project=$1 AND invocation=$2"
            }
            BuildOrdinal::B => {
                "UPDATE release_invocations SET claim_b=$3 WHERE project=$1 AND invocation=$2"
            }
        };
        sqlx::query(query)
            .bind(project.to_string())
            .bind(id.0.as_str())
            .bind(token.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        release_audit(
            &mut tx,
            project,
            id,
            match ordinal {
                BuildOrdinal::A => "BUILD_A_CLAIMED",
                BuildOrdinal::B => "BUILD_B_CLAIMED",
            },
        )
        .await?;
        tx.commit().await.map_err(db)?;

        Ok(Some(BuildClaim { ordinal, token }))
    }

    async fn stage(
        &self,
        project: ProjectId,
        id: &BuildInvocationIdentity,
        role: ReleaseRole,
        reference: &ArtifactReference,
        claim: Option<&BuildClaim>,
    ) -> Result<()> {
        if reference.schema != 1
            || reference.producer != RELEASE_PRODUCER
            || reference.size == 0
            || reference.size > MAX_RELEASE_ARTIFACT_BYTES
        {
            return Err(JobStoreError::Invalid);
        }

        let mut tx = self.pool.begin().await.map_err(db)?;
        let record = release_load(&mut tx, project, id).await?;
        prerequisites(&record, role)?;

        if let Some(existing) = record.references.iter().find(|r| r.role == role) {
            if existing.artifact != *reference {
                return Err(JobStoreError::Conflict);
            }

            tx.commit().await.map_err(db)?;
            return Ok(());
        }

        let ordinal = match role {
            ReleaseRole::ArtifactA | ReleaseRole::ResultA => Some(BuildOrdinal::A),
            ReleaseRole::ArtifactB | ReleaseRole::ResultB => Some(BuildOrdinal::B),
            _ => None,
        };

        if let Some(ordinal) = ordinal {
            let claim = claim.ok_or(JobStoreError::Precondition)?;
            let query = match ordinal {
                BuildOrdinal::A => {
                    "SELECT claim_a FROM release_invocations WHERE project=$1 AND invocation=$2"
                }
                BuildOrdinal::B => {
                    "SELECT claim_b FROM release_invocations WHERE project=$1 AND invocation=$2"
                }
            };
            let token: Option<String> = sqlx::query_scalar(query)
                .bind(project.to_string())
                .bind(id.0.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;

            if claim.ordinal != ordinal
                || token.as_deref() != Some(claim.token.to_string().as_str())
            {
                return Err(JobStoreError::Precondition);
            }
        }

        sqlx::query(
            "INSERT INTO release_evidence(project,invocation,role,reference) VALUES ($1,$2,$3,$4)",
        )
        .bind(project.to_string())
        .bind(id.0.as_str())
        .bind(role_name(role)?)
        .bind(json(reference)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        release_audit(
            &mut tx,
            project,
            id,
            &format!("{}_STAGED", role_name(role)?),
        )
        .await?;
        tx.commit().await.map_err(db)?;

        Ok(())
    }

    async fn available(
        &self,
        project: ProjectId,
        id: &BuildInvocationIdentity,
        role: ReleaseRole,
        reference: &ArtifactReference,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let record = release_load(&mut tx, project, id).await?;
        prerequisites(&record, role)?;
        let existing = record
            .references
            .iter()
            .find(|r| r.role == role)
            .ok_or(JobStoreError::Precondition)?;

        if existing.artifact != *reference {
            return Err(JobStoreError::Conflict);
        }

        if !existing.available {
            sqlx::query("UPDATE release_evidence SET available=TRUE WHERE project=$1 AND invocation=$2 AND role=$3")
                .bind(project.to_string()).bind(id.0.as_str()).bind(role_name(role)?)
                .execute(&mut *tx).await.map_err(db)?;
            release_audit(
                &mut tx,
                project,
                id,
                &format!("{}_AVAILABLE", role_name(role)?),
            )
            .await?;
        }

        tx.commit().await.map_err(db)?;

        Ok(())
    }
}
