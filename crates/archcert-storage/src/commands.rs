//! Private command coordination. No target execution, signing or policy selection.

mod jobs;

use super::{PostgresJobRepository, Result, db, decode, json, now, state, valid_lease};
use archcert_application::{glassmere::commands::*, jobs::JobStoreError};
use archcert_domain::{
    Sha256Digest,
    jobs::{ControlCommandId, IdempotencyKey, LeaseToken},
};
use async_trait::async_trait;
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction, postgres::PgRow};

async fn transaction(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("SET LOCAL statement_timeout='3s'")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await
        .map_err(db)?;

    Ok(tx)
}

fn record(row: &PgRow) -> Result<ControlCommandRecord> {
    let command: ResolvedControlCommand = decode(row.try_get("request").map_err(db)?)?;
    command.validate()?;
    let request_sha256 =
        Sha256Digest::parse(row.try_get::<String, _>("request_sha256").map_err(db)?)
            .map_err(|_| JobStoreError::Invalid)?;

    if command.digest()? != request_sha256 {
        return Err(JobStoreError::Invalid);
    }

    let outcome: Option<ControlCommandOutcome> = super::optional(row, "outcome")?;
    let state = state(row, "state")?;

    if let Some(outcome) = &outcome {
        command.validate_outcome(outcome)?;

        if outcome.state() != state {
            return Err(JobStoreError::Invalid);
        }
    }

    Ok(ControlCommandRecord {
        id: ControlCommandId::parse(row.try_get::<&str, _>("id").map_err(db)?)?,
        command,
        request_sha256,
        intent_sha256: Sha256Digest::parse(row.try_get::<String, _>("intent_sha256").map_err(db)?)
            .map_err(|_| JobStoreError::Invalid)?,
        state,
        created_at: row.try_get("created_at").map_err(db)?,
        dispatches: u32::try_from(row.try_get::<i32, _>("dispatches").map_err(db)?)
            .map_err(|_| JobStoreError::Invalid)?,
        outcome,
    })
}

async fn audit(c: &mut PgConnection, id: ControlCommandId, event: &str) -> Result<()> {
    sqlx::query("INSERT INTO control_command_audit(command,event) VALUES ($1,$2)")
        .bind(id.to_string())
        .bind(event)
        .execute(c)
        .await
        .map_err(db)?;

    Ok(())
}

async fn grant(
    c: &mut PgConnection,
    scope: &CommandScope,
    context: &Sha256Digest,
    operation: &str,
) -> Result<()> {
    // Lock both provisioning rows: revocation and acceptance cannot cross unnoticed.
    let row = sqlx::query(
        "SELECT g.actor FROM repository_grants r
         JOIN control_command_grants g USING(project,repository,actor)
         WHERE g.project=$1 AND g.repository=$2 AND g.actor=$3
           AND g.authority_context=$4 AND g.operation=$5
         FOR SHARE OF r,g",
    )
    .bind(scope.project.to_string())
    .bind(scope.repository.as_str())
    .bind(scope.actor.as_str())
    .bind(context.as_str())
    .bind(operation)
    .fetch_optional(c)
    .await
    .map_err(db)?;

    if row.is_none() {
        return Err(JobStoreError::Unauthorized);
    }

    Ok(())
}

async fn object_scope(c: &mut PgConnection, command: &ResolvedControlCommand) -> Result<()> {
    let scope = &command.scope;
    let scoped = match &command.action {
        ResolvedControlAction::RequestCertification {
            inputs,
            reviewed_session,
        } => {
            let accepted: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM accepted_sources
                    WHERE submission=$1 AND project=$2 AND repository=$3 AND source=$4
                 )",
            )
            .bind(inputs.submission.to_string())
            .bind(scope.project.to_string())
            .bind(scope.repository.as_str())
            .bind(json(&inputs.source)?)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;

            let reviewed = if let Some(session) = reviewed_session {
                sqlx::query_scalar(
                    "SELECT EXISTS(
                        SELECT 1 FROM ironcrest_sessions
                        WHERE id=$1 AND project=$2
                          AND pin->>'repository'=$3 AND pin->>'actor'=$4
                          AND pin->>'submission'=$5 AND pin->'source'=$6
                          AND pin->'policy'=$7 AND pin->>'base_plan_sha256'=$8
                     )",
                )
                .bind(session.to_string())
                .bind(scope.project.to_string())
                .bind(scope.repository.as_str())
                .bind(scope.actor.as_str())
                .bind(inputs.submission.to_string())
                .bind(json(&inputs.source)?)
                .bind(json(&inputs.policy)?)
                .bind(inputs.plan_sha256.as_str())
                .fetch_one(&mut *c)
                .await
                .map_err(db)?
            } else {
                !archcert_application::ironcrest::requires_reviewed_chain(&inputs.policy.id)
            };

            accepted && reviewed
        }
        ResolvedControlAction::RequestReleaseBuild {
            admission,
            source_certificate,
        } => {
            let source = &admission.input.certified_source;
            sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM certification_jobs j
                    JOIN accepted_sources s
                      ON s.submission=$5 AND s.project=j.project
                     AND s.repository=j.repository AND s.source=j.inputs->'source'
                    WHERE j.project=$1 AND j.repository=$2 AND j.actor=$3
                      AND j.state='COMPLETED' AND j.inputs->'source'=$4
                      AND j.certificate->'artifact'=$6
                      AND j.certificate->'issuance'->>'certificate_sha256'=$7
                 )",
            )
            .bind(scope.project.to_string())
            .bind(scope.repository.as_str())
            .bind(scope.actor.as_str())
            .bind(json(&source.source)?)
            .bind(admission.submission.to_string())
            .bind(json(source_certificate)?)
            .bind(source.certificate_sha256.as_str())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?
        }
        ResolvedControlAction::RequestReleaseReadinessEvaluation { invocation } => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM release_invocations
                    WHERE project=$1 AND invocation=$2
                      AND admission->'input'->'certified_source'->>'repository'=$3
                      AND admission->>'actor'=$4
                 )",
            )
            .bind(scope.project.to_string())
            .bind(invocation.0.as_str())
            .bind(scope.repository.as_str())
            .bind(scope.actor.as_str())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?
        }
        ResolvedControlAction::CancelEligibleJob { job } => sqlx::query_scalar(
            "SELECT EXISTS(
                    SELECT 1 FROM certification_jobs
                    WHERE id=$1 AND project=$2 AND repository=$3 AND actor=$4
                 )",
        )
        .bind(job.to_string())
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?,
        ResolvedControlAction::RetryEligibleJob { job, attempt } => sqlx::query_scalar(
            "SELECT EXISTS(
                    SELECT 1 FROM certification_jobs j
                    JOIN certification_attempts a ON a.job=j.id
                    WHERE j.id=$1 AND j.project=$2 AND j.repository=$3 AND j.actor=$4
                      AND a.id=$5
                 )",
        )
        .bind(job.to_string())
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(attempt.to_string())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?,
    };

    if !scoped {
        return Err(JobStoreError::Unauthorized);
    }

    Ok(())
}

fn dispatcher_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(JobStoreError::Invalid);
    }

    Ok(())
}

async fn effect_scope(
    c: &mut PgConnection,
    command: &ResolvedControlCommand,
    outcome: &ControlCommandOutcome,
) -> Result<()> {
    let ControlCommandOutcome::Applied { effect } = outcome else {
        return Ok(());
    };

    let scope = &command.scope;
    let established: bool = match effect.as_ref() {
        CommandEffect::CertificationRequested { job: Some(job), .. } => {
            let ResolvedControlAction::RequestCertification {
                inputs,
                reviewed_session,
            } = &command.action
            else {
                return Err(JobStoreError::Invalid);
            };

            let row = sqlx::query(
                "SELECT inputs FROM certification_jobs WHERE id=$1 AND project=$2 AND repository=$3 AND actor=$4",
            )
            .bind(job.to_string())
            .bind(scope.project.to_string())
            .bind(scope.repository.as_str())
            .bind(scope.actor.as_str())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;

            if let Some(row) = row {
                let actual: archcert_domain::jobs::JobInputs =
                    decode(row.try_get("inputs").map_err(db)?)?;

                if reviewed_session.is_some() {
                    // Reviewed admission legitimately adds the mandatory challenge plan.
                    // Its existing create-only linkage must establish that admission.
                    let linked: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM ironcrest_admissions WHERE session=$1 AND job=$1)",
                    )
                    .bind(job.to_string())
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
                    linked
                        && actual.submission == inputs.submission
                        && actual.source == inputs.source
                        && actual.policy == inputs.policy
                } else {
                    actual == **inputs
                }
            } else {
                false
            }
        }
        CommandEffect::CertificationRequested { job: None, .. } => {
            object_scope(c, command).await?;
            true
        }
        CommandEffect::ReleaseBuildRequested { invocation } => {
            let ResolvedControlAction::RequestReleaseBuild { admission, .. } = &command.action
            else {
                return Err(JobStoreError::Invalid);
            };

            sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM release_invocations
                    WHERE project=$1 AND invocation=$2 AND admission=$3
                 )",
            )
            .bind(scope.project.to_string())
            .bind(invocation.0.as_str())
            .bind(json(admission.as_ref())?)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?
        }
        CommandEffect::JobCanceled { job } => sqlx::query_scalar(
            "SELECT EXISTS(
                    SELECT 1 FROM certification_jobs
                    WHERE id=$1 AND project=$2 AND repository=$3 AND actor=$4
                      AND state='INCONCLUSIVE' AND failure='OPERATOR_CANCELLATION'
                 )",
        )
        .bind(job.to_string())
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?,
        CommandEffect::JobRecoveryRequested { job, attempt } => sqlx::query_scalar(
            "SELECT EXISTS(
                    SELECT 1 FROM certification_jobs j
                    JOIN certification_attempts a ON a.job=j.id
                    WHERE j.id=$1 AND j.project=$2 AND j.repository=$3 AND j.actor=$4
                      AND a.id=$5 AND a.state='LOST' AND a.ended_at IS NOT NULL
                      AND EXISTS(
                        SELECT 1 FROM audit_events e
                        WHERE e.job=j.id AND e.attempt=a.id AND e.event='AttemptRecovered'
                      )
                 )",
        )
        .bind(job.to_string())
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(attempt.to_string())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?,
        CommandEffect::ReadinessEvaluated { observation } => {
            object_scope(c, command).await?;
            let admission: serde_json::Value = sqlx::query_scalar(
                "SELECT admission FROM release_invocations WHERE project=$1 AND invocation=$2",
            )
            .bind(scope.project.to_string())
            .bind(&observation.subject.invocation)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
            let admission: archcert_application::release::ReleaseAdmission = decode(admission)?;
            let source = &admission.input.certified_source;
            admission.input.identity()?.0.as_str() == observation.subject.invocation
                && observation.subject.source == source.source
                && observation.subject.certificate.as_deref()
                    == Some(source.certificate_sha256.as_str())
        }
    };

    if !established {
        return Err(JobStoreError::Precondition);
    }

    Ok(())
}

impl PostgresJobRepository {
    /// Explicit private authority provisioning, never called by the panel or a target.
    /// Existing repository grants alone enable no operational command.
    pub async fn grant_control_command(
        &self,
        scope: &CommandScope,
        context: &Sha256Digest,
        action: &ResolvedControlAction,
    ) -> Result<()> {
        self.grant_control_operation(scope, context, action.operation())
            .await
    }

    /// Explicit trusted provisioning without constructing an executable request.
    /// This does not create the separately required repository grant.
    pub async fn grant_control_operation(
        &self,
        scope: &CommandScope,
        context: &Sha256Digest,
        operation: ControlOperation,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO control_command_grants(project,repository,actor,authority_context,operation)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        )
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(context.as_str())
        .bind(operation.name())
        .execute(&self.pool)
        .await
        .map_err(db)?;

        Ok(())
    }
}

#[async_trait]
impl ControlCommandRepository for PostgresJobRepository {
    async fn accept(
        &self,
        command: &ResolvedControlCommand,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord> {
        command.validate()?;
        let scope = &command.scope;
        let request = command.digest()?;
        let intent = command.intent(key)?;

        let mut tx = transaction(&self.pool).await?;
        grant(
            &mut tx,
            scope,
            &command.authority_context,
            command.action.name(),
        )
        .await?;
        object_scope(&mut tx, command).await?;

        // A retained key always resolves its original receipt, including known rejection.
        let previous = sqlx::query(
            "SELECT c.*, k.request_sha256 AS bound_request_sha256
             FROM control_command_keys k JOIN control_commands c ON c.id=k.command
             WHERE k.project=$1 AND k.repository=$2 AND k.actor=$3 AND k.idempotency_key=$4",
        )
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(key.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;

        if let Some(row) = previous {
            let record = record(&row)?;

            if record.request_sha256 != request {
                return Err(JobStoreError::Conflict);
            }

            let bound_request_sha256: String = row.try_get("bound_request_sha256").map_err(db)?;
            if bound_request_sha256 != request.as_str() {
                return Err(JobStoreError::Conflict);
            }

            tx.commit().await.map_err(db)?;

            return Ok(record);
        }

        // Serialize short acceptance for this content identity. PostgreSQL's hash
        // is a coordination key only; the canonical SHA-256 remains the identity.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(intent.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let current = sqlx::query(
            "SELECT * FROM control_commands
             WHERE project=$1 AND repository=$2 AND actor=$3 AND intent_sha256=$4
               AND state <> 'REJECTED'
             FOR UPDATE",
        )
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(intent.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;

        let (record, inserted) = if let Some(row) = current {
            (record(&row)?, false)
        } else {
            let row = sqlx::query(
                "INSERT INTO control_commands(
                    id,project,repository,actor,authority_context,operation,
                    request,request_sha256,intent_sha256
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *",
            )
            .bind(ControlCommandId::new().to_string())
            .bind(scope.project.to_string())
            .bind(scope.repository.as_str())
            .bind(scope.actor.as_str())
            .bind(command.authority_context.as_str())
            .bind(command.action.name())
            .bind(json(command)?)
            .bind(request.as_str())
            .bind(intent.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;

            (record(&row)?, true)
        };

        if record.request_sha256 != request {
            return Err(JobStoreError::Conflict);
        }

        let alias = sqlx::query(
            "INSERT INTO control_command_keys(
                project,repository,actor,idempotency_key,command,request_sha256
             ) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        )
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(key.as_str())
        .bind(record.id.to_string())
        .bind(request.as_str())
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected()
            == 1;
        let bound: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM control_command_keys
                WHERE project=$1 AND repository=$2 AND actor=$3
                  AND idempotency_key=$4 AND command=$5 AND request_sha256=$6
             )",
        )
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .bind(key.as_str())
        .bind(record.id.to_string())
        .bind(request.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;

        if !bound {
            return Err(JobStoreError::Conflict);
        }

        if inserted {
            audit(&mut tx, record.id, "CommandRequested").await?;
        }

        if alias {
            audit(&mut tx, record.id, "RetryKeyBound").await?;
        }

        tx.commit().await.map_err(db)?;

        Ok(record)
    }

    async fn get(
        &self,
        scope: &CommandScope,
        id: ControlCommandId,
    ) -> Result<ControlCommandRecord> {
        let mut tx = transaction(&self.pool).await?;
        // Scope in SQL prevents an identifier from disclosing a foreign request.
        let row = sqlx::query(
            "SELECT c.* FROM control_commands c
             JOIN repository_grants r USING(project,repository,actor)
             JOIN control_command_grants g
               USING(project,repository,actor,authority_context,operation)
             WHERE c.id=$1 AND c.project=$2 AND c.repository=$3 AND c.actor=$4",
        )
        .bind(id.to_string())
        .bind(scope.project.to_string())
        .bind(scope.repository.as_str())
        .bind(scope.actor.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(JobStoreError::Unauthorized)?;
        let record = record(&row)?;

        tx.commit().await.map_err(db)?;

        Ok(record)
    }

    async fn claim(
        &self,
        dispatcher: &str,
        lease_seconds: u32,
    ) -> Result<Option<ControlCommandAssignment>> {
        dispatcher_name(dispatcher)?;
        valid_lease(lease_seconds)?;

        let mut tx = transaction(&self.pool).await?;
        let row = sqlx::query(
            "SELECT c.* FROM control_commands c
             JOIN repository_grants r USING(project,repository,actor)
             JOIN control_command_grants g
               USING(project,repository,actor,authority_context,operation)
             WHERE c.state='REQUESTED'
                OR (c.state='PROCESSING'
                    AND c.lease_until <= floor(extract(epoch FROM clock_timestamp())))
             ORDER BY c.created_at,c.id LIMIT 1 FOR UPDATE OF c SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;

        let Some(row) = row else {
            tx.commit().await.map_err(db)?;
            return Ok(None);
        };

        let record = record(&row)?;
        grant(
            &mut tx,
            &record.command.scope,
            &record.command.authority_context,
            record.command.action.name(),
        )
        .await?;

        let token = LeaseToken::new();
        let until = now(&mut tx).await? + i64::from(lease_seconds);
        let row = sqlx::query(
            "UPDATE control_commands
             SET state='PROCESSING',dispatcher=$2,token=$3,
                 lease_until=$4,dispatches=dispatches+1
             WHERE id=$1 RETURNING *",
        )
        .bind(record.id.to_string())
        .bind(dispatcher)
        .bind(token.to_string())
        .bind(until)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let record = self::record(&row)?;
        audit(&mut tx, record.id, "CommandClaimed").await?;

        tx.commit().await.map_err(db)?;

        Ok(Some(ControlCommandAssignment {
            lease: ControlCommandLease {
                command: record.id,
                dispatcher: dispatcher.into(),
                token,
            },
            record,
        }))
    }

    async fn renew(&self, lease: &ControlCommandLease, lease_seconds: u32) -> Result<()> {
        valid_lease(lease_seconds)?;

        let mut tx = transaction(&self.pool).await?;
        let record = fenced(&mut tx, lease).await?;
        grant(
            &mut tx,
            &record.command.scope,
            &record.command.authority_context,
            record.command.action.name(),
        )
        .await?;

        let until = now(&mut tx).await? + i64::from(lease_seconds);
        sqlx::query("UPDATE control_commands SET lease_until=$2 WHERE id=$1")
            .bind(lease.command.to_string())
            .bind(until)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(&mut tx, lease.command, "CommandRenewed").await?;

        tx.commit().await.map_err(db)
    }

    async fn finish(
        &self,
        lease: &ControlCommandLease,
        outcome: &ControlCommandOutcome,
    ) -> Result<()> {
        let mut tx = transaction(&self.pool).await?;
        let record = fenced(&mut tx, lease).await?;
        grant(
            &mut tx,
            &record.command.scope,
            &record.command.authority_context,
            record.command.action.name(),
        )
        .await?;
        publish(&mut tx, lease, &record, outcome).await?;

        tx.commit().await.map_err(db)
    }
}

async fn publish(
    c: &mut PgConnection,
    lease: &ControlCommandLease,
    record: &ControlCommandRecord,
    outcome: &ControlCommandOutcome,
) -> Result<()> {
    record.command.validate_outcome(outcome)?;
    effect_scope(&mut *c, &record.command, outcome).await?;

    // A receipt cannot substitute for its corresponding durable domain transition.
    let state = outcome.state();
    let event = match state {
        ControlCommandState::Applied => "CommandApplied",
        ControlCommandState::Rejected => "CommandRejected",
        ControlCommandState::Inconclusive => "CommandInconclusive",
        _ => return Err(JobStoreError::Invalid),
    };
    sqlx::query(
        "UPDATE control_commands
         SET state=$2,outcome=$3,dispatcher=NULL,token=NULL,lease_until=NULL
         WHERE id=$1",
    )
    .bind(lease.command.to_string())
    .bind(json(&state)?.as_str().ok_or(JobStoreError::Invalid)?)
    .bind(json(outcome)?)
    .execute(&mut *c)
    .await
    .map_err(db)?;
    audit(&mut *c, lease.command, event).await?;

    Ok(())
}

async fn fenced(c: &mut PgConnection, lease: &ControlCommandLease) -> Result<ControlCommandRecord> {
    let row = sqlx::query(
        "SELECT * FROM control_commands
         WHERE id=$1 AND state='PROCESSING' AND dispatcher=$2 AND token=$3
           AND lease_until > floor(extract(epoch FROM clock_timestamp()))
         FOR UPDATE",
    )
    .bind(lease.command.to_string())
    .bind(&lease.dispatcher)
    .bind(lease.token.to_string())
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(JobStoreError::Precondition)?;

    record(&row)
}
