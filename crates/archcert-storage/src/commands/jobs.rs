//! Atomic job mutation and receipt publication. Owns no target execution capability.

use super::{fenced, grant, object_scope, publish, transaction};
use crate::{PostgresJobRepository, Result, db, job_mutations};
use archcert_application::{
    glassmere::commands::*,
    jobs::{CreateJob, JobStoreError},
};
use archcert_domain::{Sha256Digest, jobs::IdempotencyKey};
use async_trait::async_trait;

#[async_trait]
impl ControlJobCommandExecutor for PostgresJobRepository {
    async fn apply_job_command(
        &self,
        lease: &ControlCommandLease,
        selected_context: &Sha256Digest,
    ) -> Result<ControlCommandOutcome> {
        let mut tx = transaction(&self.pool).await?;
        let record = fenced(&mut tx, lease).await?;
        let command = &record.command;

        // These operations require their existing separate review/build/verifier ports.
        // Calling the local executor cannot downgrade their authority requirements.
        if !matches!(
            command.action,
            ResolvedControlAction::RequestCertification {
                reviewed_session: None,
                ..
            } | ResolvedControlAction::CancelEligibleJob { .. }
                | ResolvedControlAction::RetryEligibleJob { .. }
        ) {
            return Err(JobStoreError::Invalid);
        }

        grant(
            &mut tx,
            &command.scope,
            &command.authority_context,
            command.action.name(),
        )
        .await?;
        object_scope(&mut tx, command).await?;

        let outcome = if command.authority_context != *selected_context {
            ControlCommandOutcome::Rejected {
                reason: CommandFailure::UnsupportedAuthorityContext,
            }
        } else {
            let result = match &command.action {
                ResolvedControlAction::RequestCertification { inputs, .. } => {
                    let request = CreateJob {
                        inputs: inputs.as_ref().clone(),
                        idempotency: IdempotencyKey::parse(format!(
                            "glassmere-command:{}",
                            record.id
                        ))?,
                    };
                    job_mutations::create(&mut tx, &request).await.map(|job| {
                        CommandEffect::CertificationRequested {
                            job: Some(job.id),
                            session: None,
                        }
                    })
                }
                ResolvedControlAction::CancelEligibleJob { job } => {
                    job_mutations::cancel(&mut tx, *job)
                        .await
                        .map(|()| CommandEffect::JobCanceled { job: *job })
                }
                ResolvedControlAction::RetryEligibleJob { job, attempt } => {
                    job_mutations::retry(&mut tx, *job, *attempt)
                        .await
                        .map(|()| CommandEffect::JobRecoveryRequested {
                            job: *job,
                            attempt: *attempt,
                        })
                }
                _ => return Err(JobStoreError::Invalid),
            };

            match result {
                Ok(effect) => ControlCommandOutcome::Applied {
                    effect: Box::new(effect),
                },
                // All precondition checks precede mutation in these shared helpers.
                Err(JobStoreError::Precondition) => ControlCommandOutcome::Rejected {
                    reason: CommandFailure::DomainPrecondition,
                },
                Err(error) => return Err(error),
            }
        };

        publish(&mut tx, lease, &record, &outcome).await?;
        tx.commit().await.map_err(db)?;

        Ok(outcome)
    }
}
