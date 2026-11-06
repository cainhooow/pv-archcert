//! Atomic verified M6 admission and operational receipt; never claims execution.

use super::{fenced, grant, object_scope, publish, transaction};
use crate::{PostgresJobRepository, Result, db, release};
use archcert_application::{glassmere::commands::*, jobs::JobStoreError};
use archcert_domain::Sha256Digest;
use async_trait::async_trait;

#[async_trait]
impl ControlReleaseCommandExecutor for PostgresJobRepository {
    async fn apply_release_build(
        &self,
        lease: &ControlCommandLease,
        selected_context: &Sha256Digest,
        prepared: &PreparedReleaseBuild,
    ) -> Result<ControlCommandOutcome> {
        let mut tx = transaction(&self.pool).await?;
        let record = fenced(&mut tx, lease).await?;
        prepared.validate(&record)?;
        let command = &record.command;

        grant(
            &mut tx,
            &command.scope,
            &command.authority_context,
            command.action.name(),
        )
        .await?;
        object_scope(&mut tx, command).await?;
        let ResolvedControlAction::RequestReleaseBuild { admission, .. } = &command.action else {
            return Err(JobStoreError::Invalid);
        };

        let outcome = if command.authority_context != *selected_context {
            ControlCommandOutcome::Rejected {
                reason: CommandFailure::UnsupportedAuthorityContext,
            }
        } else {
            let release = release::prepare_open(admission)?;
            release.apply(&mut tx).await?;

            ControlCommandOutcome::Applied {
                effect: Box::new(CommandEffect::ReleaseBuildRequested {
                    invocation: admission.input.identity()?,
                }),
            }
        };

        publish(&mut tx, lease, &record, &outcome).await?;
        tx.commit().await.map_err(db)?;

        Ok(outcome)
    }
}
