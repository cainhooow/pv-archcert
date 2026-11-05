//! Read-only evaluation with fenced historical publication, separate from release authority.

use super::*;
use crate::glassmere::PROJECTION_SCHEMA;

/// Narrow observation port. It grants no mutation, execution or signing capability.
#[async_trait]
pub trait ReleaseReadinessObserver: Send + Sync {
    /// Recheck current authority dependencies for this exact admitted invocation.
    async fn observe(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
    ) -> Result<ReleaseReadiness, JobStoreError>;
}

/// Mediate one requested observation. A receipt is historical even when it records ALLOWED.
pub struct ReadinessRequestEvaluator<'a> {
    /// Existing scoped command journal, with its independent grants and generation fence.
    pub commands: &'a dyn ControlCommandRepository,
    /// Explicit observation capability. Absence conservatively records unavailability.
    pub observer: Option<&'a dyn ReleaseReadinessObserver>,
}

impl ReadinessRequestEvaluator<'_> {
    /// Reauthorize before observation and publish only through the original command fence.
    /// Publication independently checks the immutable release/source/certificate binding.
    pub async fn evaluate(
        &self,
        assignment: &ControlCommandAssignment,
        selected_context: &Sha256Digest,
    ) -> Result<ControlCommandOutcome, JobStoreError> {
        if assignment.record.id != assignment.lease.command {
            return Err(JobStoreError::Invalid);
        }

        let record = self
            .commands
            .get(&assignment.record.command.scope, assignment.lease.command)
            .await?;
        let ResolvedControlAction::RequestReleaseReadinessEvaluation { invocation } =
            &record.command.action
        else {
            return Err(JobStoreError::Invalid);
        };
        if record.state != ControlCommandState::Processing
            || record.dispatches != assignment.record.dispatches
        {
            return Err(JobStoreError::Precondition);
        }

        let outcome = if record.command.authority_context != *selected_context {
            ControlCommandOutcome::Rejected {
                reason: CommandFailure::UnsupportedAuthorityContext,
            }
        } else {
            let observation = match self.observer {
                Some(observer) => {
                    observer
                        .observe(record.command.scope.project, invocation)
                        .await
                }
                None => Err(JobStoreError::Unavailable),
            };

            match observation {
                Ok(observation) if observation.schema != PROJECTION_SCHEMA => {
                    ControlCommandOutcome::Inconclusive {
                        reason: CommandFailure::UnsupportedAuthorityContext,
                    }
                }
                Ok(observation) => {
                    let outcome = ControlCommandOutcome::Applied {
                        effect: Box::new(CommandEffect::ReadinessEvaluated {
                            observation: Box::new(observation),
                        }),
                    };

                    if record.command.validate_outcome(&outcome).is_err() {
                        ControlCommandOutcome::Inconclusive {
                            reason: CommandFailure::IdentityMismatch,
                        }
                    } else {
                        outcome
                    }
                }
                Err(JobStoreError::Unavailable | JobStoreError::SemanticContextLimit) => {
                    ControlCommandOutcome::Inconclusive {
                        reason: CommandFailure::InfrastructureUnavailable,
                    }
                }
                Err(JobStoreError::Invalid | JobStoreError::Precondition) => {
                    ControlCommandOutcome::Inconclusive {
                        reason: CommandFailure::IdentityMismatch,
                    }
                }
                Err(error) => return Err(error),
            }
        };

        self.commands.finish(&assignment.lease, &outcome).await?;

        Ok(outcome)
    }
}
