//! Trusted operational requests and polling, without target execution or signing keys.

use anyhow::Result;
use archcert_application::{
    glassmere::commands::*,
    ironcrest::{IroncrestWorkflow, ReviewedIroncrestAdmission},
    jobs::JobStoreError,
};
use archcert_control_plane::{ControlPlane, commands::CommandCredentials, read_private};
use archcert_domain::{ProjectId, Sha256Digest, jobs::IdempotencyKey, source::RepositoryId};
use archcert_protocol::commands::ControlCommandResponse;

#[derive(clap::Args)]
pub(super) struct ReadinessArgs {
    #[arg(long)]
    project: ProjectId,
    #[arg(long)]
    repository: String,
    #[arg(long)]
    invocation: String,
    #[arg(long)]
    authority_context: String,
    #[arg(long)]
    idempotency_key: String,
    #[arg(long)]
    credentials: std::path::PathBuf,
    /// Owned mode-0600 file containing only the separate command credential.
    #[arg(long)]
    token_file: std::path::PathBuf,
}

pub(super) async fn request_readiness(state: &ControlPlane, args: ReadinessArgs) -> Result<()> {
    let repository = RepositoryId::parse(args.repository)?;
    let invocation =
        archcert_domain::release::BuildInvocationIdentity(Sha256Digest::parse(args.invocation)?);
    let context = Sha256Digest::parse(args.authority_context)?;
    let key = IdempotencyKey::parse(args.idempotency_key)?;
    let credentials = CommandCredentials::load(&args.credentials, &state.configuration)?;
    let token_bytes = read_private(&args.token_file, 256)?;
    let token = std::str::from_utf8(&token_bytes).map_err(|_| JobStoreError::Invalid)?;
    let authorization = credentials.authorize(
        &state.configuration,
        token,
        args.project,
        &repository,
        ControlOperation::RequestReleaseReadinessEvaluation,
        Some(&context),
    )?;

    let record = state
        .request_readiness(&authorization, invocation, &key)
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ControlCommandResponse::from(record))?
    );

    Ok(())
}

#[derive(clap::Args)]
pub(super) struct DispatchArgs {
    /// Explicit public-key/recipe observation selection. Readiness also requires
    /// ARCHCERT_OBSERVATION_DATABASE_URL with a separately provisioned SELECT-only role.
    #[arg(long)]
    observation_config: Option<std::path::PathBuf>,
    #[arg(long, default_value = "development-command-dispatcher")]
    dispatcher: String,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(5..=300))]
    lease_seconds: u32,
    /// Authority-only crash checkpoint; never selected by a browser or target.
    #[arg(long, value_parser = ["claimed", "published"])]
    stop_after: Option<String>,
    /// Wait for an external regression harness to send actual SIGKILL.
    #[arg(long)]
    hold_checkpoint: bool,
}

fn checkpoint(args: &DispatchArgs, stage: &str) {
    if args.stop_after.as_deref() == Some(stage) {
        eprintln!("Controlled Glassmere command interruption after {stage}");
        if args.hold_checkpoint {
            loop {
                std::thread::park();
            }
        }

        std::process::exit(75);
    }
}

async fn reviewed_admission(
    state: &ControlPlane,
    record: &ControlCommandRecord,
    session: archcert_domain::jobs::JobId,
) -> std::result::Result<ReviewedIroncrestAdmission, JobStoreError> {
    let prepared = state
        .prepare_ironcrest(record.command.scope.project, session)
        .await?;
    let workflow = IroncrestWorkflow {
        repository: &state.repository,
        artifacts: state.artifacts.as_ref(),
    };
    let review = workflow.restore_retained_review(&prepared.request).await?;
    let admission = workflow
        .freeze_admission(prepared.admission_context(&review))
        .await?;
    record.command.validate_reviewed_admission(&admission)?;

    Ok(admission)
}

async fn restore_with_renewal(
    state: &ControlPlane,
    assignment: &ControlCommandAssignment,
    session: archcert_domain::jobs::JobId,
    lease_seconds: u32,
) -> std::result::Result<ReviewedIroncrestAdmission, JobStoreError> {
    let preparation = reviewed_admission(state, &assignment.record, session);
    tokio::pin!(preparation);
    let mut heartbeat =
        tokio::time::interval(std::time::Duration::from_secs(u64::from(lease_seconds / 3)));
    heartbeat.tick().await;

    loop {
        tokio::select! {
            result = &mut preparation => return result,
            _ = heartbeat.tick() => {
                ControlCommandRepository::renew(&state.repository, &assignment.lease, lease_seconds).await?;
            }
        }
    }
}

pub(super) async fn dispatch(state: &ControlPlane, args: DispatchArgs) -> Result<()> {
    state.repository.check_command_readiness().await?;
    let Some(assignment) =
        ControlCommandRepository::claim(&state.repository, &args.dispatcher, args.lease_seconds)
            .await?
    else {
        println!("{{\"status\":\"IDLE\"}}");
        return Ok(());
    };
    checkpoint(&args, "claimed");

    let record = &assignment.record;
    let scope = &record.command.scope;
    let selection = state
        .configuration
        .grant_for(&scope.actor, scope.project, &scope.repository)
        .and_then(|grant| grant.command_context());
    let context = match selection {
        Ok(context) if context == record.command.authority_context => Some(context),
        Ok(_)
        | Err(JobStoreError::Unauthorized | JobStoreError::Invalid | JobStoreError::Precondition) => {
            None
        }
        Err(error) => return Err(error.into()),
    };

    if let Some(context) = context {
        match &record.command.action {
            ResolvedControlAction::RequestCertification {
                reviewed_session: Some(session),
                ..
            } => {
                match restore_with_renewal(state, &assignment, *session, args.lease_seconds).await {
                    Ok(admission) => {
                        state
                            .repository
                            .apply_reviewed_certification(&assignment.lease, &context, &admission)
                            .await?;
                    }
                    Err(JobStoreError::Precondition | JobStoreError::SemanticContextLimit) => {
                        state
                            .repository
                            .finish(
                                &assignment.lease,
                                &ControlCommandOutcome::Rejected {
                                    reason: CommandFailure::ReviewRequired,
                                },
                            )
                            .await?;
                    }
                    Err(JobStoreError::Invalid) => {
                        state
                            .repository
                            .finish(
                                &assignment.lease,
                                &ControlCommandOutcome::Rejected {
                                    reason: CommandFailure::IdentityMismatch,
                                },
                            )
                            .await?;
                    }
                    // Infrastructure/commit uncertainty remains claimed for exact recovery.
                    Err(error) => return Err(error.into()),
                }
            }
            ResolvedControlAction::RequestCertification {
                reviewed_session: None,
                ..
            }
            | ResolvedControlAction::CancelEligibleJob { .. }
            | ResolvedControlAction::RetryEligibleJob { .. } => {
                state
                    .repository
                    .apply_job_command(&assignment.lease, &context)
                    .await?;
            }
            ResolvedControlAction::RequestReleaseReadinessEvaluation { .. } => {
                let observer = match (
                    args.observation_config.as_ref(),
                    std::env::var("ARCHCERT_OBSERVATION_DATABASE_URL").ok(),
                ) {
                    (Some(path), Some(url)) => {
                        Some(archcert_observation::QueryService::connect(&url, path).await?)
                    }
                    _ => None,
                };
                let evaluator = ReadinessRequestEvaluator {
                    commands: &state.repository,
                    observer: observer
                        .as_ref()
                        .map(|query| query as &dyn ReleaseReadinessObserver),
                };
                evaluator.evaluate(&assignment, &context).await?;
            }
            ResolvedControlAction::RequestReleaseBuild { .. } => {
                state
                    .repository
                    .finish(
                        &assignment.lease,
                        &ControlCommandOutcome::Rejected {
                            reason: CommandFailure::UnsupportedAuthorityContext,
                        },
                    )
                    .await?;
            }
        }
    } else {
        // No domain mutation has been attempted under an unavailable/changed selection.
        state
            .repository
            .finish(
                &assignment.lease,
                &ControlCommandOutcome::Rejected {
                    reason: CommandFailure::UnsupportedAuthorityContext,
                },
            )
            .await?;
    }

    checkpoint(&args, "published");
    let receipt = ControlCommandRepository::get(&state.repository, scope, record.id).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ControlCommandResponse::from(receipt))?
    );

    Ok(())
}
