//! Private request and verified workflow admission. No target execution or signing.

use super::*;
use archcert_domain::jobs::JobId;

/// Identifier-only private workflow request; authority selection stays in provisioning.
#[derive(clap::Args)]
pub(crate) struct BuildArgs {
    #[arg(long)]
    project: ProjectId,
    #[arg(long)]
    repository: String,
    /// Exact owned completed certification; no posted certificate or build inputs.
    #[arg(long)]
    job: String,
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

/// Authenticate a fixed request without accepting executable or signing parameters.
pub(crate) async fn request_build(state: &ControlPlane, args: BuildArgs) -> Result<()> {
    let repository = RepositoryId::parse(args.repository)?;
    let job = JobId::parse(&args.job)?;
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
        ControlOperation::RequestReleaseBuild,
        Some(&context),
    )?;

    let record = state
        .request_release_build(&authorization, job, &key)
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ControlCommandResponse::from(record))?
    );

    Ok(())
}

async fn prepare_build(
    state: &ControlPlane,
    assignment: &ControlCommandAssignment,
    context: &Sha256Digest,
    args: &DispatchArgs,
) -> std::result::Result<PreparedReleaseBuild, JobStoreError> {
    let path = args
        .observation_config
        .as_ref()
        .ok_or(JobStoreError::Unavailable)?;
    let url = std::env::var("ARCHCERT_OBSERVATION_DATABASE_URL")
        .map_err(|_| JobStoreError::Unavailable)?;
    let verifier = archcert_observation::QueryService::connect(&url, path).await?;

    ReleaseBuildRequestPreparer {
        commands: &state.repository,
        artifacts: state.artifacts.as_ref(),
        verifier: &verifier,
    }
    .prepare(assignment, context)
    .await
}

pub(super) async fn dispatch_build(
    state: &ControlPlane,
    assignment: &ControlCommandAssignment,
    context: &Sha256Digest,
    args: &DispatchArgs,
) -> Result<()> {
    let prepared = match prepare_build(state, assignment, context, args).await {
        Ok(prepared) => prepared,
        Err(JobStoreError::Unavailable | JobStoreError::SemanticContextLimit) => {
            // Verification has no domain side effect. A new explicit key may retry;
            // its original key must continue to report this exact known rejection.
            state
                .repository
                .finish(
                    &assignment.lease,
                    &ControlCommandOutcome::Rejected {
                        reason: CommandFailure::InfrastructureUnavailable,
                    },
                )
                .await?;
            return Ok(());
        }
        Err(JobStoreError::Invalid | JobStoreError::Precondition) => {
            state
                .repository
                .finish(
                    &assignment.lease,
                    &ControlCommandOutcome::Rejected {
                        reason: CommandFailure::IdentityMismatch,
                    },
                )
                .await?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    match state
        .repository
        .apply_release_build(&assignment.lease, context, &prepared)
        .await
    {
        Ok(_) => Ok(()),
        Err(JobStoreError::Conflict) => {
            // The executor rolled back; the existing immutable M6 admission differs.
            state
                .repository
                .finish(
                    &assignment.lease,
                    &ControlCommandOutcome::Rejected {
                        reason: CommandFailure::DomainPrecondition,
                    },
                )
                .await?;
            Ok(())
        }
        // Grant/fence failures and commit uncertainty must not become known rejection.
        Err(error) => Err(error.into()),
    }
}
