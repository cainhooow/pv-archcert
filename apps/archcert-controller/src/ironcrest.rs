//! Thin trusted CLI composition for application-owned durable review/admission.

use anyhow::{Result, ensure};
use archcert_application::{ironcrest::*, semantic::*};
use archcert_control_plane::{ControlPlane, read_private};
use archcert_domain::{ProjectId, ingress::SourceSubmissionId, jobs::JobId, source::RepositoryId};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum IroncrestCommand {
    /// Authenticate a source request and reserve a non-executing review session.
    Open(OpenArgs),
    /// Persist exact authority-selected inputs; print only request identity metadata.
    Prepare(SessionArgs),
    /// Restore accepted review, or use explicitly provisioned local replay/failure.
    Review(ReviewArgs),
    /// Inspect scoped durable review metadata without invoking a reviewer.
    Show(SessionArgs),
}

#[derive(Args)]
pub struct OpenArgs {
    #[arg(long)]
    project: String,
    #[arg(long)]
    repository: String,
    #[arg(long)]
    submission: String,
    #[arg(long)]
    session: String,
    #[arg(long)]
    token_file: PathBuf,
    /// Authority-only recovery qualification after the committed session creation.
    #[arg(long)]
    hold_checkpoint: bool,
}

#[derive(Args)]
pub struct SessionArgs {
    #[arg(long)]
    project: String,
    #[arg(long)]
    session: String,
    /// Authority-controlled process exit after an accepted durable publication.
    #[arg(long,value_parser=["profile","knowledge","impact","request"])]
    stop_after: Option<String>,
    /// Authority-only regression hook: wait for the harness to send SIGKILL.
    #[arg(long)]
    hold_checkpoint: bool,
}

#[derive(Args)]
pub struct ReviewArgs {
    #[arg(long)]
    project: String,
    #[arg(long)]
    session: String,
    /// Private authority-provisioned exact replay. Absence means unavailable.
    #[arg(long)]
    response_file: Option<PathBuf>,
    #[arg(long,value_parser=["claim","response","review","gate","plan","admitted"])]
    stop_after: Option<String>,
    /// Authority-only regression hook: wait for the harness to send SIGKILL.
    #[arg(long)]
    hold_checkpoint: bool,
}

fn checkpoint(selected: Option<&str>, stage: &str, hold: bool) {
    if selected == Some(stage) {
        eprintln!("Controlled Ironcrest interruption after {stage}");

        if hold {
            loop {
                std::thread::park();
            }
        }

        std::process::exit(75);
    }
}

struct ClaimCheckpoint<'a> {
    inner: &'a dyn SemanticReviewer,
    stop: Option<&'a str>,
    hold: bool,
}

#[async_trait::async_trait]
impl SemanticReviewer for ClaimCheckpoint<'_> {
    async fn review(
        &self,
        request: &SemanticReviewRequest,
    ) -> Result<ReviewerOutput, SemanticReviewError> {
        checkpoint(self.stop, "claim", self.hold);
        let output = self.inner.review(request).await;
        checkpoint(self.stop, "response", self.hold);

        output
    }
}

pub async fn command(state: &ControlPlane, command: IroncrestCommand) -> Result<()> {
    match command {
        IroncrestCommand::Open(args) => {
            let token = read_private(&args.token_file, 1024)?;
            let actor = state
                .configuration
                .authenticate(std::str::from_utf8(&token)?.trim())?;
            let session = state
                .open_ironcrest(
                    actor,
                    args.project.parse()?,
                    RepositoryId::parse(args.repository)?,
                    SourceSubmissionId::parse(&args.submission)?,
                    JobId::parse(&args.session)?,
                )
                .await?;

            if args.hold_checkpoint {
                checkpoint(Some("session"), "session", true);
            }

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "review_recovery": session.review_recovery(),
                    "session": session
                }))?
            );
        }
        IroncrestCommand::Show(args) => {
            let session = state
                .repository
                .review_session(args.project.parse()?, JobId::parse(&args.session)?)
                .await?;
            state.configuration.grant_for(
                &session.pin.actor,
                session.pin.project,
                &session.pin.repository,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "review_recovery": session.review_recovery(),
                    "session": session
                }))?
            );
        }
        IroncrestCommand::Prepare(args) => {
            let prepared = state
                .prepare_ironcrest(args.project.parse()?, JobId::parse(&args.session)?)
                .await?;
            let workflow = IroncrestWorkflow {
                repository: &state.repository,
                artifacts: state.artifacts.as_ref(),
            };
            workflow
                .prepare_with_checkpoints(
                    &prepared.request,
                    &prepared.knowledge,
                    &prepared.impact,
                    prepared.profile.artifact(),
                    &|role| {
                        let stage = match role {
                            IroncrestEvidenceRole::AuthorityProfile => "profile",
                            IroncrestEvidenceRole::Knowledge => "knowledge",
                            IroncrestEvidenceRole::Impact => "impact",
                            IroncrestEvidenceRole::Request => "request",
                            _ => "unsupported",
                        };
                        checkpoint(args.stop_after.as_deref(), stage, args.hold_checkpoint);

                        Ok(())
                    },
                )
                .await?;

            let mut summary = serde_json::json!({
                "session": prepared.id,
                "request_sha256": prepared.request.artifact().digest(),
                "binding": prepared.request.binding(),
                "reviewer": prepared.request.selection(),
                "measurements": prepared.measurements,
                "package_sha256": prepared.request.package().map(|p|p.artifact().digest()),
                "coverage": prepared.request.package().map(|p|p.coverage())
            });

            if let Some(identity) = prepared.request.semantic_identity() {
                summary["semantic_identity"] = serde_json::json!(identity);
            }

            println!("{summary}");
        }
        IroncrestCommand::Review(args) => {
            let prepared = state
                .prepare_ironcrest(args.project.parse()?, JobId::parse(&args.session)?)
                .await?;
            let workflow = IroncrestWorkflow {
                repository: &state.repository,
                artifacts: state.artifacts.as_ref(),
            };
            workflow
                .prepare(
                    &prepared.request,
                    &prepared.knowledge,
                    &prepared.impact,
                    prepared.profile.artifact(),
                )
                .await?;
            let reviewer: Box<dyn SemanticReviewer> = if let Some(path) = args.response_file {
                Box::new(archcert_semantic::ReplayReviewer::new(
                    prepared.request.artifact().digest().clone(),
                    read_private(&path, 65536)?,
                )?)
            } else {
                Box::new(archcert_semantic::UnavailableReviewer)
            };
            let review = workflow
                .review_or_restore(
                    &prepared.request,
                    &ClaimCheckpoint {
                        inner: reviewer.as_ref(),
                        stop: args.stop_after.as_deref(),
                        hold: args.hold_checkpoint,
                    },
                )
                .await?;
            checkpoint(args.stop_after.as_deref(), "review", args.hold_checkpoint);
            let decision = workflow.persist_gate(&prepared.request, &review).await?;
            checkpoint(args.stop_after.as_deref(), "gate", args.hold_checkpoint);

            if decision == SemanticGateDecision::Block
                || semantic_gate(&prepared.request, Some(&review)) != SemanticGateDecision::Continue
            {
                let mut summary = serde_json::json!({
                    "session": prepared.id,
                    "semantic_gate": decision,
                    "status": if decision == SemanticGateDecision::Block {
                        "SEMANTIC_BLOCK"
                    } else {
                        "INCONCLUSIVE"
                    },
                    "certificate": "NOT_ISSUED"
                });

                if let Some(identity) = prepared.request.semantic_identity() {
                    summary["semantic_identity"] = serde_json::json!(identity);
                    summary["provider_outcome"] =
                        serde_json::json!(review.supplement().map(|s| s.outcome));
                    summary["provider_error"] = serde_json::json!(review.error());
                }

                println!("{summary}");
                return Ok(());
            }

            let admission = workflow
                .freeze_admission(prepared.admission_context(&review))
                .await?;
            checkpoint(args.stop_after.as_deref(), "plan", args.hold_checkpoint);
            let job = state.repository.admit_reviewed(&admission).await?;
            checkpoint(args.stop_after.as_deref(), "admitted", args.hold_checkpoint);

            ensure!(job.id == prepared.id, "reserved Ironcrest job changed");

            println!("{}", serde_json::to_string_pretty(&job)?);
        }
    }

    Ok(())
}

/// Restore accepted semantic evidence and immutable plan without a provider call.
pub async fn restore_admission(
    state: &ControlPlane,
    project: ProjectId,
    id: JobId,
) -> Result<ReviewedIroncrestAdmission> {
    let prepared = state.prepare_ironcrest(project, id).await?;
    let workflow = IroncrestWorkflow {
        repository: &state.repository,
        artifacts: state.artifacts.as_ref(),
    };
    let review = workflow
        .review_or_restore(&prepared.request, &archcert_semantic::UnavailableReviewer)
        .await?;
    let admission = workflow
        .freeze_admission(prepared.admission_context(&review))
        .await?;
    state.repository.admitted_review(&admission).await?;

    Ok(admission)
}
