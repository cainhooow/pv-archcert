//! Authority-only M6 composition. Keys are loaded after all target cleanup.

use anyhow::{Result, ensure};
use archcert_application::{
    configuration::RuntimeConfiguration,
    execution::ExecutionRequest,
    materialization::{MaterializationRequest, SourceMaterializer},
    release::*,
};
use archcert_certificate::{CertificateEnvelope, release::*};
use archcert_control_plane::{ControlPlane, read_private};
use archcert_crypto::{PublicKey, local::LocalDevelopmentSigner};
use archcert_domain::{
    Sha256Digest,
    execution::ExecutionOutcome,
    ingress::{GitActorId, SourceSubmissionId},
    materialization::{MaterializationLimits, SnapshotReference},
    release::*,
};
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_runner::{DockerRootlessRunner, DockerRuntime};
use std::{fs, path::PathBuf, sync::Arc};

/// Trusted operator arguments, never deserialized from target configuration.
#[derive(clap::Args)]
pub struct ReleaseArgs {
    #[arg(long)]
    project: String,
    #[arg(long)]
    repository: String,
    #[arg(long)]
    actor: String,
    #[arg(long)]
    submission: String,
    #[arg(long)]
    source_certificate: PathBuf,
    #[arg(long)]
    source_key: PathBuf,
    #[arg(long)]
    source_policy: String,
    #[arg(long)]
    image: String,
    #[arg(long)]
    dependencies: String,
    #[arg(long)]
    toolchain: String,
    #[arg(long)]
    binary: String,
    #[arg(long)]
    release_key: PathBuf,
    #[arg(long)]
    development_key: PathBuf,
    #[arg(long)]
    workspace_root: PathBuf,
    #[arg(long)]
    docker: PathBuf,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_parser = ["input", "build-a", "build-b", "reproducibility", "payload", "signed", "permit-upload"])]
    stop_after: Option<String>,
    #[arg(long)]
    hold_checkpoint: bool,
}

fn checkpoint(args: &ReleaseArgs, stage: &str) {
    if args.stop_after.as_deref() == Some(stage) {
        eprintln!("Controlled M6 interruption after {stage}");

        if args.hold_checkpoint {
            loop {
                std::thread::park();
            }
        }

        std::process::exit(75);
    }
}

struct Builder {
    source: Arc<archcert_domain::source::SourceSnapshot>,
    recipe: RustReleaseRecipe,
    invocation: BuildInvocationIdentity,
    runtime: RuntimeConfiguration,
}

type BuildExecution = Result<
    archcert_application::execution::CollectedExecution,
    archcert_application::execution::ExecutionFailure,
>;

impl Builder {
    fn execute_recipe(&self) -> Result<(BuildExecution, bool)> {
        let profile = self.recipe.execution_profile()?;
        let runtime = DockerRuntime::for_release(
            self.runtime.docker_executable.clone(),
            self.runtime.docker_endpoint.clone(),
        )?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(
            &self.runtime.workspace_root,
        )?);
        let prepared = materializer.prepare(
            &self.source,
            &MaterializationRequest {
                snapshot: SnapshotReference {
                    project: self.source.project(),
                    repository: self.source.repository().clone(),
                    identity: self.source.identity().clone(),
                },
                limits: MaterializationLimits::default(),
            },
        )?;

        let request = ExecutionRequest::new(
            prepared.runner_input,
            profile,
            self.recipe.description().command.clone(),
        );
        let execution = match request {
            Ok(request) => DockerRootlessRunner::new(runtime).execute_file(request),
            Err(error) => Err(archcert_application::execution::ExecutionFailure {
                error,
                evidence: None,
                cleanup: archcert_application::materialization::CleanupStatus::NotCreated,
                events: vec![],
            }),
        };
        let cleanup = prepared.cleanup.destroy().is_ok();

        Ok((execution, cleanup))
    }
}

impl ReleaseBuilder for Builder {
    fn build(&self, input: &BuildInputManifest, ordinal: BuildOrdinal) -> BuildOutput {
        let mut result = BuildResult {
            schema: 1,
            kind: "ARCHCERT_BUILD_RESULT".into(),
            invocation: self.invocation.clone(),
            ordinal,
            source: input.certified_source.clone(),
            recipe: input.recipe_identity.clone(),
            environment: input.environment_identity.clone(),
            completion: BuildCompletion::Inconclusive,
            execution: None,
            cleanup_complete: false,
            artifact: None,
        };

        let mut artifact = None;
        if let Ok((execution, cleanup)) = self.execute_recipe() {
            let collected = match execution {
                Ok(collected) => collected,
                Err(failure) => {
                    result.execution = failure.evidence.map(|e| *e);
                    result.cleanup_complete = cleanup
                        && failure.cleanup
                            == archcert_application::materialization::CleanupStatus::Destroyed;
                    return BuildOutput {
                        result,
                        artifact: None,
                    };
                }
            };
            let e = collected.execution.evidence;
            result.cleanup_complete = cleanup;

            if cleanup && e.outcome == ExecutionOutcome::Completed && e.exit_code == Some(0) {
                if let Some(bytes) = collected.artifact
                    && let Ok(identity) = artifact_identity(&bytes)
                {
                    result.completion = BuildCompletion::Complete;
                    result.artifact = Some(identity);
                    artifact = Some(bytes);
                }
            } else if cleanup
                && e.outcome == ExecutionOutcome::Completed
                && e.exit_code.is_some_and(|c| c != 0)
            {
                result.completion = BuildCompletion::TargetFailed;
            }

            result.execution = Some(e);
        }

        BuildOutput { result, artifact }
    }
}

/// Resumes accepted evidence and exact payload/signature publication after restart.
pub async fn run(state: &ControlPlane, args: ReleaseArgs) -> Result<()> {
    let source_key =
        PublicKey::from_hex(std::str::from_utf8(&read_private(&args.source_key, 1024)?)?.trim())?;
    let release_key =
        PublicKey::from_hex(std::str::from_utf8(&read_private(&args.release_key, 1024)?)?.trim())?;
    let certificate_bytes = read_private(&args.source_certificate, 65_536)?;
    let certificate = CertificateEnvelope::read(certificate_bytes.as_slice())?;
    let source = certified_source(&certificate, &source_key)?;
    ensure!(
        source.project.to_string() == args.project && source.repository.as_str() == args.repository,
        "source certificate scope differs from requested release"
    );

    let actor = GitActorId::parse(args.actor.clone())?;
    let submission = SourceSubmissionId::parse(&args.submission)?;
    let snapshot = state.release_source(&actor, &submission, &source).await?;
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: args.image.clone(),
            dependency_bundle_sha256: Sha256Digest::parse(args.dependencies.clone())?,
            toolchain_sha256: Sha256Digest::parse(args.toolchain.clone())?,
        },
        &args.binary,
    )?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: source,
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: Sha256Digest::parse(args.source_policy.clone())?,
        source_authority_key_sha256: Sha256Digest::parse(source_key.key_id().as_str())?,
        release_authority_key_sha256: Sha256Digest::parse(release_key.key_id().as_str())?,
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };
    verify_source(&input, &recipe, &certificate, &source_key, &release_key)?;

    let workspace = fs::canonicalize(&args.workspace_root)?;
    for path in [
        &args.source_key,
        &args.release_key,
        &args.source_certificate,
        &args.development_key,
        &args.output,
    ] {
        let resolved = if path.exists() {
            fs::canonicalize(path)?
        } else {
            fs::canonicalize(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("invalid authority path"))?,
            )?
            .join(
                path.file_name()
                    .ok_or_else(|| anyhow::anyhow!("invalid authority path"))?,
            )
        };
        ensure!(
            !resolved.starts_with(&workspace)
                && !resolved.starts_with(&state.configuration.source_store),
            "authority path is inside a target source or workspace root"
        );
    }

    let workflow = ReleaseWorkflow {
        repository: &state.repository,
        artifacts: &*state.artifacts,
    };
    workflow
        .admit(
            &ReleaseAdmission {
                input_reference: release_reference(&release_bytes(&input)?),
                input: input.clone(),
                submission,
                actor,
            },
            &recipe,
            &certificate_bytes,
        )
        .await?;
    println!("{}", serde_json::json!({"invocation": input.identity()?}));
    checkpoint(&args, "input");

    let builder = Builder {
        source: Arc::new(snapshot),
        recipe: recipe.clone(),
        invocation: input.identity()?,
        runtime: RuntimeConfiguration {
            docker_executable: args.docker.clone(),
            docker_endpoint: args.endpoint.clone(),
            workspace_root: workspace,
        },
    };
    let a = workflow
        .run_build(&input, BuildOrdinal::A, &builder)
        .await?;
    checkpoint(&args, "build-a");
    let b = workflow
        .run_build(&input, BuildOrdinal::B, &builder)
        .await?;
    checkpoint(&args, "build-b");
    let comparison = workflow.compare(&input).await?;
    checkpoint(&args, "reproducibility");
    println!("{}", serde_json::to_string(&comparison)?);
    ensure!(
        comparison.verdict == ReproducibilityVerdict::Reproducible,
        "release not eligible; no permit"
    );

    let artifact = workflow
        .read(&input, ReleaseRole::ArtifactA)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing release artifact"))?;
    let draft = ReleasePermitDraft::prepare(ReleasePermitContext {
        input: &input,
        recipe: &recipe,
        source_certificate: &certificate,
        source_key: &source_key,
        release_key: &release_key,
        a: &a,
        b: &b,
        reproducibility: &comparison,
        artifact: &artifact,
    })?;
    let durable = workflow.prepare_payload(&input, draft.bytes()).await?;
    checkpoint(&args, "payload");

    // No untrusted execution remains. Private custody is acquired only here.
    let envelope = if let Some(bytes) = workflow.read(&input, ReleaseRole::PermitEnvelope).await? {
        let envelope = ReleasePermitEnvelope::read(bytes.as_slice())?;
        ensure!(
            envelope.verify(&release_key)? == *draft.identity(),
            "stored permit identity differs"
        );
        envelope
    } else {
        let signer = LocalDevelopmentSigner::load(&args.development_key)?;
        draft.issue(&durable, &signer)?
    };
    checkpoint(&args, "signed");
    let bytes = envelope.to_json()?;
    workflow
        .publish(&input, ReleaseRole::PermitEnvelope, &bytes, None)
        .await?;
    checkpoint(&args, "permit-upload");

    // Export is not authority: immutable storage and the signature remain required.
    let identity = envelope.authorize_artifact(
        &release_key,
        input.certified_source.project,
        &input.certified_source.repository,
        &artifact,
    )?;
    fs::create_dir(&args.output)?;
    fs::write(args.output.join("release-permit.json"), &bytes)?;
    fs::write(args.output.join("artifact"), &artifact)?;
    fs::write(args.output.join("build-input.json"), release_bytes(&input)?)?;
    println!(
        "{}",
        serde_json::json!({"status": "RELEASE_PERMITTED", "permit": identity,
        "notice": "DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY"})
    );

    Ok(())
}

/// Trusted project-scoped status; execution fencing tokens never enter this view.
pub async fn show(state: &ControlPlane, project: &str, invocation: &str) -> Result<()> {
    let project = project.parse()?;
    ensure!(
        state
            .configuration
            .grants
            .iter()
            .any(|g| g.project == project),
        "project is not provisioned for this authority"
    );
    let identity = BuildInvocationIdentity(Sha256Digest::parse(invocation)?);
    let record = ReleaseRepository::get(&state.repository, project, &identity).await?;
    ensure!(
        state
            .configuration
            .grants
            .iter()
            .any(|g| g.project == project
                && g.repository == record.admission.input.certified_source.repository),
        "repository is not provisioned for this authority"
    );
    println!("{}", serde_json::to_string_pretty(&record)?);

    Ok(())
}
