//! ArchCert command-line client bootstrap.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "archcert",
    version,
    about = "ArchCert source inspection and engineering execution evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Independently inspects exact Git source without executing target code.
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// Runs development isolated execution and collects engineering evidence.
    Run(Box<RunArgs>),
    /// Runs development execution and deterministic unsigned policy evaluation; issues no certificate.
    Evaluate(Box<RunArgs>),
    /// Checks strict project requests against the development authority catalog; executes nothing.
    ConfigCheck {
        /// Path to the project-owned ArchCert request configuration.
        #[arg(long, default_value = "archcert.toml")]
        file: PathBuf,
    },
}

/// Authority/operator dry-run inputs. Repository TOML never supplies runtime settings.
#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit Git directory containing selected loose objects.
    #[arg(long)]
    git_dir: PathBuf,
    /// Exact full Git commit ID.
    #[arg(long)]
    commit: String,
    /// Expected independent source SHA-256 (64 hexadecimal characters).
    #[arg(long)]
    snapshot: String,
    /// Registered authority project UUID.
    #[arg(long)]
    project: String,
    /// Registered authority repository label.
    #[arg(long)]
    repository: String,
    /// Existing private mode-0700 materialization root.
    #[arg(long)]
    workspace_root: PathBuf,
    /// Operator-approved profile to provision: python, rust or node (no version assertion).
    #[arg(long)]
    profile: String,
    /// Authority-provisioned immutable repository@sha256 image; no automatic pull.
    #[arg(long)]
    image: String,
    /// Absolute trusted Docker CLI path.
    #[arg(long)]
    docker: PathBuf,
    /// Explicit Unix runtime endpoint; rootless verification is mandatory.
    #[arg(long)]
    endpoint: String,
    /// Sandbox working directory (/source or /work and descendants).
    #[arg(long, default_value = "/source")]
    working_directory: String,
    /// Operator-owned mandatory commands TOML; must reside outside target-controlled source.
    #[arg(long)]
    authority_config: Option<PathBuf>,
    /// Project request TOML, using the same parser as config-check.
    #[arg(long, conflicts_with_all = ["command", "working_directory"])]
    config: Option<PathBuf>,
    /// Literal development program and argv, required when --config is absent.
    #[arg(last = true, required_unless_present_any = ["config", "authority_config"])]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    /// Inspects loose objects in an explicit bare or `.git` directory (development only).
    Inspect {
        /// Explicit Git directory; working-tree files and refs are ignored.
        repository_path: PathBuf,
        /// Full SHA-1/SHA-256 commit object ID; HEAD and abbreviations are rejected.
        commit: String,
        /// Registered project UUID supplied by the authority.
        #[arg(long)]
        project: String,
        /// Authority repository identity, independent of the local path.
        #[arg(long)]
        repository: String,
        /// Development-only: verify/seal under this existing private authority root,
        /// emit evidence, then explicitly destroy the ephemeral workspace. No source runs.
        #[arg(long)]
        materialize_under: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Source { command } => source_command(command),
        Command::ConfigCheck { file } => config_check(&file),
        Command::Run(args) => run_command(*args, false),
        Command::Evaluate(args) => run_command(*args, true),
    }
}

#[cfg(unix)]
fn source_command(command: SourceCommand) -> Result<()> {
    use archcert_application::source::{SourceSubmission, ingest_source};
    use archcert_domain::{
        GitObjectId, ProjectId,
        source::{RepositoryId, SourceLimits},
    };
    use archcert_source::{LocalGitGateway, MemorySourceStore};
    match command {
        SourceCommand::Inspect {
            repository_path,
            commit,
            project,
            repository,
            materialize_under,
        } => {
            let project: ProjectId = serde_json::from_value(serde_json::Value::String(project))?;
            let repository = RepositoryId::parse(repository)?;
            let submission = SourceSubmission {
                project,
                repository: repository.clone(),
                requested_commit: GitObjectId::parse(commit)?,
            };
            let gateway = LocalGitGateway::new(repository, repository_path);
            let mut store = MemorySourceStore::default();
            match ingest_source(&gateway, &mut store, submission, SourceLimits::default()) {
                Ok(result) => {
                    if let Some(root) = materialize_under {
                        use archcert_application::materialization::{
                            MaterializationRequest, materialize_source,
                        };
                        use archcert_domain::materialization::{
                            MaterializationLimits, SnapshotReference,
                        };
                        use archcert_materialization::{
                            AuthorityWorkspaceRoot, UnixSourceMaterializer,
                        };
                        let materializer =
                            UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&root)?);
                        let request = MaterializationRequest {
                            snapshot: SnapshotReference {
                                project: result.snapshot.project(),
                                repository: result.snapshot.repository().clone(),
                                identity: result.snapshot.identity().clone(),
                            },
                            limits: MaterializationLimits::default(),
                        };
                        let prepared = match materialize_source(&store, &materializer, &request) {
                            Ok(prepared) => prepared,
                            Err(failure) => {
                                eprintln!(
                                    "{}",
                                    serde_json::to_string_pretty(
                                        &serde_json::json!({"events": failure.events, "cleanup": failure.cleanup})
                                    )?
                                );
                                return Err(failure.into());
                            }
                        };
                        let destruction = prepared.cleanup.destroy()?;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "source": result.evidence, "materialization": prepared.evidence, "events": prepared.events,
                                "destruction": {"workspace": destruction.workspace, "status": destruction.status,
                                    "destroyed_at": destruction.destroyed_at, "event": destruction.event},
                            }))?
                        );
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result.evidence)?);
                    }
                }
                Err(rejection) => {
                    eprintln!("{}", serde_json::to_string_pretty(&rejection.events)?);
                    return Err(rejection.into());
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn source_command(_command: SourceCommand) -> Result<()> {
    anyhow::bail!("local source inspection is supported only on Unix in this milestone")
}

fn read_project_configuration(
    file: &PathBuf,
) -> Result<archcert_application::configuration::ProjectConfiguration> {
    let input =
        fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    Ok(archcert_application::configuration::ProjectConfiguration::read(input)?)
}

fn config_check(file: &PathBuf) -> Result<()> {
    let config = read_project_configuration(file)?;
    if let Some(request) = config.execution_request() {
        archcert_application::validation::check_development_request(request)?;
    }
    println!("configuration request valid: {}", config.name());
    Ok(())
}

#[cfg(unix)]
fn run_command(args: RunArgs, evaluate_policy: bool) -> Result<()> {
    use archcert_application::{
        configuration::RuntimeConfiguration,
        execution::{ExecutionFailure, SandboxRunner},
        materialization::{MaterializationRequest, materialize_source},
        source::{SourceSubmission, ingest_source},
        validation::{
            AuthorityConfiguration, EvidenceCategory, ProjectExecutionRequest, RequestedStep,
            ValidationObservation,
        },
    };
    use archcert_domain::{
        GitObjectId, ProjectId, Sha256Digest,
        execution::{ExecutionCommand, ExecutionOutcome},
        materialization::{MaterializationLimits, SnapshotReference},
        source::{RepositoryId, SourceLimits},
    };
    use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
    use archcert_runner::{DockerRootlessRunner, DockerRuntime};
    use archcert_source::{LocalGitGateway, MemorySourceStore};
    let authority = AuthorityConfiguration::development(vec![(args.profile.clone(), args.image)])?;
    let authority = if let Some(file) = &args.authority_config {
        let config = read_project_configuration(file)?;
        let request = config
            .execution_request()
            .context("authority commands required")?;
        authority.with_required_steps(
            request
                .steps()
                .iter()
                .map(
                    |s| archcert_application::validation::AuthorityRequiredStep {
                        id: s.id.clone(),
                        profile: request.profile().into(),
                        command: s.command.clone(),
                        evidence: s.evidence,
                    },
                )
                .collect(),
        )?
    } else {
        authority
    };
    let policy = archcert_policy::development_bundle()?;
    let config = args
        .config
        .as_ref()
        .map(read_project_configuration)
        .transpose()?;
    let direct_request;
    let project_request = if let Some(config) = &config {
        config.execution_request()
    } else if !args.command.is_empty() {
        let (program, argv) = args.command.split_first().context("program required")?;
        direct_request = ProjectExecutionRequest::new(
            args.profile,
            vec![RequestedStep {
                id: "development-command".into(),
                command: ExecutionCommand::new(
                    program.clone(),
                    argv.to_vec(),
                    args.working_directory,
                )?,
                evidence: EvidenceCategory::Execution,
            }],
        );
        Some(&direct_request)
    } else {
        None
    };
    let plan = authority.resolve(project_request)?;
    anyhow::ensure!(!plan.steps().is_empty(), "no execution steps requested");
    let runtime = RuntimeConfiguration {
        docker_executable: args.docker,
        docker_endpoint: args.endpoint,
        workspace_root: args.workspace_root,
    };
    let runner = DockerRootlessRunner::new(DockerRuntime::new(
        runtime.docker_executable,
        runtime.docker_endpoint,
    )?);
    // execute performs its own preflight; a failed preflight must remain observable to policy.
    let repository = RepositoryId::parse(args.repository)?;
    let project: ProjectId = serde_json::from_value(serde_json::Value::String(args.project))?;
    let gateway = LocalGitGateway::new(repository.clone(), args.git_dir);
    let mut store = MemorySourceStore::default();
    let source = ingest_source(
        &gateway,
        &mut store,
        SourceSubmission {
            project,
            repository,
            requested_commit: GitObjectId::parse(args.commit)?,
        },
        SourceLimits::default(),
    )?;
    anyhow::ensure!(
        source.snapshot.identity().snapshot_sha256 == Sha256Digest::parse(args.snapshot)?,
        "source identity mismatch"
    );
    let materializer =
        UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&runtime.workspace_root)?);
    let mut results = Vec::new();
    let mut successful = true;
    let mut all_observations = Vec::new();
    let mut expected_executions = Vec::new();
    for step in plan.steps() {
        let prepared = materialize_source(
            &store,
            &materializer,
            &MaterializationRequest {
                snapshot: SnapshotReference {
                    project,
                    repository: source.snapshot.repository().clone(),
                    identity: source.snapshot.identity().clone(),
                },
                limits: MaterializationLimits::default(),
            },
        )?;
        let execution = match step.execution_request(prepared.runner_input) {
            Ok(request) => runner.execute(request),
            Err(error) => Err(ExecutionFailure {
                error,
                evidence: None,
                cleanup: archcert_application::materialization::CleanupStatus::NotCreated,
                events: vec![],
            }),
        };
        // Control plane always attempts source cleanup, including source-bound request failure.
        let source_cleanup = prepared.cleanup.destroy();
        successful &= source_cleanup.is_ok()
            && execution.as_ref().is_ok_and(|r| {
                r.evidence.outcome == ExecutionOutcome::Completed && r.evidence.exit_code == Some(0)
            });
        let bound_execution = match &execution {
            Ok(result) => result.evidence.execution,
            Err(failure) => failure
                .evidence
                .as_ref()
                .map_or_else(archcert_domain::execution::ExecutionId::new, |e| {
                    e.execution
                }),
        };
        expected_executions.push(archcert_policy::ExpectedExecution {
            step: step.id().into(),
            execution: bound_execution,
        });
        let mut observations = match &execution {
            Ok(result) => Some(ValidationObservation::from_execution(
                &plan,
                step,
                &result.evidence,
            )?),
            Err(failure) => failure
                .evidence
                .as_ref()
                .map(|evidence| ValidationObservation::from_execution(&plan, step, evidence))
                .transpose()?,
        };
        if observations.is_none() {
            observations = Some(vec![ValidationObservation {
                schema: 1,
                plan_sha256: plan.digest()?,
                profile: step.profile().name().into(),
                id: archcert_application::validation::ObservationId {
                    execution: bound_execution,
                    step: step.id().into(),
                    kind: archcert_application::validation::ObservationKind::ExecutionFinished,
                },
                source: source.snapshot.identity().clone(),
                producer: "archcert-controller-v1/0.1.0".into(),
                fact: archcert_application::validation::ObservationFact::ExecutionFinished {
                    outcome: ExecutionOutcome::SandboxFailure,
                    exit_code: None,
                    category: step.evidence_category(),
                },
            }]);
        }
        if let Some(observed) = &observations {
            all_observations.extend(observed.clone());
        }
        results.push(serde_json::json!({
            "step":step.id(), "origin":step.origin(), "observations":observations,
            "execution":match &execution {Ok(result)=>serde_json::to_value(result)?,Err(failure)=>serde_json::to_value(failure)?},
            "source_cleanup":match &source_cleanup {Ok(receipt)=>serde_json::json!({"status":receipt.status,"workspace":receipt.workspace}),Err(error)=>serde_json::json!({"error":error})},
        }));
    }
    let evaluation = if evaluate_policy {
        Some(archcert_policy::evaluate(
            &policy,
            policy.identity(),
            archcert_policy::EvaluationInput {
                source: &source.snapshot,
                plan: &plan,
                executions: &expected_executions,
                observations: &all_observations,
                evaluated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            },
        )?)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "kind":if evaluate_policy {"UNSIGNED POLICY EVALUATION"} else {"ENGINEERING_EXECUTION_EVIDENCE"},
            "notice":"NOT A CERTIFICATE", "certificate":"NOT ISSUED", "source":source.evidence,
            "plan":plan, "expected_executions":expected_executions, "steps":results, "evaluation":evaluation,
        }))?
    );
    anyhow::ensure!(
        successful,
        "development execution did not complete successfully with cleanup"
    );
    Ok(())
}

#[cfg(not(unix))]
fn run_command(_: RunArgs, _: bool) -> Result<()> {
    anyhow::bail!("execution requires Unix source preparation and a rootless Linux OCI daemon")
}
