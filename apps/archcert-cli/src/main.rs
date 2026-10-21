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
    /// Issues a DEVELOPMENT CERTIFICATE after execution, eligibility, signing and verification.
    Certify(Box<CertifyArgs>),
    /// Verifies a certificate offline under an explicitly trusted Ed25519 public key.
    Verify {
        certificate: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Creates a DEVELOPMENT ONLY local key outside repositories and workspaces.
    DevelopmentKeygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Checks strict project requests against the development authority catalog; executes nothing.
    ConfigCheck {
        /// Path to the project-owned ArchCert request configuration.
        #[arg(long, default_value = "archcert.toml")]
        file: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
struct CertifyArgs {
    #[command(flatten)]
    run: RunArgs,
    /// Explicit authority-owned DEVELOPMENT ONLY PKCS#8 private-key file.
    #[arg(long)]
    development_key: PathBuf,
    /// Separately selected trusted public-key hex file.
    #[arg(long)]
    public_key: PathBuf,
    /// New authority evidence directory outside source and materialization roots.
    #[arg(long)]
    output: PathBuf,
}

struct CertificationOptions {
    key: PathBuf,
    public_key: PathBuf,
    output: PathBuf,
}

/// Authority/operator dry-run inputs. Repository TOML never supplies runtime settings.
#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Explicit Git directory containing selected loose objects.
    #[arg(
        long,
        required_unless_present = "source_submission",
        conflicts_with = "source_submission"
    )]
    git_dir: Option<PathBuf>,
    /// Exact full Git commit ID.
    #[arg(
        long,
        required_unless_present = "source_submission",
        conflicts_with = "source_submission"
    )]
    commit: Option<String>,
    /// Accepted Northgate submission UUID; no Git acquisition occurs during execution.
    #[arg(long, requires = "source_store")]
    source_submission: Option<String>,
    /// Authority-owned development submission store.
    #[arg(long, requires = "source_submission")]
    source_store: Option<PathBuf>,
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
    /// Operator-approved family: python, rust, node or rust-workspace-v1; tools require an approved image.
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
    /// Shows immutable source-ingress evidence for an accepted Northgate submission.
    Show {
        submission: String,
        #[arg(long)]
        store: PathBuf,
    },
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
        Command::Run(args) => run_command(*args, false, None),
        Command::Evaluate(args) => run_command(*args, true, None),
        Command::Certify(args) => {
            validate_authority_paths(&args)?;
            run_command(
                args.run,
                true,
                Some(CertificationOptions {
                    key: args.development_key,
                    public_key: args.public_key,
                    output: args.output,
                }),
            )
        }
        Command::Verify {
            certificate,
            public_key,
        } => verify_command(&certificate, &public_key),
        Command::DevelopmentKeygen {
            private_key,
            public_key,
        } => development_keygen(&private_key, &public_key),
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
        SourceCommand::Show { submission, store } => {
            let store = archcert_gateway::DevelopmentSubmissionStore::open(&store, 32)?;
            let source = store.load(&archcert_domain::ingress::SourceSubmissionId::parse(
                &submission,
            )?)?;
            println!("{}", serde_json::to_string_pretty(&source.evidence)?);

            Ok(())
        }
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
                                    serde_json::to_string_pretty(&serde_json::json!({
                                        "events": failure.events,
                                        "cleanup": failure.cleanup
                                    }))?
                                );
                                return Err(failure.into());
                            }
                        };
                        let destruction = prepared.cleanup.destroy()?;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "source": result.evidence,
                                "materialization": prepared.evidence,
                                "events": prepared.events,
                                "destruction": {
                                    "workspace": destruction.workspace,
                                    "status": destruction.status,
                                    "destroyed_at": destruction.destroyed_at,
                                    "event": destruction.event
                                },
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
fn run_command(
    args: RunArgs,
    evaluate_policy: bool,
    certification: Option<CertificationOptions>,
) -> Result<()> {
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
    let mut store = MemorySourceStore::default();
    let source = if let Some(id) = args.source_submission {
        use archcert_application::source::{SourceEvidence, SourceIngestion, SourceStore};
        let source_store = archcert_gateway::DevelopmentSubmissionStore::open(
            args.source_store
                .as_ref()
                .context("source store required")?,
            32,
        )?;
        let accepted =
            source_store.load(&archcert_domain::ingress::SourceSubmissionId::parse(&id)?)?;

        anyhow::ensure!(
            accepted.snapshot.project() == project && accepted.snapshot.repository() == &repository,
            "submission scope mismatch"
        );

        let snapshot = store.retain(accepted.snapshot)?;
        let evidence = SourceEvidence {
            submission: SourceSubmission {
                project,
                repository,
                requested_commit: snapshot.identity().commit.clone(),
            },
            identity: snapshot.identity().clone(),
            entry_count: snapshot.files().len() as u64,
            object_count: snapshot.object_count(),
            total_bytes: snapshot.total_bytes(),
            unresolved: snapshot.external().to_vec(),
            status: snapshot.status(),
            validation_version: "archcert-northgate-store-v1".into(),
            schema_version: snapshot.schema_version(),
            resolved_binding: (snapshot.schema_version() == 2).then(|| snapshot.binding().clone()),
            created_at: snapshot.created_at(),
            limits: SourceLimits::default(),
        };
        SourceIngestion {
            snapshot,
            evidence,
            events: Vec::new(),
        }
    } else {
        let gateway = LocalGitGateway::new(
            repository.clone(),
            args.git_dir.context("Git directory required")?,
        );
        ingest_source(
            &gateway,
            &mut store,
            SourceSubmission {
                project,
                repository,
                requested_commit: GitObjectId::parse(
                    args.commit.context("exact commit required")?,
                )?,
            },
            SourceLimits::default(),
        )?
    };

    anyhow::ensure!(
        source.snapshot.identity().snapshot_sha256 == Sha256Digest::parse(args.snapshot)?,
        "source identity mismatch"
    );

    let materializer =
        UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&runtime.workspace_root)?);
    let mut results = Vec::new();
    let mut execution_records = Vec::new();
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

        match &execution {
            Ok(r) => execution_records.push(r.evidence.clone()),
            Err(f) => {
                if let Some(e) = &f.evidence {
                    execution_records.push((**e).clone());
                }
            }
        }

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
            "step": step.id(),
            "origin": step.origin(),
            "observations": observations,
            "execution": match &execution {
                Ok(result) => serde_json::to_value(result)?,
                Err(failure) => serde_json::to_value(failure)?,
            },
            "source_cleanup": match &source_cleanup {
                Ok(receipt) => serde_json::json!({
                    "status": receipt.status,
                    "workspace": receipt.workspace,
                }),
                Err(error) => serde_json::json!({
                    "error": error,
                }),
            },
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

    let report = serde_json::json!({
        "kind": if evaluate_policy {
            "UNSIGNED POLICY EVALUATION"
        } else {
            "ENGINEERING_EXECUTION_EVIDENCE"
        },
        "notice": "NOT A CERTIFICATE",
        "certificate": "NOT ISSUED",
        "source": source.evidence,
        "plan": plan,
        "expected_executions": expected_executions,
        "steps": results,
        "evaluation": evaluation,
    });

    if let Some(options) = certification {
        // All execute calls and source cleanup attempts have ended. Refuse issuance
        // after any execution/cleanup failure; private keys have not been loaded.
        fs::create_dir(&options.output)
            .context("evidence output must be a new authority directory")?;
        fs::write(
            options.output.join("evidence.json"),
            serde_json::to_vec_pretty(&report)?,
        )?;
        let issuance = (|| -> Result<_> {
            anyhow::ensure!(
                successful,
                "execution or cleanup failed; CERTIFICATE NOT ISSUED"
            );

            let e = evaluation.context("missing evaluation")?;

            anyhow::ensure!(
                e.eligibility
                    == archcert_policy::CertificationEligibility::EligibleForCertification,
                "evaluation not eligible; CERTIFICATE NOT ISSUED"
            );

            let key = read_public_key(&options.public_key)?;

            let draft = archcert_certificate::CertificateDraft::prepare(
                archcert_certificate::IssuanceContext {
                    source: &source.snapshot,
                    plan: &plan,
                    executions: &expected_executions,
                    observations: &all_observations,
                    execution_records: &execution_records,
                    bundle: &policy,
                    selected: policy.identity(),
                },
                Some(e),
                archcert_certificate::IssuanceMetadata {
                    issued_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs(),
                    certifier: "archcert-development-cli".into(),
                },
                key.clone(),
            )?;

            fs::write(
                options.output.join("evidence-bundle.json"),
                draft.evidence_bundle().canonical_bytes(),
            )?;
            fs::write(
                options.output.join("evidence-manifest.json"),
                draft.manifest().canonical_bytes(),
            )?;
            fs::write(
                options.output.join("canonical-certificate.json"),
                draft.certificate().bytes(),
            )?;

            // This is the first private-key operation in certify, after the complete
            // eligibility/integrity/reference gate and after target destruction.
            let issued = issue_development(draft, &options.key)?;
            fs::write(
                options.output.join("certificate.json"),
                issued.envelope().to_json()?,
            )?;
            fs::write(options.output.join("public-key.hex"), key.to_hex())?;
            let envelope: serde_json::Value =
                serde_json::from_slice(&issued.envelope().to_json()?)?;
            fs::write(
                options.output.join("signature.hex"),
                envelope["signature"].as_str().context("signature")?,
            )?;

            let verified = issued.verification().report();
            fs::write(
                options.output.join("verification.json"),
                serde_json::to_vec_pretty(&verified)?,
            )?;

            Ok(verified)
        })();

        match issuance {
            Ok(verified) => {
                println!("{}", serde_json::to_string_pretty(&verified)?);
                return Ok(());
            }
            Err(error) => {
                let rejection = serde_json::json!({
                    "certificate": "CERTIFICATE NOT ISSUED",
                    "eligibility": report["evaluation"]["eligibility"],
                    "reason": error.to_string()
                });
                fs::write(
                    options.output.join("rejection.json"),
                    serde_json::to_vec_pretty(&rejection)?,
                )?;
                println!("{}", serde_json::to_string_pretty(&rejection)?);
                return Err(error);
            }
        }
    }

    println!("{}", serde_json::to_string_pretty(&report)?);

    anyhow::ensure!(
        successful,
        "development execution did not complete successfully with cleanup"
    );

    Ok(())
}

#[cfg(not(unix))]
fn run_command(_: RunArgs, _: bool, _: Option<CertificationOptions>) -> Result<()> {
    anyhow::bail!("execution requires Unix source preparation and a rootless Linux OCI daemon")
}

fn read_public_key(path: &std::path::Path) -> Result<archcert_crypto::PublicKey> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(66).read_to_end(&mut bytes)?;

    let text = std::str::from_utf8(&bytes)?;

    Ok(archcert_crypto::PublicKey::from_hex(
        text.strip_suffix('\n').unwrap_or(text),
    )?)
}

fn verify_command(certificate: &std::path::Path, public_key: &std::path::Path) -> Result<()> {
    let result = (|| -> Result<_> {
        let key = read_public_key(public_key)?;
        let envelope =
            archcert_certificate::CertificateEnvelope::read(fs::File::open(certificate)?)?;

        Ok(envelope.verify(&key)?.report())
    })();

    match result {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);

            Ok(())
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "VERIFICATION FAILED",
                    "reason": error.to_string()
                }))?
            );
            Err(error)
        }
    }
}

fn validate_authority_paths(args: &CertifyArgs) -> Result<()> {
    let git = fs::canonicalize(
        args.run
            .git_dir
            .as_ref()
            .or(args.run.source_store.as_ref())
            .context("source root required")?,
    )?;
    let source_root = if git.file_name().is_some_and(|s| s == ".git") {
        git.parent().context("repository parent")?
    } else {
        &git
    };

    let workspace = fs::canonicalize(&args.run.workspace_root)?;

    for path in [&args.development_key, &args.public_key, &args.output] {
        let parent = fs::canonicalize(
            path.parent()
                .context("explicit authority parent required")?,
        )?;

        anyhow::ensure!(
            !parent.starts_with(source_root) && !parent.starts_with(&workspace),
            "authority key and output paths must be outside source and materialization roots"
        );

        if path.exists() {
            let resolved = fs::canonicalize(path)?;

            anyhow::ensure!(
                !resolved.starts_with(source_root) && !resolved.starts_with(&workspace),
                "authority path resolves inside source or materialization root"
            );
        }
    }

    Ok(())
}

#[cfg(unix)]
fn development_keygen(private_key: &std::path::Path, public_key: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let mut public_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(public_key)?;
    let key = archcert_crypto::local::LocalDevelopmentSigner::generate(private_key)?;

    public_file.write_all(key.to_hex().as_bytes())?;
    println!(
        "DEVELOPMENT ONLY / NOT PRODUCTION KEY MANAGEMENT; signing key ID {}",
        key.key_id().as_str()
    );

    Ok(())
}

#[cfg(not(unix))]
fn development_keygen(_: &std::path::Path, _: &std::path::Path) -> Result<()> {
    anyhow::bail!("development keys require Unix")
}

#[cfg(unix)]
fn issue_development(
    draft: archcert_certificate::CertificateDraft,
    path: &std::path::Path,
) -> Result<archcert_certificate::IssuedCertificate> {
    let signer = archcert_crypto::local::LocalDevelopmentSigner::load(path)?;

    Ok(draft.issue(&signer)?)
}

#[cfg(not(unix))]
fn issue_development(
    _: archcert_certificate::CertificateDraft,
    _: &std::path::Path,
) -> Result<archcert_certificate::IssuedCertificate> {
    anyhow::bail!("development signer requires Unix")
}
