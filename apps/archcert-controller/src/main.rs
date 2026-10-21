//! Trusted durable orchestration. Execution runs in a separate credential-free process.
mod ironcrest;
mod runtime;
use anyhow::{Context, Result, ensure};
use archcert_application::{
    artifacts::ImmutableArtifactStore,
    jobs::*,
    validation::{ObservationFact, ObservationId, ObservationKind, ValidationObservation},
    worker::{MAX_RESULT_BYTES, WorkerAssignment, WorkerResult, pinned_plan},
};
use archcert_certificate::{CertificateDraft, IssuanceContext, IssuanceMetadata};
use archcert_control_plane::{ControlPlane, ControlPlaneConfiguration, read_private};
use archcert_crypto::PublicKey;
use archcert_domain::{execution::ExecutionOutcome, jobs::*, source::digest_bytes};
use archcert_protocol::protobuf::worker::{decode_result, encode_assignment};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Durable pre-admission Ironcrest lifecycle under explicit authority controls.
    Ironcrest {
        #[command(subcommand)]
        command: ironcrest::IroncrestCommand,
    },
    /// Explicitly provisions configured development scope grants, without schema DDL.
    Provision,
    /// Checks control-plane/storage readiness without execution or signing.
    Doctor,
    /// Inspects or removes old unlocked development artifact stages, never final objects.
    ReconcileArtifacts {
        #[arg(long)]
        project: String,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value_t = 3600)]
        minimum_age_seconds: u64,
    },
    /// Advances one durable job, or resumes retained evaluation/signing after restart.
    RunOnce(Box<RunArgs>),
    /// Inspects or safely reconciles exact-attempt runtime ownership and durable state.
    Reconcile(runtime::ReconcileArgs),
    /// Shows internal authority state, including all attempts.
    Show { job: String },
    /// Recovers the exact expired attempt only after durable fenced cleanup.
    Recover {
        job: String,
        #[arg(long)]
        attempt: String,
    },
}
#[derive(clap::Args)]
struct RunArgs {
    #[arg(long)]
    worker_binary: PathBuf,
    #[arg(long)]
    workspace_root: PathBuf,
    #[arg(long)]
    runtime_state_root: Option<PathBuf>,
    #[arg(long)]
    docker: PathBuf,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    development_key: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long, default_value = "development-worker")]
    worker_id: String,
    /// Authority lease duration; heartbeats run at one third of this bounded lifetime.
    #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u32).range(5..=300))]
    lease_seconds: u32,
    /// Authority-only controlled crash injection. Never read from target configuration.
    #[arg(long,value_parser=["lease","staging","evidence-upload","evidence","evaluation","prepared","signed","certificate-upload","challenge","before-evaluation","before-signing"])]
    stop_after: Option<String>,
    /// Authority-only regression hook: wait for the harness to send SIGKILL.
    #[arg(long)]
    hold_checkpoint: bool,
}
fn checkpoint(args: &RunArgs, stage: &str) {
    if args.stop_after.as_deref() == Some(stage) {
        eprintln!("Controlled Ravenport interruption after {stage}");
        if args.hold_checkpoint {
            loop {
                std::thread::park();
            }
        }
        std::process::exit(75);
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let state = ControlPlane::connect(
        &std::env::var("ARCHCERT_DATABASE_URL")?,
        ControlPlaneConfiguration::load(&args.config)?,
    )
    .await?;
    match args.command {
        Command::Ironcrest { command } => ironcrest::command(&state, command).await?,
        Command::Doctor => {
            state.repository.check_readiness().await?;
            state.artifacts.check_readiness()?;
            println!("{{\"control_plane\":\"READY\",\"artifact_store\":\"READY\"}}");
        }
        Command::ReconcileArtifacts {
            project,
            apply,
            minimum_age_seconds,
        } => {
            let project: archcert_domain::ProjectId = project.parse()?;
            ensure!(
                state
                    .configuration
                    .grants
                    .iter()
                    .any(|g| g.project == project),
                "project is not provisioned for this authority"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&state.artifacts.reconcile_staging(
                    project,
                    apply,
                    minimum_age_seconds
                )?)?
            );
        }
        Command::Reconcile(args) => {
            let blocked = runtime::all(&state, &args).await?;
            println!(
                "{}",
                serde_json::json!({"blocked":blocked,"applied":args.apply})
            );
            ensure!(
                !blocked || !args.apply,
                "runtime reconciliation remains blocked"
            );
        }
        Command::Provision => {
            state.provision().await?;
            println!("Authority grants provisioned");
        }
        Command::Show { job } => println!(
            "{}",
            serde_json::to_string_pretty(&state.repository.get(JobId::parse(&job)?).await?)?
        ),
        Command::Recover { job, attempt } => {
            let id = JobId::parse(&job)?;
            state
                .repository
                .recover(id, AttemptId::parse(&attempt)?)
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&state.repository.get(id).await?)?
            );
        }
        Command::RunOnce(args) => {
            if let Some(id) = state.repository.continuations().await?.first().copied() {
                resume(&state, id, &args).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&state.repository.get(id).await?)?
                );
            } else {
                let root = runtime::state_root(&args)?;
                let startup = runtime::ReconcileArgs {
                    docker: args.docker.clone(),
                    endpoint: args.endpoint.clone(),
                    runtime_state_root: root.clone(),
                    workspace_root: args.workspace_root.clone(),
                    apply: true,
                    recover: true,
                    job: None,
                };
                ensure!(
                    !runtime::all(&state, &startup).await?,
                    "startup reconciliation is blocked; no new execution admitted"
                );
                if let Some(id) = state.repository.continuations().await?.first().copied() {
                    resume(&state, id, &args).await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&state.repository.get(id).await?)?
                    );
                    return Ok(());
                }
                let runtime = runtime::runtime(&args)?;
                let binding = runtime::binding(&runtime, &root)?;
                if let Some(assignment) = state
                    .repository
                    .claim(&args.worker_id, args.lease_seconds)
                    .await?
                {
                    let id = assignment.job.id;
                    checkpoint(&args, "lease");
                    let source = state.source(&assignment.job.inputs)?;
                    let mut source_artifact = Vec::new();
                    archcert_source::write_snapshot(&source, &mut source_artifact)?;
                    let work = WorkerAssignment {
                        job: id,
                        attempt: assignment.lease.attempt,
                        inputs: assignment.job.inputs.clone(),
                        source_artifact,
                    };
                    state.repository.start(&assignment.lease).await?;
                    state
                        .repository
                        .bind_runtime(&assignment.lease, &binding)
                        .await?;
                    archcert_runner::ExecutionGateRoot::open(&root)?.create(
                        id,
                        assignment.lease.attempt,
                        &binding,
                    )?;
                    let bytes = execute(&state, &assignment.lease, &work, &args).await?;
                    let result = decode_result(&bytes)?;
                    result.validate(id, assignment.lease.attempt, &assignment.job.inputs)?;
                    archcert_runner::ExecutionGateRoot::open(&root)?
                        .lock(id, assignment.lease.attempt)?
                        .revoke()?;
                    if args.stop_after.as_deref() == Some("staging") {
                        let reference = ArtifactReference {
                            sha256: digest_bytes(&bytes),
                            size: bytes.len() as u64,
                            schema: 1,
                            producer: "archcert-controller-v1/0.1.0".into(),
                        };
                        state
                            .repository
                            .stage_artifact(
                                id,
                                Some(assignment.lease.attempt),
                                "EXECUTION",
                                &reference,
                            )
                            .await?;
                        checkpoint(&args, "staging");
                    }
                    let reference = persist(
                        &state,
                        &assignment.job,
                        Some(assignment.lease.attempt),
                        "EXECUTION",
                        &bytes,
                    )
                    .await?;
                    checkpoint(&args, "evidence-upload");
                    state
                        .repository
                        .accept_evidence(&assignment.lease, &reference)
                        .await?;
                    checkpoint(&args, "evidence");
                    resume(&state, id, &args).await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&state.repository.get(id).await?)?
                    );
                } else {
                    println!("{{\"status\":\"IDLE\"}}");
                }
            }
        }
    }
    Ok(())
}
async fn execute(
    state: &ControlPlane,
    lease: &Lease,
    work: &WorkerAssignment,
    args: &RunArgs,
) -> Result<Vec<u8>> {
    ensure!(
        args.worker_binary.is_absolute()
            && args.worker_binary.canonicalize()? == args.worker_binary,
        "worker executable must be an explicit canonical authority path"
    );
    use std::os::unix::fs::DirBuilderExt;
    let workspace = args.workspace_root.join(work.attempt.to_string());
    archcert_materialization::AuthorityWorkspaceRoot::open(&args.workspace_root)?;
    std::fs::DirBuilder::new().mode(0o700).create(&workspace)?;
    let runtime_root = runtime::state_root(args)?;
    let mut child = tokio::process::Command::new(&args.worker_binary)
        .env_clear()
        .env("TMPDIR", &workspace)
        .arg("--workspace-root")
        .arg(&workspace)
        .arg("--runtime-state-root")
        .arg(runtime_root)
        .arg("--docker")
        .arg(&args.docker)
        .arg("--endpoint")
        .arg(&args.endpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    // No controller environment, database URL, object capability or signer path is inherited.
    let input = encode_assignment(work)?;
    let mut stdin = child.stdin.take().context("worker stdin")?;
    let writer = tokio::spawn(async move {
        stdin.write_all(&input).await?;
        stdin.shutdown().await
    });
    let stdout = child.stdout.take().context("worker stdout")?;
    let reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_RESULT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        Ok::<_, std::io::Error>(bytes)
    });
    let mut ticker = tokio::time::interval(Duration::from_secs(u64::from(args.lease_seconds / 3)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let deadline = tokio::time::sleep(Duration::from_secs(3500));
    tokio::pin!(deadline);
    let status = loop {
        tokio::select! {
            status=child.wait()=>break status?,
            _=ticker.tick()=>{state.repository.renew(lease,args.lease_seconds).await?;},
            _=&mut deadline=>{child.kill().await?;anyhow::bail!("worker deadline exceeded; cleanup confirmation required");}
        }
    };
    writer.await??;
    let bytes = reader.await??;
    ensure!(
        status.success() && bytes.len() <= MAX_RESULT_BYTES,
        "worker failed; lease recovery requires cleanup confirmation"
    );
    Ok(bytes)
}
async fn persist(
    state: &ControlPlane,
    job: &CertificationJob,
    attempt: Option<AttemptId>,
    kind: &str,
    bytes: &[u8],
) -> Result<ArtifactReference> {
    let reference = ArtifactReference {
        sha256: digest_bytes(bytes),
        size: bytes.len() as u64,
        schema: 1,
        producer: "archcert-controller-v1/0.1.0".into(),
    };
    state
        .repository
        .stage_artifact(job.id, attempt, kind, &reference)
        .await?;
    state
        .artifacts
        .put(job.inputs.project, &reference, bytes)
        .await?;
    let retained = state.artifacts.get(job.inputs.project, &reference).await?;
    ensure!(retained == bytes, "artifact publication mismatch");
    state
        .repository
        .artifact_available(job.id, attempt, kind, &reference)
        .await?;
    Ok(reference)
}
fn policy(inputs: &JobInputs) -> Result<archcert_policy::PolicyBundle> {
    let bundle = if inputs.policy.id == archcert_policy::IRONCREST_CONTROLLED_POLICY_ID {
        archcert_policy::ironcrest_controlled_bundle()?
    } else if inputs.policy.id == archcert_policy::RUST_CONTROLLED_POLICY_ID {
        archcert_policy::rust_controlled_bundle()?
    } else {
        archcert_policy::development_bundle()?
    };
    let p = bundle.identity();
    ensure!(
        p.id == inputs.policy.id
            && p.version == inputs.policy.version
            && p.sha256 == inputs.policy.sha256,
        "pinned policy is unavailable; never substitute latest policy"
    );
    Ok(bundle)
}
fn observations(
    result: &WorkerResult,
    plan: &archcert_application::validation::ValidationPlan,
) -> Result<Vec<ValidationObservation>> {
    let mut observations = Vec::new();
    for (step, record) in plan.steps().iter().zip(&result.steps) {
        if let Some(e) = &record.evidence {
            observations.extend(ValidationObservation::from_execution(plan, step, e)?);
        } else {
            observations.push(ValidationObservation {
                schema: 1,
                plan_sha256: plan.digest()?,
                profile: step.profile().name().into(),
                id: ObservationId {
                    execution: record.execution,
                    step: step.id().into(),
                    kind: ObservationKind::ExecutionFinished,
                },
                source: result.source.clone(),
                producer: "archcert-controller-v1/0.1.0".into(),
                fact: ObservationFact::ExecutionFinished {
                    outcome: ExecutionOutcome::SandboxFailure,
                    exit_code: None,
                    category: step.evidence_category(),
                },
            });
        }
    }
    Ok(observations)
}
fn issuance_failure_category(error: &archcert_certificate::CertificateError) -> FailureCategory {
    match error {
        archcert_certificate::CertificateError::Signing(_)
        | archcert_certificate::CertificateError::SigningKeyMismatch => {
            FailureCategory::SigningFailure
        }
        _ => FailureCategory::VerificationFailure,
    }
}
async fn resume(state: &ControlPlane, id: JobId, args: &RunArgs) -> Result<()> {
    checkpoint(args, "evidence");
    let mut job = state.repository.get(id).await?;
    ensure!(
        matches!(job.state, JobState::Evaluating | JobState::Signing),
        "job has no continuation"
    );
    if let Some(attempt) = job.attempts.last()
        && let Some(bound) = &attempt.runtime
        && bound.cleanup != RuntimeCleanupState::Succeeded
    {
        let root = runtime::state_root(args)?;
        let runtime = runtime::runtime(args)?;
        ensure!(
            runtime::one(
                state,
                &runtime,
                &root,
                &args.workspace_root,
                id,
                attempt.id,
                true
            )
            .await?
                == RuntimeCleanupState::Succeeded,
            "durable evidence retained; runtime cleanup must finish before continuation"
        );
        job = state.repository.get(id).await?;
    }
    let attempt = job.attempts.last().context("attempt missing")?;
    let evidence = attempt
        .evidence
        .as_ref()
        .context("durable evidence missing")?;
    let result = decode_result(&state.artifacts.get(job.inputs.project, evidence).await?)?;
    result.validate(id, attempt.id, &job.inputs)?;
    let ironcrest =
        if archcert_application::ironcrest::requires_reviewed_chain(&job.inputs.policy.id) {
            let admission = ironcrest::restore_admission(state, job.inputs.project, id).await?;
            let workflow = archcert_application::ironcrest::IroncrestWorkflow {
                repository: &state.repository,
                artifacts: state.artifacts.as_ref(),
            };
            let challenges = workflow
                .record_challenges(&admission, &job, &result)
                .await?;
            checkpoint(args, "challenge");
            Some(challenges)
        } else {
            None
        };
    checkpoint(args, "before-evaluation");
    let source = state.source(&job.inputs)?;
    let plan = pinned_plan(&job.inputs)?;
    let bundle = policy(&job.inputs)?;
    let executions: Vec<_> = result
        .steps
        .iter()
        .map(|s| archcert_policy::ExpectedExecution {
            step: s.step.clone(),
            execution: s.execution,
        })
        .collect();
    let observations = observations(&result, &plan)?;
    let records: Vec<_> = result
        .steps
        .iter()
        .filter_map(|s| s.evidence.clone())
        .collect();
    let evaluation = archcert_policy::evaluate(
        &bundle,
        bundle.identity(),
        archcert_policy::EvaluationInput {
            source: &source,
            plan: &plan,
            executions: &executions,
            observations: &observations,
            evaluated_at: u64::try_from(
                job.evaluation_at
                    .context("evaluation phase timestamp missing")?,
            )?,
        },
    )?;
    let clean = result
        .steps
        .iter()
        .all(|s| s.source_cleaned && s.sandbox_cleaned && s.evidence.is_some());
    let decision = if !clean
        || evaluation.eligibility == archcert_policy::CertificationEligibility::Inconclusive
    {
        EvaluationDecision::Inconclusive
    } else if evaluation.eligibility
        == archcert_policy::CertificationEligibility::EligibleForCertification
    {
        EvaluationDecision::Eligible
    } else {
        EvaluationDecision::NotEligible
    };
    let bytes = archcert_evidence::canonical_bytes(&evaluation)?;
    if job.evaluation.is_none() {
        let reference = persist(state, &job, None, "EVALUATION", &bytes).await?;
        state
            .repository
            .record_evaluation(id, &reference, decision)
            .await?;
        checkpoint(args, "evaluation");
        job = state.repository.get(id).await?;
    } else {
        let stored = state
            .artifacts
            .get(
                job.inputs.project,
                job.evaluation.as_ref().context("evaluation missing")?,
            )
            .await?;
        ensure!(stored == bytes, "durable evaluation mismatch");
    }
    if decision != EvaluationDecision::Eligible {
        return Ok(());
    }
    let key =
        PublicKey::from_hex(std::str::from_utf8(&read_private(&args.public_key, 1024)?)?.trim())?;
    // A durable prepared issuance fixes time/key/payload across all crash boundaries.
    let issued_at = job.issuance.as_ref().map_or(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        |i| i.issued_at,
    );
    checkpoint(args, "before-signing");
    let ironcrest_evidence = ironcrest.map(|e| e.for_issuance()).transpose()?;
    let context = IssuanceContext {
        source: &source,
        plan: &plan,
        executions: &executions,
        observations: &observations,
        execution_records: &records,
        bundle: &bundle,
        selected: bundle.identity(),
    };
    let metadata = IssuanceMetadata {
        issued_at,
        certifier: "archcert-ravenport-development".into(),
    };
    let draft = if let Some(evidence) = &ironcrest_evidence {
        CertificateDraft::prepare_ironcrest(
            context,
            Some(evaluation),
            metadata,
            key.clone(),
            evidence,
        )?
    } else {
        CertificateDraft::prepare(context, Some(evaluation), metadata, key.clone())?
    };
    let issuance = PreparedIssuance {
        certificate_sha256: draft.certificate().digest().clone(),
        signing_key_id: key.key_id().as_str().into(),
        issued_at,
    };
    persist(
        state,
        &job,
        None,
        "BUNDLE",
        draft.evidence_bundle().canonical_bytes(),
    )
    .await?;
    persist(
        state,
        &job,
        None,
        "MANIFEST",
        draft.manifest().canonical_bytes(),
    )
    .await?;
    state.repository.prepare_issuance(id, &issuance).await?;
    checkpoint(args, "prepared");
    let signer = match archcert_crypto::local::LocalDevelopmentSigner::load(&args.development_key) {
        Ok(signer) => signer,
        Err(e) => {
            state
                .repository
                .note_failure(id, FailureCategory::SigningFailure)
                .await?;
            return Err(e.into());
        }
    };
    let issued = match draft.issue(&signer) {
        Ok(issued) => issued,
        Err(e) => {
            state
                .repository
                .note_failure(id, issuance_failure_category(&e))
                .await?;
            return Err(e.into());
        }
    };
    checkpoint(args, "signed");
    let envelope = issued.envelope().to_json()?;
    issued.envelope().verify(&key)?;
    let reference = persist(state, &job, None, "CERTIFICATE", &envelope).await?;
    checkpoint(args, "certificate-upload");
    let value: serde_json::Value = serde_json::from_slice(&envelope)?;
    let certificate = PersistedCertificate {
        issuance,
        artifact: reference,
        signature: value["signature"]
            .as_str()
            .context("signature missing")?
            .into(),
        verified: true,
    };
    state.repository.complete(id, &certificate).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_errors_and_signature_rejection_have_distinct_audit_categories() {
        assert_eq!(
            issuance_failure_category(&archcert_certificate::CertificateError::Signing(
                archcert_crypto::SigningFailure::SigningFailed
            )),
            FailureCategory::SigningFailure
        );
        assert_eq!(
            issuance_failure_category(&archcert_certificate::CertificateError::SigningKeyMismatch),
            FailureCategory::SigningFailure
        );
        assert_eq!(
            issuance_failure_category(&archcert_certificate::CertificateError::VerificationFailed),
            FailureCategory::VerificationFailure
        );
    }
}
