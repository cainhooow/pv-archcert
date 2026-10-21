//! Leased execution process. No database, object-store or signing credentials.

use anyhow::{Result, ensure};
use archcert_application::{
    execution::SandboxRunner,
    materialization::{CleanupStatus, MaterializationRequest, materialize_source},
    source::SourceStore,
    worker::{MAX_ASSIGNMENT_BYTES, StepResult, WorkerResult, pinned_plan},
};
use archcert_domain::{
    execution::ExecutionId,
    materialization::{MaterializationLimits, SnapshotReference},
    source::SourceLimits,
};
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_protocol::protobuf::worker::{decode_assignment, encode_result};
use archcert_runner::{DockerRootlessRunner, DockerRuntime};
use archcert_source::{MemorySourceStore, read_snapshot};
use clap::{Parser, Subcommand};
use std::{
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    workspace_root: Option<PathBuf>,
    #[arg(long)]
    docker: PathBuf,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    runtime_state_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Observes runtime prerequisites without accepting an assignment or starting a target.
    Doctor,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if matches!(args.command, Some(Command::Doctor)) {
        let runner = DockerRootlessRunner::new(DockerRuntime::new(args.docker, args.endpoint)?);
        let observed = runner.verify_environment()?;
        println!("{}", serde_json::to_string(&observed)?);
        return Ok(());
    }

    let workspace_root = args.workspace_root.ok_or_else(|| {
        anyhow::anyhow!("--workspace-root is required when executing an assignment")
    })?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_ASSIGNMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;

    let assignment = decode_assignment(&bytes)?;
    let inputs = &assignment.inputs;
    let snapshot = read_snapshot(
        assignment.source_artifact.as_slice(),
        SourceLimits::default(),
    )?;

    ensure!(
        snapshot.project() == inputs.project
            && snapshot.repository() == &inputs.repository
            && snapshot.identity() == &inputs.source,
        "assignment source binding mismatch"
    );

    snapshot.require_complete()?;
    let plan = pinned_plan(inputs)?;
    let mut store = MemorySourceStore::default();
    store.retain(snapshot)?;

    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&workspace_root)?);
    let runner = DockerRootlessRunner::for_attempt(
        DockerRuntime::new(args.docker, args.endpoint)?,
        args.runtime_state_root.ok_or_else(|| {
            anyhow::anyhow!("--runtime-state-root is required for durable execution")
        })?,
        assignment.job,
        assignment.attempt,
    );

    let mut steps = Vec::new();

    for step in plan.steps() {
        let prepared = materialize_source(
            &store,
            &materializer,
            &MaterializationRequest {
                snapshot: SnapshotReference {
                    project: inputs.project,
                    repository: inputs.repository.clone(),
                    identity: inputs.source.clone(),
                },
                limits: MaterializationLimits::default(),
            },
        );
        let record = match prepared {
            Ok(prepared) => {
                let execution = match step.execution_request(prepared.runner_input) {
                    Ok(request) => runner.execute(request),
                    Err(error) => Err(archcert_application::execution::ExecutionFailure {
                        error,
                        evidence: None,
                        cleanup: CleanupStatus::NotCreated,
                        events: vec![],
                    }),
                };

                let source_cleaned = prepared.cleanup.destroy().is_ok();

                match execution {
                    Ok(result) => StepResult {
                        step: step.id().into(),
                        execution: result.evidence.execution,
                        evidence: Some(result.evidence),
                        source_cleaned,
                        sandbox_cleaned: result.cleanup == CleanupStatus::Destroyed,
                    },
                    Err(failure) => StepResult {
                        step: step.id().into(),
                        execution: failure
                            .evidence
                            .as_ref()
                            .map_or_else(ExecutionId::new, |e| e.execution),
                        evidence: failure.evidence.map(|e| *e),
                        source_cleaned,
                        sandbox_cleaned: failure.cleanup != CleanupStatus::Failed,
                    },
                }
            }
            Err(failure) => StepResult {
                step: step.id().into(),
                execution: ExecutionId::new(),
                evidence: None,
                source_cleaned: failure.cleanup != CleanupStatus::Failed,
                sandbox_cleaned: true,
            },
        };
        steps.push(record);
    }

    let result = WorkerResult {
        schema: 1,
        job: assignment.job,
        attempt: assignment.attempt,
        source: inputs.source.clone(),
        plan_sha256: inputs.plan_sha256.clone(),
        producer: "archcert-worker-v1/0.1.0".into(),
        steps,
    };

    result.validate(assignment.job, assignment.attempt, inputs)?;

    std::io::stdout().write_all(&encode_result(&result)?)?;

    Ok(())
}
