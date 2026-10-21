//! Trusted local runtime reconciliation. DB and local gate fencing precede removal.

use super::*;
use archcert_runner::{DockerRuntime, ExecutionGateRoot};
use std::{collections::BTreeSet, fs, os::unix::fs::DirBuilderExt, path::Path};

#[derive(clap::Args)]
pub struct ReconcileArgs {
    #[arg(long)]
    pub docker: PathBuf,
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub runtime_state_root: PathBuf,
    #[arg(long)]
    pub workspace_root: PathBuf,
    /// Without this flag, inventory and classification are read-only.
    #[arg(long)]
    pub apply: bool,
    /// After confirmed durable cleanup, allow exact expired-attempt recovery.
    #[arg(long, requires = "apply")]
    pub recover: bool,
    #[arg(long)]
    pub job: Option<String>,
}

pub fn state_root(args: &RunArgs) -> Result<PathBuf> {
    let path = args
        .runtime_state_root
        .clone()
        .unwrap_or_else(|| args.workspace_root.with_extension("runtime"));

    ensure!(path.is_absolute(), "runtime state root must be absolute");

    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }

    ExecutionGateRoot::open(&path)?;

    Ok(path.canonicalize()?)
}

pub fn runtime(args: &RunArgs) -> Result<DockerRuntime> {
    Ok(DockerRuntime::new(
        args.docker.clone(),
        args.endpoint.clone(),
    )?)
}

pub fn binding(runtime: &DockerRuntime, root: &Path) -> Result<RuntimeBinding> {
    let observed = runtime.observed_identity()?;

    Ok(RuntimeBinding {
        endpoint: observed.runtime_information["authority/endpoint"].clone(),
        daemon_id: observed.runtime_information["ID"].clone(),
        gate_root: root.to_string_lossy().into(),
    })
}

/// Reconciles exactly one DB-known expired/closed attempt. Unknown authority is retained.
pub async fn one(
    state: &ControlPlane,
    runtime: &DockerRuntime,
    root: &Path,
    workspace_root: &Path,
    job: JobId,
    attempt: AttemptId,
    apply: bool,
) -> Result<RuntimeCleanupState> {
    let candidate = state.repository.cleanup_candidate(job, attempt).await?;

    ensure!(
        candidate.binding.gate_root == root.to_string_lossy(),
        "runtime gate root disagrees with durable binding"
    );

    if !apply {
        return Ok(candidate.cleanup);
    }

    let gates = ExecutionGateRoot::open(root)?;
    let mut gate = match gates.lock(job, attempt) {
        Ok(gate) => gate,
        Err(_) => {
            state
                .repository
                .block_cleanup(job, attempt, &candidate.binding)
                .await?;
            return Ok(RuntimeCleanupState::Blocked);
        }
    };

    ensure!(
        gate.binding() == &candidate.binding,
        "local gate disagrees with durable binding"
    );

    gate.revoke()?;

    if candidate.cleanup != RuntimeCleanupState::Succeeded {
        state
            .repository
            .fence_runtime(job, attempt, &candidate.binding)
            .await?;
    }

    let outcome = match runtime.reconcile_attempt(job, attempt, &gate) {
        Ok(outcome) => outcome,
        Err(_) => RuntimeCleanupState::Failed,
    };
    let outcome = if outcome == RuntimeCleanupState::Succeeded {
        // Workspaces are contained beneath an explicit verified authority root and
        // an immutable attempt UUID. Project paths never select the removal root.
        let workspaces = archcert_materialization::AuthorityWorkspaceRoot::open(workspace_root)?;

        if workspaces.destroy_attempt_directory(attempt).is_ok() {
            outcome
        } else {
            RuntimeCleanupState::Failed
        }
    } else {
        outcome
    };
    state
        .repository
        .finish_cleanup(job, attempt, &candidate.binding, outcome)
        .await?;

    Ok(outcome)
}

pub async fn all(state: &ControlPlane, args: &ReconcileArgs) -> Result<bool> {
    let runtime = DockerRuntime::new(args.docker.clone(), args.endpoint.clone())?;
    let inventory = runtime.inventory()?;
    let mut jobs: BTreeSet<String> = state
        .repository
        .expired()
        .await?
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut blocked = false;

    for object in &inventory {
        if !object.owned {
            eprintln!(
                "{}",
                serde_json::json!({
                    "classification": "UNKNOWN_OWNERSHIP",
                    "object": object
                })
            );
            blocked = true;
        }

        if let Some(job) = object.job {
            jobs.insert(job.to_string());
        }
    }

    if let Some(job) = &args.job {
        jobs.clear();
        jobs.insert(JobId::parse(job)?.to_string());
    }

    for id in jobs {
        let id = JobId::parse(&id)?;
        let view = match state.repository.get(id).await {
            Ok(view) => view,
            Err(JobStoreError::Precondition) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "classification": "UNKNOWN_JOB",
                        "job": id
                    })
                );
                blocked = true;
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        for attempt in &view.attempts {
            let relevant = inventory
                .iter()
                .any(|o| o.job == Some(id) && o.attempt == Some(attempt.id));

            if attempt.runtime.is_none() {
                if relevant || attempt.state == AttemptState::Running {
                    blocked = true;
                    continue;
                }

                if args.apply && args.recover && attempt.state == AttemptState::Leased {
                    state.repository.recover(id, attempt.id).await?;
                }

                continue;
            }

            match one(
                state,
                &runtime,
                &args.runtime_state_root,
                &args.workspace_root,
                id,
                attempt.id,
                args.apply,
            )
            .await
            {
                Ok(outcome) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "job": id,
                            "attempt": attempt.id,
                            "cleanup": outcome,
                            "applied": args.apply
                        })
                    );

                    if outcome != RuntimeCleanupState::Succeeded {
                        blocked = true;
                    }

                    if args.apply
                        && args.recover
                        && outcome == RuntimeCleanupState::Succeeded
                        && view.state == JobState::Running
                        && view.attempts.last().is_some_and(|a| a.id == attempt.id)
                    {
                        if let Some(reference) =
                            state.repository.available_execution(id, attempt.id).await?
                        {
                            let bytes =
                                state.artifacts.get(view.inputs.project, &reference).await?;
                            decode_result(&bytes)?.validate(id, attempt.id, &view.inputs)?;
                            state
                                .repository
                                .recover_evidence(id, attempt.id, &reference)
                                .await?;
                        } else {
                            state.repository.recover(id, attempt.id).await?;
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.downcast_ref::<JobStoreError>(),
                        Some(JobStoreError::Precondition)
                    ) =>
                {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "job": id,
                            "attempt": attempt.id,
                            "classification": "ACTIVE_OR_UNAVAILABLE_FOR_CLEANUP"
                        })
                    );
                }
                Err(e) => return Err(e),
            }
        }

        for object in inventory.iter().filter(|o| o.job == Some(id)) {
            if object
                .attempt
                .is_none_or(|a| !view.attempts.iter().any(|known| known.id == a))
            {
                blocked = true;
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "classification": "UNKNOWN_ATTEMPT",
                        "object": object
                    })
                );
            }
        }
    }

    Ok(blocked)
}
