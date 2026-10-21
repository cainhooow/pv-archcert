//! Native-capable opt-in runtime recovery tests; no database/signing authority.
#![cfg(unix)]

use archcert_application::jobs::{RuntimeBinding, RuntimeCleanupState};
use archcert_domain::{
    execution::ExecutionId,
    jobs::{AttemptId, JobId},
};
use archcert_runner::{DockerRuntime, ExecutionGateRoot};
use std::{path::PathBuf, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    cli: PathBuf,
    endpoint: String,
    config: tempfile::TempDir,
    root: tempfile::TempDir,
    runtime: DockerRuntime,
    containers: Vec<String>,
    images: Vec<String>,
    binding: RuntimeBinding,
}

impl Fixture {
    fn new() -> Result<Self> {
        let cli: PathBuf = std::env::var("ARCHCERT_TEST_DOCKER")?.into();
        let endpoint = std::env::var("ARCHCERT_TEST_ENDPOINT")?;
        let config = tempfile::tempdir()?;
        let root = tempfile::tempdir()?;

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let runtime = DockerRuntime::new(cli.clone(), endpoint.clone())?;
        let observed = runtime.observed_identity()?;
        let binding = RuntimeBinding {
            endpoint: endpoint.clone(),
            daemon_id: observed.runtime_information["ID"].clone(),
            gate_root: root.path().canonicalize()?.to_string_lossy().into(),
        };

        Ok(Self {
            cli,
            endpoint,
            config,
            root,
            runtime,
            containers: vec![],
            images: vec![],
            binding,
        })
    }

    fn call(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.cli)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--config")
            .arg(self.config.path())
            .arg("--host")
            .arg(&self.endpoint)
            .args(args)
            .output()?;

        if !out.status.success() {
            return Err(format!(
                "fixture runtime command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }

        Ok(String::from_utf8(out.stdout)?.trim().to_owned())
    }

    fn create(
        &mut self,
        job: JobId,
        attempt: AttemptId,
        execution: ExecutionId,
        prep: bool,
        image: &str,
    ) -> Result<String> {
        let name = format!("archcert-{execution}{}", if prep { "-prepare" } else { "" });
        let labels = [
            "archcert.owner=execution-v1".into(),
            "archcert.ownership=2".into(),
            format!("archcert.job={execution}"),
            format!("archcert.execution={execution}"),
            format!("archcert.certification-job={job}"),
            format!("archcert.attempt={attempt}"),
        ];
        let mut args = vec![
            "container",
            "create",
            "--pull=never",
            "--runtime=runc",
            "--name",
            &name,
            "--network=none",
            "--cgroupns=private",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--user=10001:10001",
            "--read-only",
            "--memory=64m",
            "--memory-swap=64m",
            "--pids-limit=16",
            "--cpus=0.25",
            "--log-driver=none",
            "--entrypoint=python3",
        ];

        for label in &labels {
            args.extend(["--label", label]);
        }

        args.extend([
            image,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(120)",
        ]);
        self.containers.push(name.clone());
        self.call(&args)?;

        Ok(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Exact random fixture handles only; never selects arbitrary runtime state.
        for container in &self.containers {
            let _ = self.call(&["container", "rm", "--force", "--volumes", container]);
        }

        for image in &self.images {
            let _ = self.call(&["image", "rm", image]);
        }
    }
}

#[test]
#[ignore = "requires explicit rootless runtime; exercises orphan cleanup and failure/retry"]
fn owned_orphans_are_fenced_wrong_attempts_reject_and_image_cleanup_retries() -> Result {
    let mut f = Fixture::new()?;
    let job = JobId::new();
    let attempt = AttemptId::new();
    let execution = ExecutionId::new();
    let gates = ExecutionGateRoot::open(&f.root.path().canonicalize()?)?;
    gates.create(job, attempt, &f.binding)?;
    let mut gate = gates.lock(job, attempt)?;
    let base = std::env::var("ARCHCERT_TEST_IMAGE")?;
    let prep = f.create(job, attempt, execution, true, &base)?;
    let image = format!("archcert-job:{execution}");
    f.images.push(image.clone());
    f.call(&["container", "commit", &prep, &image])?;
    let target = f.create(job, attempt, execution, false, &image)?;
    f.call(&["container", "start", &target])?;

    assert_eq!(
        f.call(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            &target
        ])?,
        "true"
    );
    assert!(f.runtime.reconcile_attempt(job, attempt, &gate).is_err());

    gate.revoke()?;

    assert!(
        f.runtime
            .reconcile_attempt(job, AttemptId::new(), &gate)
            .is_err()
    );

    let foreign = f.create(
        JobId::new(),
        AttemptId::new(),
        ExecutionId::new(),
        false,
        &image,
    )?;

    // A foreign reference blocks image removal. It must not be removed to make cleanup pass.
    assert!(f.runtime.reconcile_attempt(job, attempt, &gate).is_err());
    assert!(
        !f.call(&["container", "inspect", "--format", "{{.Id}}", &foreign])?
            .is_empty()
    );

    f.call(&["container", "rm", "--force", "--volumes", &foreign])?;

    assert_eq!(
        f.runtime.reconcile_attempt(job, attempt, &gate)?,
        RuntimeCleanupState::Succeeded
    );
    assert!(
        !f.runtime
            .inventory()?
            .iter()
            .any(|o| o.job == Some(job) && o.attempt == Some(attempt))
    );
    assert!(gate.authorize().is_err());

    Ok(())
}

#[test]
#[ignore = "requires explicit rootless runtime; absence cannot clear an interrupted create"]
fn empty_inventory_does_not_clear_uncertain_creation() -> Result {
    let f = Fixture::new()?;
    let job = JobId::new();
    let attempt = AttemptId::new();
    let gates = ExecutionGateRoot::open(&f.root.path().canonicalize()?)?;
    gates.create(job, attempt, &f.binding)?;
    let mut gate = gates.lock(job, attempt)?;
    gate.begin_creation()?;
    drop(gate);
    let mut gate = gates.lock(job, attempt)?;
    gate.revoke()?;

    assert_eq!(
        f.runtime.reconcile_attempt(job, attempt, &gate)?,
        RuntimeCleanupState::Blocked
    );
    assert!(gate.authorize().is_err());

    Ok(())
}

#[test]
#[ignore = "requires explicit rootless runtime; unknown labels must be reported and retained"]
fn unknown_archcert_labels_are_retained() -> Result {
    let mut f = Fixture::new()?;
    let name = format!("archcert-unknown-{}", ExecutionId::new());
    f.containers.push(name.clone());
    let image = std::env::var("ARCHCERT_TEST_IMAGE")?;
    let id = f.call(&[
        "container",
        "create",
        "--pull=never",
        "--name",
        &name,
        "--network=none",
        "--label",
        "archcert.owner=execution-v1",
        "--entrypoint=/usr/bin/env",
        &image,
        "--version",
    ])?;
    let object = f
        .runtime
        .inventory()?
        .into_iter()
        .find(|o| o.id == id)
        .ok_or("unknown object was silently omitted")?;

    assert!(!object.owned);
    assert!(object.job.is_none());
    assert!(object.attempt.is_none());

    Ok(())
}
