use crate::{
    archive,
    process::{self, IoPolicy, ProcessOutput},
};
use archcert_application::{
    execution::{ExecutionFailure, ExecutionRequest, ExecutionResult, SandboxRunner},
    materialization::{CleanupStatus, VerifiedSourceExport},
};
use archcert_domain::execution::*;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CONTROL_BYTES: u64 = 256 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const USER: &str = "10001:10001";

/// Authority-only Docker client configuration. Never derive this from project TOML.
pub struct DockerRuntime {
    executable: PathBuf,
    endpoint: String,
    configuration: tempfile::TempDir,
}
impl DockerRuntime {
    /// Requires an absolute trusted executable and explicit Unix API endpoint.
    /// A fresh empty Docker config excludes proxies, auth and credential helpers.
    pub fn new(executable: PathBuf, endpoint: String) -> Result<Self, ExecutionError> {
        if !executable.is_absolute()
            || !executable.is_file()
            || endpoint.len() > 4096
            || endpoint.bytes().any(|b| b.is_ascii_control())
            || !endpoint.strip_prefix("unix://").is_some_and(|p| {
                Path::new(p).is_absolute()
                    && Path::new(p).file_name().is_some()
                    && Path::new(p)
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            })
        {
            return Err(ExecutionError::InvalidRuntimeConfiguration);
        }
        let configuration = tempfile::Builder::new()
            .prefix("archcert-runtime-")
            .tempdir()
            .map_err(|_| ExecutionError::RuntimeFailure)?;
        fs::write(configuration.path().join("config.json"), b"{}")
            .map_err(|_| ExecutionError::RuntimeFailure)?;
        Ok(Self {
            executable,
            endpoint,
            configuration,
        })
    }
    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.configuration.path())
            .current_dir(self.configuration.path())
            .arg("--config")
            .arg(self.configuration.path())
            .arg("--host")
            .arg(&self.endpoint)
            .args(args);
        command
    }
    fn call(
        &self,
        args: &[String],
        input: &[u8],
        max: u64,
    ) -> Result<ProcessOutput, ExecutionError> {
        let output = process::run(
            self.command(args),
            input,
            IoPolicy {
                timeout: CONTROL_TIMEOUT,
                stdout: max,
                stderr: CONTROL_BYTES,
                prefix: max,
            },
            || {},
        )?;
        if output.code != Some(0)
            || output.trigger.is_some()
            || !output.stdout.complete
            || !output.stderr.complete
        {
            return Err(ExecutionError::RuntimeFailure);
        }
        Ok(output)
    }
    fn json(&self, args: &[&str]) -> Result<Value, ExecutionError> {
        let args = args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let out = self.call(&args, &[], CONTROL_BYTES)?;
        serde_json::from_slice(&out.stdout.excerpt).map_err(|_| ExecutionError::RuntimeFailure)
    }
    fn stop(&self, name: &str) {
        let _ = self.call(
            &strings(&["container", "kill", "--signal", "KILL", name]),
            &[],
            CONTROL_BYTES,
        );
    }
    fn preflight(&self) -> Result<ObservedRuntimeIdentity, ExecutionError> {
        let info = self.json(&["info", "--format", "{{json .}}"])?;
        verify_daemon(&info)?;
        let version = self.json(&["version", "--format", "{{json .}}"])?;
        let server_version = field(&version["Server"], "Version")?.to_owned();
        if server_version != field(&info, "ServerVersion")? {
            return Err(ExecutionError::RuntimeFailure);
        }
        let mut runtime_information = std::collections::BTreeMap::new();
        runtime_information.insert("authority/endpoint".into(), self.endpoint.clone());
        for key in [
            "ID",
            "KernelVersion",
            "OperatingSystem",
            "Architecture",
            "CgroupVersion",
            "CgroupDriver",
            "DefaultRuntime",
        ] {
            let value = field(&info, key)?;
            if value.is_empty() {
                return Err(ExecutionError::EnvironmentNotProven);
            }
            runtime_information.insert(key.into(), value.into());
        }
        runtime_information.insert(
            "SecurityOptions".into(),
            info["SecurityOptions"].to_string(),
        );
        runtime_information.insert("Warnings".into(), info["Warnings"].to_string());
        let components = version["Server"]["Components"]
            .as_array()
            .ok_or(ExecutionError::RuntimeFailure)?;
        for component in components {
            runtime_information.insert(
                format!("component/{}", field(component, "Name")?),
                field(component, "Version")?.into(),
            );
        }
        Ok(ObservedRuntimeIdentity {
            client_path: self
                .executable
                .to_str()
                .ok_or(ExecutionError::InvalidRuntimeConfiguration)?
                .into(),
            client_version: field(&version["Client"], "Version")?.into(),
            server_version,
            runtime_information,
        })
    }
}

/// Initial OCI backend. All target commands run inside a verified rootless sandbox.
pub struct DockerRootlessRunner {
    runtime: DockerRuntime,
}
impl DockerRootlessRunner {
    /// Composes an explicit authority-owned Docker client.
    pub fn new(runtime: DockerRuntime) -> Self {
        Self { runtime }
    }
    /// Non-executing capability probe. Failure never permits a rootful fallback.
    pub fn verify_environment(&self) -> Result<ObservedRuntimeIdentity, ExecutionError> {
        self.runtime.preflight()
    }
}
fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, ExecutionError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(ExecutionError::RuntimeFailure)
}
fn first(v: &Value) -> Result<&Value, ExecutionError> {
    v.as_array()
        .filter(|a| a.len() == 1)
        .and_then(|a| a.first())
        .ok_or(ExecutionError::RuntimeFailure)
}
fn empty(v: Option<&Value>) -> bool {
    v.is_none_or(|v| {
        v.is_null()
            || v.as_array().is_some_and(Vec::is_empty)
            || v.as_object().is_some_and(serde_json::Map::is_empty)
    })
}
fn image_id(v: &Value) -> Result<String, ExecutionError> {
    let id = v.as_str().ok_or(ExecutionError::RuntimeFailure)?;
    let hash = id
        .strip_prefix("sha256:")
        .ok_or(ExecutionError::RuntimeFailure)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ExecutionError::RuntimeFailure);
    }
    Ok(id.into())
}
fn verify_daemon(info: &Value) -> Result<(), ExecutionError> {
    let options = info["SecurityOptions"]
        .as_array()
        .ok_or(ExecutionError::EnvironmentNotProven)?;
    let contains = |name: &str| options.iter().any(|v| v.as_str() == Some(name));
    if info["OSType"] != "linux"
        || info["CgroupVersion"] != "2"
        || info["CgroupDriver"] != "systemd"
        || info["DefaultRuntime"] != "runc"
        || !contains("name=rootless")
        || !contains("name=seccomp,profile=builtin")
        || [
            "MemoryLimit",
            "SwapLimit",
            "PidsLimit",
            "CpuCfsQuota",
            "CpuCfsPeriod",
        ]
        .iter()
        .any(|k| info[*k] != true)
        || !supported_warnings(info.get("Warnings"))
        || info["Runtimes"].get("runc").is_none()
    {
        return Err(ExecutionError::EnvironmentNotProven);
    }
    Ok(())
}

fn supported_warnings(warnings: Option<&Value>) -> bool {
    if empty(warnings) {
        return true;
    }
    // This profile enforces CPU quota, not cpuset pinning or block-I/O throttling.
    // Unknown warnings and missing required resource flags still reject.
    warnings.and_then(Value::as_array).is_some_and(|items| {
        items.iter().all(|warning| {
            matches!(
                warning.as_str(),
                Some(
                    "WARNING: No cpuset support"
                        | "WARNING: No io.weight support"
                        | "WARNING: No io.weight (per device) support"
                        | "WARNING: No io.max (rbps) support"
                        | "WARNING: No io.max (wbps) support"
                        | "WARNING: No io.max (riops) support"
                        | "WARNING: No io.max (wiops) support"
                )
            )
        })
    })
}

/// A synchronous guard also attempts bounded cleanup during unwinding. Crashes
/// still require orphan discovery; random job/workspace labels identify leftovers.
struct SandboxLease<'a> {
    runtime: &'a DockerRuntime,
    prep: String,
    target: String,
    image_tag: String,
    touched: bool,
    destroyed: bool,
}
impl SandboxLease<'_> {
    fn cleanup(&mut self) -> CleanupStatus {
        if !self.touched {
            self.destroyed = true;
            return CleanupStatus::NotCreated;
        }
        // Names are chosen before create/commit, so a lost successful response can
        // still be cleaned up. Never select by project-controlled labels.
        let mut failed = false;
        for name in [&self.target, &self.prep] {
            match self.runtime.call(
                &strings(&["container", "rm", "--force", "--volumes", name]),
                &[],
                CONTROL_BYTES,
            ) {
                Ok(_) => {}
                Err(_) => {
                    // Distinguish authoritative absence from a disconnected daemon.
                    let list = self.runtime.call(
                        &strings(&[
                            "container",
                            "ls",
                            "--all",
                            "--filter",
                            &format!("name=^/{name}$"),
                            "--format",
                            "{{.Names}}",
                        ]),
                        &[],
                        CONTROL_BYTES,
                    );
                    if !list.is_ok_and(|p| p.stdout.excerpt.is_empty()) {
                        failed = true;
                    }
                }
            }
        }
        if self
            .runtime
            .call(
                &strings(&["image", "rm", &self.image_tag]),
                &[],
                CONTROL_BYTES,
            )
            .is_err()
        {
            let list = self.runtime.call(
                &strings(&[
                    "image",
                    "ls",
                    "--quiet",
                    "--filter",
                    &format!("reference={}", self.image_tag),
                ]),
                &[],
                CONTROL_BYTES,
            );
            if !list.is_ok_and(|p| p.stdout.excerpt.is_empty()) {
                failed = true;
            }
        }
        if failed {
            CleanupStatus::Failed
        } else {
            self.destroyed = true;
            CleanupStatus::Destroyed
        }
    }
}
impl Drop for SandboxLease<'_> {
    fn drop(&mut self) {
        if !self.destroyed {
            let _ = self.cleanup();
        }
    }
}

impl<S: VerifiedSourceExport> SandboxRunner<S> for DockerRootlessRunner {
    fn execute(&self, request: ExecutionRequest<S>) -> Result<ExecutionResult, ExecutionFailure> {
        let id = ExecutionId::new();
        let mut lease = SandboxLease {
            runtime: &self.runtime,
            prep: format!("archcert-{id}-prepare"),
            target: format!("archcert-{id}"),
            image_tag: format!("archcert-job:{id}"),
            touched: false,
            destroyed: false,
        };
        let mut events = vec![ExecutionEvent::ExecutionPrepared];
        let attempt = self.execute_inner(&request, id, &mut lease, &mut events);
        let cleanup = lease.cleanup();
        if cleanup == CleanupStatus::Failed {
            events.push(ExecutionEvent::SandboxCleanupFailed);
        } else if cleanup == CleanupStatus::Destroyed {
            events.push(ExecutionEvent::SandboxDestroyed);
        }
        match (attempt, cleanup) {
            (Ok(evidence), CleanupStatus::Destroyed) => Ok(ExecutionResult {
                evidence,
                cleanup,
                events,
            }),
            (Ok(evidence), _) => Err(ExecutionFailure {
                error: ExecutionError::CleanupFailed,
                evidence: Some(Box::new(evidence)),
                cleanup,
                events,
            }),
            (Err(error), _) => Err(ExecutionFailure {
                error,
                evidence: None,
                cleanup,
                events,
            }),
        }
    }
}
impl DockerRootlessRunner {
    fn execute_inner<S: VerifiedSourceExport>(
        &self,
        request: &ExecutionRequest<S>,
        id: ExecutionId,
        lease: &mut SandboxLease<'_>,
        events: &mut Vec<ExecutionEvent>,
    ) -> Result<ExecutionEvidence, ExecutionError> {
        let started = Instant::now();
        let started_at_ms = now()?;
        let limits = request.profile().limits();
        limits.validate()?;
        request.profile().authorize(request.command())?;
        let files = request
            .input()
            .source()
            .verified_files()
            .map_err(|_| ExecutionError::SourceIntegrity)?;
        let binding = request.input().source().source_binding();
        let manifest = archcert_domain::source::SourceManifest::new(
            files
                .iter()
                .map(archcert_domain::source::SourceFile::manifest_entry)
                .collect(),
        )
        .map_err(|_| ExecutionError::SourceIntegrity)?;
        if binding
            .digest(&manifest)
            .map_err(|_| ExecutionError::SourceIntegrity)?
            != request.input().expected_source_identity().snapshot_sha256
        {
            return Err(ExecutionError::SourceIntegrity);
        }
        let source_tar = archive::encode(&files)?;
        let observed_runtime = self.runtime.preflight()?;
        let image = self
            .runtime
            .json(&["image", "inspect", request.profile().image()])?;
        let image = first(&image)?;
        let base_image_id = image_id(&image["Id"])?;
        if image["Os"] != "linux"
            || !image["RepoDigests"].as_array().is_some_and(|v| {
                v.iter()
                    .any(|d| d.as_str() == Some(request.profile().image()))
            })
            || !empty(image["Config"].get("Volumes"))
            || !empty(image["Config"].get("OnBuild"))
        {
            return Err(ExecutionError::ImagePolicy);
        }
        let image_env = image["Config"]["Env"]
            .as_array()
            .ok_or(ExecutionError::ImagePolicy)?;
        // Preparation container NEVER STARTS. Its writable root is populated by
        // authority archive extraction, then frozen into a job-local image layer.
        let mut prepare = strings(&[
            "container",
            "create",
            "--pull=never",
            "--name",
            &lease.prep,
            "--network=none",
            "--runtime=runc",
            "--cgroupns=private",
            "--entrypoint",
            "/usr/bin/env",
        ]);
        add_labels(&mut prepare, id, request);
        prepare.push(base_image_id.clone());
        prepare.push("--version".into());
        lease.touched = true;
        self.runtime.call(&prepare, &[], CONTROL_BYTES)?;
        self.runtime.call(
            &strings(&[
                "container",
                "cp",
                "--archive",
                "-",
                &format!("{}:/", lease.prep),
            ]),
            &source_tar,
            CONTROL_BYTES,
        )?;
        self.runtime.call(
            &strings(&["container", "commit", &lease.prep, &lease.image_tag]),
            &[],
            CONTROL_BYTES,
        )?;
        let committed = self.runtime.json(&["image", "inspect", &lease.image_tag])?;
        let execution_image_id = image_id(&first(&committed)?["Id"])?;
        let mut create = target_args(request, id, &lease.target, &execution_image_id, image_env)?;
        self.runtime.call(&create, &[], CONTROL_BYTES)?;
        create.clear();
        events.push(ExecutionEvent::SandboxCreated);
        let inspection = self
            .runtime
            .json(&["container", "inspect", &lease.target])?;
        verify_container(first(&inspection)?, request, id, &execution_image_id)?;
        let view = self.runtime.call(
            &strings(&["container", "cp", &format!("{}:/source", lease.target), "-"]),
            &[],
            archive::MAX_ARCHIVE,
        )?;
        archive::verify_bound(
            &view.stdout.excerpt,
            request.input().expected_source_identity(),
            &binding,
        )?;
        // Recheck host source as well; authority-source mutation cannot silently
        // relabel a different execution image.
        request
            .input()
            .source()
            .verified_files()
            .map_err(|_| ExecutionError::SourceIntegrity)?;
        if request.input().source().source_binding() != binding {
            return Err(ExecutionError::SourceIntegrity);
        }
        let mut state = ExecutionState::Preparing
            .advance(ExecutionState::Ready)?
            .advance(ExecutionState::Running)?;
        events.push(ExecutionEvent::ExecutionStarted);
        let output = process::run(
            self.runtime
                .command(&strings(&["container", "start", "--attach", &lease.target])),
            &[],
            IoPolicy {
                timeout: Duration::from_millis(limits.timeout_ms),
                stdout: limits.stdout_bytes,
                stderr: limits.stderr_bytes,
                prefix: limits.excerpt_bytes,
            },
            || self.runtime.stop(&lease.target),
        )?;
        if output.trigger.is_some() {
            state = state.advance(ExecutionState::Terminating)?;
        }
        if output.trigger == Some(TerminationReason::Timeout) {
            events.push(ExecutionEvent::ExecutionTimedOut);
        }
        // Inspect runtime state, not text printed by target or the client exit code.
        let after = self
            .runtime
            .json(&["container", "inspect", &lease.target])?;
        let after = first(&after)?;
        if after["State"]["Running"] != false || after["State"]["Dead"] != false {
            return Err(ExecutionError::RuntimeFailure);
        }
        let (outcome, termination, exit_code) = classify(&output, &after["State"]);
        state = state.advance(ExecutionState::Finished)?;
        if state != ExecutionState::Finished {
            return Err(ExecutionError::RuntimeFailure);
        }
        events.push(ExecutionEvent::ExecutionCompleted);
        Ok(ExecutionEvidence {
            execution: id,
            source: request.input().expected_source_identity().clone(),
            workspace: request.input().workspace(),
            backend: "DockerRootlessRunner".into(),
            backend_version: "archcert-docker-cli-v1".into(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            observed_runtime,
            toolchain: ToolchainObservation::NotObserved,
            image_digest: request.profile().image().into(),
            base_image_id,
            execution_image_id,
            profile: request.profile().name().into(),
            command: request.command().clone(),
            network: NetworkPolicy::Denied,
            limits,
            environment_keys: sandbox_environment().into_keys().collect(),
            container_user: USER.into(),
            started_at_ms,
            ended_at_ms: now()?,
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            exit_code,
            termination,
            stdout: output.stdout,
            stderr: output.stderr,
            outcome,
        })
    }
}
fn now() -> Result<u64, ExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(ExecutionError::RuntimeFailure)
}
fn add_labels<S: VerifiedSourceExport>(
    args: &mut Vec<String>,
    id: ExecutionId,
    request: &ExecutionRequest<S>,
) {
    for label in [
        format!("archcert.job={id}"),
        format!("archcert.workspace={}", request.input().workspace()),
        "archcert.owner=execution-v1".into(),
    ] {
        args.push("--label".into());
        args.push(label);
    }
}
fn tmpfs(path: &str, bytes: u64, executable: bool) -> String {
    format!(
        "{path}:rw,nosuid,nodev,{},size={bytes},mode=0700,uid=10001,gid=10001",
        if executable { "exec" } else { "noexec" }
    )
}
fn target_args<S: VerifiedSourceExport>(
    request: &ExecutionRequest<S>,
    id: ExecutionId,
    name: &str,
    image: &str,
    image_env: &[Value],
) -> Result<Vec<String>, ExecutionError> {
    let limits = request.profile().limits();
    let mut args = strings(&[
        "container",
        "create",
        "--pull=never",
        "--name",
        name,
        "--runtime=runc",
        "--network=none",
        "--ipc=none",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--read-only",
        "--user",
        USER,
        "--hostname=archcert",
        "--log-driver=none",
        "--no-healthcheck",
        "--restart=no",
        "--stop-signal=SIGKILL",
        "--ulimit=nofile=256:256",
        "--ulimit=core=0:0",
        "--entrypoint",
        "/usr/bin/env",
        "--workdir",
        request.command().working_directory(),
    ]);
    for (key, value) in [
        ("--memory", limits.memory_bytes.to_string()),
        ("--memory-swap", limits.memory_bytes.to_string()),
        ("--cpu-period", "100000".into()),
        (
            "--cpu-quota",
            (u64::from(limits.cpu_millis) * 100).to_string(),
        ),
        ("--pids-limit", limits.pids.to_string()),
        ("--shm-size", "1048576".into()),
    ] {
        args.push(key.into());
        args.push(value);
    }
    for (path, bytes, exec) in [
        ("/work", limits.scratch_bytes, true),
        ("/tmp", limits.scratch_bytes, false),
        ("/output", limits.output_bytes, false),
        ("/home/archcert", limits.scratch_bytes, false),
    ] {
        args.push("--tmpfs".into());
        args.push(tmpfs(path, bytes, exec));
    }
    let environment = sandbox_environment();
    // CLI's environment is cleared. Passing KEY without a value removes an
    // inherited image ENV; it cannot read a host secret from this client.
    for inherited in image_env {
        let key = inherited
            .as_str()
            .and_then(|e| e.split_once('=').map(|(k, _)| k))
            .ok_or(ExecutionError::ImagePolicy)?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ExecutionError::ImagePolicy);
        }
        if !environment.contains_key(key) {
            args.push("--env".into());
            args.push(key.into());
        }
    }
    for (key, value) in &environment {
        args.push("--env".into());
        args.push(format!("{key}={value}"));
    }
    add_labels(&mut args, id, request);
    args.push(image.into());
    args.push("-i".into());
    args.extend(environment.iter().map(|(k, v)| format!("{k}={v}")));
    args.push(request.command().program().into());
    args.extend_from_slice(request.command().args());
    Ok(args)
}

fn verify_container<S: VerifiedSourceExport>(
    v: &Value,
    request: &ExecutionRequest<S>,
    id: ExecutionId,
    image: &str,
) -> Result<(), ExecutionError> {
    let h = &v["HostConfig"];
    let c = &v["Config"];
    let l = request.profile().limits();
    let expected_env: BTreeSet<_> = sandbox_environment()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    // Docker keeps KEY tombstones for removed image ENV in Config.Env. They
    // contain no value and env -i clears the entire inherited environment before
    // executing the target. Any unexpected KEY=value fails closed.
    let actual_env: BTreeSet<_> = c["Env"]
        .as_array()
        .ok_or(ExecutionError::RuntimeFailure)?
        .iter()
        .map(|v| v.as_str().ok_or(ExecutionError::ImagePolicy))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|s| s.contains('='))
        .map(str::to_owned)
        .collect();
    let mut expected_cmd = vec!["-i".to_owned()];
    expected_cmd.extend(
        sandbox_environment()
            .iter()
            .map(|(k, v)| format!("{k}={v}")),
    );
    expected_cmd.push(request.command().program().into());
    expected_cmd.extend_from_slice(request.command().args());
    if c["Cmd"] != serde_json::json!(expected_cmd)
        || c["Labels"]["archcert.job"] != id.to_string()
        || c["Labels"]["archcert.workspace"] != request.input().workspace().to_string()
        || c["Labels"]["archcert.owner"] != "execution-v1"
        || c["Hostname"] != "archcert"
        || c["Healthcheck"]["Test"] != serde_json::json!(["NONE"])
        || h["RestartPolicy"]["Name"] != "no"
        || h["PublishAllPorts"] != false
        || !empty(h.get("GroupAdd"))
        || !empty(h.get("ExtraHosts"))
        || !empty(h.get("Links"))
        || !empty(h.get("Mounts"))
        || v["Image"] != image
        || c["User"] != USER
        || c["WorkingDir"] != request.command().working_directory()
        || c["Tty"] != false
        || actual_env != expected_env
        || c["Entrypoint"] != serde_json::json!(["/usr/bin/env"])
        || h["Privileged"] != false
        || h["ReadonlyRootfs"] != true
        || h["NetworkMode"] != "none"
        || h["IpcMode"] != "none"
        || h["PidMode"] != ""
        || h["UsernsMode"] != ""
        || h["CgroupnsMode"] != "private"
        || h["Runtime"] != "runc"
        || h["CapDrop"] != serde_json::json!(["ALL"])
        || !empty(h.get("CapAdd"))
        || h["SecurityOpt"] != serde_json::json!(["no-new-privileges=true"])
        || !empty(h.get("Binds"))
        || !empty(h.get("Devices"))
        || !empty(h.get("DeviceRequests"))
        || !empty(h.get("VolumesFrom"))
        || !empty(h.get("PortBindings"))
        || !empty(c.get("Volumes"))
        || h["Memory"] != l.memory_bytes
        || h["MemorySwap"] != l.memory_bytes
        || h["PidsLimit"] != l.pids
        || h["CpuPeriod"] != 100000
        || h["CpuQuota"] != u64::from(l.cpu_millis) * 100
        || h["LogConfig"]["Type"] != "none"
        || v["State"]["Status"] != "created"
    {
        return Err(ExecutionError::EnvironmentNotProven);
    }
    let mounts = v["Mounts"]
        .as_array()
        .ok_or(ExecutionError::RuntimeFailure)?;
    if mounts.iter().any(|m| m["Type"] != "tmpfs") {
        return Err(ExecutionError::EnvironmentNotProven);
    }
    let expected = serde_json::json!({"/work":tmpfs("/work",l.scratch_bytes,true).split_once(':').map(|(_,s)|s).unwrap_or_default(),
        "/tmp":tmpfs("/tmp",l.scratch_bytes,false).split_once(':').map(|(_,s)|s).unwrap_or_default(),
        "/output":tmpfs("/output",l.output_bytes,false).split_once(':').map(|(_,s)|s).unwrap_or_default(),
        "/home/archcert":tmpfs("/home/archcert",l.scratch_bytes,false).split_once(':').map(|(_,s)|s).unwrap_or_default()});
    if h["Tmpfs"] != expected {
        return Err(ExecutionError::EnvironmentNotProven);
    }
    Ok(())
}
fn classify(
    output: &ProcessOutput,
    state: &Value,
) -> (ExecutionOutcome, TerminationReason, Option<i64>) {
    let exit = state["ExitCode"].as_i64();
    if let Some(reason) = output.trigger {
        return (
            if reason == TerminationReason::Timeout {
                ExecutionOutcome::TimedOut
            } else {
                ExecutionOutcome::ResourceLimit
            },
            reason,
            exit,
        );
    }
    let Some(oom_killed) = state["OOMKilled"].as_bool() else {
        return (
            ExecutionOutcome::SandboxFailure,
            TerminationReason::RuntimeFailure,
            exit,
        );
    };
    if oom_killed {
        return (
            ExecutionOutcome::ResourceLimit,
            TerminationReason::MemoryLimit,
            exit,
        );
    }
    if state["Status"] != "exited" || state["Error"].as_str().is_none_or(|s| !s.is_empty()) {
        return (
            ExecutionOutcome::StartFailure,
            TerminationReason::RuntimeFailure,
            exit,
        );
    }
    if !output.stdout.complete
        || !output.stderr.complete
        || exit.is_none()
        || output.code.map(i64::from) != exit
    {
        return (
            ExecutionOutcome::SandboxFailure,
            TerminationReason::RuntimeFailure,
            exit,
        );
    }
    if exit.is_some_and(|code| code >= 128) {
        return (
            ExecutionOutcome::Terminated,
            TerminationReason::SignalConvention,
            exit,
        );
    }
    (ExecutionOutcome::Completed, TerminationReason::Exit, exit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_application::materialization::{MaterializationRequest, SourceMaterializer};
    use archcert_domain::{
        GitObjectId, ProjectId,
        materialization::{MaterializationLimits, SnapshotReference},
        source::{RepositoryId, SourceFile, SourceMode, SourcePath, SourceSnapshot},
    };
    use archcert_materialization::{
        AuthorityWorkspaceRoot, MaterializedDirectory, UnixSourceMaterializer,
    };
    use std::os::unix::fs::PermissionsExt;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn daemon() -> Value {
        serde_json::json!({"OSType":"linux","CgroupVersion":"2","CgroupDriver":"systemd",
        "SecurityOptions":["name=rootless","name=seccomp,profile=builtin"],"MemoryLimit":true,"SwapLimit":true,
        "PidsLimit":true,"CpuCfsQuota":true,"CpuCfsPeriod":true,"Runtimes":{"runc":{}},"DefaultRuntime":"runc","ID":"test-daemon","ServerVersion":"test", "KernelVersion":"test-kernel", "OperatingSystem":"test-linux", "Architecture":"test-arch", "Warnings":null})
    }
    fn mock(mode: &str) -> Result<(tempfile::TempDir, DockerRuntime), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let executable = temp.path().canonicalize()?.join("runtime-mock");
        fs::write(
            &executable,
            include_bytes!("../tests/fixtures/runtime_mock.py"),
        )?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let runtime = DockerRuntime::new(executable, "unix:///not-a-real-runtime.sock".into())?;
        fs::write(
            runtime.configuration.path().join("config.json"),
            serde_json::to_vec(&serde_json::json!({"mock_mode":mode,"info":daemon()}))?,
        )?;
        Ok((temp, runtime))
    }
    fn request() -> Result<
        (
            tempfile::TempDir,
            archcert_materialization::WorkspaceLease,
            ExecutionRequest<MaterializedDirectory>,
        ),
        Box<dyn std::error::Error>,
    > {
        let root = tempfile::tempdir()?;
        let root_path = root.path().canonicalize()?;
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
        let snapshot = SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("test/runner")?,
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![SourceFile::new(
                SourcePath::from_bytes(b"a")?,
                SourceMode::File,
                b"source".to_vec(),
            )],
            3,
            1,
        )?;
        let prepared = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&root_path)?)
            .prepare(
                &snapshot,
                &MaterializationRequest {
                    snapshot: SnapshotReference {
                        project: snapshot.project(),
                        repository: snapshot.repository().clone(),
                        identity: snapshot.identity().clone(),
                    },
                    limits: MaterializationLimits::default(),
                },
            )?;
        let profile = ExecutionProfile::new(
            "fixture".into(),
            format!("test@sha256:{}", "b".repeat(64)),
            vec!["python3".into()],
            ExecutionLimits::default(),
        )?;
        let command = ExecutionCommand::new(
            "python3".into(),
            vec!["/source/hostile.py".into(), "normal".into()],
            "/source".into(),
        )?;
        Ok((
            root,
            prepared.cleanup,
            ExecutionRequest::new(prepared.runner_input, profile, command)?,
        ))
    }
    #[test]
    fn rootless_cgroups_seccomp_and_linux_are_required_without_override() {
        assert_eq!(verify_daemon(&daemon()), Ok(()));
        for key in [
            "OSType",
            "CgroupVersion",
            "CgroupDriver",
            "SecurityOptions",
            "MemoryLimit",
            "SwapLimit",
            "PidsLimit",
            "CpuCfsQuota",
            "CpuCfsPeriod",
            "Runtimes",
            "DefaultRuntime",
        ] {
            let mut invalid = daemon();
            invalid[key] = Value::Null;
            assert_eq!(
                verify_daemon(&invalid),
                Err(ExecutionError::EnvironmentNotProven),
                "{key}"
            );
        }
        for options in [
            serde_json::json!(["name=seccomp,profile=builtin"]),
            serde_json::json!(["name=rootless", "name=seccomp,profile=unconfined"]),
        ] {
            let mut invalid = daemon();
            invalid["SecurityOptions"] = options;
            assert!(verify_daemon(&invalid).is_err());
        }
        let mut warning = daemon();
        warning["Warnings"] = serde_json::json!(["No memory limit support"]);
        assert!(verify_daemon(&warning).is_err());
        warning["Warnings"] = serde_json::json!([
            "WARNING: No cpuset support",
            "WARNING: No io.max (rbps) support"
        ]);
        assert!(verify_daemon(&warning).is_ok());
        warning["MemoryLimit"] = serde_json::json!(false);
        assert!(verify_daemon(&warning).is_err());
    }
    #[test]
    fn malformed_inspect_oom_state_cannot_become_success() -> TestResult {
        let stream = CapturedStream {
            sha256: archcert_domain::source::digest_bytes(b""),
            observed_bytes: 0,
            excerpt: vec![],
            truncated: false,
            complete: true,
        };
        let output = ProcessOutput {
            code: Some(0),
            stdout: stream.clone(),
            stderr: stream,
            trigger: None,
        };
        assert_eq!(
            classify(
                &output,
                &serde_json::json!({"OOMKilled":false,"Status":"exited","Error":"","ExitCode":0})
            )
            .0,
            ExecutionOutcome::Completed
        );
        for malformed in [
            Value::Null,
            serde_json::json!(0),
            serde_json::json!("false"),
        ] {
            let state = serde_json::json!({"OOMKilled":malformed,"Status":"exited","Error":"","ExitCode":0});
            assert_eq!(
                classify(&output, &state).0,
                ExecutionOutcome::SandboxFailure
            );
        }
        let identity = mock("removed")?.1.preflight()?;
        assert_eq!(identity.client_version, "test-client");
        assert_eq!(identity.server_version, "test");
        assert_eq!(
            identity.runtime_information["component/runc"],
            "test-runtime"
        );
        assert!(identity.client_path.ends_with("runtime-mock"));
        assert_eq!(identity.runtime_information["ID"], "test-daemon");
        assert_eq!(
            identity.runtime_information["authority/endpoint"],
            "unix:///not-a-real-runtime.sock"
        );
        Ok(())
    }
    #[test]
    fn runtime_endpoint_is_bounded_local_authority_configuration() -> TestResult {
        let (_temp, runtime) = mock("removed")?;
        for endpoint in [
            "tcp://127.0.0.1:2375",
            "ssh://runtime.example",
            "unix://relative.sock",
            "unix:///",
            "unix:///run/../rootful.sock",
            "unix:///run/rootless\n.sock",
            "unix:///run/rootless\0.sock",
        ] {
            assert!(DockerRuntime::new(runtime.executable.clone(), endpoint.into()).is_err());
        }
        assert!(
            DockerRuntime::new(
                runtime.executable.clone(),
                format!("unix:///{}", "a".repeat(4096))
            )
            .is_err()
        );
        let command = runtime.command(&strings(&["info"]));
        let args: Vec<_> = command.get_args().map(|s| s.to_string_lossy()).collect();
        assert!(args.windows(2).any(|a| a == ["--host", &runtime.endpoint]));
        assert!(
            !args
                .iter()
                .any(|s| s.contains("--context") || s.contains("--tls"))
        );
        Ok(())
    }
    #[test]
    fn argv_has_no_shell_host_mounts_runtime_socket_or_ambient_environment() -> TestResult {
        let (_root, lease, request) = request()?;
        let args = target_args(
            &request,
            ExecutionId::new(),
            "job",
            "sha256:test",
            &[serde_json::json!("GITHUB_TOKEN=image-value")],
        )?;
        assert!(args.contains(&"--network=none".into()));
        assert!(args.contains(&"--read-only".into()));
        for forbidden in [
            "--privileged",
            "--network=host",
            "--pid=host",
            "--ipc=host",
            "--userns=host",
            "/var/run/docker.sock",
            "--mount",
            "--volume",
            "sh",
            "-c",
        ] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
        assert!(!args.iter().any(|a| a.contains("image-value")));
        assert!(args.windows(2).any(|a| a == ["--env", "GITHUB_TOKEN"]));
        assert!(args.ends_with(&[
            "python3".into(),
            "/source/hostile.py".into(),
            "normal".into()
        ]));
        lease.destroy()?;
        Ok(())
    }
    #[test]
    fn recorded_docker_configuration_rejects_each_authority_downgrade() -> TestResult {
        let (_root, lease, request) = request()?;
        let id = ExecutionId::new();
        let mut valid: Value =
            serde_json::from_str(include_str!("../tests/fixtures/docker-inspect.json"))?;
        valid["Config"]["Labels"] = serde_json::json!({"archcert.job":id.to_string(),"archcert.workspace":request.input().workspace().to_string(),"archcert.owner":"execution-v1"});
        let image = format!("sha256:{}", "a".repeat(64));
        verify_container(&valid, &request, id, &image)?;
        for (key, value) in [
            ("Privileged", serde_json::json!(true)),
            ("NetworkMode", serde_json::json!("host")),
            ("PidMode", serde_json::json!("host")),
            ("IpcMode", serde_json::json!("host")),
            ("UsernsMode", serde_json::json!("host")),
            ("ReadonlyRootfs", serde_json::json!(false)),
            ("Memory", serde_json::json!(0)),
            ("MemorySwap", serde_json::json!(-1)),
            ("PidsLimit", serde_json::json!(0)),
            ("CpuQuota", serde_json::json!(0)),
            ("CapAdd", serde_json::json!(["SYS_ADMIN"])),
            ("Binds", serde_json::json!(["/:/host"])),
            ("Devices", serde_json::json!([{"PathOnHost":"/dev/sda"}])),
            ("SecurityOpt", serde_json::json!(["seccomp=unconfined"])),
            ("Tmpfs", serde_json::json!({"/":"rw"})),
        ] {
            let mut invalid = valid.clone();
            invalid["HostConfig"][key] = value;
            assert!(
                verify_container(&invalid, &request, id, &image).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("User", serde_json::json!("0:0")),
            (
                "Env",
                serde_json::json!(["HOME=/Users/developer", "OPENAI_API_KEY=host-secret"]),
            ),
            ("Cmd", serde_json::json!(["-i", "sh", "-c", "target"])),
            ("Labels", serde_json::json!({})),
            ("Volumes", serde_json::json!({"/host":{}})),
        ] {
            let mut invalid = valid.clone();
            invalid["Config"][key] = value;
            assert!(
                verify_container(&invalid, &request, id, &image).is_err(),
                "{key}"
            );
        }
        lease.destroy()?;
        Ok(())
    }
    #[test]
    fn bounded_mock_io_and_runtime_environment_exclusion() -> TestResult {
        let (_temp, runtime) = mock("removed")?;
        assert_eq!(runtime.preflight()?.server_version, "test");
        let env = runtime.json(&["mock-env"])?;
        for key in [
            "SSH_AUTH_SOCK",
            "DATABASE_URL",
            "OPENAI_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_API_VERSION",
            "KUBECONFIG",
        ] {
            assert!(env.get(key).is_none(), "{key}");
        }
        assert_eq!(
            env["HOME"],
            runtime
                .configuration
                .path()
                .to_str()
                .ok_or("invalid test path")?
        );
        let out = process::run(
            runtime.command(&strings(&["mock-output"])),
            &[],
            IoPolicy {
                timeout: Duration::from_secs(5),
                stdout: 65536,
                stderr: 65536,
                prefix: 8,
            },
            || {},
        )?;
        assert_eq!(out.code, Some(7));
        assert_eq!(out.stdout.observed_bytes, 16000);
        assert_eq!(out.stderr.observed_bytes, 17000);
        assert_eq!(
            out.stdout.sha256,
            archcert_domain::source::digest_bytes(&vec![b'a'; 16000])
        );
        assert!(out.stdout.complete && out.stdout.truncated);
        Ok(())
    }
    #[test]
    fn cleanup_distinguishes_destroyed_absent_disconnected_and_orphan() -> TestResult {
        for (mode, expected) in [
            ("removed", CleanupStatus::Destroyed),
            ("absent", CleanupStatus::Destroyed),
            ("disconnected", CleanupStatus::Failed),
            ("cleanup-failure", CleanupStatus::Failed),
        ] {
            let (_temp, runtime) = mock(mode)?;
            let mut lease = SandboxLease {
                runtime: &runtime,
                prep: "prep".into(),
                target: "target".into(),
                image_tag: "archcert-job:test".into(),
                touched: true,
                destroyed: false,
            };
            assert_eq!(lease.cleanup(), expected, "{mode}");
        }
        Ok(())
    }
    #[test]
    fn panic_unwinding_attempts_sandbox_destruction() -> TestResult {
        let (_temp, runtime) = mock("removed")?;
        let result = std::panic::catch_unwind(|| {
            let _lease = SandboxLease {
                runtime: &runtime,
                prep: "prep".into(),
                target: "target".into(),
                image_tag: "archcert-job:test".into(),
                touched: true,
                destroyed: false,
            };
            panic!("injected authority panic");
        });
        assert!(result.is_err());
        let calls = fs::read_to_string(runtime.configuration.path().join("calls.jsonl"))?;
        assert!(
            calls.contains("target")
                && calls.contains("prep")
                && calls.contains("archcert-job:test")
        );
        Ok(())
    }
    #[test]
    fn runtime_failure_never_becomes_target_test_failure_or_success() -> TestResult {
        let (_temp, runtime) = mock("removed")?;
        let mut output = process::run(
            runtime.command(&strings(&["mock-output"])),
            &[],
            IoPolicy {
                timeout: Duration::from_secs(5),
                stdout: 65536,
                stderr: 65536,
                prefix: 8,
            },
            || {},
        )?;
        let mut state =
            serde_json::json!({"Status":"exited","Error":"","ExitCode":7,"OOMKilled":false});
        assert_eq!(classify(&output, &state).0, ExecutionOutcome::Completed);
        state["ExitCode"] = serde_json::json!(0);
        assert_eq!(
            classify(&output, &state).0,
            ExecutionOutcome::SandboxFailure
        );
        state["OOMKilled"] = serde_json::json!(true);
        assert_eq!(classify(&output, &state).1, TerminationReason::MemoryLimit);
        output.trigger = Some(TerminationReason::Timeout);
        assert_eq!(classify(&output, &state).0, ExecutionOutcome::TimedOut);
        output.trigger = Some(TerminationReason::StdoutLimit);
        assert_eq!(classify(&output, &state).0, ExecutionOutcome::ResourceLimit);
        Ok(())
    }
    #[test]
    fn controller_deadline_kills_a_hung_runtime_client() -> TestResult {
        let (_temp, runtime) = mock("removed")?;
        let mut terminated = false;
        let started = Instant::now();
        let output = process::run(
            runtime.command(&strings(&["mock-hang"])),
            &[],
            IoPolicy {
                timeout: Duration::from_millis(50),
                stdout: 1024,
                stderr: 1024,
                prefix: 8,
            },
            || terminated = true,
        )?;
        assert!(terminated);
        assert_eq!(output.trigger, Some(TerminationReason::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }
}
