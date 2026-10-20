//! Real hostile-code tests. Ignored unless explicitly run against provisioned rootless OCI.
#![cfg(unix)]
use archcert_application::{
    execution::{ExecutionRequest, ExecutionResult, SandboxRunner},
    materialization::{CleanupStatus, MaterializationRequest, SourceMaterializer},
};
use archcert_domain::{
    GitObjectId, ProjectId,
    execution::{
        ExecutionCommand, ExecutionEvent, ExecutionLimits, ExecutionOutcome, ExecutionProfile,
        TerminationReason,
    },
    materialization::{MaterializationLimits, SnapshotReference},
    source::{RepositoryId, SourceFile, SourceMode, SourcePath, SourceSnapshot, digest_bytes},
};
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_runner::{DockerRootlessRunner, DockerRuntime};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const FIXTURE: &[u8] = include_bytes!("fixtures/hostile.py");

fn settings() -> Result<(PathBuf, String, String), Box<dyn std::error::Error>> {
    Ok((
        std::env::var("ARCHCERT_TEST_DOCKER")?.into(),
        std::env::var("ARCHCERT_TEST_ENDPOINT")?,
        std::env::var("ARCHCERT_TEST_IMAGE")?,
    ))
}
fn execute(
    mode: &str,
    extra: &[String],
    limits: ExecutionLimits,
    cwd: &str,
) -> Result<ExecutionResult, Box<dyn std::error::Error>> {
    let (cli, endpoint, image) = settings()?;
    let runner = DockerRootlessRunner::new(DockerRuntime::new(cli.clone(), endpoint.clone())?);
    runner.verify_environment()?;
    let root = tempfile::tempdir()?;
    let root_path = root.path().canonicalize()?;
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))?;
    let source = SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("archcert/hostile-fixture")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![
            SourceFile::new(
                SourcePath::from_bytes(b"hostile.py")?,
                SourceMode::File,
                FIXTURE.to_vec(),
            ),
            SourceFile::new(
                SourcePath::from_bytes(b"accepted.txt")?,
                SourceMode::File,
                b"accepted bytes\n".to_vec(),
            ),
            SourceFile::new(
                SourcePath::from_bytes(b"escape")?,
                SourceMode::Symlink,
                b"/etc/archcert-host-only-marker".to_vec(),
            ),
        ],
        3,
        1,
    )?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&root_path)?);
    let prepared = materializer.prepare(
        &source,
        &MaterializationRequest {
            snapshot: SnapshotReference {
                project: source.project(),
                repository: source.repository().clone(),
                identity: source.identity().clone(),
            },
            limits: MaterializationLimits::default(),
        },
    )?;
    let mut args = vec!["/source/hostile.py".into(), mode.into()];
    args.extend_from_slice(extra);
    let request = ExecutionRequest::new(
        prepared.runner_input,
        ExecutionProfile::new(
            "fixture-python".into(),
            image,
            vec!["python3".into()],
            limits,
        )?,
        ExecutionCommand::new("python3".into(), args, cwd.into())?,
    )?;
    let result = runner.execute(request);
    // Source identity is checked after target attempts, before source cleanup.
    let files = source.manifest().entries();
    assert_eq!(files.len(), 3);
    let source_path = prepared.cleanup.location().as_path().join("accepted.txt");
    assert_eq!(fs::read(source_path)?, b"accepted bytes\n");
    assert_eq!(
        fs::read(prepared.cleanup.location().as_path().join("hostile.py"))?,
        FIXTURE
    );
    prepared.cleanup.destroy()?;
    let result = result?;
    assert_eq!(result.evidence.source, source.identity().clone());
    assert_eq!(result.cleanup, CleanupStatus::Destroyed);
    assert_eq!(
        result.events.last(),
        Some(&ExecutionEvent::SandboxDestroyed)
    );
    // Independent daemon query proves no job-labelled child or stopped container
    // survives cleanup. Do not infer child death from stdout.
    let config = tempfile::tempdir()?;
    let listing = Command::new(&cli)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("--config")
        .arg(config.path())
        .args([
            "--host",
            &endpoint,
            "container",
            "ls",
            "--all",
            "--filter",
            &format!("label=archcert.job={}", result.evidence.execution),
            "--quiet",
        ])
        .output()?;
    assert!(listing.status.success());
    assert!(listing.stdout.is_empty());
    let images = Command::new(&cli)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("--config")
        .arg(config.path())
        .args([
            "--host",
            &endpoint,
            "image",
            "ls",
            "--quiet",
            "--filter",
            &format!("label=archcert.job={}", result.evidence.execution),
        ])
        .output()?;
    assert!(images.status.success());
    assert!(images.stdout.is_empty(), "job-local image survived cleanup");
    if let Some(directory) = std::env::var_os("ARCHCERT_TEST_EVIDENCE_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(format!("{}.json", result.evidence.execution)))?;
        file.write_all(&serde_json::to_vec(&result)?)?;
    }
    Ok(result)
}
fn completed(mode: &str, extra: &[String]) -> TestResult {
    let result = execute(mode, extra, ExecutionLimits::default(), "/source")?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "stderr bytes: {:?}",
        result.evidence.stderr.excerpt
    );
    Ok(())
}
#[test]
#[ignore = "requires explicit rootless OCI endpoint and pinned locally provisioned Python image"]
fn successful_command_stdout_stderr_and_nonzero_exit() -> TestResult {
    let result = execute("normal", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(result.evidence.stdout.excerpt, b"normal stdout\n");
    assert_eq!(result.evidence.stderr.excerpt, b"normal stderr\n");
    assert_eq!(
        result.evidence.stdout.sha256,
        digest_bytes(b"normal stdout\n")
    );
    assert_eq!(
        result.evidence.stderr.sha256,
        digest_bytes(b"normal stderr\n")
    );
    assert!(result.evidence.stdout.complete && result.evidence.stderr.complete);
    let result = execute("nonzero", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(result.evidence.exit_code, Some(7));
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(result.evidence.stdout.excerpt, b"ARCHCERT RESULT: PASS\n");
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn stdout_stderr_prefixes_binary_and_terminal_bytes_are_safe() -> TestResult {
    let result = execute("prefix", &[], ExecutionLimits::default(), "/source")?;
    assert!(result.evidence.stdout.truncated && result.evidence.stderr.truncated);
    assert_eq!(result.evidence.stdout.excerpt.len(), 8192);
    assert_eq!(
        result.evidence.stdout.sha256,
        digest_bytes(&vec![b'a'; 16000])
    );
    assert_eq!(
        result.evidence.stderr.sha256,
        digest_bytes(&vec![b'b'; 17000])
    );
    let binary = execute("binary", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(binary.evidence.stdout.excerpt, b"\x1b[2J\xffstdout\x00");
    assert!(!serde_json::to_string(&binary)?.contains('\x1b'));
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn timeout_infinite_loop_and_detached_children_are_destroyed() -> TestResult {
    for mode in ["timeout", "children", "double-fork"] {
        let limits = ExecutionLimits {
            timeout_ms: 1500,
            ..ExecutionLimits::default()
        };
        let result = execute(mode, &[], limits, "/source")?;
        assert_eq!(result.evidence.outcome, ExecutionOutcome::TimedOut);
        assert_eq!(result.evidence.termination, TerminationReason::Timeout);
        assert!(
            result
                .evidence
                .stdout
                .excerpt
                .starts_with(format!("{mode}-started").as_bytes())
        );
        assert!(result.events.contains(&ExecutionEvent::ExecutionTimedOut));
    }
    completed("exit-with-child", &[])
}
#[test]
#[ignore = "requires rootless OCI"]
fn stdout_and_stderr_floods_terminate_externally() -> TestResult {
    for (mode, reason) in [
        ("stdout-flood", TerminationReason::StdoutLimit),
        ("stderr-flood", TerminationReason::StderrLimit),
    ] {
        let limits = ExecutionLimits {
            stdout_bytes: 32768,
            stderr_bytes: 32768,
            ..ExecutionLimits::default()
        };
        let result = execute(mode, &[], limits, "/source")?;
        assert_eq!(result.evidence.outcome, ExecutionOutcome::ResourceLimit);
        assert_eq!(result.evidence.termination, reason);
        assert!(
            result.evidence.stdout.excerpt.len() <= 8192
                && result.evidence.stderr.excerpt.len() <= 8192
        );
    }
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn memory_exhaustion_is_runtime_oom_not_a_test_failure() -> TestResult {
    let limits = ExecutionLimits {
        memory_bytes: 64 * 1024 * 1024,
        timeout_ms: 5000,
        ..ExecutionLimits::default()
    };
    let result = execute("memory", &[], limits, "/source")?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::ResourceLimit);
    assert_eq!(result.evidence.termination, TerminationReason::MemoryLimit);
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn fork_bomb_and_cpu_memory_pid_cgroup_limits() -> TestResult {
    let limits = ExecutionLimits {
        pids: 16,
        ..ExecutionLimits::default()
    };
    let result = execute("fork", &[], limits, "/source")?;
    assert_eq!(result.evidence.exit_code, Some(0));
    assert!(
        result
            .evidence
            .stdout
            .excerpt
            .starts_with(b"pid-limit-blocked")
    );
    completed(
        "resources",
        &[
            ExecutionLimits::default().memory_bytes.to_string(),
            ExecutionLimits::default().pids.to_string(),
        ],
    )
}
#[test]
#[ignore = "requires rootless OCI"]
fn clean_environment_and_host_credential_canary() -> TestResult {
    // Poison only an isolated test subprocess; Rust 2024 process-wide set_var is
    // deliberately avoided. Test child runs this test with a recursion sentinel.
    if std::env::var_os("ARCHCERT_CANARY_CHILD").is_none() {
        let canary = "archcert-canary-host-only-m3-8f17";
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args([
                "--ignored",
                "--exact",
                "clean_environment_and_host_credential_canary",
                "--nocapture",
            ])
            .env("ARCHCERT_CANARY_CHILD", "1");
        for key in [
            "ARCHCERT_TEST_HOST_SECRET",
            "SSH_AUTH_SOCK",
            "DATABASE_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_API_VERSION",
            "KUBECONFIG",
        ] {
            child.env(key, canary);
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output
                .stdout
                .windows(canary.len())
                .any(|w| w == canary.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(canary.len())
                .any(|w| w == canary.as_bytes())
        );
        return Ok(());
    }
    let result = execute("environment", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "{:?}",
        result.evidence.stderr.excerpt
    );
    let canary = b"archcert-canary-host-only-m3-8f17";
    for bytes in [
        &result.evidence.stdout.excerpt,
        &result.evidence.stderr.excerpt,
    ] {
        assert!(!bytes.windows(canary.len()).any(|w| w == canary));
    }
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn host_files_source_mutation_and_runtime_socket_are_blocked() -> TestResult {
    let marker = tempfile::NamedTempFile::new()?;
    fs::write(marker.path(), b"host-only filesystem canary")?;
    completed(
        "filesystem",
        &[
            marker.path().canonicalize()?.to_string_lossy().into_owned(),
            "/Users/cainho/.ssh/id_ed25519".into(),
            "/home/cainho.guest/.ssh/authorized_keys".into(),
            "/etc/archcert-host-only-marker".into(),
        ],
    )
}
#[test]
#[ignore = "requires rootless OCI"]
fn dns_tcp_http_metadata_and_host_gateway_have_no_route() -> TestResult {
    completed("network", &[])
}
#[test]
#[ignore = "requires rootless OCI; records IPv6 unavailability or explicit TCP/UDP no-route behavior"]
fn ipv6_metadata_and_external_routes_are_denied() -> TestResult {
    let result = execute("ipv6", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "{:?}",
        result.evidence.stderr.excerpt
    );
    let observation: serde_json::Value = serde_json::from_slice(&result.evidence.stdout.excerpt)?;
    assert!(matches!(
        observation["ipv6_socket"].as_str(),
        Some("available" | "unavailable")
    ));
    if observation["ipv6_socket"] == "available" {
        assert_eq!(observation["external_routes"], "denied");
    }
    // Retain the actual disabled/address facts in the operator's bounded test log.
    println!("IPv6 observation: {observation}");
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn loopback_remains_private_and_available() -> TestResult {
    let result = execute("loopback", &[], ExecutionLimits::default(), "/source")?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "{:?}",
        result.evidence.stderr.excerpt
    );
    let observation: serde_json::Value = serde_json::from_slice(&result.evidence.stdout.excerpt)?;
    assert_eq!(observation["ipv4_loopback"], "available");
    println!("Private loopback observation: {observation}");
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI and actual cgroup v2 CPU throttling"]
fn cpu_quota_throttles_target_execution() -> TestResult {
    let result = execute(
        "cpu-throttling",
        &[],
        ExecutionLimits {
            cpu_millis: 100,
            timeout_ms: 15000,
            ..ExecutionLimits::default()
        },
        "/source",
    )?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "{:?}",
        result.evidence.stderr.excerpt
    );
    println!(
        "CPU throttling observation: {}",
        String::from_utf8_lossy(&result.evidence.stdout.excerpt)
    );
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn process_churn_and_nested_shells_remain_within_pid_limit() -> TestResult {
    let result = execute(
        "process-churn",
        &[],
        ExecutionLimits {
            pids: 16,
            ..ExecutionLimits::default()
        },
        "/source",
    )?;
    assert_eq!(result.evidence.outcome, ExecutionOutcome::Completed);
    assert_eq!(
        result.evidence.exit_code,
        Some(0),
        "{:?}",
        result.evidence.stderr.excerpt
    );
    Ok(())
}
#[test]
#[ignore = "requires rootless OCI"]
fn host_process_observation_is_blocked_and_user_is_unprivileged() -> TestResult {
    completed("process", &[std::process::id().to_string()])
}
#[test]
#[ignore = "requires rootless OCI"]
fn working_directory_and_bounded_temporary_disk() -> TestResult {
    let result = execute(
        "cwd",
        &["/work".into()],
        ExecutionLimits::default(),
        "/work",
    )?;
    assert_eq!(result.evidence.exit_code, Some(0));
    assert_eq!(result.evidence.stdout.excerpt, b"/work\n");
    for path in ["/work", "/tmp", "/output", "/home/archcert"] {
        completed("disk", &[path.into()])?;
    }
    Ok(())
}
