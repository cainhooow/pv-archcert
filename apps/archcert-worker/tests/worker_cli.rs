//! The execution process rejects substituted source before runtime access.
use archcert_application::worker::*;
use archcert_domain::{GitObjectId, ProjectId, ingress::*, jobs::*, source::*};
use std::io::Write;
#[test]
fn substituted_source_never_reaches_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let profile = "python";
    let image = format!("python@sha256:{}", "a".repeat(64));
    let toml = include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml");
    let plan = resolve_authority_plan(profile, &image, toml)?;
    let project = ProjectId::new();
    let repository = RepositoryId::parse("fixture/repo")?;
    let source = SourceSnapshot::seal(
        project,
        repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1700000000,
    )?;
    let mut bytes = Vec::new();
    archcert_source::write_snapshot(&source, &mut bytes)?;
    let mut identity = source.identity().clone();
    identity.snapshot_sha256 = digest_bytes(b"substitution");
    let assignment = WorkerAssignment {
        job: JobId::new(),
        attempt: AttemptId::new(),
        inputs: JobInputs {
            project,
            repository,
            submission: SourceSubmissionId::new(),
            source: identity,
            actor: GitActorId::parse(JobId::new().to_string())?,
            policy: PolicyPin {
                id: "development".into(),
                version: "1.0.0".into(),
                sha256: digest_bytes(b"policy"),
            },
            profile: profile.into(),
            image,
            plan_sha256: plan.digest()?,
            authority_toml: toml.into(),
            maximum_attempts: 1,
        },
        source_artifact: bytes,
    };
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_archcert-worker"))
        .env_clear()
        .args([
            "--workspace-root",
            "/does-not-exist",
            "--docker",
            "/does-not-exist",
            "--endpoint",
            "unix:///does-not-exist",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("stdin missing")?.write_all(
        &archcert_protocol::protobuf::worker::encode_assignment(&assignment)?,
    )?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("assignment source binding mismatch"));
    Ok(())
}
