//! End-to-end source inspection using an independently constructed Git tree.
#![cfg(unix)]

use std::{
    error::Error,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn git(path: &Path, args: &[&str], input: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut process = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("missing PATH")?)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.com")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.com")
        .arg("--git-dir")
        .arg(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    process
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(input)?;
    let output = process.wait_with_output()?;

    if !output.status.success() {
        return Err("Git fixture construction failed".into());
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[test]
fn cli_emits_structured_evidence_for_known_source_and_rejects_head() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().canonicalize()?.join("fixture.git");
    git(&path, &["init", "--bare", "--object-format=sha1"], b"")?;
    let blob = git(&path, &["hash-object", "-w", "--stdin"], b"abc")?;
    let tree = git(
        &path,
        &["mktree"],
        format!("100644 blob {blob}\ta\n").as_bytes(),
    )?;
    let commit = git(&path, &["commit-tree", &tree], b"fixture\n")?;

    let invoke = |oid: &str| {
        Command::new(env!("CARGO_BIN_EXE_archcert"))
            .args(["source", "inspect"])
            .arg(&path)
            .arg(oid)
            .args([
                "--project",
                "00000000-0000-4000-8000-000000000001",
                "--repository",
                "test/source",
            ])
            .output()
    };
    let output = invoke(&commit)?;

    assert!(output.status.success());

    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(evidence["identity"]["commit"], commit);
    assert_eq!(evidence["identity"]["tree"], tree);
    assert_eq!(
        evidence["identity"]["snapshot_sha256"],
        "252d8a8aa373a45994b32021ac661a412b3c90138086686e41aaf92a491b2175"
    );
    assert_eq!(evidence["status"], "COMPLETE");
    assert_eq!(evidence["entry_count"], 1);
    assert_eq!(evidence["validation_version"], "archcert-loose-v1");

    let workspace_root = temporary.path().canonicalize()?.join("workspaces");
    std::fs::create_dir(&workspace_root)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o700))?;

    let materialized = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args(["source", "inspect"])
        .arg(&path)
        .arg(&commit)
        .args([
            "--project",
            "00000000-0000-4000-8000-000000000001",
            "--repository",
            "test/source",
            "--materialize-under",
        ])
        .arg(&workspace_root)
        .output()?;

    assert!(
        materialized.status.success(),
        "{}",
        String::from_utf8_lossy(&materialized.stderr)
    );

    let prepared: serde_json::Value = serde_json::from_slice(&materialized.stdout)?;

    assert_eq!(
        prepared["materialization"]["observed_digest"],
        evidence["identity"]["snapshot_sha256"]
    );
    assert_eq!(prepared["materialization"]["status"], "HANDED_OFF");
    assert_eq!(prepared["destruction"]["status"], "DESTROYED");
    assert_eq!(std::fs::read_dir(workspace_root)?.count(), 0);

    let invalid = invoke("HEAD")?;

    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());

    Ok(())
}
