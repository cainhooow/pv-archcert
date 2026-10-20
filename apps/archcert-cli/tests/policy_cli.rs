//! Development CLI result vocabulary and unavailable-runner policy boundary.
use std::{error::Error, fs, process::Command};
type R = Result<(), Box<dyn Error>>;
#[test]
fn evaluate_help_has_no_policy_downgrade_or_signing_switch() -> R {
    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args(["evaluate", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("unsigned policy evaluation"));
    assert!(help.contains("--authority-config"));
    assert!(help.contains("--config"));
    for forbidden in [
        "--policy",
        "--waiver",
        "--sign",
        "--skip",
        "--not-applicable",
    ] {
        assert!(!help.contains(forbidden));
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn unavailable_real_runner_emits_inconclusive_command_and_never_fabricates_setup_facts() -> R {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let run_git = |args: &[&str]| -> R {
        let out = Command::new("git")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .args(["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0"])
            .args(args)
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    };
    run_git(&["init", "--template="])?;
    fs::write(repo.join("checks.py"), "print('TESTS PASSED')\n")?;
    run_git(&["add", "checks.py"])?;
    run_git(&["commit", "-m", "controlled fixture"])?;
    let head = Command::new("git")
        .current_dir(&repo)
        .args(["rev-parse", "HEAD"])
        .output()?;
    assert!(head.status.success());
    let commit = String::from_utf8(head.stdout)?.trim().to_owned();
    let workspaces = root.join("workspaces");
    fs::create_dir(&workspaces)?;
    fs::set_permissions(&workspaces, fs::Permissions::from_mode(0o700))?;
    let bin = env!("CARGO_BIN_EXE_archcert");
    let inspected = Command::new(bin)
        .args(["source", "inspect"])
        .arg(repo.join(".git"))
        .arg(&commit)
        .args([
            "--project",
            "00000000-0000-4000-8000-000000000004",
            "--repository",
            "fixture/policy-cli",
        ])
        .output()?;
    assert!(inspected.status.success());
    let source: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
    let report = Command::new(bin)
        .args(["evaluate", "--git-dir"])
        .arg(repo.join(".git"))
        .args([
            "--commit",
            &commit,
            "--snapshot",
            source["identity"]["snapshot_sha256"]
                .as_str()
                .ok_or("digest")?,
            "--project",
            "00000000-0000-4000-8000-000000000004",
            "--repository",
            "fixture/policy-cli",
            "--workspace-root",
        ])
        .arg(&workspaces)
        .args([
            "--profile",
            "python",
            "--image",
            &format!("approved@sha256:{}", "a".repeat(64)),
            "--docker",
            "/usr/bin/false",
            "--endpoint",
            "unix:///unavailable",
            "--authority-config",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/policy/CONTROLLED_AUTHORITY.toml"
        ))
        .output()?;
    assert!(!report.status.success());
    let report: serde_json::Value = serde_json::from_slice(&report.stdout)?;
    assert_eq!(report["kind"], "UNSIGNED POLICY EVALUATION");
    assert_eq!(report["notice"], "NOT A CERTIFICATE");
    assert_eq!(report["evaluation"]["eligibility"], "NOT_ELIGIBLE");
    for property in report["evaluation"]["properties"]
        .as_array()
        .ok_or("properties")?
    {
        match property["property"].as_str().ok_or("property")? {
            "SOURCE_COMPLETE" => assert_eq!(property["verdict"], "PROVEN"),
            "TEST_SUITE_COMPLETES" | "BUILD_COMPLETES" | "TYPECHECK_COMPLETES" => {
                assert_eq!(property["verdict"], "INCONCLUSIVE")
            }
            _ => assert_eq!(property["verdict"], "NOT_PROVEN"),
        }
    }
    assert_eq!(fs::read_dir(workspaces)?.count(), 0);
    Ok(())
}
