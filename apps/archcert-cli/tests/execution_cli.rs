//! Project requests never become authority runtime configuration.
use std::{error::Error, fs, process::Command};
#[test]
fn project_config_accepts_structured_requests_and_rejects_security_settings()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let config = root.path().join("archcert.toml");
    let valid = "schema=1\n[project]\nname='fixture'\n[execution]\nprofile='node'\n[[execution.commands]]\nname='typecheck'\nprogram='pnpm'\nargs=['typecheck']\n";
    fs::write(&config, valid)?;
    let check = || {
        Command::new(env!("CARGO_BIN_EXE_archcert"))
            .args(["config-check", "--file"])
            .arg(&config)
            .output()
    };
    assert!(check()?.status.success());
    for setting in [
        "privileged=true",
        "network='host'",
        "mounts=['/:/host']",
        "docker_socket=true",
        "environment={OPENAI_API_KEY='secret'}",
        "memory='unlimited'",
        "image='target-controlled:latest'",
    ] {
        let invalid = valid.replace("profile='node'", &format!("profile='node'\n{setting}"));
        fs::write(&config, invalid)?;
        assert!(!check()?.status.success(), "{setting}");
    }
    fs::write(
        &config,
        valid.replace("program='pnpm'", "program='sh -c test'"),
    )?;
    assert!(!check()?.status.success());
    Ok(())
}
#[test]
fn execution_help_exposes_only_structural_dry_run_inputs() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args(["run", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for required in [
        "--snapshot",
        "--profile",
        "--image",
        "--endpoint",
        "--working-directory",
        "--config",
    ] {
        assert!(help.contains(required));
    }
    assert!(help.contains("engineering evidence"));
    assert!(!help.contains("Validates the local"));
    for forbidden in [
        "--privileged",
        "--mount",
        "--network",
        "--env",
        "--disable-isolation",
    ] {
        assert!(!help.contains(forbidden));
    }
    Ok(())
}

#[test]
fn run_resolves_project_configuration_before_contacting_runtime() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let config = root.path().join("archcert.toml");
    fs::write(
        &config,
        "schema=1\n[project]\nname='fixture'\n[execution]\nprofile='rust'\n[[execution.commands]]\nname='test'\nprogram='cargo'\nargs=['test']\n",
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args([
            "run",
            "--git-dir",
            "/nonexistent",
            "--commit",
            &"a".repeat(40),
            "--snapshot",
            &"b".repeat(64),
            "--project",
            "00000000-0000-4000-8000-000000000001",
            "--repository",
            "test/project",
            "--workspace-root",
            "/nonexistent",
            "--profile",
            "node",
            "--image",
            &format!("approved@sha256:{}", "c".repeat(64)),
            "--docker",
            "/no-client",
            "--endpoint",
            "unix:///no-runtime",
            "--config",
        ])
        .arg(config)
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?.contains("unknown authority execution profile: rust")
    );
    Ok(())
}
