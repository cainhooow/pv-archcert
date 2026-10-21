//! Offline verification and authority command contract, with no OCI dependency.

use serde_json::{Value, json};
use std::{fs, process::Command};
type R = Result<(), Box<dyn std::error::Error>>;

const VECTOR: &[u8] =
    include_bytes!("../../../crates/archcert-certificate/tests/fixtures/openssl-vector.json");

#[test]
fn verify_works_without_repo_runtime_network_private_key_or_environment() -> R {
    let dir = tempfile::tempdir()?;
    let value: Value = serde_json::from_slice(VECTOR)?;
    let certificate = dir.path().join("certificate.json");
    let public = dir.path().join("public.hex");
    fs::write(&certificate, VECTOR)?;
    fs::write(&public, value["public_key"].as_str().ok_or("key")?)?;

    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .env_clear()
        .current_dir(dir.path())
        .arg("verify")
        .arg(&certificate)
        .arg("--public-key")
        .arg(&public)
        .output()?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(report["status"], "CERTIFIED");
    assert_eq!(report["revocation"], "NOT IMPLEMENTED");
    assert_eq!(report["signature"], "SIGNATURE VALID");
    assert_eq!(report["structure"], "CERTIFICATE STRUCTURE VALID");

    let mut bad = value.clone();
    bad["signature"] = json!("00".repeat(64));
    fs::write(&certificate, serde_json::to_vec(&bad)?)?;

    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .env_clear()
        .current_dir(dir.path())
        .arg("verify")
        .arg(&certificate)
        .arg("--public-key")
        .arg(&public)
        .output()?;

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CERTIFIED"));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?["status"],
        "VERIFICATION FAILED"
    );

    fs::write(&certificate, VECTOR)?;
    // RFC 8032 test public key is a valid unrelated Ed25519 key, with no fallback.
    fs::write(
        &public,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .env_clear()
        .current_dir(dir.path())
        .arg("verify")
        .arg(&certificate)
        .arg("--public-key")
        .arg(&public)
        .output()?;

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CERTIFIED"));

    Ok(())
}

#[test]
fn certify_has_explicit_development_authority_and_no_eligibility_bypass() -> R {
    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args(["certify", "--help"])
        .output()?;

    assert!(output.status.success());

    let help = String::from_utf8(output.stdout)?;

    for required in [
        "--development-key",
        "--public-key",
        "--authority-config",
        "--output",
    ] {
        assert!(help.contains(required));
    }

    for forbidden in [
        "--skip",
        "--force",
        "--waiver",
        "--algorithm",
        "--eligible",
        "--evaluation",
    ] {
        assert!(!help.contains(forbidden));
    }

    let verify = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .args(["verify", "certificate.json"])
        .output()?;

    assert!(!verify.status.success());

    Ok(())
}

#[cfg(unix)]
#[test]
fn development_keygen_uses_temporary_private_files_and_only_prints_public_identity() -> R {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let private = dir.path().join("key.der");
    let public = dir.path().join("public.hex");

    let output = Command::new(env!("CARGO_BIN_EXE_archcert"))
        .arg("development-keygen")
        .arg("--private-key")
        .arg(&private)
        .arg("--public-key")
        .arg(&public)
        .output()?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;

    assert!(stdout.contains("DEVELOPMENT ONLY / NOT PRODUCTION KEY MANAGEMENT"));
    assert_eq!(fs::metadata(&private)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(&public)?.len(), 64);

    let private_bytes = fs::read(&private)?;
    let private_hex = private_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert!(!stdout.contains(&private_hex));
    assert!(output.stderr.is_empty());

    Ok(())
}
