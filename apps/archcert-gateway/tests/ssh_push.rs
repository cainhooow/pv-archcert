//! Actual public-key SSH transport, not an object-directory copy.
#![cfg(unix)]
#[test]
fn real_ssh_git_push_and_authentication_restrictions() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let retained = tempfile::tempdir()?;
    let result = std::process::Command::new("python3")
        .arg(root.join("scripts/test-northgate"))
        .args(["--binary", env!("CARGO_BIN_EXE_archcert-gateway")])
        .arg("--retain")
        .arg(retained.path())
        .current_dir(root)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for name in ["ordinary", "sha256", "incomplete", "resolved"] {
        let evidence: archcert_gateway::IngressEvidence = serde_json::from_slice(&std::fs::read(
            retained.path().join(format!("{name}.json")),
        )?)?;
        let encoded = std::fs::read(retained.path().join(format!("{name}.pb")))?;
        let decoded = archcert_protocol::protobuf::decode_submission(&encoded)?;
        assert_eq!(decoded, evidence.source_submission_state()?, "{name}");
    }
    Ok(())
}
