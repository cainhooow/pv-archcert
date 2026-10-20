//! Generates only authority-owned, explicitly enumerated ArchCert contracts.
use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    // prost-build otherwise appends an ambient include path. Candidate schemas
    // and machine-local include overrides must never enter authority generation.
    if env::var_os("PROTOC_INCLUDE").is_some() {
        return Err("PROTOC_INCLUDE must be unset; ArchCert uses pinned bundled includes".into());
    }
    let root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest directory missing")?)
            .join("../../proto");
    let files = [
        root.join("archcert/common/v1/identity.proto"),
        root.join("archcert/source/v1/source.proto"),
        root.join("archcert/execution/v1/worker.proto"),
    ];
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .file_descriptor_set_path(
            PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR missing")?).join("archcert-v1.bin"),
        )
        .compile_protos(&files, &[root, protoc_bin_vendored::include_path()?])?;
    Ok(())
}
