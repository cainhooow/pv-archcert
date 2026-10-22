//! Live M6 collection on independent rootless sandboxes; never runs targets on host.
#![cfg(unix)]

use archcert_application::{
    execution::ExecutionRequest,
    materialization::{MaterializationRequest, SourceMaterializer},
    release::*,
};
use archcert_domain::{
    GitObjectId, ProjectId,
    materialization::{MaterializationLimits, SnapshotReference},
    source::*,
};
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_runner::{DockerRootlessRunner, DockerRuntime};
use std::{fs, os::unix::fs::PermissionsExt};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn build(source: &SourceSnapshot, recipe: &RustReleaseRecipe) -> R<Vec<u8>> {
    let root = tempfile::tempdir()?;
    let path = root.path().canonicalize()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);
    let prepared = materializer.prepare(
        source,
        &MaterializationRequest {
            snapshot: SnapshotReference {
                project: source.project(),
                repository: source.repository().clone(),
                identity: source.identity().clone(),
            },
            limits: MaterializationLimits::default(),
        },
    )?;
    let runner = DockerRootlessRunner::new(DockerRuntime::for_release(
        std::env::var("ARCHCERT_TEST_DOCKER")?.into(),
        std::env::var("ARCHCERT_TEST_ENDPOINT")?,
    )?);
    let result = runner.execute_file(ExecutionRequest::new(
        prepared.runner_input,
        recipe.execution_profile()?,
        recipe.description().command.clone(),
    )?);
    prepared.cleanup.destroy()?;
    let result = result?;

    assert_eq!(
        result.execution.evidence.exit_code,
        Some(0),
        "{:?}",
        result.execution.evidence.stderr
    );
    assert_eq!(
        result.execution.evidence.stdout.excerpt,
        b"ARCHCERT_BUILD_READY_V1\n"
    );

    result
        .artifact
        .ok_or_else(|| "missing collected artifact".into())
}

#[test]
#[ignore = "requires explicit authority Rust image and independently provisioned rootless daemon"]
fn independent_rust_builds_collect_equal_bytes_and_detect_real_nondeterminism() -> R {
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: std::env::var("ARCHCERT_TEST_RUST_IMAGE")?,
            dependency_bundle_sha256: digest_bytes(b"empty fixture dependency closure"),
            toolchain_sha256: digest_bytes(b"explicit test image toolchain"),
        },
        "fixture",
    )?;
    let source = |random: bool| -> R<SourceSnapshot> {
        let mut files = vec![
            (
                "Cargo.toml",
                b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                    .to_vec(),
            ),
            (
                "Cargo.lock",
                b"version = 4\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n".to_vec(),
            ),
            (
                "src/main.rs",
                if random {
                    b"fn main() { println!(\"{}\", env!(\"NONDETERMINISTIC\")); }\n".to_vec()
                } else {
                    b"fn main() { println!(\"deterministic\"); }\n".to_vec()
                },
            ),
        ];
        if random {
            files.push(("build.rs", b"use std::io::Read;\nfn main() { let mut b=[0u8;32]; std::fs::File::open(\"/dev/urandom\").unwrap().read_exact(&mut b).unwrap(); println!(\"cargo:rustc-env=NONDETERMINISTIC={b:?}\"); }\n".to_vec()));
        }
        Ok(SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("fixture/release")?,
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            files
                .into_iter()
                .map(|(p, b)| {
                    Ok(SourceFile::new(
                        SourcePath::from_bytes(p.as_bytes())?,
                        SourceMode::File,
                        b,
                    ))
                })
                .collect::<Result<Vec<_>, SourceError>>()?,
            4,
            1,
        )?)
    };
    let deterministic = source(false)?;
    let a = build(&deterministic, &recipe)?;
    let b = build(&deterministic, &recipe)?;
    assert_eq!(a, b);

    let nondeterministic = source(true)?;
    let a = build(&nondeterministic, &recipe)?;
    let b = build(&nondeterministic, &recipe)?;
    assert_ne!(digest_bytes(&a), digest_bytes(&b));

    Ok(())
}

#[test]
#[ignore = "requires explicit authority Rust image and independently provisioned rootless daemon"]
fn authority_collector_rejects_links_special_files_directories_and_extra_outputs() -> R {
    use archcert_domain::execution::{ExecutionCommand, ExecutionProfile};

    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: std::env::var("ARCHCERT_TEST_RUST_IMAGE")?,
            dependency_bundle_sha256: digest_bytes(b"no target dependency acquisition"),
            toolchain_sha256: digest_bytes(b"explicit test image"),
        },
        "fixture",
    )?;

    for setup in [
        "os.symlink('/source', '/output/artifact')",
        "os.mkdir('/output/artifact')",
        "os.mkfifo('/output/artifact')",
        "open('/output/artifact','wb').write(b'bytes'); open('/output/extra','wb').write(b'extra')",
    ] {
        let root = tempfile::tempdir()?;
        let path = root.path().canonicalize()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let source = SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("fixture/output-rejection")?,
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![],
            1,
            1,
        )?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);
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
        let command = ExecutionCommand::new(
            "/usr/bin/python3".into(),
            vec![
                "-I".into(),
                "-c".into(),
                format!(
                    "import os,signal,time\n{setup}\nsignal.signal(signal.SIGUSR1,lambda *_:exit(0))\nos.write(1,b'ARCHCERT_BUILD_READY_V1\\n')\nwhile True: time.sleep(1)\n"
                ),
            ],
            "/source".into(),
        )?;
        let runner = DockerRootlessRunner::new(DockerRuntime::for_release(
            std::env::var("ARCHCERT_TEST_DOCKER")?.into(),
            std::env::var("ARCHCERT_TEST_ENDPOINT")?,
        )?);
        let execution = runner.execute_file(ExecutionRequest::new(
            prepared.runner_input,
            ExecutionProfile::new(
                "output-negative-test".into(),
                recipe.description().environment.image.clone(),
                vec!["/usr/bin/python3".into()],
                recipe.description().limits,
            )?,
            command,
        )?);
        prepared.cleanup.destroy()?;

        let failure = execution.err().ok_or("unsafe output was accepted")?;
        assert_eq!(
            failure.cleanup,
            archcert_application::materialization::CleanupStatus::Destroyed
        );
    }

    Ok(())
}
