//! Knowledge identity across actual verified workspaces and independent processes.
#![cfg(unix)]

use archcert_application::{
    knowledge::*,
    materialization::{MaterializationRequest, SourceMaterializer},
    source::{SourceSubmission, ingest_source},
};
use archcert_domain::{
    GitObjectId,
    materialization::{MaterializationLimits, SnapshotReference},
    source::*,
};
use archcert_knowledge::RustSyntaxExtractor;
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_source::{LocalGitGateway, MemorySourceStore, read_snapshot, write_snapshot};
use std::{
    fs::{self, File, FileTimes, Permissions},
    os::unix::fs::PermissionsExt,
    process::Command,
    time::{Duration, Instant, UNIX_EPOCH},
};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn engine() -> Result<KnowledgeEngine, KnowledgeError> {
    KnowledgeEngine::new(
        vec![Box::new(RustSyntaxExtractor)],
        KnowledgeLimits::default(),
    )
}

fn fixture() -> R<SourceSnapshot> {
    Ok(SourceSnapshot::seal(
        "a57e0000-0000-4000-8000-000000000007".parse()?,
        RepositoryId::parse("asterwyn/materialization")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![
            SourceFile::new(
                SourcePath::from_bytes(b"src/lib.rs")?,
                SourceMode::File,
                b"mod shared; pub use shared::*;".to_vec(),
            ),
            SourceFile::new(
                SourcePath::from_bytes("src/partição.rs".as_bytes())?,
                SourceMode::File,
                b"pub fn work() {}".to_vec(),
            ),
            SourceFile::new(
                SourcePath::from_bytes(b"host.rs")?,
                SourceMode::Symlink,
                b"/host/DO_NOT_READ.rs".to_vec(),
            ),
        ],
        1,
        1,
    )?)
}

#[test]
fn extraction_is_identical_across_verified_materializations_and_metadata() -> R {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    fs::set_permissions(&root, Permissions::from_mode(0o700))?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&root)?);
    let accepted = fixture()?;
    let expected = engine()?.extract(&accepted, &[], None)?;
    let request = MaterializationRequest {
        snapshot: SnapshotReference {
            project: accepted.project(),
            repository: accepted.repository().clone(),
            identity: accepted.identity().clone(),
        },
        limits: MaterializationLimits::default(),
    };
    let mut workspaces = Vec::new();

    for ordinal in 0..3 {
        let prepared = materializer.prepare(&accepted, &request)?;
        let path = prepared.cleanup.location().as_path().to_owned();
        workspaces.push(path.clone());
        File::open(path.join("src/lib.rs"))?.set_times(
            FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_000 + ordinal)),
        )?;
        let mut files = prepared.runner_input.source().verified_files()?;

        if ordinal % 2 == 0 {
            files.reverse();
        }

        let reconstructed = SourceSnapshot::seal(
            accepted.project(),
            accepted.repository().clone(),
            accepted.identity().commit.clone(),
            accepted.identity().tree.clone(),
            files,
            100 + ordinal,
            2_000 + ordinal,
        )?;
        let actual = engine()?.extract(&reconstructed, &[], None)?;

        assert_eq!(reconstructed.identity(), accepted.identity());
        assert_eq!(actual.artifact().bytes(), expected.artifact().bytes());
        assert!(
            actual
                .body()
                .blind_spots
                .iter()
                .any(|b| b.code == "UNSUPPORTED_STRUCTURE"
                    && b.path.as_ref().is_some_and(|p| p.as_str() == "host.rs"))
        );
        prepared.cleanup.destroy()?;
    }

    workspaces.sort();
    workspaces.dedup();
    assert_eq!(workspaces.len(), 3);

    Ok(())
}

#[test]
fn knowledge_subprocess() -> R {
    let Some(input) = std::env::var_os("ARCHCERT_M7_TEST_SNAPSHOT") else {
        return Ok(());
    };
    let output = std::env::var_os("ARCHCERT_M7_TEST_OUTPUT").ok_or("test output missing")?;
    let source = read_snapshot(File::open(input)?, SourceLimits::default())?;
    let knowledge = engine()?.extract(&source, &[], None)?;
    let impact = analyze_impact(&knowledge, None)?;
    fs::write(&output, knowledge.artifact().bytes())?;
    fs::write(
        std::path::Path::new(&output).with_extension("impact"),
        impact.artifact().bytes(),
    )?;

    Ok(())
}

#[test]
fn independent_processes_and_cwd_preserve_canonical_knowledge_and_impact() -> R {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    let input = root.join("accepted.snapshot");
    let source = fixture()?;
    write_snapshot(&source, File::create(&input)?)?;
    let expected = engine()?.extract(&source, &[], None)?;
    let expected_impact = analyze_impact(&expected, None)?;

    for ordinal in 0..3 {
        let cwd = root.join(format!("independent-{ordinal}"));
        fs::create_dir(&cwd)?;
        let output = cwd.join("knowledge.json");
        let status = Command::new(std::env::current_exe()?)
            .args(["--exact", "knowledge_subprocess"])
            .current_dir(&cwd)
            .env("ARCHCERT_M7_TEST_SNAPSHOT", &input)
            .env("ARCHCERT_M7_TEST_OUTPUT", &output)
            .output()?;

        assert!(status.status.success(), "isolated extraction failed");
        assert_eq!(fs::read(&output)?, expected.artifact().bytes());
        assert_eq!(
            fs::read(output.with_extension("impact"))?,
            expected_impact.artifact().bytes()
        );
    }

    Ok(())
}

#[test]
#[ignore = "requires an authority-selected exact loose-object Git repository and evidence output"]
fn characterize_exact_source_without_target_execution() -> R {
    let git =
        std::env::var_os("ARCHCERT_M7_GIT_DIRECTORY").ok_or("exact Git directory required")?;
    let commit = std::env::var("ARCHCERT_M7_COMMIT")?;
    let output = std::env::var_os("ARCHCERT_M7_MEASUREMENTS").ok_or("evidence output required")?;
    let repository = RepositoryId::parse("archcert/archcert")?;
    let accepted = ingest_source(
        &LocalGitGateway::new(repository.clone(), git),
        &mut MemorySourceStore::default(),
        SourceSubmission {
            project: "a57e0000-0000-4000-8000-000000000007".parse()?,
            repository,
            requested_commit: GitObjectId::parse(commit)?,
        },
        SourceLimits::default(),
    )
    .map_err(|_| "exact source acquisition failed")?;
    let started = Instant::now();
    let knowledge = engine()?.extract(&accepted.snapshot, &[], None)?;
    let generation = started.elapsed();
    let started = Instant::now();
    let impact = analyze_impact(&knowledge, None)?;
    let traversal = started.elapsed();
    let measurements = serde_json::json!({
        "source": accepted.snapshot.identity(),
        "source_files": accepted.snapshot.files().len(),
        "source_bytes": accepted.snapshot.total_bytes(),
        "nodes": knowledge.body().nodes.len(),
        "edges": knowledge.body().edges.len(),
        "blind_spots": knowledge.body().blind_spots.len(),
        "knowledge_bytes": knowledge.artifact().bytes().len(),
        "knowledge_sha256": knowledge.artifact().digest(),
        "impact_bytes": impact.artifact().bytes().len(),
        "impact_sha256": impact.artifact().digest(),
        "generation_microseconds": generation.as_micros(),
        "impact_microseconds": traversal.as_micros(),
        "full_review": impact.body().full_review,
        "authority_bundles": [],
        "coverage": knowledge.body().coverage,
        "certificate_status": "UNSIGNED_ENGINEERING_MEASUREMENT"
    });
    fs::write(output, serde_json::to_vec_pretty(&measurements)?)?;

    assert!(impact.body().full_review);
    assert_eq!(
        impact.body().review_files.len(),
        accepted.snapshot.files().len()
    );

    Ok(())
}

fn git_fixture(repository: &std::path::Path, args: &[&str], input: &[u8]) -> R<Vec<u8>> {
    use std::{io::Write, process::Stdio};

    let mut child = Command::new("git")
        .env_clear()
        .env(
            "PATH",
            std::env::var_os("PATH").ok_or("fixture PATH missing")?,
        )
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "gc.auto=0",
            "-c",
            "user.name=Asterwyn fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-C",
        ])
        .arg(repository)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("fixture stdin missing")?
        .write_all(input)?;
    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err("fixture Git command failed".into());
    }

    Ok(output.stdout)
}

#[test]
fn branches_history_availability_and_pack_layout_cannot_change_exact_knowledge() -> R {
    use archcert_source::{GitObjectFormat, PackLimits, PackedGitGateway};

    let temporary = tempfile::tempdir()?;
    let path = temporary.path().canonicalize()?;
    git_fixture(&path, &["init"], b"")?;
    fs::write(path.join("lib.rs"), b"pub fn work() {}")?;
    git_fixture(&path, &["add", "lib.rs"], b"")?;
    git_fixture(&path, &["commit", "-m", "Controlled source fixture"], b"")?;
    let commit = String::from_utf8(git_fixture(&path, &["rev-parse", "HEAD"], b"")?)?
        .trim()
        .to_owned();
    let repository = RepositoryId::parse("asterwyn/history")?;
    let submission = SourceSubmission {
        project: "a57e0000-0000-4000-8000-000000000007".parse()?,
        repository: repository.clone(),
        requested_commit: GitObjectId::parse(&commit)?,
    };
    let acquire = || -> R<_> {
        ingest_source(
            &LocalGitGateway::new(repository.clone(), path.join(".git")),
            &mut MemorySourceStore::default(),
            submission.clone(),
            SourceLimits::default(),
        )
        .map_err(|_| "exact fixture acquisition failed".into())
    };
    let original = acquire()?;
    let expected = engine()?.extract(&original.snapshot, &[], None)?;
    let tree = String::from_utf8(git_fixture(&path, &["rev-parse", "HEAD^{tree}"], b"")?)?
        .trim()
        .to_owned();
    let rewritten = String::from_utf8(git_fixture(
        &path,
        &["commit-tree", &tree, "-p", &commit],
        b"Different immutable commit\n",
    )?)?
    .trim()
    .to_owned();

    for args in [
        vec!["update-ref", "refs/heads/other", &commit],
        vec!["symbolic-ref", "HEAD", "refs/heads/other"],
        vec!["pack-refs", "--all"],
        vec!["update-ref", "refs/heads/other", &rewritten],
        vec!["update-ref", "--no-deref", "HEAD", &commit],
    ] {
        git_fixture(&path, &args, b"")?;
        let acquired = acquire()?;
        assert_eq!(
            engine()?
                .extract(&acquired.snapshot, &[], None)?
                .artifact()
                .bytes(),
            expected.artifact().bytes()
        );
    }

    fs::write(path.join(".git/shallow"), format!("{commit}\n"))?;
    fs::remove_file(path.join(".git/logs/HEAD"))?;
    let shallow = acquire()?;
    assert_eq!(
        engine()?
            .extract(&shallow.snapshot, &[], None)?
            .artifact()
            .bytes(),
        expected.artifact().bytes()
    );

    let mut previous_pack = None;

    for args in [
        vec![
            "pack-objects",
            "--stdout",
            "--revs",
            "--window=0",
            "--depth=0",
            "--compression=0",
        ],
        vec![
            "pack-objects",
            "--stdout",
            "--revs",
            "--window=10",
            "--depth=10",
            "--compression=9",
        ],
    ] {
        let pack = git_fixture(&path, &args, format!("{commit}\n").as_bytes())?;

        if let Some(previous) = previous_pack.replace(pack.clone()) {
            assert_ne!(previous, pack, "fixture must perturb actual pack bytes");
        }

        let gateway = PackedGitGateway::new(
            repository.clone(),
            &pack,
            GitObjectFormat::Sha1,
            PackLimits::default(),
        )?;
        let accepted = ingest_source(
            &gateway,
            &mut MemorySourceStore::default(),
            submission.clone(),
            SourceLimits::default(),
        )
        .map_err(|_| "packed acquisition failed")?;
        assert_eq!(
            engine()?
                .extract(&accepted.snapshot, &[], None)?
                .artifact()
                .bytes(),
            expected.artifact().bytes()
        );
    }

    assert!(expected.body().coverage.iter().any(|c| c.dimension
        == archcert_domain::knowledge::CoverageDimension::GitBaseline
        && c.state == archcert_domain::knowledge::CoverageState::NotAvailable));

    Ok(())
}
