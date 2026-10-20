//! Behavioral tests use Git only to manufacture fixtures, never in the adapter.
#![cfg(unix)]

use archcert_application::source::{
    SourceEvent, SourceIngestion, SourceRejection, SourceSubmission, ingest_source,
};
use archcert_domain::{
    GitObjectId, ProjectId,
    source::{
        ExternalSource, RepositoryId, ResourceLimit, SourceError, SourceLimits, SourceMode,
        SourceStatus,
    },
};
use archcert_source::{LocalGitGateway, MemorySourceStore};
use flate2::{Compression, write::ZlibEncoder};
use sha2::Digest;
use std::{
    error::Error,
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

struct Repository {
    _temporary: TempDir,
    path: PathBuf,
    identity: RepositoryId,
}

impl Repository {
    fn new(format: &str) -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        // macOS's /var alias belongs to the test host, not the hostile repository.
        let path = temporary.path().canonicalize()?.join("source.git");
        let output = Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").ok_or("missing PATH")?)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["init", "--bare", &format!("--object-format={format}")])
            .arg(&path)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "fixture Git init failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(Self {
            _temporary: temporary,
            path,
            identity: RepositoryId::parse("test/source")?,
        })
    }

    fn git(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut child = Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").ok_or("missing PATH")?)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("--git-dir")
            .arg(&self.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing fixture stdin")?
            .write_all(input)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "fixture Git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output.stdout)
    }

    fn object(&self, kind: &str, bytes: &[u8]) -> Result<GitObjectId, Box<dyn Error>> {
        let output = self.git(
            &["hash-object", "--literally", "-w", "--stdin", "-t", kind],
            bytes,
        )?;
        Ok(GitObjectId::parse(String::from_utf8(output)?.trim())?)
    }

    fn raw_tree(
        &self,
        entries: &[(&str, &[u8], &GitObjectId)],
    ) -> Result<GitObjectId, Box<dyn Error>> {
        let mut bytes = Vec::new();
        for (mode, name, oid) in entries {
            bytes.extend_from_slice(mode.as_bytes());
            bytes.push(b' ');
            bytes.extend_from_slice(name);
            bytes.push(0);
            bytes.extend_from_slice(&hex::decode(oid.as_str())?);
        }
        self.object("tree", &bytes)
    }

    fn commit(&self, tree: &GitObjectId, message: &str) -> Result<GitObjectId, Box<dyn Error>> {
        self.object("commit", format!("tree {}\nauthor Fixture <fixture@example.com> 1700000000 +0000\ncommitter Fixture <fixture@example.com> 1700000000 +0000\n\n{message}\n", tree.as_str()).as_bytes())
    }

    fn ingest(
        &self,
        commit: &GitObjectId,
        limits: SourceLimits,
    ) -> Result<SourceIngestion, SourceRejection> {
        let gateway = LocalGitGateway::new(self.identity.clone(), &self.path);
        ingest_source(
            &gateway,
            &mut MemorySourceStore::default(),
            SourceSubmission {
                project: ProjectId::new(),
                repository: self.identity.clone(),
                requested_commit: commit.clone(),
            },
            limits,
        )
    }

    fn one_file(
        &self,
        bytes: &[u8],
        mode: &str,
    ) -> Result<(GitObjectId, GitObjectId, GitObjectId), Box<dyn Error>> {
        let blob = self.object("blob", bytes)?;
        let tree = self.raw_tree(&[(mode, b"file", &blob)])?;
        Ok((self.commit(&tree, "fixture")?, tree, blob))
    }

    fn object_path(&self, oid: &GitObjectId) -> PathBuf {
        self.path
            .join("objects")
            .join(&oid.as_str()[..2])
            .join(&oid.as_str()[2..])
    }
}

fn rejected(result: Result<SourceIngestion, SourceRejection>, expected: SourceError) -> TestResult {
    let Err(rejection) = result else {
        return Err("invalid source was accepted".into());
    };
    assert_eq!(rejection.error, expected);
    assert!(
        matches!(rejection.events.last(), Some(SourceEvent::Rejected(error)) if *error == expected)
    );
    assert!(
        !rejection
            .events
            .iter()
            .any(|e| matches!(e, SourceEvent::SnapshotCreated(_)))
    );
    Ok(())
}

#[test]
fn normal_nested_empty_binary_unicode_and_symlink_source() -> TestResult {
    let repo = Repository::new("sha1")?;
    let text = repo.object("blob", b"hello\n")?;
    let empty = repo.object("blob", b"")?;
    let binary = repo.object("blob", &[0, 255, 128, 10])?;
    let link = repo.object("blob", b"../../outside-secret")?;
    let nested = repo.raw_tree(&[("100644", b"empty", &empty)])?;
    let tree = repo.raw_tree(&[
        ("100644", b"binary", &binary),
        ("40000", b"dir", &nested),
        ("120000", b"link", &link),
        ("100644", "résumé.txt".as_bytes(), &text),
        ("100644", b"text", &text),
    ])?;
    let commit = repo.commit(&tree, "normal")?;
    // An independent Git parser must also accept the normal fixture.
    repo.git(&["fsck", "--strict", "--no-reflogs", commit.as_str()], b"")?;
    let result = repo.ingest(&commit, SourceLimits::default())?;
    assert_eq!(result.evidence.identity.commit, commit);
    assert_eq!(result.evidence.identity.tree, tree);
    assert_eq!(result.evidence.entry_count, 5);
    assert_eq!(result.evidence.object_count, 8);
    assert_eq!(result.evidence.status, SourceStatus::Complete);
    assert_eq!(result.snapshot.files()[1].path().as_str(), "dir/empty");
    let symlink = result
        .snapshot
        .files()
        .iter()
        .find(|f| f.mode() == SourceMode::Symlink)
        .ok_or("missing symlink")?;
    assert_eq!(symlink.bytes(), b"../../outside-secret");
    result
        .snapshot
        .verify(&result.evidence.identity.snapshot_sha256)?;
    assert!(matches!(
        result.events.as_slice(),
        [
            SourceEvent::Received(_),
            SourceEvent::Quarantined,
            SourceEvent::ValidationStarted,
            SourceEvent::Accepted(SourceStatus::Complete),
            SourceEvent::SnapshotCreated(_)
        ]
    ));
    Ok(())
}

#[test]
fn same_tree_reproduces_identity_across_commits_and_git_hash_algorithms() -> TestResult {
    let mut identities = Vec::new();
    for format in ["sha1", "sha256"] {
        let repo = Repository::new(format)?;
        let (first, tree, _) = repo.one_file(b"same source", "100644")?;
        let second = repo.commit(&tree, "different commit metadata")?;
        assert_ne!(first, second);
        let a = repo.ingest(&first, SourceLimits::default())?;
        let b = repo.ingest(&second, SourceLimits::default())?;
        assert_eq!(
            a.evidence.identity.snapshot_sha256,
            b.evidence.identity.snapshot_sha256
        );
        identities.push(a.evidence.identity.snapshot_sha256);
    }
    assert_eq!(identities[0], identities[1]);
    Ok(())
}

#[test]
fn changed_content_and_executable_mode_change_source_identity() -> TestResult {
    let repo = Repository::new("sha1")?;
    let mut identities = Vec::new();
    for (bytes, mode) in [
        (b"original".as_slice(), "100644"),
        (b"changed", "100644"),
        (b"original", "100755"),
    ] {
        let (commit, _, _) = repo.one_file(bytes, mode)?;
        identities.push(
            repo.ingest(&commit, SourceLimits::default())?
                .evidence
                .identity
                .snapshot_sha256,
        );
    }
    assert_ne!(identities[0], identities[1]);
    assert_ne!(identities[0], identities[2]);
    Ok(())
}

#[test]
fn unresolved_lfs_and_submodule_are_explicit_in_evidence() -> TestResult {
    let repo = Repository::new("sha1")?;
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 123456789\n",
        "a".repeat(64)
    );
    let blob = repo.object("blob", pointer.as_bytes())?;
    let absent_submodule = GitObjectId::parse("b".repeat(40))?;
    let tree = repo.raw_tree(&[
        ("100644", b"large.bin", &blob),
        ("160000", b"module", &absent_submodule),
    ])?;
    let result = repo.ingest(&repo.commit(&tree, "external")?, SourceLimits::default())?;
    assert_eq!(
        result.evidence.status,
        SourceStatus::IncompleteExternalSource
    );
    assert!(
        matches!(result.evidence.unresolved.as_slice(), [ExternalSource::Lfs { expected_size: 123456789, .. }, ExternalSource::Submodule { commit, .. }] if *commit == absent_submodule)
    );
    assert_eq!(
        result.snapshot.require_complete(),
        Err(SourceError::IncompleteExternalSource)
    );
    assert!(result.events.iter().any(|e| matches!(
        e,
        SourceEvent::Accepted(SourceStatus::IncompleteExternalSource)
    )));
    Ok(())
}

#[test]
fn missing_commit_tree_blob_and_wrong_types_are_distinct() -> TestResult {
    let repo = Repository::new("sha1")?;
    let absent = GitObjectId::parse("1".repeat(40))?;
    rejected(
        repo.ingest(&absent, SourceLimits::default()),
        SourceError::CommitNotFound,
    )?;
    rejected(
        repo.ingest(
            &repo.commit(&absent, "missing tree")?,
            SourceLimits::default(),
        ),
        SourceError::MissingTree,
    )?;
    let tree = repo.raw_tree(&[("100644", b"file", &absent)])?;
    rejected(
        repo.ingest(
            &repo.commit(&tree, "missing blob")?,
            SourceLimits::default(),
        ),
        SourceError::MissingBlob,
    )?;
    let blob = repo.object("blob", b"not a commit")?;
    rejected(
        repo.ingest(&blob, SourceLimits::default()),
        SourceError::ObjectTypeMismatch,
    )?;
    rejected(
        repo.ingest(
            &repo.commit(&blob, "wrong tree type")?,
            SourceLimits::default(),
        ),
        SourceError::ObjectTypeMismatch,
    )?;
    let wrong_blob_tree = repo.raw_tree(&[("100644", b"file", &tree)])?;
    rejected(
        repo.ingest(
            &repo.commit(&wrong_blob_tree, "wrong blob type")?,
            SourceLimits::default(),
        ),
        SourceError::ObjectTypeMismatch,
    )?;
    Ok(())
}

#[test]
fn malicious_tree_paths_are_rejected_before_materialization() -> TestResult {
    let repo = Repository::new("sha1")?;
    let blob = repo.object("blob", b"hostile")?;
    for name in [
        b"..".as_slice(),
        b"/absolute",
        b"a/../b",
        b"",
        b"a\\b",
        b"C:drive",
        &[255],
        "cafe\u{301}".as_bytes(),
        b".git",
    ] {
        let tree = repo.raw_tree(&[("100644", name, &blob)])?;
        rejected(
            repo.ingest(
                &repo.commit(&tree, "invalid path")?,
                SourceLimits::default(),
            ),
            SourceError::InvalidSourcePath,
        )?;
    }
    Ok(())
}

#[test]
fn duplicate_normalization_and_empty_directory_collisions_fail_closed() -> TestResult {
    let repo = Repository::new("sha1")?;
    let blob = repo.object("blob", b"bytes")?;
    let empty = repo.raw_tree(&[])?;
    for entries in [
        vec![("100644", b"A".as_slice(), &blob), ("100644", b"a", &blob)],
        vec![("100644", b"a".as_slice(), &blob), ("100644", b"a", &blob)],
        vec![
            ("40000", b"DIR".as_slice(), &empty),
            ("40000", b"dir", &empty),
        ],
    ] {
        let tree = repo.raw_tree(&entries)?;
        rejected(
            repo.ingest(&repo.commit(&tree, "collision")?, SourceLimits::default()),
            SourceError::PathCollision,
        )?;
    }
    Ok(())
}

#[test]
fn malformed_graphs_and_unsupported_modes_are_rejected() -> TestResult {
    let repo = Repository::new("sha1")?;
    let blob = repo.object("blob", b"content")?;
    let malformed_commit = repo.object("commit", b"tree invalid\n\nmessage")?;
    rejected(
        repo.ingest(&malformed_commit, SourceLimits::default()),
        SourceError::MalformedGitObject,
    )?;
    for bytes in [b"100644 file\0short".as_slice(), b"no mode or terminator"] {
        let tree = repo.object("tree", bytes)?;
        rejected(
            repo.ingest(
                &repo.commit(&tree, "malformed tree")?,
                SourceLimits::default(),
            ),
            SourceError::MalformedGitObject,
        )?;
    }
    let tree = repo.raw_tree(&[("100600", b"file", &blob)])?;
    rejected(
        repo.ingest(&repo.commit(&tree, "unsupported")?, SourceLimits::default()),
        SourceError::UnsupportedGitEntry,
    )?;
    let unsorted = repo.raw_tree(&[("100644", b"z", &blob), ("100644", b"a", &blob)])?;
    rejected(
        repo.ingest(
            &repo.commit(&unsorted, "unsorted")?,
            SourceLimits::default(),
        ),
        SourceError::MalformedGitObject,
    )?;
    Ok(())
}

#[test]
fn compressed_corruption_and_object_substitution_are_rejected() -> TestResult {
    let repo = Repository::new("sha1")?;
    let (commit, _, blob) = repo.one_file(b"original", "100644")?;
    let other = repo.object("blob", b"substitute")?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(repo.object_path(&blob), fs::Permissions::from_mode(0o644))?;
    fs::copy(repo.object_path(&other), repo.object_path(&blob))?;
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::ObjectIdentityMismatch,
    )?;
    fs::set_permissions(repo.object_path(&blob), fs::Permissions::from_mode(0o644))?;
    fs::write(repo.object_path(&blob), b"invalid zlib stream")?;
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::MalformedGitObject,
    )?;
    Ok(())
}

#[test]
fn trailing_compressed_bytes_and_invalid_declared_size_are_rejected() -> TestResult {
    let repo = Repository::new("sha1")?;
    let (commit, _, blob) = repo.one_file(b"data", "100644")?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(repo.object_path(&blob), fs::Permissions::from_mode(0o644))?;
    let mut compressed = fs::read(repo.object_path(&blob))?;
    compressed.extend_from_slice(b"trailing");
    fs::write(repo.object_path(&blob), compressed)?;
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::MalformedGitObject,
    )?;
    let bytes = b"blob 999\0data";
    let oid = GitObjectId::parse(hex::encode(sha1::Sha1::digest(bytes)))?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    let object_path = repo.object_path(&oid);
    fs::create_dir_all(object_path.parent().ok_or("missing object parent")?)?;
    fs::write(object_path, encoder.finish()?)?;
    let tree = repo.raw_tree(&[("100644", b"file", &oid)])?;
    rejected(
        repo.ingest(&repo.commit(&tree, "wrong size")?, SourceLimits::default()),
        SourceError::MalformedGitObject,
    )?;
    Ok(())
}

#[test]
fn snapshot_owns_bytes_after_repository_tampering() -> TestResult {
    let repo = Repository::new("sha1")?;
    let (commit, _, blob) = repo.one_file(b"original", "100644")?;
    let result = repo.ingest(&commit, SourceLimits::default())?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(repo.object_path(&blob), fs::Permissions::from_mode(0o644))?;
    fs::write(repo.object_path(&blob), b"changed after acceptance")?;
    result
        .snapshot
        .verify(&result.evidence.identity.snapshot_sha256)?;
    assert_eq!(result.snapshot.files()[0].bytes(), b"original");
    assert_eq!(
        result
            .snapshot
            .verify(&archcert_domain::source::digest_bytes(b"wrong")),
        Err(SourceError::SnapshotDigestMismatch)
    );
    assert!(repo.ingest(&commit, SourceLimits::default()).is_err());
    Ok(())
}

#[test]
fn symlink_payload_never_reads_outside_source_and_object_symlinks_fail() -> TestResult {
    let repo = Repository::new("sha1")?;
    let secret = repo.path.parent().ok_or("missing parent")?.join("secret");
    fs::write(&secret, b"private material")?;
    let (commit, _, blob) = repo.one_file(
        secret.to_str().ok_or("non-UTF-8 fixture path")?.as_bytes(),
        "120000",
    )?;
    let result = repo.ingest(&commit, SourceLimits::default())?;
    assert_eq!(
        result.snapshot.files()[0].bytes(),
        secret.as_os_str().as_encoded_bytes()
    );
    assert_ne!(result.snapshot.files()[0].bytes(), b"private material");
    fs::remove_file(repo.object_path(&blob))?;
    std::os::unix::fs::symlink(&secret, repo.object_path(&blob))?;
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::RepositoryAccessFailure,
    )?;
    Ok(())
}

#[test]
fn every_configured_resource_budget_fails_closed() -> TestResult {
    let repo = Repository::new("sha1")?;
    let blob = repo.object("blob", b"source bytes")?;
    let child = repo.raw_tree(&[("100644", b"file", &blob)])?;
    let tree = repo.raw_tree(&[("40000", b"dir", &child)])?;
    let commit = repo.commit(&tree, "limits")?;
    let defaults = SourceLimits::default();
    for (limits, resource) in [
        (
            SourceLimits {
                max_files: 0,
                ..defaults
            },
            ResourceLimit::Files,
        ),
        (
            SourceLimits {
                max_total_bytes: 1,
                ..defaults
            },
            ResourceLimit::TotalBytes,
        ),
        (
            SourceLimits {
                max_blob_bytes: 1,
                ..defaults
            },
            ResourceLimit::BlobBytes,
        ),
        (
            SourceLimits {
                max_tree_depth: 0,
                ..defaults
            },
            ResourceLimit::TreeDepth,
        ),
        (
            SourceLimits {
                max_objects: 1,
                ..defaults
            },
            ResourceLimit::Objects,
        ),
        (
            SourceLimits {
                max_object_bytes: 1,
                ..defaults
            },
            ResourceLimit::ObjectBytes,
        ),
        (
            SourceLimits {
                max_object_work_bytes: 1,
                ..defaults
            },
            ResourceLimit::ObjectWorkBytes,
        ),
    ] {
        rejected(
            repo.ingest(&commit, limits),
            SourceError::LimitExceeded(resource),
        )?;
    }
    Ok(())
}

#[test]
fn no_hooks_filters_worktree_refs_or_configuration_are_executed_or_trusted() -> TestResult {
    let repo = Repository::new("sha1")?;
    let (commit, _, _) = repo.one_file(b"trusted only after hashing", "100644")?;
    let marker = repo.path.join("EXECUTED");
    fs::write(
        repo.path.join("hooks/post-checkout"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        repo.path.join("hooks/post-checkout"),
        fs::Permissions::from_mode(0o755),
    )?;
    // Malformed config would break Git CLI repository discovery; this adapter ignores it.
    fs::write(repo.path.join("config"), b"[malformed configuration\n")?;
    fs::write(repo.path.join("HEAD"), b"ref: ../../outside\n")?;
    fs::write(repo.path.join("file"), b"uncommitted substituted worktree")?;
    let result = repo.ingest(&commit, SourceLimits::default())?;
    assert_eq!(
        result.snapshot.files()[0].bytes(),
        b"trusted only after hashing"
    );
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn packed_only_repository_is_rejected_instead_of_using_git_fallback() -> TestResult {
    let repo = Repository::new("sha1")?;
    let (commit, _, _) = repo.one_file(b"packed", "100644")?;
    repo.git(&["update-ref", "refs/heads/main", commit.as_str()], b"")?;
    repo.git(&["repack", "-a", "-d"], b"")?;
    assert!(!repo.object_path(&commit).exists());
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::CommitNotFound,
    )?;
    Ok(())
}

#[test]
fn large_compressed_blobs_are_bounded_during_inflation() -> TestResult {
    let repo = Repository::new("sha1")?;
    let content = vec![b'x'; 128 * 1024];
    let (commit, _, blob) = repo.one_file(&content, "100644")?;
    let accepted = repo.ingest(&commit, SourceLimits::default())?;
    assert_eq!(accepted.snapshot.files()[0].bytes(), content);
    rejected(
        repo.ingest(
            &commit,
            SourceLimits {
                max_object_bytes: 4096,
                ..SourceLimits::default()
            },
        ),
        SourceError::LimitExceeded(ResourceLimit::ObjectBytes),
    )?;
    let compressed = fs::read(repo.object_path(&blob))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(repo.object_path(&blob), fs::Permissions::from_mode(0o644))?;
    fs::write(repo.object_path(&blob), &compressed[..compressed.len() - 2])?;
    rejected(
        repo.ingest(&commit, SourceLimits::default()),
        SourceError::MalformedGitObject,
    )?;
    Ok(())
}

#[test]
fn repository_mapping_and_locator_symlinks_fail_closed() -> TestResult {
    use archcert_application::source::GitGateway;
    let repo = Repository::new("sha1")?;
    let (commit, _, _) = repo.one_file(b"source", "100644")?;
    let gateway = LocalGitGateway::new(repo.identity.clone(), &repo.path);
    assert!(matches!(
        gateway.quarantine(&RepositoryId::parse("different")?),
        Err(SourceError::RepositoryAccessFailure)
    ));
    let alias = repo
        .path
        .parent()
        .ok_or("missing parent")?
        .join("alias.git");
    std::os::unix::fs::symlink(&repo.path, &alias)?;
    let gateway = LocalGitGateway::new(repo.identity.clone(), alias);
    rejected(
        ingest_source(
            &gateway,
            &mut MemorySourceStore::default(),
            SourceSubmission {
                project: ProjectId::new(),
                repository: repo.identity.clone(),
                requested_commit: commit,
            },
            SourceLimits::default(),
        ),
        SourceError::RepositoryAccessFailure,
    )?;
    Ok(())
}

#[test]
fn packed_and_loose_ingestion_have_identical_canonical_source() -> TestResult {
    use archcert_source::{GitObjectFormat, PackLimits, PackedGitGateway};
    for (name, format) in [
        ("sha1", GitObjectFormat::Sha1),
        ("sha256", GitObjectFormat::Sha256),
    ] {
        let repository = Repository::new(name)?;
        let blob = repository.object("blob", b"packed and loose source\n")?;
        let tree =
            repository.raw_tree(&[("100644", b"file", &blob), ("120000", b"link", &blob)])?;
        let commit = repository.commit(&tree, "same exact source")?;
        let loose = repository.ingest(&commit, SourceLimits::default())?;
        let pack = repository.git(
            &["pack-objects", "--stdout", "--revs"],
            format!("{}\n", commit.as_str()).as_bytes(),
        )?;
        let gateway = PackedGitGateway::new(
            repository.identity.clone(),
            &pack,
            format,
            PackLimits::default(),
        )?;
        let packed = ingest_source(
            &gateway,
            &mut MemorySourceStore::default(),
            loose.evidence.submission.clone(),
            SourceLimits::default(),
        )?;
        assert_eq!(packed.snapshot.identity(), loose.snapshot.identity());
        assert_eq!(
            packed.snapshot.manifest().canonical_bytes(),
            loose.snapshot.manifest().canonical_bytes()
        );
        assert!(gateway_for_wrong_scope(&pack, format, &commit)?);
    }
    Ok(())
}
fn gateway_for_wrong_scope(
    pack: &[u8],
    format: archcert_source::GitObjectFormat,
    commit: &GitObjectId,
) -> Result<bool, Box<dyn Error>> {
    let gateway = archcert_source::PackedGitGateway::new(
        RepositoryId::parse("authority/one")?,
        pack,
        format,
        archcert_source::PackLimits::default(),
    )?;
    Ok(ingest_source(
        &gateway,
        &mut MemorySourceStore::default(),
        SourceSubmission {
            project: ProjectId::new(),
            repository: RepositoryId::parse("authority/two")?,
            requested_commit: commit.clone(),
        },
        SourceLimits::default(),
    )
    .is_err())
}

fn synthetic_pack(
    entries: &[(gix_pack::data::entry::Header, Vec<u8>)],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out =
        gix_pack::data::header::encode(gix_pack::data::Version::V2, entries.len() as u32).to_vec();
    for (header, bytes) in entries {
        header.write_to(bytes.len() as u64, &mut out)?;
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(bytes)?;
        out.extend_from_slice(&z.finish()?);
    }
    out.extend_from_slice(&sha1::Sha1::digest(out.clone()));
    Ok(out)
}

#[test]
fn malformed_oversized_pack_and_missing_delta_base_fail_closed() -> TestResult {
    use archcert_source::{GitObjectFormat, PackLimits, PackedGitGateway, receive_pack};
    use gix_pack::data::entry::Header;
    let identity = RepositoryId::parse("test/packs")?;
    let valid = synthetic_pack(&[(Header::Blob, b"abc".to_vec())])?;
    let load = |bytes: &[u8], limits| {
        PackedGitGateway::new(identity.clone(), bytes, GitObjectFormat::Sha1, limits)
    };
    for bytes in [
        b"malformed".to_vec(),
        valid[..valid.len() - 1].to_vec(),
        [valid.clone(), vec![0]].concat(),
    ] {
        assert!(load(&bytes, PackLimits::default()).is_err());
    }
    let mut corrupted = valid.clone();
    *corrupted.last_mut().ok_or("empty pack")? ^= 1;
    assert!(matches!(
        load(&corrupted, PackLimits::default()),
        Err(SourceError::ObjectIdentityMismatch)
    ));
    assert!(
        load(
            &valid,
            PackLimits {
                max_pack_bytes: (valid.len() - 1) as u64,
                ..PackLimits::default()
            }
        )
        .is_err()
    );
    assert!(
        load(
            &valid,
            PackLimits {
                max_object_bytes: 2,
                ..PackLimits::default()
            }
        )
        .is_err()
    );
    let too_many = synthetic_pack(&[(Header::Blob, b"a".to_vec()), (Header::Blob, b"b".to_vec())])?;
    assert!(
        load(
            &too_many,
            PackLimits {
                max_objects: 1,
                ..PackLimits::default()
            }
        )
        .is_err()
    );
    let base_id = gix_hash::ObjectId::from_hex(b"1111111111111111111111111111111111111111")?;
    let missing = synthetic_pack(&[(
        Header::RefDelta { base_id },
        b"\x03\x04\x90\x03\x01d".to_vec(),
    )])?;
    assert!(load(&missing, PackLimits::default()).is_err());
    // Declared zero output with a nonempty stream is rejected at the first chunk.
    let mut bomb = gix_pack::data::header::encode(gix_pack::data::Version::V2, 1).to_vec();
    Header::Blob.write_to(0, &mut bomb)?;
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(&vec![0; 1024 * 1024])?;
    bomb.extend_from_slice(&z.finish()?);
    bomb.extend_from_slice(&sha1::Sha1::digest(bomb.clone()));
    assert!(
        receive_pack(
            std::io::Cursor::new(bomb),
            GitObjectFormat::Sha1,
            PackLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn ref_and_offset_deltas_decode_and_depth_expansion_budgets_apply() -> TestResult {
    use archcert_source::{GitObjectFormat, PackLimits, PackedGitGateway};
    use gix_pack::data::entry::Header;
    let id = RepositoryId::parse("test/deltas")?;
    let base_id =
        gix_hash::ObjectId::from_hex(hex::encode(sha1::Sha1::digest(b"blob 3\0abc")).as_bytes())?;
    let pack = synthetic_pack(&[
        (Header::Blob, b"abc".to_vec()),
        (
            Header::RefDelta { base_id },
            b"\x03\x04\x90\x03\x01d".to_vec(),
        ),
    ])?;
    PackedGitGateway::new(
        id.clone(),
        &pack,
        GitObjectFormat::Sha1,
        PackLimits::default(),
    )?;
    assert!(
        PackedGitGateway::new(
            id.clone(),
            &pack,
            GitObjectFormat::Sha1,
            PackLimits {
                max_delta_depth: 0,
                ..PackLimits::default()
            }
        )
        .is_err()
    );
    let repeated_base =
        gix_hash::ObjectId::from_hex(hex::encode(sha1::Sha1::digest(b"blob 3\0abc")).as_bytes())?;
    let duplicate = synthetic_pack(&[
        (Header::Blob, b"abc".to_vec()),
        (
            Header::RefDelta {
                base_id: repeated_base,
            },
            b"\x03\x03\x90\x03".to_vec(),
        ),
        (
            Header::RefDelta {
                base_id: repeated_base,
            },
            b"\x03\x04\x90\x03\x01d".to_vec(),
        ),
    ])?;
    PackedGitGateway::new(
        id.clone(),
        &duplicate,
        GitObjectFormat::Sha1,
        PackLimits::default(),
    )?;
    // Make a real ofs chain using library header encoding; no custom production delta parser.
    let mut out = gix_pack::data::header::encode(gix_pack::data::Version::V2, 35).to_vec();
    let mut previous = 0;
    for n in 0..35 {
        let at = out.len();
        let (header, payload) = if n == 0 {
            (Header::Blob, b"a".to_vec())
        } else {
            (
                Header::OfsDelta {
                    base_distance: (at - previous) as u64,
                },
                vec![n as u8, n as u8 + 1, 0x90, n as u8, 1, b'z'],
            )
        };
        header.write_to(payload.len() as u64, &mut out)?;
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&payload)?;
        out.extend_from_slice(&z.finish()?);
        previous = at;
    }
    out.extend_from_slice(&sha1::Sha1::digest(out.clone()));
    assert!(matches!(
        PackedGitGateway::new(
            id.clone(),
            &out,
            GitObjectFormat::Sha1,
            PackLimits::default()
        ),
        Err(SourceError::LimitExceeded(ResourceLimit::DeltaDepth))
    ));
    PackedGitGateway::new(
        id.clone(),
        &out,
        GitObjectFormat::Sha1,
        PackLimits {
            max_delta_depth: 40,
            ..PackLimits::default()
        },
    )?;
    let expansion = synthetic_pack(&[(Header::Blob, vec![b'a'; 100_000])])?;
    assert!(matches!(
        PackedGitGateway::new(
            id.clone(),
            &expansion,
            GitObjectFormat::Sha1,
            PackLimits {
                max_expansion_ratio: 1,
                ..PackLimits::default()
            }
        ),
        Err(SourceError::LimitExceeded(ResourceLimit::DeltaExpansion))
    ));
    assert!(
        PackedGitGateway::new(
            id,
            &pack,
            GitObjectFormat::Sha1,
            PackLimits {
                max_decoded_bytes: 10,
                ..PackLimits::default()
            }
        )
        .is_err()
    );
    Ok(())
}
