//! Filesystem behavior and adversarial phase-boundary regressions; no target code runs.
#![cfg(unix)]

use archcert_application::{
    materialization::{
        CleanupStatus, MaterializationEvent, MaterializationFailure, MaterializationRequest,
        SourceMaterializer, materialize_source,
    },
    source::SourceStore,
};
use archcert_domain::{
    GitObjectId, ProjectId,
    materialization::{
        MaterializationBudget, MaterializationError as Error, MaterializationLimits,
        MaterializationState, SnapshotReference,
    },
    source::{RepositoryId, SourceFile, SourceLimits, SourceMode, SourcePath, SourceSnapshot},
};
use archcert_materialization::{
    AuthorityWorkspaceRoot, PendingMaterialization, UnixSourceMaterializer,
};
use archcert_source::MemorySourceStore;
use std::{
    error::Error as StdError,
    fs::{self, File, FileTimes, Permissions},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, UNIX_EPOCH},
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn StdError>>;

struct Fixture {
    _temporary: TempDir,
    root: std::path::PathBuf,
    materializer: UnixSourceMaterializer,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn StdError>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        fs::set_permissions(&root, Permissions::from_mode(0o700))?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&root)?);
        Ok(Self {
            _temporary: temporary,
            root,
            materializer,
        })
    }
    fn begin(
        &self,
        snapshot: &SourceSnapshot,
    ) -> Result<PendingMaterialization, MaterializationFailure> {
        self.materializer.begin(snapshot, &request(snapshot))
    }
}
fn source(entries: &[(&str, SourceMode, &[u8])]) -> Result<SourceSnapshot, Box<dyn StdError>> {
    let files = entries
        .iter()
        .map(|(p, m, b)| {
            Ok(SourceFile::new(
                SourcePath::from_bytes(p.as_bytes())?,
                *m,
                b.to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, archcert_domain::source::SourceError>>()?;
    Ok(SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("test/source")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        files,
        3,
        1,
    )?)
}
fn request(snapshot: &SourceSnapshot) -> MaterializationRequest {
    MaterializationRequest {
        snapshot: SnapshotReference {
            project: snapshot.project(),
            repository: snapshot.repository().clone(),
            identity: snapshot.identity().clone(),
        },
        limits: MaterializationLimits::default(),
    }
}
fn rejected<T>(
    result: Result<T, MaterializationFailure>,
) -> Result<MaterializationFailure, Box<dyn StdError>> {
    let Err(failure) = result else {
        return Err("unsafe materialization succeeded".into());
    };
    assert!(
        failure
            .events
            .iter()
            .any(|e| matches!(e, MaterializationEvent::Rejected(_)))
    );
    assert!(
        !failure
            .events
            .iter()
            .any(|e| matches!(e, MaterializationEvent::RunnerInputIssued(_)))
    );
    Ok(failure)
}

#[test]
fn text_binary_empty_nested_executable_unicode_and_symlink_round_trip() -> TestResult {
    use SourceMode::*;
    let fixture = Fixture::new()?;
    let snapshot = source(&[
        ("text", File, b"hello\n"),
        ("binary", File, &[0, 255, 128]),
        ("empty", File, b""),
        ("nested/deeper/run", Executable, b"#!/bin/sh\nexit 99\n"),
        ("résumé.txt", File, b"Unicode name"),
        ("link", Symlink, b"../../outside"),
    ])?;
    let result = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    let path = result.cleanup.location().as_path();
    assert_eq!(fs::read(path.join("text"))?, b"hello\n");
    assert_eq!(fs::read(path.join("binary"))?, [0, 255, 128]);
    assert_eq!(fs::read(path.join("empty"))?, b"");
    assert_eq!(
        fs::read_link(path.join("link"))?.as_os_str().as_bytes(),
        b"../../outside"
    );
    assert_eq!(
        fs::metadata(path.join("text"))?.permissions().mode() & 0o7777,
        0o400
    );
    assert_eq!(
        fs::metadata(path.join("nested/deeper/run"))?
            .permissions()
            .mode()
            & 0o7777,
        0o500
    );
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o7777, 0o500);
    assert_eq!(
        result.evidence.expected_digest,
        result.evidence.observed_digest
    );
    assert_eq!(result.evidence.entry_count, 6);
    assert_eq!(result.evidence.total_bytes_written, snapshot.total_bytes());
    assert_eq!(result.evidence.status, MaterializationState::HandedOff);
    assert_eq!(
        result.runner_input.expected_source_identity(),
        snapshot.identity()
    );
    result.runner_input.source().directory_fd()?;
    assert!(matches!(
        result.events.as_slice(),
        [
            MaterializationEvent::Started(_),
            MaterializationEvent::Verified(_),
            MaterializationEvent::Sealed(_),
            MaterializationEvent::RunnerInputIssued(_)
        ]
    ));
    let receipt = result.cleanup.destroy()?;
    assert_eq!(receipt.status, MaterializationState::Destroyed);
    assert!(matches!(
        receipt.event,
        MaterializationEvent::WorkspaceDestroyed(_)
    ));
    assert!(result.runner_input.source().directory_fd().is_err());
    assert_eq!(fs::read_dir(&fixture.root)?.count(), 0);
    Ok(())
}

#[test]
fn same_snapshot_twice_has_same_digest_and_distinct_workspaces() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"abc")])?;
    let first = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    let second = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    assert_eq!(
        first.evidence.observed_digest,
        second.evidence.observed_digest
    );
    assert_eq!(
        first.evidence.observed_digest.as_str(),
        "252d8a8aa373a45994b32021ac661a412b3c90138086686e41aaf92a491b2175"
    );
    assert_ne!(
        first.runner_input.workspace(),
        second.runner_input.workspace()
    );
    first.cleanup.destroy()?;
    second.cleanup.destroy()?;
    Ok(())
}

#[test]
fn empty_snapshot_produces_verified_empty_root() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[])?;
    let result = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    assert_eq!(
        fs::read_dir(result.cleanup.location().as_path())?.count(),
        0
    );
    assert_eq!(
        result.evidence.observed_digest,
        snapshot.identity().snapshot_sha256
    );
    result.cleanup.destroy()?;
    Ok(())
}

#[test]
fn lfs_and_submodule_fail_before_destination_creation() -> TestResult {
    let fixture = Fixture::new()?;
    let lfs = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 50\n",
        "a".repeat(64)
    );
    for snapshot in [
        source(&[("large", SourceMode::File, lfs.as_bytes())])?,
        source(&[("module", SourceMode::Submodule, "a".repeat(40).as_bytes())])?,
    ] {
        let failure = rejected(fixture.begin(&snapshot))?;
        assert_eq!(failure.error, Error::SnapshotNotComplete);
        assert_eq!(failure.cleanup, CleanupStatus::NotCreated);
    }
    assert_eq!(fs::read_dir(&fixture.root)?.count(), 0);
    Ok(())
}

#[test]
fn wrong_expected_source_and_store_scope_fail_closed() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"abc")])?;
    let mut request = request(&snapshot);
    request.snapshot.identity.snapshot_sha256 = archcert_domain::source::digest_bytes(b"wrong");
    assert_eq!(
        rejected(fixture.materializer.begin(&snapshot, &request))?.error,
        Error::MaterializationIntegrityMismatch
    );
    let mut store = MemorySourceStore::default();
    let correct_request = self::request(&snapshot);
    store.retain(snapshot)?;
    let mut wrong_scope = correct_request.clone();
    wrong_scope.snapshot.project = ProjectId::new();
    assert_eq!(
        rejected(materialize_source(
            &store,
            &fixture.materializer,
            &wrong_scope
        ))?
        .error,
        Error::SnapshotUnavailable
    );
    let result = materialize_source(&store, &fixture.materializer, &correct_request)?;
    drop(store);
    assert_eq!(
        fs::read(result.cleanup.location().as_path().join("a"))?,
        b"abc"
    );
    result.cleanup.destroy()?;
    Ok(())
}

#[test]
fn mutation_wrong_mode_missing_extra_file_and_changed_link_are_detected() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[
        ("a", SourceMode::File, b"original"),
        ("link", SourceMode::Symlink, b"a"),
    ])?;
    for attack in 0..5 {
        let pending = fixture.begin(&snapshot)?;
        let path = pending.location().as_path().to_owned();
        match attack {
            0 => fs::write(path.join("a"), b"mutated")?,
            1 => fs::set_permissions(path.join("a"), Permissions::from_mode(0o700))?,
            2 => fs::remove_file(path.join("a"))?,
            3 => fs::write(path.join("extra"), b"substituted")?,
            4 => {
                fs::remove_file(path.join("link"))?;
                std::os::unix::fs::symlink("../../outside", path.join("link"))?;
            }
            _ => return Err("invalid test case".into()),
        }
        let failure = rejected(pending.verify_and_seal())?;
        assert!(matches!(
            failure.error,
            Error::MaterializationIntegrityMismatch | Error::EntryTypeConflict
        ));
        assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
        assert!(!path.exists());
    }
    Ok(())
}

#[test]
fn extra_empty_directory_is_detected_even_though_schema_excludes_directories() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"abc")])?;
    let pending = fixture.begin(&snapshot)?;
    fs::create_dir(pending.location().as_path().join("extra"))?;
    let failure = rejected(pending.verify_and_seal())?;
    assert_eq!(failure.error, Error::EntryTypeConflict);
    Ok(())
}

#[test]
fn symlink_host_escape_never_reads_writes_or_changes_host_target_permissions() -> TestResult {
    let fixture = Fixture::new()?;
    let host = tempfile::tempdir()?;
    let secret = host.path().join("secret");
    fs::write(&secret, b"HOST SECRET")?;
    fs::set_permissions(&secret, Permissions::from_mode(0o600))?;
    let snapshot = source(&[("link", SourceMode::Symlink, secret.as_os_str().as_bytes())])?;
    let result = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    assert!(
        fs::symlink_metadata(result.cleanup.location().as_path().join("link"))?
            .file_type()
            .is_symlink()
    );
    result.cleanup.destroy()?;
    assert_eq!(fs::read(&secret)?, b"HOST SECRET");
    assert_eq!(fs::metadata(&secret)?.permissions().mode() & 0o7777, 0o600);
    Ok(())
}

#[test]
fn directory_swap_between_write_and_verification_does_not_follow_host_symlink() -> TestResult {
    let fixture = Fixture::new()?;
    let host = tempfile::tempdir()?;
    fs::write(host.path().join("file"), b"HOST SECRET")?;
    let snapshot = source(&[("dir/file", SourceMode::File, b"accepted")])?;
    let pending = fixture.begin(&snapshot)?;
    let path = pending.location().as_path().to_owned();
    fs::rename(path.join("dir"), path.join("moved"))?;
    std::os::unix::fs::symlink(host.path(), path.join("dir"))?;
    assert!(matches!(
        rejected(pending.verify_and_seal())?.error,
        Error::EntryTypeConflict
    ));
    assert_eq!(fs::read(host.path().join("file"))?, b"HOST SECRET");
    assert!(!path.exists());
    Ok(())
}

#[test]
fn file_substitution_and_host_hardlink_are_rejected_without_chmod_on_host() -> TestResult {
    let fixture = Fixture::new()?;
    let host = tempfile::tempdir()?;
    let secret = host.path().join("secret");
    fs::write(&secret, b"HOST SECRET")?;
    fs::set_permissions(&secret, Permissions::from_mode(0o600))?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    for hardlink in [false, true] {
        let pending = fixture.begin(&snapshot)?;
        let path = pending.location().as_path().to_owned();
        fs::remove_file(path.join("a"))?;
        if hardlink {
            fs::hard_link(&secret, path.join("a"))?;
        } else {
            std::os::unix::fs::symlink(&secret, path.join("a"))?;
        }
        assert_eq!(
            rejected(pending.verify_and_seal())?.error,
            Error::EntryTypeConflict
        );
        assert_eq!(fs::read(&secret)?, b"HOST SECRET");
        assert_eq!(fs::metadata(&secret)?.permissions().mode() & 0o7777, 0o600);
    }
    Ok(())
}

#[test]
fn post_seal_mutation_is_rejected_at_final_handoff() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let sealed = fixture.begin(&snapshot)?.verify_and_seal()?;
    assert_eq!(sealed.evidence().status, MaterializationState::Sealed);
    let file = sealed.location().as_path().join("a");
    // The owner can undo Unix permissions. This deliberately exercises that remaining risk.
    fs::set_permissions(&file, Permissions::from_mode(0o600))?;
    fs::write(&file, b"mutated after seal")?;
    fs::set_permissions(&file, Permissions::from_mode(0o400))?;
    let failure = rejected(sealed.handoff())?;
    assert_eq!(failure.error, Error::MaterializationIntegrityMismatch);
    assert_eq!(failure.cleanup, CleanupStatus::Destroyed);
    Ok(())
}

#[test]
fn timestamp_changes_do_not_change_reconstructed_identity() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let pending = fixture.begin(&snapshot)?;
    File::open(pending.location().as_path().join("a"))?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(5)))?;
    let result = pending.verify_and_seal()?.handoff()?;
    assert_eq!(
        result.evidence.observed_digest,
        snapshot.identity().snapshot_sha256
    );
    result.cleanup.destroy()?;
    Ok(())
}

#[test]
fn every_materialization_budget_is_enforced_before_writes() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[
        ("dir/file", SourceMode::File, b"12345"),
        ("link", SourceMode::Symlink, b"dir/file"),
    ])?;
    let defaults = MaterializationLimits::default();
    for (limits, budget) in [
        (
            MaterializationLimits {
                source: SourceLimits {
                    max_files: 0,
                    ..defaults.source
                },
                ..defaults
            },
            MaterializationBudget::Entries,
        ),
        (
            MaterializationLimits {
                source: SourceLimits {
                    max_total_bytes: 1,
                    ..defaults.source
                },
                ..defaults
            },
            MaterializationBudget::Bytes,
        ),
        (
            MaterializationLimits {
                source: SourceLimits {
                    max_blob_bytes: 1,
                    ..defaults.source
                },
                ..defaults
            },
            MaterializationBudget::SingleFile,
        ),
        (
            MaterializationLimits {
                source: SourceLimits {
                    max_tree_depth: 0,
                    ..defaults.source
                },
                ..defaults
            },
            MaterializationBudget::Depth,
        ),
        (
            MaterializationLimits {
                max_symlinks: 0,
                ..defaults
            },
            MaterializationBudget::Symlinks,
        ),
        (
            MaterializationLimits {
                max_directories: 0,
                ..defaults
            },
            MaterializationBudget::Directories,
        ),
    ] {
        let mut request = request(&snapshot);
        request.limits = limits;
        let failure = rejected(fixture.materializer.begin(&snapshot, &request))?;
        assert_eq!(failure.error, Error::LimitExceeded(budget));
        assert_eq!(failure.cleanup, CleanupStatus::NotCreated);
    }
    assert_eq!(fs::read_dir(&fixture.root)?.count(), 0);
    Ok(())
}

#[test]
fn invalid_symlink_payloads_are_explicitly_unsupported_and_never_rewritten() -> TestResult {
    let fixture = Fixture::new()?;
    for target in [b"".as_slice(), b"a\0b"] {
        let snapshot = source(&[("link", SourceMode::Symlink, target)])?;
        assert_eq!(
            rejected(fixture.begin(&snapshot))?.error,
            Error::UnsupportedFilesystemFeature
        );
    }
    let snapshot = source(&[("link", SourceMode::Symlink, &[0xff, b'a'])])?;
    let result = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    assert_eq!(
        fs::read_link(result.cleanup.location().as_path().join("link"))?
            .as_os_str()
            .as_bytes(),
        [0xff, b'a']
    );
    result.cleanup.destroy()?;
    Ok(())
}

#[test]
fn authority_root_must_be_private_absolute_and_not_a_symlink() -> TestResult {
    assert!(matches!(
        AuthorityWorkspaceRoot::open(Path::new("relative")),
        Err(Error::UnsafeDestination)
    ));
    let fixture = Fixture::new()?;
    let alias = fixture.root.join("alias");
    std::os::unix::fs::symlink(&fixture.root, &alias)?;
    assert!(matches!(
        AuthorityWorkspaceRoot::open(&alias),
        Err(Error::UnsafeDestination)
    ));
    fs::set_permissions(&fixture.root, Permissions::from_mode(0o755))?;
    assert!(matches!(
        AuthorityWorkspaceRoot::open(&fixture.root),
        Err(Error::UnsafeDestination)
    ));
    fs::set_permissions(&fixture.root, Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn root_name_substitution_cannot_redirect_verification_or_cleanup() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let pending = fixture.begin(&snapshot)?;
    let original = pending.location().as_path().to_owned();
    let moved = fixture.root.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join("host-data"), b"do not remove")?;
    let failure = rejected(pending.verify_and_seal())?;
    assert_eq!(failure.error, Error::EntryTypeConflict);
    assert_eq!(failure.cleanup, CleanupStatus::Failed);
    assert_eq!(fs::read(original.join("host-data"))?, b"do not remove");
    Ok(())
}

#[test]
fn abandoned_workspace_gets_best_effort_cleanup_without_success_evidence() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("dir/a", SourceMode::File, b"accepted")])?;
    let pending = fixture.begin(&snapshot)?;
    let path = pending.location().as_path().to_owned();
    drop(pending);
    assert!(!path.exists());
    Ok(())
}

#[test]
fn retained_writable_descriptor_can_mutate_permissions_seal_but_handoff_detects_it() -> TestResult {
    use std::{
        io::Write,
        sync::{Arc, Barrier},
    };
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let pending = fixture.begin(&snapshot)?;
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(pending.location().as_path().join("a"))?;
    let barrier = Arc::new(Barrier::new(2));
    let other = Arc::clone(&barrier);
    let mutation = std::thread::spawn(move || -> std::io::Result<()> {
        other.wait();
        writer.write_all(b"MUTATION")
    });
    let sealed = pending.verify_and_seal()?;
    barrier.wait();
    mutation.join().map_err(|_| "mutation thread failed")??;
    assert_eq!(
        rejected(sealed.handoff())?.error,
        Error::MaterializationIntegrityMismatch
    );
    Ok(())
}

#[test]
fn authority_parent_rename_keeps_operations_anchored_to_the_original_directory() -> TestResult {
    let fixture = Fixture::new()?;
    let authority = fixture.root.join("authority");
    fs::create_dir(&authority)?;
    fs::set_permissions(&authority, Permissions::from_mode(0o700))?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&authority)?);
    let moved = fixture.root.join("moved-authority");
    fs::rename(&authority, &moved)?;
    let host = tempfile::tempdir()?;
    fs::write(host.path().join("secret"), b"HOST")?;
    std::os::unix::fs::symlink(host.path(), &authority)?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let result = materializer.prepare(&snapshot, &request(&snapshot))?;
    let actual = moved.join(result.runner_input.workspace().to_string());
    assert_eq!(fs::read(actual.join("a"))?, b"accepted");
    assert_eq!(fs::read_dir(host.path())?.count(), 1);
    result.cleanup.destroy()?;
    assert!(!actual.exists());
    assert_eq!(fs::read(host.path().join("secret"))?, b"HOST");
    Ok(())
}

#[test]
fn host_umask_and_credentials_are_exercised_in_isolated_test_processes() -> TestResult {
    for mask in ["022", "077"] {
        let fixture = Fixture::new()?;
        fs::write(
            fixture.root.join("host-token"),
            b"DO NOT COPY HOST CREDENTIAL",
        )?;
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "child_materialization_with_hostile_environment",
                "--test-threads=1",
            ])
            .env("ARCHCERT_TEST_UMASK", mask)
            .env("HOME", &fixture.root)
            .env("GIT_CONFIG", fixture.root.join("host-token"))
            .env("GIT_CONFIG_GLOBAL", fixture.root.join("host-token"))
            .env("SSH_AUTH_SOCK", fixture.root.join("host-token"))
            .env("AWS_SECRET_ACCESS_KEY", "DO NOT COPY")
            .env("DATABASE_URL", "DO NOT COPY")
            .env("OPENAI_API_KEY", "DO NOT COPY")
            .env("TMPDIR", "/invalid-should-not-be-used")
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn child_materialization_with_hostile_environment() -> TestResult {
    let Some(mask) = std::env::var_os("ARCHCERT_TEST_UMASK") else {
        return Ok(());
    };
    // Process isolation avoids a global umask race in the parallel test harness.
    let mask = if mask == "022" { 0o022 } else { 0o077 };
    let old = rustix::process::umask(rustix::fs::Mode::from_bits_retain(mask));
    let temporary =
        tempfile::tempdir_in("/private/tmp").or_else(|_| tempfile::tempdir_in("/tmp"))?;
    let path = temporary.path().canonicalize()?;
    fs::set_permissions(&path, Permissions::from_mode(0o700))?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);
    let snapshot = source(&[
        (".gitconfig", SourceMode::File, b"tracked project data"),
        (".ssh/config", SourceMode::File, b"tracked ssh data"),
        ("run", SourceMode::Executable, b"passive executable bytes"),
    ])?;
    let result = materializer.prepare(&snapshot, &request(&snapshot))?;
    let directory = result.cleanup.location().as_path();
    assert_eq!(
        fs::read(directory.join(".gitconfig"))?,
        b"tracked project data"
    );
    assert_eq!(
        fs::read(directory.join(".ssh/config"))?,
        b"tracked ssh data"
    );
    assert_eq!(fs::read_dir(directory)?.count(), 3);
    for unexpected in [
        ".git",
        "host-token",
        ".aws",
        "archcert-runtime.toml",
        "source-store.toml",
    ] {
        assert!(!directory.join(unexpected).exists());
    }
    assert_eq!(
        result.evidence.observed_digest,
        snapshot.identity().snapshot_sha256
    );
    result.cleanup.destroy()?;
    rustix::process::umask(old);
    Ok(())
}

#[test]
fn execution_export_reverifies_after_handoff_and_rejects_destroyed_source() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = source(&[("a", SourceMode::File, b"accepted")])?;
    let prepared = fixture
        .materializer
        .prepare(&snapshot, &request(&snapshot))?;
    assert_eq!(
        prepared.runner_input.source().verified_files()?[0].bytes(),
        b"accepted"
    );
    let path = prepared.cleanup.location().as_path().join("a");
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    fs::write(&path, b"tampered")?;
    fs::set_permissions(&path, Permissions::from_mode(0o400))?;
    assert!(prepared.runner_input.source().verified_files().is_err());
    prepared.cleanup.destroy()?;
    assert!(prepared.runner_input.source().verified_files().is_err());
    Ok(())
}

#[test]
fn execution_export_uses_descriptor_after_authority_parent_rename() -> TestResult {
    let fixture = Fixture::new()?;
    let authority = fixture.root.join("authority");
    fs::create_dir(&authority)?;
    fs::set_permissions(&authority, Permissions::from_mode(0o700))?;
    let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&authority)?);
    let snapshot = source(&[
        ("dir/a", SourceMode::File, b"accepted"),
        ("escape", SourceMode::Symlink, b"/host/secret"),
    ])?;
    let prepared = materializer.prepare(&snapshot, &request(&snapshot))?;
    fs::rename(&authority, fixture.root.join("renamed"))?;
    fs::create_dir(&authority)?;
    fs::write(authority.join("host-only-marker"), b"must not export")?;
    let files = prepared.runner_input.source().verified_files()?;
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|f| f.bytes() == b"accepted"));
    assert!(files.iter().any(|f| f.bytes() == b"/host/secret"));
    prepared.cleanup.destroy()?;
    Ok(())
}
