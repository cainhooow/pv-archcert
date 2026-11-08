//! Replaceable bounded development storage. No database/job scheduler.

use crate::{IngressError, IngressEvidence, unavailable};
use archcert_domain::{ingress::SourceSubmissionId, source::SourceSnapshot};
use archcert_source::{read_snapshot, write_snapshot};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

/// Private, owner-controlled directory and one nonblocking receive lease.
/// One admitted session bounds process-wide concurrent ingress. Rejections consume
/// capacity; operators explicitly archive/reset this development store.
pub struct DevelopmentSubmissionStore {
    root: File,
    path: PathBuf,
    _lock: File,
    maximum: u32,
}

pub(crate) fn private_root(path: &Path) -> Result<File, IngressError> {
    if !path.is_absolute() {
        return Err(IngressError::Unavailable);
    }

    let mut fd = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;

    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                fd = openat(
                    &fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(unavailable)?;
                let metadata = rustix::fs::fstat(&fd).map_err(unavailable)?;
                let trusted_owner =
                    metadata.st_uid == 0 || metadata.st_uid == rustix::process::geteuid().as_raw();
                let protected_children =
                    metadata.st_mode & 0o022 == 0 || metadata.st_mode & 0o1000 != 0;

                if !trusted_owner || !protected_children {
                    return Err(IngressError::Unavailable);
                }
            }
            _ => return Err(IngressError::Unavailable),
        }
    }

    let file = File::from(fd);
    let m = file.metadata().map_err(unavailable)?;

    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(IngressError::Unavailable);
    }

    Ok(file)
}

pub(crate) fn regular(parent: &File, name: &str, flags: OFlags) -> Result<File, IngressError> {
    let fd = openat(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(unavailable)?;
    let file = File::from(fd);
    let m = file.metadata().map_err(unavailable)?;

    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(IngressError::Unavailable);
    }

    Ok(file)
}

pub(crate) fn read_private_configuration(path: &Path) -> Result<Vec<u8>, IngressError> {
    let parent = private_root(path.parent().ok_or(IngressError::Unavailable)?)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(IngressError::Unavailable)?;
    let file = regular(&parent, name, OFlags::RDONLY)?;

    if file.metadata().map_err(unavailable)?.len() > 262144 {
        return Err(IngressError::Unavailable);
    }

    let mut bytes = Vec::new();
    file.take(262145)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;

    if bytes.len() > 262144 {
        return Err(IngressError::Unavailable);
    }

    Ok(bytes)
}

/// Read-only accepted source and its independently retained ingress evidence.
pub struct StoredSubmission {
    /// Owned immutable bytes with verified source identity.
    pub snapshot: SourceSnapshot,
    /// Operational metadata; never reconstructs acceptance by itself.
    pub evidence: IngressEvidence,
}

fn consistent(snapshot: &SourceSnapshot, evidence: &IngressEvidence) -> bool {
    !(snapshot.schema_version() != evidence.source_schema
        || snapshot.binding().original()
            != evidence.resolution.as_ref().map(|r| &r.parent.identity)
        || evidence.resolution.as_ref().is_some_and(|r| {
            r.parent.project != snapshot.project()
                || &r.parent.repository != snapshot.repository()
                || r.lfs_resolved
                    != snapshot
                        .binding()
                        .dependencies()
                        .iter()
                        .filter(|d| {
                            matches!(d, archcert_domain::source::ResolvedDependency::Lfs { .. })
                        })
                        .count() as u64
                || r.submodules_resolved
                    != snapshot
                        .binding()
                        .dependencies()
                        .iter()
                        .filter(|d| {
                            matches!(
                                d,
                                archcert_domain::source::ResolvedDependency::Submodule { .. }
                            )
                        })
                        .count() as u64
        })
        || snapshot.project() != evidence.project
        || snapshot.repository() != &evidence.repository
        || Some(snapshot.identity()) != evidence.source.as_ref()
        || Some(snapshot.status()) != evidence.completeness
        || crate::external_evidence(snapshot) != evidence.external_sources
        || evidence.lfs_unresolved
            != snapshot
                .external()
                .iter()
                .filter(|e| matches!(e, archcert_domain::source::ExternalSource::Lfs { .. }))
                .count() as u64
        || evidence.submodules_unresolved
            != snapshot
                .external()
                .iter()
                .filter(|e| matches!(e, archcert_domain::source::ExternalSource::Submodule { .. }))
                .count() as u64
        || evidence.status
            != if snapshot.require_complete().is_ok() {
                "ACCEPTED"
            } else {
                "INCOMPLETE_EXTERNAL_SOURCE"
            }
        || evidence.accepted_at.is_none())
}

impl Drop for DevelopmentSubmissionStore {
    fn drop(&mut self) {
        // A concurrently forked child can temporarily share this open file
        // description until CLOEXEC applies. Release the lease explicitly rather
        // than waiting for every duplicated descriptor to disappear.
        let _ = flock(&self._lock, FlockOperation::Unlock);
    }
}

impl DevelopmentSubmissionStore {
    /// Opens an existing private root and obtains the single active-session lease.
    pub fn open(path: &Path, maximum: u32) -> Result<Self, IngressError> {
        if !(1..=32).contains(&maximum) {
            return Err(IngressError::Unavailable);
        }

        let root = private_root(path)?;
        let lock = regular(&root, ".receive-lock", OFlags::RDWR | OFlags::CREATE)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                IngressError::Limit
            } else {
                IngressError::Unavailable
            }
        })?;

        Ok(Self {
            root,
            path: path.into(),
            _lock: lock,
            maximum,
        })
    }

    fn capacity(&self) -> Result<(), IngressError> {
        let mut count = 0u32;

        for entry in fs::read_dir(&self.path).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;

            if entry.file_name() == ".receive-lock" {
                continue;
            }

            count = count.checked_add(1).ok_or(IngressError::Limit)?;

            if count >= self.maximum {
                return Err(IngressError::Limit);
            }
        }

        Ok(())
    }

    pub(crate) fn quarantine(&self) -> Result<tempfile::TempDir, IngressError> {
        self.capacity()?;
        tempfile::Builder::new()
            .prefix("quarantine-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&self.path)
            .map_err(unavailable)
    }

    fn publish(
        &mut self,
        snapshot: Option<&SourceSnapshot>,
        evidence: &IngressEvidence,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), IngressError> {
        // Quarantine occupies one slot until receive returns. One publication can
        // coexist with it; the next receive counts only retained attempts.
        let temporary = tempfile::Builder::new()
            .prefix("publishing-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&self.path)
            .map_err(unavailable)?;
        let root = private_root(temporary.path())?;

        if let Some(snapshot) = snapshot {
            let mut file = regular(
                &root,
                "snapshot.bin",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            )?;
            write_snapshot(snapshot, &mut file).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            rustix::fs::fchmod(&file, Mode::RUSR).map_err(unavailable)?;
        }

        let bytes = serde_json::to_vec_pretty(evidence).map_err(unavailable)?;

        if bytes.len() > 65536 {
            return Err(IngressError::Failure(crate::IngressFailure::new(
                crate::IngressCode::IngressInternalError,
            )));
        }

        let mut file = regular(
            &root,
            "evidence.json",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        )?;
        file.write_all(&bytes).map_err(unavailable)?;
        file.sync_all().map_err(unavailable)?;
        rustix::fs::fchmod(&file, Mode::RUSR).map_err(unavailable)?;

        let destination = evidence.submission.to_string();

        if rustix::fs::statat(
            &self.root,
            destination.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .is_ok()
        {
            return Err(IngressError::Unavailable);
        }

        // Staging and fsync may consume the remaining session. Never publish an
        // accepted snapshot after that deadline; rejection evidence remains writable.
        if snapshot.is_some() && deadline.is_some_and(|end| std::time::Instant::now() >= end) {
            return Err(IngressError::Failure(crate::IngressFailure::new(
                crate::IngressCode::IngressSessionTimeout,
            )));
        }

        // Authority-only root and random UUID prevent candidate path selection.
        fs::rename(temporary.path(), self.path.join(destination)).map_err(unavailable)?;

        Ok(())
    }

    pub(crate) fn accept(
        &mut self,
        snapshot: &SourceSnapshot,
        evidence: &IngressEvidence,
    ) -> Result<(), IngressError> {
        self.accept_with_deadline(snapshot, evidence, None)
    }

    fn accept_with_deadline(
        &mut self,
        snapshot: &SourceSnapshot,
        evidence: &IngressEvidence,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), IngressError> {
        snapshot
            .verify(&snapshot.identity().snapshot_sha256)
            .map_err(unavailable)?;

        if !consistent(snapshot, evidence) {
            return Err(IngressError::Rejected);
        }

        self.publish(Some(snapshot), evidence, deadline)
    }

    pub(crate) fn reject(&mut self, evidence: &IngressEvidence) -> Result<(), IngressError> {
        self.publish(None, evidence, None)
    }

    /// Retrieves one exact accepted submission, rehashing bytes and comparing the
    /// full scope/commit/tree/digest. Rejected attempts cannot create source state.
    pub fn load(&self, id: &SourceSubmissionId) -> Result<StoredSubmission, IngressError> {
        load_submission(&self.root, id)
    }
}

/// Read-only accepted-source capability. Readers cannot receive, resolve or publish.
/// Immutable published submissions may be safely read concurrently with admission.
pub struct AcceptedSubmissionReader {
    root: File,
}

impl AcceptedSubmissionReader {
    /// Opens only the private accepted-source root, without acquiring the receive lease.
    pub fn open(path: &Path) -> Result<Self, IngressError> {
        Ok(Self {
            root: private_root(path)?,
        })
    }

    /// Reloads/rehashes exact accepted bytes and checks full ingress/source binding.
    pub fn load(&self, id: &SourceSubmissionId) -> Result<StoredSubmission, IngressError> {
        load_submission(&self.root, id)
    }
}

fn load_submission(
    authority_root: &File,
    id: &SourceSubmissionId,
) -> Result<StoredSubmission, IngressError> {
    let fd: OwnedFd = openat(
        authority_root,
        id.to_string(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;
    let root = File::from(fd);
    let mut file = regular(&root, "evidence.json", OFlags::RDONLY)?;

    if file.metadata().map_err(unavailable)?.len() > 65536 {
        return Err(IngressError::Unavailable);
    }

    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    let evidence: IngressEvidence = serde_json::from_slice(&bytes).map_err(unavailable)?;

    if &evidence.submission != id
        || !["ACCEPTED", "INCOMPLETE_EXTERNAL_SOURCE"].contains(&evidence.status.as_str())
        || evidence.accepted_at.is_none()
    {
        return Err(IngressError::Rejected);
    }

    let file = regular(&root, "snapshot.bin", OFlags::RDONLY)?;

    // Admission limits are frozen per submission. Current host settings never
    // reinterpret historical source bytes or prevent independent accepted reload.
    let capacity = evidence
        .diagnostics
        .capacity
        .unwrap_or_default()
        .validate()?;
    let artifact_cap = capacity.source_limits.max_total_bytes + 8 * 1024 * 1024 + 24;

    if file.metadata().map_err(unavailable)?.len() > artifact_cap {
        return Err(IngressError::Unavailable);
    }

    let snapshot = read_snapshot(file, capacity.source_limits).map_err(unavailable)?;

    if !consistent(&snapshot, &evidence) {
        return Err(IngressError::Rejected);
    }

    Ok(StoredSubmission { snapshot, evidence })
}

impl crate::SubmissionStore for DevelopmentSubmissionStore {
    fn accept(
        &mut self,
        snapshot: &SourceSnapshot,
        evidence: &IngressEvidence,
    ) -> Result<(), IngressError> {
        DevelopmentSubmissionStore::accept(self, snapshot, evidence)
    }

    fn accept_before(
        &mut self,
        snapshot: &SourceSnapshot,
        evidence: &IngressEvidence,
        deadline: std::time::Instant,
    ) -> Result<(), IngressError> {
        self.accept_with_deadline(snapshot, evidence, Some(deadline))
    }

    fn reject(&mut self, evidence: &IngressEvidence) -> Result<(), IngressError> {
        DevelopmentSubmissionStore::reject(self, evidence)
    }

    fn load(&self, id: &SourceSubmissionId) -> Result<StoredSubmission, IngressError> {
        DevelopmentSubmissionStore::load(self, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_limits_concurrency_capacity_and_rejects_symlink_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let path = root.path().canonicalize()?;
        let store = DevelopmentSubmissionStore::open(&path, 1)?;
        let reader = AcceptedSubmissionReader::open(&path)?;

        assert!(reader.load(&SourceSubmissionId::new()).is_err());
        assert!(AcceptedSubmissionReader::open(&path).is_ok());
        assert!(DevelopmentSubmissionStore::open(&path, 1).is_err());

        let quarantine = store.quarantine()?;

        assert!(store.quarantine().is_err());

        drop(quarantine);
        let inherited_description = store._lock.try_clone()?;
        drop(store);

        assert!(DevelopmentSubmissionStore::open(&path, 1).is_ok());

        drop(inherited_description);
        let link = path.join("link");
        std::os::unix::fs::symlink(&path, &link)?;

        assert!(DevelopmentSubmissionStore::open(&link, 1).is_err());

        let untrusted = path.join("untrusted-parent");
        fs::create_dir(&untrusted)?;
        fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777))?;
        let child = untrusted.join("private-child");
        fs::create_dir(&child)?;
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;

        assert!(DevelopmentSubmissionStore::open(&child, 1).is_err());

        let config = path.join("configuration.json");
        fs::write(&config, b"{}")?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
        let config_link = path.join("configuration-link");
        std::os::unix::fs::symlink(&config, &config_link)?;

        assert!(read_private_configuration(&config_link).is_err());

        Ok(())
    }
}

#[cfg(test)]
mod publication_deadline_tests {
    use super::*;
    use archcert_domain::{
        GitObjectId, ProjectId,
        ingress::{DeviceKeyId, GitActorId},
        source::RepositoryId,
    };

    #[test]
    fn expired_publication_leaves_only_rejection_evidence() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().canonicalize()?;
        let mut store = DevelopmentSubmissionStore::open(&path, 2)?;
        let project = ProjectId::new();
        let repository = RepositoryId::parse("test/source")?;
        let snapshot = SourceSnapshot::seal(
            project,
            repository.clone(),
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            Vec::new(),
            1,
            0,
        )?;
        let id = SourceSubmissionId::new();
        let evidence = IngressEvidence {
            diagnostics: Default::default(),
            submission: id.clone(),
            actor: GitActorId::parse("00000000-0000-4000-8000-000000000001".into())?,
            device: DeviceKeyId::parse("c".repeat(64))?,
            project,
            repository,
            transport: "SSH_PUBLIC_KEY".into(),
            received_refs: Vec::new(),
            requested_commit: None,
            source: None,
            object_format: archcert_source::GitObjectFormat::Sha1,
            pack_sha256: None,
            pack_bytes: 0,
            pack_objects: 0,
            pack_limits: Default::default(),
            git_adapter: None,
            lfs_unresolved: 0,
            submodules_unresolved: 0,
            external_sources: Vec::new(),
            source_schema: 1,
            resolution: None,
            completeness: None,
            status: "REJECTED".into(),
            received_at: 0,
            accepted_at: None,
            events: vec![crate::IngressEvent::GitSubmissionRejected],
            candidate: format!("refs/archcert/candidates/{project}/{id}"),
        };
        let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);

        let result = store.publish(Some(&snapshot), &evidence, Some(expired));

        assert!(
            matches!(result, Err(IngressError::Failure(failure)) if failure.code == crate::IngressCode::IngressSessionTimeout)
        );
        assert!(!path.join(id.to_string()).exists());

        store.reject(&evidence)?;

        assert!(path.join(id.to_string()).join("evidence.json").is_file());
        assert!(!path.join(id.to_string()).join("snapshot.bin").exists());
        assert!(store.load(&id).is_err());
        assert_eq!(fs::read_dir(&path)?.count(), 2);

        Ok(())
    }
}
