//! Explicitly UNENCRYPTED development object storage with create-only publication.
use archcert_application::{
    artifacts::ImmutableArtifactStore,
    jobs::{ArtifactReference, JobStoreError},
};
use archcert_domain::{ProjectId, jobs::JobId, source::digest_bytes};
use async_trait::async_trait;
use rustix::fs::{AtFlags, Mode, OFlags, linkat, mkdirat, openat, unlinkat};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
type Result<T> = std::result::Result<T, JobStoreError>;
fn io(_: impl std::fmt::Debug) -> JobStoreError {
    JobStoreError::Unavailable
}
fn metadata(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(io)?;
    if m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
    {
        return Err(JobStoreError::Invalid);
    }
    Ok(())
}
fn verify(r: &ArtifactReference, bytes: &[u8]) -> Result<()> {
    if r.size == 0
        || r.size > 64 * 1024 * 1024
        || bytes.len() as u64 != r.size
        || digest_bytes(bytes) != r.sha256
    {
        Err(JobStoreError::Invalid)
    } else {
        Ok(())
    }
}
/// Filesystem adapter for tests/local development. No production encryption claim.
pub struct FilesystemArtifactStore {
    root: File,
}
impl FilesystemArtifactStore {
    /// Opens an existing private authority directory with trusted no-follow ancestors.
    /// Choosing this method explicitly acknowledges unencrypted development storage.
    pub fn open_unencrypted_development(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(JobStoreError::Invalid);
        }
        let mut root = File::from(
            rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    root = File::from(
                        openat(
                            &root,
                            name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(io)?,
                    );
                    let m = root.metadata().map_err(io)?;
                    if !(m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                        || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
                    {
                        return Err(JobStoreError::Invalid);
                    }
                }
                _ => return Err(JobStoreError::Invalid),
            }
        }
        metadata(&root, true)?;
        Ok(Self { root })
    }
    fn scope(&self, project: ProjectId, create: bool) -> Result<File> {
        let name = project.to_string();
        if create {
            match mkdirat(&self.root, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => self.root.sync_all().map_err(io)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(io(e)),
            }
        }
        let file = File::from(
            openat(
                &self.root,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        metadata(&file, true)?;
        Ok(file)
    }
    fn read(scope: &File, r: &ArtifactReference) -> Result<Vec<u8>> {
        if r.size == 0 || r.size > 64 * 1024 * 1024 {
            return Err(JobStoreError::Invalid);
        }
        let file = File::from(
            openat(
                scope,
                r.sha256.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        metadata(&file, false)?;
        if file.metadata().map_err(io)?.len() != r.size {
            return Err(JobStoreError::Invalid);
        }
        let mut bytes = Vec::new();
        file.take(r.size + 1).read_to_end(&mut bytes).map_err(io)?;
        verify(r, &bytes)?;
        Ok(bytes)
    }
}
#[async_trait]
impl ImmutableArtifactStore for FilesystemArtifactStore {
    async fn put(&self, project: ProjectId, r: &ArtifactReference, bytes: &[u8]) -> Result<()> {
        verify(r, bytes)?;
        let scope = self.scope(project, true)?;
        let stage = format!(".staging-{}", JobId::new());
        let mut file = File::from(
            openat(
                &scope,
                &stage,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io)?,
        );
        let result = (|| {
            file.write_all(bytes).map_err(io)?;
            file.sync_all().map_err(io)?;
            rustix::fs::fchmod(&file, Mode::RUSR).map_err(io)?;
            // linkat is atomic create-only; never rename/overwrite a final immutable key.
            match linkat(&scope, &stage, &scope, r.sha256.as_str(), AtFlags::empty()) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(io(e)),
            }
            scope.sync_all().map_err(io)?;
            Ok(())
        })();
        unlinkat(&scope, &stage, AtFlags::empty()).map_err(io)?;
        scope.sync_all().map_err(io)?;
        result?;
        // Also detects corrupt preexisting objects; never replaces them to repair state.
        Self::read(&scope, r).map(|_| ())
    }
    async fn get(&self, project: ProjectId, r: &ArtifactReference) -> Result<Vec<u8>> {
        Self::read(&self.scope(project, false)?, r)
    }
}
