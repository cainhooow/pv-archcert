//! Local durable execution gate. Only trusted authority processes access these files.
use archcert_application::jobs::RuntimeBinding;
use archcert_domain::{
    execution::ExecutionError,
    jobs::{AttemptId, JobId},
};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

type Result<T> = std::result::Result<T, ExecutionError>;
fn failure(_: impl std::fmt::Debug) -> ExecutionError {
    ExecutionError::EnvironmentNotProven
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    job: JobId,
    attempt: AttemptId,
    binding: RuntimeBinding,
}

/// Descriptor-anchored private authority directory on a local filesystem.
pub struct ExecutionGateRoot {
    directory: File,
}
impl ExecutionGateRoot {
    /// Opens existing private storage without following any symlink ancestor.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ExecutionError::InvalidRuntimeConfiguration);
        }
        let mut directory = File::from(
            rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(failure)?,
        );
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    directory = File::from(
                        openat(
                            &directory,
                            name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(failure)?,
                    );
                    let m = directory.metadata().map_err(failure)?;
                    if !(m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                        || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
                    {
                        return Err(ExecutionError::EnvironmentNotProven);
                    }
                }
                _ => return Err(ExecutionError::InvalidRuntimeConfiguration),
            }
        }
        let m = directory.metadata().map_err(failure)?;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        Ok(Self { directory })
    }
    /// Creates a never-reused attempt gate before dispatch. Existing files reject.
    pub fn create(&self, job: JobId, attempt: AttemptId, binding: &RuntimeBinding) -> Result<()> {
        capacity(&self.directory)?;
        binding.validate().map_err(failure)?;
        let mut file = File::from(
            openat(
                &self.directory,
                attempt.to_string(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(failure)?,
        );
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(failure)?;
        let mut bytes = serde_json::to_vec(&Header {
            job,
            attempt,
            binding: binding.clone(),
        })
        .map_err(failure)?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        self.directory.sync_all().map_err(failure)?;
        Ok(())
    }
    /// Takes exclusive nonblocking execution/reconciliation ownership of this gate.
    /// A live/suspended execution cannot be bypassed by lease expiry.
    pub fn lock(&self, job: JobId, attempt: AttemptId) -> Result<ExecutionGateLease> {
        let mut file = File::from(
            openat(
                &self.directory,
                attempt.to_string(),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(failure)?,
        );
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(failure)?;
        let m = file.metadata().map_err(failure)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o077 != 0
            || m.len() > 65536
        {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        if bytes.last() != Some(&b'\n') {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        let mut lines = bytes.split(|b| *b == b'\n');
        let header: Header =
            serde_json::from_slice(lines.next().ok_or(ExecutionError::EnvironmentNotProven)?)
                .map_err(failure)?;
        header.binding.validate().map_err(failure)?;
        if header.job != job || header.attempt != attempt {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        let mut revoked = false;
        let mut pending = false;
        for line in lines {
            match line {
                b"+" if !pending && !revoked => pending = true,
                b"-" if pending && !revoked => pending = false,
                b"!" => revoked = true,
                b"" => {}
                _ => return Err(ExecutionError::EnvironmentNotProven),
            }
        }
        file.seek(SeekFrom::End(0)).map_err(failure)?;
        Ok(ExecutionGateLease {
            file,
            job,
            attempt,
            binding: header.binding,
            revoked,
            pending,
        })
    }
}

/// Exclusive operation gate; dropping it releases the OS lock, never revocation.
pub struct ExecutionGateLease {
    file: File,
    job: JobId,
    attempt: AttemptId,
    binding: RuntimeBinding,
    revoked: bool,
    pending: bool,
}
impl ExecutionGateLease {
    /// Exact immutable scope; a revoked gate cannot authorize another attempt's cleanup.
    pub fn matches(&self, job: JobId, attempt: AttemptId) -> bool {
        self.job == job && self.attempt == attempt
    }
    /// Immutable observed runtime binding.
    pub fn binding(&self) -> &RuntimeBinding {
        &self.binding
    }
    /// True after durable local revocation, including after process restart.
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    /// An interrupted create/commit may still complete at the daemon. Never infer absence.
    pub fn uncertain_creation(&self) -> bool {
        self.pending
    }
    /// Required before each complete execution. The exclusive lock lasts through cleanup.
    pub fn authorize(&self) -> Result<()> {
        capacity(&self.file)?;
        if self.revoked || self.pending {
            Err(ExecutionError::EnvironmentNotProven)
        } else {
            Ok(())
        }
    }
    fn append(&mut self, marker: &[u8]) -> Result<()> {
        if self.file.metadata().map_err(failure)?.len() + marker.len() as u64 > 65536 {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        self.file.write_all(marker).map_err(failure)?;
        self.file.sync_all().map_err(failure)
    }
    /// Revokes future work before committing the database fence. Never deletes the gate.
    pub fn revoke(&mut self) -> Result<()> {
        if !self.revoked {
            self.append(b"!\n")?;
            self.revoked = true;
        }
        Ok(())
    }
    /// Journals a potentially late resource creation before submitting it to the daemon.
    pub fn begin_creation(&mut self) -> Result<()> {
        self.authorize()?;
        self.append(b"+\n")?;
        self.pending = true;
        Ok(())
    }
    /// Clears uncertainty only after the runtime returned a successful completed response.
    pub fn finish_creation(&mut self) -> Result<()> {
        if self.revoked || !self.pending {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        self.append(b"-\n")?;
        self.pending = false;
        Ok(())
    }
}

fn capacity(file: &File) -> Result<()> {
    let stat = rustix::fs::fstatvfs(file).map_err(failure)?;
    // A bounded admission defense, not a storage scheduler or reserved-space guarantee.
    if (stat.f_bavail as u128) * (stat.f_frsize as u128) < 1024 * 1024 * 1024
        || stat.f_favail < 1024
    {
        return Err(ExecutionError::EnvironmentNotProven);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn stale_workers_wrong_attempts_and_uncertain_creates_fail_closed()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = root.path().canonicalize()?;
        let gates = ExecutionGateRoot::open(&path)?;
        let job = JobId::new();
        let attempt = AttemptId::new();
        let binding = RuntimeBinding {
            endpoint: "unix:///test.sock".into(),
            daemon_id: "test-daemon".into(),
            gate_root: path.to_string_lossy().into(),
        };
        gates.create(job, attempt, &binding)?;
        assert!(gates.create(job, attempt, &binding).is_err());
        assert!(gates.lock(JobId::new(), attempt).is_err());
        let mut lease = gates.lock(job, attempt)?;
        assert!(
            gates.lock(job, attempt).is_err(),
            "a live execution must block reconciliation"
        );
        lease.authorize()?;
        lease.begin_creation()?;
        lease.finish_creation()?;
        drop(lease);
        let mut reconciliation = gates.lock(job, attempt)?;
        reconciliation.revoke()?;
        drop(reconciliation);
        let stale = gates.lock(job, attempt)?;
        assert!(stale.revoked());
        assert!(stale.authorize().is_err());
        drop(stale);
        let other = AttemptId::new();
        gates.create(job, other, &binding)?;
        let mut interrupted = gates.lock(job, other)?;
        interrupted.begin_creation()?;
        drop(interrupted);
        let mut recovered = gates.lock(job, other)?;
        assert!(recovered.uncertain_creation());
        assert!(recovered.authorize().is_err());
        recovered.revoke()?;
        drop(recovered);
        assert!(gates.lock(job, other)?.uncertain_creation());
        Ok(())
    }
}
