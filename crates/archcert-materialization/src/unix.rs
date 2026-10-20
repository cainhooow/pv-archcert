use archcert_application::materialization::{
    CleanupStatus, MaterializationEvent, MaterializationEvidence, MaterializationFailure,
    MaterializationRequest, MaterializationResult, MaterializedSource, RunnerInput, SealStatus,
    SourceMaterializer, VerificationStatus,
};
use archcert_domain::{
    materialization::{
        MaterializationBudget, MaterializationError as Error, MaterializationLimits,
        MaterializationState, WorkspaceId,
    },
    source::{
        ManifestEntry, SourceFile, SourceManifest, SourceMode, SourcePath, SourceSnapshot,
        digest_bytes,
    },
};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::InternalMaterializationFailure)
}
fn mode(bits: u32) -> Mode {
    // Only private constant permission masks enter this helper. RawMode differs
    // between Unix platforms (for example u16 on macOS and u32 on Linux).
    #[allow(clippy::unnecessary_cast)]
    Mode::from_raw_mode(bits as _)
}
fn directory(parent: &impl AsFd, name: impl rustix::path::Arg) -> Result<File, Error> {
    fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        .map(File::from)
        .map_err(|_| Error::EntryTypeConflict)
}

/// Validated authority-only location. No arbitrary destination path enters runner input.
#[derive(Debug)]
pub struct WorkspaceLocation(PathBuf);
impl WorkspaceLocation {
    /// Diagnostic/control-plane location only; runtime operations use anchored descriptors.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Private authority-owned directory, opened without following any path component.
///
/// Local filesystem and owner/root integrity are prerequisites. A directory FD
/// resists name substitution; it is not an OS sandbox or a revocable capability.
pub struct AuthorityWorkspaceRoot {
    directory: Arc<File>,
    location: PathBuf,
}
impl AuthorityWorkspaceRoot {
    /// Requires an explicit absolute directory owned by the current effective UID,
    /// with exact mode 0700. No HOME/TMPDIR/configuration is consulted.
    pub fn open(path: &Path) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::UnsafeDestination);
        }
        let mut fd = File::from(
            fs::open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(|_| Error::UnsafeDestination)?,
        );
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    fd = directory(&fd, name).map_err(|_| Error::UnsafeDestination)?
                }
                _ => return Err(Error::UnsafeDestination),
            }
        }
        let metadata = fd.metadata().map_err(|_| Error::UnsafeDestination)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(Error::UnsafeDestination);
        }
        Ok(Self {
            directory: Arc::new(fd),
            location: path.to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Node {
    device: u64,
    inode: u64,
}
impl Node {
    fn of(file: &File) -> Result<Self, Error> {
        let m = file.metadata().map_err(|_| Error::VerificationFailed)?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
        })
    }
    fn at(parent: &File, name: &OsStr) -> Result<Self, Error> {
        let stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::MaterializationIntegrityMismatch)?;
        Ok(Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        })
    }
}

/// Opaque materialized-directory handle for trusted sandbox mounting only.
/// Contains no authority parent, source store, source locator or credentials.
pub struct MaterializedDirectory {
    directory: Arc<File>,
    destroyed: Arc<AtomicBool>,
    workspace: WorkspaceId,
    identity: archcert_domain::SourceIdentity,
    nodes: BTreeMap<String, Node>,
    directories: BTreeSet<String>,
    limits: MaterializationLimits,
}
impl MaterializedSource for MaterializedDirectory {
    fn workspace(&self) -> WorkspaceId {
        self.workspace
    }
    fn identity(&self) -> &archcert_domain::SourceIdentity {
        &self.identity
    }
}
impl archcert_application::materialization::VerifiedSourceExport for MaterializedDirectory {
    fn verified_files(&self) -> Result<Vec<SourceFile>, Error> {
        MaterializedDirectory::verified_files(self)
    }
}
impl MaterializedDirectory {
    /// Reconstructs owned source bytes through the held descriptor immediately before
    /// sandbox transfer. Never reopens a diagnostic path or follows source symlinks.
    /// Verifies inode/device, budgets, names, directory set, modes and canonical identity.
    pub fn verified_files(&self) -> Result<Vec<SourceFile>, Error> {
        self.directory_fd()?;
        let mut walk = Walk {
            nodes: &self.nodes,
            device: Node::of(&self.directory)?.device,
            sealed: true,
            entries: Vec::new(),
            files: Some(Vec::new()),
            directories: BTreeSet::new(),
            budget: Budget::new(self.limits),
        };
        walk.visit(&self.directory, "", 0)?;
        if walk.directories != self.directories
            || SourceManifest::new(walk.entries)
                .map_err(|_| Error::VerificationFailed)?
                .digest()
                != self.identity.snapshot_sha256
        {
            return Err(Error::MaterializationIntegrityMismatch);
        }
        self.directory_fd()?;
        walk.files.ok_or(Error::VerificationFailed)
    }

    /// Borrows the source directory for trusted sandbox setup. Do not inherit this FD
    /// directly into target code: Unix directory FDs alone do not restrict `..` lookup.
    pub fn directory_fd(&self) -> Result<BorrowedFd<'_>, Error> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(Error::InvalidStateTransition);
        }
        Ok(self.directory.as_fd())
    }
}

/// Explicit successful deletion evidence; deletion is not secure media erasure.
#[derive(Debug)]
pub struct WorkspaceDestruction {
    /// Authority identity of the deleted workspace.
    pub workspace: WorkspaceId,
    /// Completed terminal state.
    pub status: MaterializationState,
    /// UTC Unix seconds after deletion.
    pub destroyed_at: u64,
    /// Structural audit receipt.
    pub event: MaterializationEvent,
}

/// Authority-only cleanup lease, kept separate from the runner source descriptor.
/// Drop attempts cleanup without an audit claim; use `destroy` to observe success/failure.
pub struct WorkspaceLease {
    parent: Arc<File>,
    root: Arc<File>,
    node: Node,
    id: WorkspaceId,
    location: WorkspaceLocation,
    destroyed: Arc<AtomicBool>,
    cleanup_budget: u64,
    owned_directories: BTreeSet<Node>,
}
impl WorkspaceLease {
    /// Authority diagnostic location; no runtime file operation relies on this path.
    pub fn location(&self) -> &WorkspaceLocation {
        &self.location
    }
    /// Explicit bounded descriptor-relative cleanup. Symlinks are unlinked, never followed.
    /// Failure is observable and must not be interpreted as destruction or secure erasure.
    pub fn destroy(mut self) -> Result<WorkspaceDestruction, Error> {
        self.cleanup()?;
        Ok(WorkspaceDestruction {
            workspace: self.id,
            status: MaterializationState::Destroyed,
            destroyed_at: now()?,
            event: MaterializationEvent::WorkspaceDestroyed(self.id),
        })
    }
    fn attached(&self) -> Result<(), Error> {
        if Node::at(&self.parent, OsStr::new(&self.id.to_string()))? != self.node {
            return Err(Error::EntryTypeConflict);
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), Error> {
        if self.destroyed.load(Ordering::Acquire) {
            return Ok(());
        }
        self.attached().map_err(|_| Error::CleanupFailed)?;
        let mut remaining = self.cleanup_budget;
        delete_contents(
            &self.root,
            self.node.device,
            &self.owned_directories,
            &mut remaining,
            0,
        )
        .map_err(|_| Error::CleanupFailed)?;
        self.attached().map_err(|_| Error::CleanupFailed)?;
        fs::unlinkat(&self.parent, self.id.to_string(), AtFlags::REMOVEDIR)
            .map_err(|_| Error::CleanupFailed)?;
        self.destroyed.store(true, Ordering::Release);
        Ok(())
    }
}
impl Drop for WorkspaceLease {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn delete_contents(
    root: &File,
    device: u64,
    owned: &BTreeSet<Node>,
    remaining: &mut u64,
    depth: u32,
) -> Result<(), Error> {
    if depth > 128 {
        return Err(Error::CleanupFailed);
    }
    fs::fchmod(root, mode(0o700)).map_err(|_| Error::CleanupFailed)?;
    for entry in Dir::read_from(root).map_err(|_| Error::CleanupFailed)? {
        let entry = entry.map_err(|_| Error::CleanupFailed)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *remaining = remaining.checked_sub(1).ok_or(Error::CleanupFailed)?;
        let stat =
            fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::CleanupFailed)?;
        if stat.st_dev as u64 != device {
            return Err(Error::CleanupFailed);
        }
        let flags = if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let child = directory(root, name)?;
            let node = Node::of(&child)?;
            if node != Node::at(root, OsStr::from_bytes(name.to_bytes()))? {
                return Err(Error::CleanupFailed);
            }
            if !owned.contains(&node) {
                // Unknown empty directories can be unlinked without chmod or recursion.
                // Unknown nonempty trees remain for explicit authority intervention.
                fs::unlinkat(root, name, AtFlags::REMOVEDIR).map_err(|_| Error::CleanupFailed)?;
                continue;
            }
            delete_contents(&child, device, owned, remaining, depth + 1)?;
            if node != Node::at(root, OsStr::from_bytes(name.to_bytes()))? {
                return Err(Error::CleanupFailed);
            }
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        // No chmod is performed on files: a substituted hardlink must never change host permissions.
        fs::unlinkat(root, name, flags).map_err(|_| Error::CleanupFailed)?;
    }
    Ok(())
}

/// Unix-first adapter. The private root is explicit authority configuration, never environment-derived.
pub struct UnixSourceMaterializer {
    root: AuthorityWorkspaceRoot,
}
impl UnixSourceMaterializer {
    /// Uses an already validated authority workspace root.
    pub fn new(root: AuthorityWorkspaceRoot) -> Self {
        Self { root }
    }

    /// Authority-only staged API: writes exact bytes but cannot issue runner input yet.
    /// This permits explicit validation/seal/handoff phases and cancellation by cleanup.
    pub fn begin(
        &self,
        snapshot: &SourceSnapshot,
        request: &MaterializationRequest,
    ) -> Result<PendingMaterialization, MaterializationFailure> {
        let result = (|| {
            if snapshot.project() != request.snapshot.project
                || snapshot.repository() != &request.snapshot.repository
                || snapshot.identity() != &request.snapshot.identity
            {
                return Err(Error::MaterializationIntegrityMismatch);
            }
            snapshot
                .verify(&request.snapshot.identity.snapshot_sha256)
                .map_err(Error::SnapshotInvalid)?;
            snapshot
                .require_complete()
                .map_err(|_| Error::SnapshotNotComplete)?;
            preflight(snapshot, request.limits)?;
            now()
        })();
        let started_at = result.map_err(MaterializationFailure::before_creation)?;
        let id = WorkspaceId::new();
        let lease = self
            .create_workspace(id, request.limits)
            .map_err(|(error, cleanup)| {
                let mut events = vec![
                    MaterializationEvent::Started(id),
                    MaterializationEvent::Rejected(error.clone()),
                ];
                if cleanup == CleanupStatus::Destroyed {
                    events.push(MaterializationEvent::WorkspaceDestroyed(id));
                }
                MaterializationFailure {
                    error,
                    events,
                    cleanup,
                }
            })?;
        let mut pending = PendingMaterialization {
            lease,
            request: request.clone(),
            nodes: BTreeMap::new(),
            directories: BTreeSet::new(),
            started_at,
            events: vec![MaterializationEvent::Started(id)],
        };
        match pending.write(snapshot) {
            Ok(()) => Ok(pending),
            Err(error) => Err(pending.reject(error)),
        }
    }

    fn create_workspace(
        &self,
        id: WorkspaceId,
        limits: MaterializationLimits,
    ) -> Result<WorkspaceLease, (Error, CleanupStatus)> {
        let name = id.to_string();
        fs::mkdirat(&self.root.directory, name.as_str(), mode(0o700)).map_err(|e| {
            let error = if e == rustix::io::Errno::EXIST {
                Error::DestinationNotEmpty
            } else {
                Error::DestinationCreationFailed
            };
            (error, CleanupStatus::NotCreated)
        })?;
        let root = match directory(&self.root.directory, name.as_str()) {
            Ok(root) => root,
            Err(error) => {
                // The authority parent is private; remove only the name just exclusively created.
                fs::unlinkat(&self.root.directory, name.as_str(), AtFlags::REMOVEDIR)
                    .map_err(|_| (Error::CleanupFailed, CleanupStatus::Failed))?;
                return Err((error, CleanupStatus::Destroyed));
            }
        };
        let node = match Node::of(&root) {
            Ok(node) => node,
            Err(error) => {
                fs::unlinkat(&self.root.directory, name.as_str(), AtFlags::REMOVEDIR)
                    .map_err(|_| (Error::CleanupFailed, CleanupStatus::Failed))?;
                return Err((error, CleanupStatus::Destroyed));
            }
        };
        let mut lease = WorkspaceLease {
            parent: Arc::clone(&self.root.directory),
            root: Arc::new(root),
            node,
            id,
            location: WorkspaceLocation(self.root.location.join(&name)),
            destroyed: Arc::new(AtomicBool::new(false)),
            cleanup_budget: limits
                .source
                .max_files
                .saturating_add(limits.max_directories)
                .saturating_add(1),
            owned_directories: BTreeSet::from([node]),
        };
        let checked = (|| {
            fs::fchmod(&lease.root, mode(0o700)).map_err(|_| Error::PermissionApplicationFailed)?;
            lease.attached()?;
            for entry in Dir::read_from(&lease.root).map_err(|_| Error::UnsafeDestination)? {
                let entry = entry.map_err(|_| Error::UnsafeDestination)?;
                if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    return Err(Error::DestinationNotEmpty);
                }
            }
            Ok(())
        })();
        if let Err(error) = checked {
            let cleanup = if lease.cleanup().is_ok() {
                CleanupStatus::Destroyed
            } else {
                CleanupStatus::Failed
            };
            return Err((error, cleanup));
        }
        Ok(lease)
    }
}
impl SourceMaterializer for UnixSourceMaterializer {
    type Source = MaterializedDirectory;
    type Cleanup = WorkspaceLease;
    fn prepare(
        &self,
        snapshot: &SourceSnapshot,
        request: &MaterializationRequest,
    ) -> Result<MaterializationResult<Self::Source, Self::Cleanup>, MaterializationFailure> {
        self.begin(snapshot, request)?.verify_and_seal()?.handoff()
    }
}

fn checked_path(bytes: &[u8]) -> Result<SourcePath, Error> {
    SourcePath::from_bytes(bytes).map_err(|_| Error::PathEscapeAttempt)
}
fn preflight(snapshot: &SourceSnapshot, limits: MaterializationLimits) -> Result<(), Error> {
    let mut budget = Budget::new(limits);
    let mut directories = BTreeSet::new();
    for file in snapshot.files() {
        let path = checked_path(file.path().as_str().as_bytes())?;
        let parts: Vec<_> = path.as_str().split('/').collect();
        budget.leaf(file.mode(), file.bytes().len() as u64)?;
        budget.depth((parts.len() - 1) as u32)?;
        for end in 1..parts.len() {
            directories.insert(parts[..end].join("/"));
            if directories.len() as u64 > limits.max_directories {
                return Err(Error::LimitExceeded(MaterializationBudget::Directories));
            }
        }
        if file.mode() == SourceMode::Symlink
            && (file.bytes().is_empty() || file.bytes().contains(&0) || file.bytes().len() > 4096)
        {
            return Err(Error::UnsupportedFilesystemFeature);
        }
    }
    if directories.len() as u64 > limits.max_directories {
        return Err(Error::LimitExceeded(MaterializationBudget::Directories));
    }
    Ok(())
}

struct Budget {
    limits: MaterializationLimits,
    leaves: u64,
    bytes: u64,
    links: u64,
    directories: u64,
}
impl Budget {
    fn new(limits: MaterializationLimits) -> Self {
        Self {
            limits,
            leaves: 0,
            bytes: 0,
            links: 0,
            directories: 0,
        }
    }
    fn depth(&self, depth: u32) -> Result<(), Error> {
        if depth > self.limits.source.max_tree_depth.min(128) {
            return Err(Error::LimitExceeded(MaterializationBudget::Depth));
        }
        Ok(())
    }
    fn directory(&mut self, depth: u32) -> Result<(), Error> {
        self.depth(depth)?;
        self.directories = self
            .directories
            .checked_add(1)
            .ok_or(Error::LimitExceeded(MaterializationBudget::Directories))?;
        if self.directories > self.limits.max_directories {
            return Err(Error::LimitExceeded(MaterializationBudget::Directories));
        }
        Ok(())
    }
    fn leaf(&mut self, mode: SourceMode, size: u64) -> Result<(), Error> {
        self.leaves = self
            .leaves
            .checked_add(1)
            .ok_or(Error::LimitExceeded(MaterializationBudget::Entries))?;
        if self.leaves > self.limits.source.max_files {
            return Err(Error::LimitExceeded(MaterializationBudget::Entries));
        }
        if size > self.limits.source.max_blob_bytes {
            return Err(Error::LimitExceeded(MaterializationBudget::SingleFile));
        }
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or(Error::LimitExceeded(MaterializationBudget::Bytes))?;
        if self.bytes > self.limits.source.max_total_bytes {
            return Err(Error::LimitExceeded(MaterializationBudget::Bytes));
        }
        if mode == SourceMode::Symlink {
            self.links = self
                .links
                .checked_add(1)
                .ok_or(Error::LimitExceeded(MaterializationBudget::Symlinks))?;
            if self.links > self.limits.max_symlinks {
                return Err(Error::LimitExceeded(MaterializationBudget::Symlinks));
            }
        }
        Ok(())
    }
}

/// Written source that has not yet passed filesystem verification; not runner input.
pub struct PendingMaterialization {
    lease: WorkspaceLease,
    request: MaterializationRequest,
    nodes: BTreeMap<String, Node>,
    directories: BTreeSet<String>,
    started_at: u64,
    events: Vec<MaterializationEvent>,
}
impl PendingMaterialization {
    /// Authority-only diagnostic location, useful for phase-specific validation.
    pub fn location(&self) -> &WorkspaceLocation {
        self.lease.location()
    }

    fn parent_for(&mut self, path: &SourcePath) -> Result<File, Error> {
        let mut parent = directory(&self.lease.root, ".")?;
        let components: Vec<_> = path.as_str().split('/').collect();
        let mut prefix = String::new();
        for component in &components[..components.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if !self.directories.contains(&prefix) {
                fs::mkdirat(&parent, *component, mode(0o700))
                    .map_err(|_| Error::EntryTypeConflict)?;
                let child = directory(&parent, *component)?;
                let node = Node::of(&child)?;
                self.lease.owned_directories.insert(node);
                fs::fchmod(&child, mode(0o700)).map_err(|_| Error::PermissionApplicationFailed)?;
                if node.device != self.lease.node.device {
                    return Err(Error::EntryTypeConflict);
                }
                self.nodes.insert(prefix.clone(), node);
                self.directories.insert(prefix.clone());
            }
            let child = directory(&parent, *component)?;
            if self.nodes.get(&prefix) != Some(&Node::of(&child)?) {
                return Err(Error::EntryTypeConflict);
            }
            parent = child;
        }
        Ok(parent)
    }
    fn write(&mut self, snapshot: &SourceSnapshot) -> Result<(), Error> {
        for file in snapshot.files() {
            let path = checked_path(file.path().as_str().as_bytes())?;
            let parent = self.parent_for(&path)?;
            let name = path
                .as_str()
                .rsplit('/')
                .next()
                .ok_or(Error::PathEscapeAttempt)?;
            match file.mode() {
                SourceMode::File | SourceMode::Executable => {
                    let fd = fs::openat(
                        &parent,
                        name,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        mode(0o600),
                    )
                    .map_err(|_| Error::FileCreationFailed)?;
                    let mut output = File::from(fd);
                    output
                        .write_all(file.bytes())
                        .map_err(|_| Error::FileCreationFailed)?;
                    fs::fchmod(
                        &output,
                        mode(if file.mode() == SourceMode::Executable {
                            0o700
                        } else {
                            0o600
                        }),
                    )
                    .map_err(|_| Error::PermissionApplicationFailed)?;
                    self.nodes
                        .insert(path.as_str().to_owned(), Node::of(&output)?);
                }
                SourceMode::Symlink => {
                    let target = CString::new(file.bytes())
                        .map_err(|_| Error::UnsupportedFilesystemFeature)?;
                    fs::symlinkat(target.as_c_str(), &parent, name)
                        .map_err(|_| Error::SymlinkCreationFailed)?;
                    self.nodes.insert(
                        path.as_str().to_owned(),
                        Node::at(&parent, OsStr::new(name))?,
                    );
                }
                SourceMode::Submodule => return Err(Error::SnapshotNotComplete),
            }
        }
        self.lease.attached()
    }
    fn verify(&self, sealed: bool) -> Result<SourceManifest, Error> {
        self.lease.attached()?;
        let mut walk = Walk {
            nodes: &self.nodes,
            device: self.lease.node.device,
            files: None,
            sealed,
            entries: Vec::new(),
            directories: BTreeSet::new(),
            budget: Budget::new(self.request.limits),
        };
        walk.visit(&self.lease.root, "", 0)?;
        self.lease.attached()?;
        if walk.directories != self.directories {
            return Err(Error::MaterializationIntegrityMismatch);
        }
        let manifest = SourceManifest::new(walk.entries)
            .map_err(|_| Error::MaterializationIntegrityMismatch)?;
        if manifest.digest() != self.request.snapshot.identity.snapshot_sha256 {
            return Err(Error::MaterializationIntegrityMismatch);
        }
        Ok(manifest)
    }
    fn reject(mut self, error: Error) -> MaterializationFailure {
        self.events
            .push(MaterializationEvent::Rejected(error.clone()));
        let cleanup = if self.lease.cleanup().is_ok() {
            self.events
                .push(MaterializationEvent::WorkspaceDestroyed(self.lease.id));
            CleanupStatus::Destroyed
        } else {
            CleanupStatus::Failed
        };
        MaterializationFailure {
            error,
            events: self.events,
            cleanup,
        }
    }
    /// Independently reconstructs all entries, applies a read-only permission seal,
    /// and reconstructs once more. Any error destroys/rejects rather than issuing input.
    pub fn verify_and_seal(mut self) -> Result<SealedMaterialization, MaterializationFailure> {
        let checked = (|| {
            let manifest = self.verify(false)?;
            let verified_at = now()?;
            self.events
                .push(MaterializationEvent::Verified(manifest.digest()));
            let mut seal_budget = self.nodes.len();
            seal_directory(&self.lease.root, "", &self.nodes, &mut seal_budget, 0)?;
            self.verify(true)?;
            let sealed_at = now()?;
            self.events
                .push(MaterializationEvent::Sealed(self.lease.id));
            Ok(MaterializationEvidence {
                snapshot: self.request.snapshot.clone(),
                workspace: self.lease.id,
                materializer_version: "archcert-unix-materializer-v1".to_owned(),
                expected_digest: self.request.snapshot.identity.snapshot_sha256.clone(),
                observed_digest: manifest.digest(),
                entry_count: manifest.entries().len() as u64,
                total_bytes_written: manifest.entries().iter().map(ManifestEntry::size).sum(),
                status: MaterializationState::Sealed,
                verification: VerificationStatus::Verified,
                seal: SealStatus::UnixPermissionsReadOnly,
                started_at: self.started_at,
                verified_at,
                sealed_at,
                handed_off_at: None,
                limits: self.request.limits,
            })
        })();
        match checked {
            Ok(evidence) => Ok(SealedMaterialization {
                pending: self,
                evidence,
            }),
            Err(error) => Err(self.reject(error)),
        }
    }
}

/// Source verified before and after permission sealing; final handoff still reverifies.
pub struct SealedMaterialization {
    pending: PendingMaterialization,
    evidence: MaterializationEvidence,
}
impl SealedMaterialization {
    /// Authority-only location; not included in runner input.
    pub fn location(&self) -> &WorkspaceLocation {
        self.pending.location()
    }
    /// Structural verified/sealed evidence before issuance.
    pub fn evidence(&self) -> &MaterializationEvidence {
        &self.evidence
    }
    /// Rechecks actual sealed bytes and attachments immediately before issuing input.
    /// Same-UID/root writes after return remain outside the Unix permission guarantee.
    pub fn handoff(
        mut self,
    ) -> Result<MaterializationResult<MaterializedDirectory, WorkspaceLease>, MaterializationFailure>
    {
        let checked = (|| {
            self.pending.verify(true)?;
            let handed_off_at = now()?;
            let source = MaterializedDirectory {
                directory: Arc::clone(&self.pending.lease.root),
                destroyed: Arc::clone(&self.pending.lease.destroyed),
                workspace: self.pending.lease.id,
                identity: self.evidence.snapshot.identity.clone(),
                nodes: self.pending.nodes.clone(),
                directories: self.pending.directories.clone(),
                limits: self.pending.request.limits,
            };
            let input = RunnerInput::from_sealed(source, &self.evidence)?;
            self.evidence.status = self
                .evidence
                .status
                .advance(MaterializationState::HandedOff)?;
            self.evidence.handed_off_at = Some(handed_off_at);
            Ok(input)
        })();
        match checked {
            Ok(runner_input) => {
                self.pending
                    .events
                    .push(MaterializationEvent::RunnerInputIssued(
                        self.pending.lease.id,
                    ));
                Ok(MaterializationResult {
                    runner_input,
                    cleanup: self.pending.lease,
                    evidence: self.evidence,
                    events: self.pending.events,
                })
            }
            Err(error) => Err(self.pending.reject(error)),
        }
    }
}

struct Walk<'a> {
    nodes: &'a BTreeMap<String, Node>,
    device: u64,
    files: Option<Vec<SourceFile>>,
    sealed: bool,
    entries: Vec<ManifestEntry>,
    directories: BTreeSet<String>,
    budget: Budget,
}
impl Walk<'_> {
    fn visit(&mut self, root: &File, prefix: &str, depth: u32) -> Result<(), Error> {
        self.budget.depth(depth)?;
        let root_metadata = root.metadata().map_err(|_| Error::VerificationFailed)?;
        if root_metadata.mode() & 0o7777 != if self.sealed { 0o500 } else { 0o700 } {
            return Err(Error::MaterializationIntegrityMismatch);
        }
        for entry in Dir::read_from(root).map_err(|_| Error::VerificationFailed)? {
            let entry = entry.map_err(|_| Error::VerificationFailed)?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            let component = checked_path(name.to_bytes())?;
            // A directory entry must be a single source component, regardless of schema validation.
            if component.as_str().contains('/') {
                return Err(Error::PathEscapeAttempt);
            }
            let path = checked_path(format!("{prefix}{}", component.as_str()).as_bytes())?;
            let stat = fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Error::MaterializationIntegrityMismatch)?;
            let node = Node {
                device: stat.st_dev as u64,
                inode: stat.st_ino as u64,
            };
            if node.device != self.device || self.nodes.get(path.as_str()) != Some(&node) {
                return Err(Error::EntryTypeConflict);
            }
            let kind = FileType::from_raw_mode(stat.st_mode);
            if kind == FileType::Directory {
                self.budget.directory(depth + 1)?;
                self.directories.insert(path.as_str().to_owned());
                let child = directory(root, name)?;
                if Node::of(&child)? != node {
                    return Err(Error::EntryTypeConflict);
                }
                self.visit(&child, &format!("{}/", path.as_str()), depth + 1)?;
            } else {
                let (source_mode, bytes) = match kind {
                    FileType::RegularFile => {
                        let mut file = File::from(
                            fs::openat(
                                root,
                                name,
                                OFlags::RDONLY
                                    | OFlags::NOFOLLOW
                                    | OFlags::NONBLOCK
                                    | OFlags::CLOEXEC,
                                Mode::empty(),
                            )
                            .map_err(|_| Error::EntryTypeConflict)?,
                        );
                        let metadata = file.metadata().map_err(|_| Error::VerificationFailed)?;
                        if !metadata.is_file() || metadata.nlink() != 1 || Node::of(&file)? != node
                        {
                            return Err(Error::EntryTypeConflict);
                        }
                        let bits = metadata.mode() & 0o7777;
                        let file_mode = match (self.sealed, bits) {
                            (false, 0o600) | (true, 0o400) => SourceMode::File,
                            (false, 0o700) | (true, 0o500) => SourceMode::Executable,
                            _ => return Err(Error::MaterializationIntegrityMismatch),
                        };
                        self.budget.leaf(file_mode, metadata.len())?;
                        let mut bytes = Vec::new();
                        (&mut file)
                            .take(metadata.len().saturating_add(1))
                            .read_to_end(&mut bytes)
                            .map_err(|_| Error::VerificationFailed)?;
                        let after = file.metadata().map_err(|_| Error::VerificationFailed)?;
                        if bytes.len() as u64 != metadata.len()
                            || after.len() != metadata.len()
                            || after.mode() != metadata.mode()
                            || after.mtime() != metadata.mtime()
                            || after.mtime_nsec() != metadata.mtime_nsec()
                            || after.ctime() != metadata.ctime()
                            || after.ctime_nsec() != metadata.ctime_nsec()
                        {
                            return Err(Error::MaterializationIntegrityMismatch);
                        }
                        (file_mode, bytes)
                    }
                    FileType::Symlink => {
                        // A fixed buffer bounds even filesystem-specific targets. A full buffer
                        // is ambiguous truncation and is rejected; target bytes are never opened.
                        let mut target = [0u8; 4097];
                        let len = fs::readlinkat_raw(root, name, &mut target[..])
                            .map_err(|_| Error::VerificationFailed)?;
                        if len == target.len() {
                            return Err(Error::UnsupportedFilesystemFeature);
                        }
                        self.budget.leaf(SourceMode::Symlink, len as u64)?;
                        (SourceMode::Symlink, target[..len].to_vec())
                    }
                    _ => return Err(Error::EntryTypeConflict),
                };
                self.entries.push(ManifestEntry::new(
                    path.clone(),
                    source_mode,
                    digest_bytes(&bytes),
                    bytes.len() as u64,
                ));
                if let Some(files) = &mut self.files {
                    files.push(SourceFile::new(path.clone(), source_mode, bytes));
                }
            }
            if Node::at(root, OsStr::from_bytes(name.to_bytes()))? != node {
                return Err(Error::EntryTypeConflict);
            }
        }
        Ok(())
    }
}

fn seal_directory(
    root: &File,
    prefix: &str,
    expected: &BTreeMap<String, Node>,
    remaining: &mut usize,
    depth: u32,
) -> Result<(), Error> {
    if depth > 128 {
        return Err(Error::SealFailed);
    }
    for entry in Dir::read_from(root).map_err(|_| Error::SealFailed)? {
        let entry = entry.map_err(|_| Error::SealFailed)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *remaining = remaining.checked_sub(1).ok_or(Error::SealFailed)?;
        let component = checked_path(name.to_bytes())?;
        if component.as_str().contains('/') {
            return Err(Error::SealFailed);
        }
        let path = format!("{prefix}{}", component.as_str());
        let stat =
            fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::SealFailed)?;
        let node = Node {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        };
        if expected.get(&path) != Some(&node) {
            return Err(Error::SealFailed);
        }
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = directory(root, name)?;
                if Node::of(&child)? != node {
                    return Err(Error::SealFailed);
                }
                seal_directory(&child, &format!("{path}/"), expected, remaining, depth + 1)?;
            }
            FileType::RegularFile => {
                let file = File::from(
                    fs::openat(
                        root,
                        name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| Error::SealFailed)?,
                );
                let metadata = file.metadata().map_err(|_| Error::SealFailed)?;
                if !metadata.is_file() || metadata.nlink() != 1 || Node::of(&file)? != node {
                    return Err(Error::SealFailed);
                }
                let target = match metadata.mode() & 0o7777 {
                    0o600 => 0o400,
                    0o700 => 0o500,
                    _ => return Err(Error::SealFailed),
                };
                fs::fchmod(&file, mode(target)).map_err(|_| Error::SealFailed)?;
            }
            FileType::Symlink => {}
            _ => return Err(Error::SealFailed),
        }
        if Node::at(root, OsStr::from_bytes(name.to_bytes()))? != node {
            return Err(Error::SealFailed);
        }
    }
    fs::fchmod(root, mode(0o500)).map_err(|_| Error::SealFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::{
        GitObjectId, ProjectId,
        materialization::SnapshotReference,
        source::{RepositoryId, SourceFile},
    };
    fn snapshot(bytes: Option<&[u8]>) -> Result<SourceSnapshot, Box<dyn std::error::Error>> {
        let files = match bytes {
            Some(bytes) => vec![SourceFile::new(
                SourcePath::from_bytes(b"a")?,
                SourceMode::File,
                bytes.to_vec(),
            )],
            None => vec![],
        };
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
    #[test]
    fn traversal_and_unsupported_separators_are_independently_rejected() {
        for path in [
            b"../outside".as_slice(),
            b"/absolute",
            b"a/../b",
            b"a\\b",
            b"C:/file",
            b"",
            &[255],
        ] {
            assert_eq!(checked_path(path), Err(Error::PathEscapeAttempt));
        }
    }
    #[test]
    fn preexisting_destination_is_never_reused_emptied_or_overwritten()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().canonicalize()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);
        let id = WorkspaceId::new();
        let destination = path.join(id.to_string());
        std::fs::create_dir(&destination)?;
        std::fs::write(destination.join("existing"), b"preserve")?;
        assert!(matches!(
            materializer.create_workspace(id, MaterializationLimits::default()),
            Err((Error::DestinationNotEmpty, CleanupStatus::NotCreated))
        ));
        assert_eq!(std::fs::read(destination.join("existing"))?, b"preserve");
        Ok(())
    }
    #[test]
    fn writer_rejects_directory_prepopulation_and_exclusive_file_conflicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().canonicalize()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);
        let empty = snapshot(None)?;
        let mut pending = materializer.begin(&empty, &request(&empty))?;
        let host = tempfile::tempdir()?;
        std::fs::write(host.path().join("a"), b"host")?;
        std::os::unix::fs::symlink(host.path(), pending.location().as_path().join("dir"))?;
        assert!(matches!(
            pending.parent_for(&SourcePath::from_bytes(b"dir/a")?),
            Err(Error::EntryTypeConflict)
        ));
        std::os::unix::fs::symlink(
            host.path().join("a"),
            pending.location().as_path().join("a"),
        )?;
        assert_eq!(
            pending.write(&snapshot(Some(b"source"))?),
            Err(Error::FileCreationFailed)
        );
        assert_eq!(std::fs::read(host.path().join("a"))?, b"host");
        drop(pending);
        assert_eq!(std::fs::read(host.path().join("a"))?, b"host");
        Ok(())
    }
}
