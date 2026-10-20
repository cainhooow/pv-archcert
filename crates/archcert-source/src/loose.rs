use archcert_application::source::{GitGateway, SourceQuarantine, ValidatedSource};
use archcert_domain::{
    GitObjectId,
    source::{
        RepositoryId, ResourceLimit, SourceError, SourceFile, SourceLimits, SourceManifest,
        SourceMode, SourcePath,
    },
};
use flate2::{Decompress, FlushDecompress, Status};
use rustix::fs::{Mode, OFlags, openat};
use sha2::Digest;
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
};

/// Development gateway for local bare directories or explicit `.git` directories.
///
/// The caller supplies an authority mapping, not repository-owned configuration.
/// Only loose SHA-1/SHA-256 objects are supported. Missing packed/alternate objects
/// fail closed. This is not a production Smart Protocol receiver.
pub struct LocalGitGateway {
    repository: RepositoryId,
    git_directory: PathBuf,
}

impl LocalGitGateway {
    /// Maps one authority repository to an explicit local object directory parent.
    pub fn new(repository: RepositoryId, git_directory: impl Into<PathBuf>) -> Self {
        Self {
            repository,
            git_directory: git_directory.into(),
        }
    }
}

// Every untrusted component is opened relative to an already held directory FD.
// NOFOLLOW prevents symlink swaps; NONBLOCK prevents malicious FIFO opens hanging.
fn open_directory(parent: &OwnedFd, name: &std::ffi::OsStr) -> Result<OwnedFd, SourceError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceError::RepositoryAccessFailure)
}

fn open_root(path: &Path) -> Result<OwnedFd, SourceError> {
    let absolute = std::path::absolute(path).map_err(|_| SourceError::RepositoryAccessFailure)?;
    let mut fd = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceError::RepositoryAccessFailure)?;
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => fd = open_directory(&fd, name)?,
            _ => return Err(SourceError::RepositoryAccessFailure),
        }
    }
    Ok(fd)
}

impl GitGateway for LocalGitGateway {
    fn quarantine(
        &self,
        repository: &RepositoryId,
    ) -> Result<Box<dyn SourceQuarantine>, SourceError> {
        if repository != &self.repository {
            return Err(SourceError::RepositoryAccessFailure);
        }
        let root = open_root(&self.git_directory)?;
        let objects = open_directory(&root, std::ffi::OsStr::new("objects"))?;
        Ok(Box::new(LooseQuarantine { objects }))
    }
}

struct LooseQuarantine {
    objects: OwnedFd,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Commit,
    Tree,
    Blob,
}

impl Kind {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Commit => b"commit",
            Self::Tree => b"tree",
            Self::Blob => b"blob",
        }
    }
    fn missing(self) -> SourceError {
        match self {
            Self::Commit => SourceError::CommitNotFound,
            Self::Tree => SourceError::MissingTree,
            Self::Blob => SourceError::MissingBlob,
        }
    }
}

struct Validation<'a> {
    store: &'a LooseQuarantine,
    limits: SourceLimits,
    visits: u64,
    total: u64,
    work_bytes: u64,
    files: Vec<SourceFile>,
    // Includes empty directories, which must not hide colliding names.
    paths: BTreeSet<String>,
}

impl Validation<'_> {
    fn charge_work(&mut self, count: u64) -> Result<(), SourceError> {
        self.work_bytes = self
            .work_bytes
            .checked_add(count)
            .ok_or(SourceError::LimitExceeded(ResourceLimit::ObjectWorkBytes))?;
        if self.work_bytes > self.limits.max_object_work_bytes {
            return Err(SourceError::LimitExceeded(ResourceLimit::ObjectWorkBytes));
        }
        Ok(())
    }

    fn read(&mut self, oid: &GitObjectId, kind: Kind) -> Result<Vec<u8>, SourceError> {
        self.visits = self
            .visits
            .checked_add(1)
            .ok_or(SourceError::LimitExceeded(ResourceLimit::Objects))?;
        if self.visits > self.limits.max_objects {
            return Err(SourceError::LimitExceeded(ResourceLimit::Objects));
        }
        let text = oid.as_str();
        let directory = match openat(
            &self.store.objects,
            &text[..2],
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Err(kind.missing()),
            Err(_) => return Err(SourceError::RepositoryAccessFailure),
        };
        let fd = match openat(
            &directory,
            &text[2..],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Err(kind.missing()),
            Err(_) => return Err(SourceError::RepositoryAccessFailure),
        };
        let mut file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|_| SourceError::RepositoryAccessFailure)?;
        if !metadata.is_file() {
            return Err(SourceError::RepositoryAccessFailure);
        }
        let cap = self.limits.max_object_bytes;
        if metadata.len() > cap {
            return Err(SourceError::LimitExceeded(ResourceLimit::ObjectBytes));
        }
        let mut compressed = Vec::new();
        (&mut file)
            .take(cap.saturating_add(1))
            .read_to_end(&mut compressed)
            .map_err(|_| SourceError::RepositoryAccessFailure)?;
        if compressed.len() as u64 > cap {
            return Err(SourceError::LimitExceeded(ResourceLimit::ObjectBytes));
        }
        self.charge_work(compressed.len() as u64)?;
        let mut decoder = Decompress::new(true);
        let mut inflated = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let previous_in = decoder.total_in();
            let previous_out = decoder.total_out();
            let status = decoder
                .decompress(
                    &compressed[previous_in as usize..],
                    &mut chunk,
                    // The output is deliberately chunked. Finish incorrectly requires
                    // a large stream to fit in one output buffer on some backends.
                    FlushDecompress::None,
                )
                .map_err(|_| SourceError::MalformedGitObject)?;
            if decoder.total_out() > cap {
                return Err(SourceError::LimitExceeded(ResourceLimit::ObjectBytes));
            }
            let written = (decoder.total_out() - previous_out) as usize;
            self.charge_work(written as u64)?;
            inflated.extend_from_slice(&chunk[..written]);
            if status == Status::StreamEnd {
                if decoder.total_in() != compressed.len() as u64 {
                    return Err(SourceError::MalformedGitObject);
                }
                break;
            }
            if previous_in == decoder.total_in() && previous_out == decoder.total_out() {
                return Err(SourceError::MalformedGitObject);
            }
        }
        let actual = if text.len() == 40 {
            hex::encode(sha1::Sha1::digest(&inflated))
        } else {
            hex::encode(sha2::Sha256::digest(&inflated))
        };
        if actual != text {
            return Err(SourceError::ObjectIdentityMismatch);
        }
        let nul = inflated
            .iter()
            .position(|b| *b == 0)
            .ok_or(SourceError::MalformedGitObject)?;
        let header = &inflated[..nul];
        let space = header
            .iter()
            .position(|b| *b == b' ')
            .ok_or(SourceError::MalformedGitObject)?;
        let type_name = &header[..space];
        if ![b"commit".as_slice(), b"tree", b"blob", b"tag"].contains(&type_name) {
            return Err(SourceError::MalformedGitObject);
        }
        if type_name != kind.bytes() {
            return Err(SourceError::ObjectTypeMismatch);
        }
        let size = &header[space + 1..];
        if size.is_empty()
            || (size.len() > 1 && size[0] == b'0')
            || !size.iter().all(u8::is_ascii_digit)
        {
            return Err(SourceError::MalformedGitObject);
        }
        let size: usize = std::str::from_utf8(size)
            .map_err(|_| SourceError::MalformedGitObject)?
            .parse()
            .map_err(|_| SourceError::MalformedGitObject)?;
        if inflated.len() - nul - 1 != size {
            return Err(SourceError::MalformedGitObject);
        }
        if kind == Kind::Blob && size as u64 > self.limits.max_blob_bytes {
            return Err(SourceError::LimitExceeded(ResourceLimit::BlobBytes));
        }
        Ok(inflated.split_off(nul + 1))
    }

    fn add_path(&mut self, path: &SourcePath) -> Result<(), SourceError> {
        if !self.paths.insert(path.collision_key()) {
            return Err(SourceError::PathCollision);
        }
        Ok(())
    }

    fn tree(&mut self, oid: &GitObjectId, prefix: &str, depth: u32) -> Result<(), SourceError> {
        // A hard parser recursion ceiling also applies when operators raise budgets.
        if depth > self.limits.max_tree_depth.min(128) {
            return Err(SourceError::LimitExceeded(ResourceLimit::TreeDepth));
        }
        let bytes = self.read(oid, Kind::Tree)?;
        let oid_len = oid.as_str().len() / 2;
        let mut cursor = 0usize;
        let mut previous_sort_key: Option<Vec<u8>> = None;
        while cursor < bytes.len() {
            let space = bytes[cursor..]
                .iter()
                .position(|b| *b == b' ')
                .ok_or(SourceError::MalformedGitObject)?
                + cursor;
            let mode = &bytes[cursor..space];
            cursor = space + 1;
            let nul = bytes[cursor..]
                .iter()
                .position(|b| *b == 0)
                .ok_or(SourceError::MalformedGitObject)?
                + cursor;
            let name = &bytes[cursor..nul];
            if name.contains(&b'/') {
                return Err(SourceError::InvalidSourcePath);
            }
            let component = SourcePath::from_bytes(name)?;
            let path =
                SourcePath::from_bytes(format!("{prefix}{}", component.as_str()).as_bytes())?;
            self.add_path(&path)?;
            let is_tree = mode == b"40000";
            let mut sort_key = name.to_vec();
            if is_tree {
                sort_key.push(b'/');
            }
            if previous_sort_key.as_ref().is_some_and(|p| p >= &sort_key) {
                return Err(SourceError::MalformedGitObject);
            }
            previous_sort_key = Some(sort_key);
            cursor = nul + 1;
            let end = cursor
                .checked_add(oid_len)
                .ok_or(SourceError::MalformedGitObject)?;
            let raw_oid = bytes
                .get(cursor..end)
                .ok_or(SourceError::MalformedGitObject)?;
            let child = GitObjectId::parse(hex::encode(raw_oid))
                .map_err(|_| SourceError::MalformedGitObject)?;
            if raw_oid.iter().all(|b| *b == 0) {
                return Err(SourceError::MalformedGitObject);
            }
            cursor = end;
            if is_tree {
                self.tree(&child, &format!("{}/", path.as_str()), depth + 1)?;
                continue;
            }
            let mode = match mode {
                b"100644" => SourceMode::File,
                b"100755" => SourceMode::Executable,
                b"120000" => SourceMode::Symlink,
                b"160000" => SourceMode::Submodule,
                _ => return Err(SourceError::UnsupportedGitEntry),
            };
            if self.files.len() as u64 >= self.limits.max_files {
                return Err(SourceError::LimitExceeded(ResourceLimit::Files));
            }
            let content = if mode == SourceMode::Submodule {
                child.as_str().as_bytes().to_vec()
            } else {
                self.read(&child, Kind::Blob)?
            };
            self.total = self
                .total
                .checked_add(content.len() as u64)
                .ok_or(SourceError::LimitExceeded(ResourceLimit::TotalBytes))?;
            if self.total > self.limits.max_total_bytes {
                return Err(SourceError::LimitExceeded(ResourceLimit::TotalBytes));
            }
            self.files.push(SourceFile::new(path, mode, content));
        }
        Ok(())
    }
}

fn parse_oid(bytes: &[u8], width: usize) -> Result<GitObjectId, SourceError> {
    if bytes.len() != width
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(SourceError::MalformedGitObject);
    }
    let oid = GitObjectId::parse(
        std::str::from_utf8(bytes).map_err(|_| SourceError::MalformedGitObject)?,
    )
    .map_err(|_| SourceError::MalformedGitObject)?;
    if bytes.iter().all(|b| *b == b'0') {
        return Err(SourceError::MalformedGitObject);
    }
    Ok(oid)
}

fn validate_person(bytes: &[u8]) -> Result<(), SourceError> {
    let closing = bytes
        .iter()
        .rposition(|b| *b == b'>')
        .ok_or(SourceError::MalformedGitObject)?;
    let opening = bytes[..closing]
        .iter()
        .position(|b| *b == b'<')
        .ok_or(SourceError::MalformedGitObject)?;
    if opening == 0 || bytes[opening - 1] != b' ' || bytes[..closing].contains(&b'\n') {
        return Err(SourceError::MalformedGitObject);
    }
    let suffix = bytes
        .get(closing + 1..)
        .ok_or(SourceError::MalformedGitObject)?;
    let text = std::str::from_utf8(suffix).map_err(|_| SourceError::MalformedGitObject)?;
    let parts: Vec<_> = text.split(' ').collect();
    if parts.len() != 3
        || !parts[0].is_empty()
        || parts[1].parse::<i64>().is_err()
        || parts[2].len() != 5
        || !matches!(parts[2].as_bytes()[0], b'+' | b'-')
        || !parts[2].as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(SourceError::MalformedGitObject);
    }
    Ok(())
}

fn commit_tree(bytes: &[u8], width: usize) -> Result<GitObjectId, SourceError> {
    let separator = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or(SourceError::MalformedGitObject)?;
    let header = &bytes[..separator];
    if header.contains(&0) || header.contains(&b'\r') {
        return Err(SourceError::MalformedGitObject);
    }
    let mut lines = header.split(|b| *b == b'\n').peekable();
    let first = lines.next().ok_or(SourceError::MalformedGitObject)?;
    let tree = parse_oid(
        first
            .strip_prefix(b"tree ")
            .ok_or(SourceError::MalformedGitObject)?,
        width,
    )?;
    while lines
        .peek()
        .is_some_and(|line| line.starts_with(b"parent "))
    {
        let line = lines.next().ok_or(SourceError::MalformedGitObject)?;
        parse_oid(&line[7..], width)?;
    }
    validate_person(
        lines
            .next()
            .and_then(|l| l.strip_prefix(b"author "))
            .ok_or(SourceError::MalformedGitObject)?,
    )?;
    validate_person(
        lines
            .next()
            .and_then(|l| l.strip_prefix(b"committer "))
            .ok_or(SourceError::MalformedGitObject)?,
    )?;
    let mut previous_extra = false;
    for line in lines {
        if line.starts_with(b" ") {
            if !previous_extra {
                return Err(SourceError::MalformedGitObject);
            }
            continue;
        }
        let space = line
            .iter()
            .position(|b| *b == b' ')
            .ok_or(SourceError::MalformedGitObject)?;
        let key = &line[..space];
        if key.is_empty()
            || !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            || [b"tree".as_slice(), b"parent", b"author", b"committer"].contains(&key)
        {
            return Err(SourceError::MalformedGitObject);
        }
        previous_extra = true;
    }
    Ok(tree)
}

impl SourceQuarantine for LooseQuarantine {
    fn validate(
        &mut self,
        commit: &GitObjectId,
        limits: SourceLimits,
    ) -> Result<ValidatedSource, SourceError> {
        let mut validation = Validation {
            store: self,
            limits,
            visits: 0,
            total: 0,
            work_bytes: 0,
            files: Vec::new(),
            paths: BTreeSet::new(),
        };
        let bytes = validation.read(commit, Kind::Commit)?;
        let tree = commit_tree(&bytes, commit.as_str().len())?;
        validation.tree(&tree, "", 0)?;
        SourceManifest::new(
            validation
                .files
                .iter()
                .map(SourceFile::manifest_entry)
                .collect(),
        )?;
        Ok(ValidatedSource {
            commit: commit.clone(),
            tree,
            files: validation.files,
            object_count: validation.visits,
        })
    }
}
