//! Immutable source data and canonical identity, independent of Git storage.
//!
//! Repository names and bytes are hostile. Constructors reject ambiguity rather
//! than normalizing it, and snapshots own the bytes used to establish identity.

use crate::{GitObjectId, ProjectId, Sha256Digest, SourceIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use unicode_normalization::is_nfc;

mod binding;

pub use binding::{ResolvedDependency, SourceBinding};

#[cfg(test)]
mod tests;

/// Structured failures shared across source ports and adapters.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
pub enum SourceError {
    /// No accepted source matches the exact authority-scoped lookup.
    #[error("accepted source snapshot unavailable")]
    SnapshotUnavailable,
    /// The exact requested commit is unavailable in the supported object store.
    #[error("requested commit not found")]
    CommitNotFound,
    /// A tree required by the selected commit is unavailable.
    #[error("required tree not found")]
    MissingTree,
    /// A file blob required by the selected tree is unavailable.
    #[error("required blob not found")]
    MissingBlob,
    /// The verified object is not of the required Git type.
    #[error("unexpected Git object type")]
    ObjectTypeMismatch,
    /// An object violates the supported Git grammar or compression format.
    #[error("malformed Git object")]
    MalformedGitObject,
    /// Received bytes do not hash to their requested Git identity.
    #[error("Git object identity mismatch")]
    ObjectIdentityMismatch,
    /// A filename cannot be represented safely under the source schema.
    #[error("invalid or unsupported source path")]
    InvalidSourcePath,
    /// Paths collide, including directory prefixes and portable case aliases.
    #[error("source path collision")]
    PathCollision,
    /// A Git mode is outside this version's source model.
    #[error("unsupported Git entry")]
    UnsupportedGitEntry,
    /// A recognizable LFS pointer is malformed or uses unsupported extensions.
    #[error("invalid or unsupported Git LFS pointer")]
    InvalidLfsPointer,
    /// A configured authority resource budget was exhausted.
    #[error("source resource limit exceeded: {0:?}")]
    LimitExceeded(ResourceLimit),
    /// Local access failed; diagnostic OS details are deliberately not evidence.
    #[error("repository access failure")]
    RepositoryAccessFailure,
    /// The adapter does not support this platform or repository representation.
    #[error("unsupported repository storage or platform")]
    UnsupportedRepository,
    /// The manifest or retained bytes do not reproduce the expected digest.
    #[error("snapshot digest mismatch")]
    SnapshotDigestMismatch,
    /// A complete source is required, but external bytes remain unresolved.
    #[error("source contains unresolved external material")]
    IncompleteExternalSource,
    /// Authority-owned state is inconsistent or a synchronization primitive failed.
    #[error("internal source integrity failure")]
    InternalIntegrityFailure,
}

/// Authority-controlled budget that caused a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ResourceLimit {
    /// Delta ancestry exceeded the authority limit before decoding.
    DeltaDepth,
    /// Resolved object expansion exceeded the authority ratio.
    DeltaExpansion,
    /// Number of source entries (including gitlinks).
    Files,
    /// Sum of source blob sizes, counting repeated paths separately.
    TotalBytes,
    /// Uncompressed individual blob size.
    BlobBytes,
    /// Directory nesting below the root.
    TreeDepth,
    /// Number of object reads, including reused trees and blobs.
    Objects,
    /// Compressed or uncompressed Git object size.
    ObjectBytes,
    /// Aggregate compressed plus inflated object bytes processed, including reuse.
    ObjectWorkBytes,
}

/// Development budgets; operators must select deployment-specific bounds.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourceLimits {
    /// Maximum leaf entries.
    pub max_files: u64,
    /// Maximum retained source bytes.
    pub max_total_bytes: u64,
    /// Maximum bytes per blob.
    pub max_blob_bytes: u64,
    /// Maximum directory depth; the root has depth zero.
    pub max_tree_depth: u32,
    /// Maximum object visits, including repeated references.
    pub max_objects: u64,
    /// Maximum compressed and inflated bytes per Git object, including header.
    pub max_object_bytes: u64,
    /// Maximum aggregate compressed plus inflated bytes processed per attempt.
    pub max_object_work_bytes: u64,
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_total_bytes: 64 * 1024 * 1024,
            max_blob_bytes: 8 * 1024 * 1024,
            max_tree_depth: 32,
            max_objects: 25_000,
            max_object_bytes: 9 * 1024 * 1024,
            max_object_work_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Authority-assigned repository identity, distinct from a local transport path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Accepts a nonempty ASCII authority label, at most 128 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, SourceError> {
        let value = value.into();

        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        {
            return Err(SourceError::UnsupportedRepository);
        }

        Ok(Self(value))
    }

    /// Returns the authority label; it must never be interpreted as a filesystem path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RepositoryId {
    type Error = SourceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A UTF-8 NFC relative Git path, preserved byte for byte without lossy conversion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SourcePath(String);

impl SourcePath {
    /// Rejects traversal, host separators, control bytes, reserved names and aliases.
    /// Non-UTF-8 and non-NFC Git names are explicitly unsupported by schema v1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SourceError> {
        let value = std::str::from_utf8(bytes).map_err(|_| SourceError::InvalidSourcePath)?;

        if value.is_empty() || value.len() > 4096 || !is_nfc(value) {
            return Err(SourceError::InvalidSourcePath);
        }

        for part in value.split('/') {
            let lower = part.to_lowercase();
            let stem = lower
                .split('.')
                .next()
                .ok_or(SourceError::InvalidSourcePath)?;

            if part.is_empty()
                || part.len() > 255
                || part == "."
                || part == ".."
                || lower == ".git"
                || part.ends_with(['.', ' '])
                || part
                    .chars()
                    .any(|c| c.is_control() || "\\:<>\"|?*".contains(c))
                || matches!(stem, "con" | "prn" | "aux" | "nul")
                || (stem.len() == 4
                    && (stem.starts_with("com") || stem.starts_with("lpt"))
                    && stem.as_bytes()[3].is_ascii_digit())
            {
                return Err(SourceError::InvalidSourcePath);
            }
        }

        Ok(Self(value.to_owned()))
    }

    /// Returns the unchanged canonical UTF-8 source name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Conservative collision key, not a replacement for the stored path.
    pub fn collision_key(&self) -> String {
        self.0.to_lowercase()
    }
}

impl TryFrom<String> for SourcePath {
    type Error = SourceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_bytes(value.as_bytes())
    }
}

/// Supported Git leaf modes; directory entries are validated separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceMode {
    /// Ordinary file, Git mode 100644.
    File,
    /// Executable file, Git mode 100755.
    Executable,
    /// Link target bytes, Git mode 120000; never followed.
    Symlink,
    /// Unresolved submodule commit, Git mode 160000.
    Submodule,
}

impl SourceMode {
    /// Numeric Git mode encoded in the canonical manifest.
    pub fn git_mode(self) -> u32 {
        match self {
            Self::File => 0o100644,
            Self::Executable => 0o100755,
            Self::Symlink => 0o120000,
            Self::Submodule => 0o160000,
        }
    }
}

/// SHA-256 computed by ArchCert, never taken from repository claims.
pub fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    // A fixed-size cryptographic output always satisfies the domain invariant.
    Sha256Digest(hex::encode(Sha256::digest(bytes)))
}

/// One immutable normalized source entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    path: SourcePath,
    mode: SourceMode,
    content_sha256: Sha256Digest,
    size: u64,
}

impl ManifestEntry {
    /// Constructs metadata; acceptance must additionally verify retained bytes.
    pub fn new(
        path: SourcePath,
        mode: SourceMode,
        content_sha256: Sha256Digest,
        size: u64,
    ) -> Self {
        Self {
            path,
            mode,
            content_sha256,
            size,
        }
    }

    /// Validated source path.
    pub fn path(&self) -> &SourcePath {
        &self.path
    }

    /// Git leaf mode.
    pub fn mode(&self) -> SourceMode {
        self.mode
    }

    /// Independently computed content identity.
    pub fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }

    /// Canonical payload size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Sorted manifest with unique paths and unambiguous directory prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceManifest {
    entries: Vec<ManifestEntry>,
}

impl SourceManifest {
    /// Sorts by UTF-8 path bytes and rejects duplicate/colliding leaf or directory names.
    pub fn new(mut entries: Vec<ManifestEntry>) -> Result<Self, SourceError> {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut names: BTreeMap<String, (String, bool)> = BTreeMap::new();

        for entry in &entries {
            let mut prefix = String::new();
            let parts: Vec<_> = entry.path.as_str().split('/').collect();

            for (index, part) in parts.iter().enumerate() {
                if !prefix.is_empty() {
                    prefix.push('/');
                }

                prefix.push_str(part);
                let leaf = index + 1 == parts.len();

                if let Some((existing, existing_leaf)) = names.get(&prefix.to_lowercase()) {
                    if existing != &prefix || leaf || *existing_leaf {
                        return Err(SourceError::PathCollision);
                    }
                } else {
                    names.insert(prefix.to_lowercase(), (prefix.clone(), leaf));
                }
            }
        }

        Ok(Self { entries })
    }

    /// Entries in canonical order.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Canonical schema v1 bytes. See ADR-0006 for the exact binary format.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ARCHCERT-SOURCE\0\x00\x00\x00\x01".to_vec();
        bytes.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());

        for entry in &self.entries {
            let path = entry.path.as_str().as_bytes();
            bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
            bytes.extend_from_slice(path);
            bytes.extend_from_slice(&entry.mode.git_mode().to_be_bytes());
            // Hex is fixed-width lowercase ASCII, avoiding fallible decoding here.
            bytes.extend_from_slice(entry.content_sha256.as_str().as_bytes());
            bytes.extend_from_slice(&entry.size.to_be_bytes());
        }

        bytes
    }

    /// SHA-256 of the complete canonical representation.
    pub fn digest(&self) -> Sha256Digest {
        digest_bytes(&self.canonical_bytes())
    }
}

/// Owned leaf bytes. Symlinks contain their target; gitlinks contain lowercase OID ASCII.
#[derive(Clone)]
pub struct SourceFile {
    path: SourcePath,
    mode: SourceMode,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Repository content can contain secrets or terminal control sequences.
        // Debug output describes the payload without disclosing its bytes.
        f.debug_struct("SourceFile")
            .field("path", &self.path)
            .field("mode", &self.mode)
            .field("size", &self.bytes.len())
            .finish()
    }
}

impl SourceFile {
    /// Takes ownership of already bounded bytes; no filesystem lookup occurs.
    pub fn new(path: SourcePath, mode: SourceMode, bytes: Vec<u8>) -> Self {
        Self { path, mode, bytes }
    }

    /// Source name, never a host path.
    pub fn path(&self) -> &SourcePath {
        &self.path
    }

    /// File semantics; symlink payloads must never be dereferenced.
    pub fn mode(&self) -> SourceMode {
        self.mode
    }

    /// Retained immutable payload.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Independently derives manifest metadata from the owned payload.
    pub fn manifest_entry(&self) -> ManifestEntry {
        ManifestEntry::new(
            self.path.clone(),
            self.mode,
            digest_bytes(&self.bytes),
            self.bytes.len() as u64,
        )
    }
}

/// Explicit unresolved material, retained as evidence rather than fetched implicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ExternalSource {
    /// An LFS pointer names content that is absent from this snapshot.
    Lfs {
        /// Source path containing the pointer.
        path: SourcePath,
        /// Claimed external content identity; not validated content evidence.
        expected_sha256: Sha256Digest,
        /// Claimed external content size.
        expected_size: u64,
    },
    /// A Gitlink references a commit outside the selected tree's blob closure.
    Submodule {
        /// Gitlink source path.
        path: SourcePath,
        /// Referenced submodule commit; source is unresolved.
        commit: GitObjectId,
    },
}

fn external_source(file: &SourceFile) -> Result<Option<ExternalSource>, SourceError> {
    if file.mode == SourceMode::Submodule {
        let oid = std::str::from_utf8(file.bytes()).map_err(|_| SourceError::MalformedGitObject)?;
        return Ok(Some(ExternalSource::Submodule {
            path: file.path.clone(),
            commit: GitObjectId::parse(oid).map_err(|_| SourceError::MalformedGitObject)?,
        }));
    }

    if !matches!(file.mode, SourceMode::File | SourceMode::Executable)
        || !file
            .bytes
            .starts_with(b"version https://git-lfs.github.com/spec/")
    {
        return Ok(None);
    }

    // Recognizable but noncanonical pointers fail closed instead of appearing complete.
    let text = std::str::from_utf8(&file.bytes).map_err(|_| SourceError::InvalidLfsPointer)?;

    if text.contains('\r') || !text.ends_with('\n') {
        return Err(SourceError::InvalidLfsPointer);
    }

    let lines: Vec<_> = text.lines().collect();

    if lines.len() != 3 || lines[0] != "version https://git-lfs.github.com/spec/v1" {
        return Err(SourceError::InvalidLfsPointer);
    }

    let oid = lines[1]
        .strip_prefix("oid sha256:")
        .ok_or(SourceError::InvalidLfsPointer)?;
    let size = lines[2]
        .strip_prefix("size ")
        .ok_or(SourceError::InvalidLfsPointer)?;

    if oid.len() != 64
        || !oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || size.is_empty()
        || (size.len() > 1 && size.starts_with('0'))
        || !size.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SourceError::InvalidLfsPointer);
    }

    Ok(Some(ExternalSource::Lfs {
        path: file.path.clone(),
        expected_sha256: Sha256Digest::parse(oid).map_err(|_| SourceError::InvalidLfsPointer)?,
        expected_size: size.parse().map_err(|_| SourceError::InvalidLfsPointer)?,
    }))
}

/// Completeness of an accepted immutable snapshot, separate from certification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceStatus {
    /// All selected source bytes are present within the supported source model.
    Complete,
    /// Pointer or gitlink bytes are retained, but required external content is absent.
    IncompleteExternalSource,
}

/// Metadata for the trusted snapshot/artifact constructor. Source identity is
/// computed from owned bytes and its versioned binding, never accepted from JSON.
pub struct SnapshotMetadata {
    /// Authority project.
    pub project: ProjectId,
    /// Authority repository.
    pub repository: RepositoryId,
    /// Exact original Git commit.
    pub commit: GitObjectId,
    /// Exact original Git root tree.
    pub tree: GitObjectId,
    /// Validated top-level Git object visits.
    pub object_count: u64,
    /// Authority audit time, excluded from identity.
    pub created_at: u64,
}

/// Immutable source snapshot; cannot be deserialized from claimed evidence.
#[derive(Debug)]
pub struct SourceSnapshot {
    project: ProjectId,
    repository: RepositoryId,
    identity: SourceIdentity,
    manifest: SourceManifest,
    binding: SourceBinding,
    files: Vec<SourceFile>,
    external: Vec<ExternalSource>,
    created_at: u64,
    object_count: u64,
}

impl SourceSnapshot {
    /// Seals owned source bytes and derives identity and completeness independently.
    /// `created_at` is authority UTC Unix seconds; it never enters the source digest.
    pub fn seal(
        project: ProjectId,
        repository: RepositoryId,
        commit: GitObjectId,
        tree: GitObjectId,
        files: Vec<SourceFile>,
        object_count: u64,
        created_at: u64,
    ) -> Result<Self, SourceError> {
        Self::seal_bound(
            SnapshotMetadata {
                project,
                repository,
                commit,
                tree,
                object_count,
                created_at,
            },
            files,
            SourceBinding::default(),
        )
    }

    /// Trusted adapter/artifact constructor. Restoring a binding is not source
    /// authentication: the caller must use an authority-owned accepted store.
    pub fn seal_bound(
        metadata: SnapshotMetadata,
        mut files: Vec<SourceFile>,
        binding: SourceBinding,
    ) -> Result<Self, SourceError> {
        let SnapshotMetadata {
            project,
            repository,
            commit,
            tree,
            object_count,
            created_at,
        } = metadata;

        if commit.as_str().len() != tree.as_str().len()
            || binding
                .original()
                .is_some_and(|o| o.commit != commit || o.tree != tree)
        {
            return Err(SourceError::MalformedGitObject);
        }

        files.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = SourceManifest::new(files.iter().map(SourceFile::manifest_entry).collect())?;
        let external = Self::external_for(&files, &binding)?;
        let identity = SourceIdentity {
            commit,
            tree,
            snapshot_sha256: binding.digest(&manifest)?,
        };

        Ok(Self {
            project,
            repository,
            identity,
            manifest,
            binding,
            files,
            external,
            created_at,
            object_count,
        })
    }

    /// Seals a newly complete representation after independently checking original
    /// dependency claims, unchanged files and all resolved content identities.
    pub fn seal_resolved(
        original: &Self,
        files: Vec<SourceFile>,
        dependencies: Vec<ResolvedDependency>,
        created_at: u64,
    ) -> Result<Self, SourceError> {
        let binding = SourceBinding::resolved(original, dependencies, &files)?;
        let mut metadata = original.metadata();
        metadata.created_at = created_at;
        Self::seal_bound(metadata, files, binding)
    }

    fn external_for(
        files: &[SourceFile],
        binding: &SourceBinding,
    ) -> Result<Vec<ExternalSource>, SourceError> {
        let external = files
            .iter()
            .filter(|f| !binding.covers(f.path()))
            .filter_map(|f| external_source(f).transpose())
            .collect::<Result<Vec<_>, _>>()?;

        if binding.schema_version() == 2 && !external.is_empty() {
            return Err(SourceError::IncompleteExternalSource);
        }

        Ok(external)
    }

    /// Credential-free immutable manifest identity recipe.
    pub fn binding(&self) -> &SourceBinding {
        &self.binding
    }

    /// Owned audit/Git metadata for trusted artifact restoration.
    pub fn metadata(&self) -> SnapshotMetadata {
        SnapshotMetadata {
            project: self.project,
            repository: self.repository.clone(),
            commit: self.identity.commit.clone(),
            tree: self.identity.tree.clone(),
            object_count: self.object_count,
            created_at: self.created_at,
        }
    }

    /// Rehashes retained bytes, validating both content metadata and the expected identity.
    /// Call at the source-store/materializer boundary; stored reports are insufficient.
    pub fn verify(&self, expected: &Sha256Digest) -> Result<(), SourceError> {
        let manifest =
            SourceManifest::new(self.files.iter().map(SourceFile::manifest_entry).collect())?;
        let external = Self::external_for(&self.files, &self.binding)?;

        if manifest != self.manifest
            || self.binding.digest(&manifest)? != *expected
            || self.identity.snapshot_sha256 != *expected
            || external != self.external
        {
            return Err(SourceError::SnapshotDigestMismatch);
        }

        Ok(())
    }

    /// Requires complete retained source before any future runner handoff.
    pub fn require_complete(&self) -> Result<(), SourceError> {
        if self.external.is_empty() {
            Ok(())
        } else {
            Err(SourceError::IncompleteExternalSource)
        }
    }

    /// Authority project identity.
    pub fn project(&self) -> ProjectId {
        self.project
    }

    /// Authority repository identity.
    pub fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    /// Preserved Git identity plus independent ArchCert identity.
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    /// Canonical manifest.
    pub fn manifest(&self) -> &SourceManifest {
        &self.manifest
    }

    /// Retained bytes, never borrowed from the developer's repository.
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    /// Explicit unresolved source dependencies.
    pub fn external(&self) -> &[ExternalSource] {
        &self.external
    }

    /// Authority creation time in UTC Unix seconds.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Snapshot schema version.
    pub fn schema_version(&self) -> u32 {
        self.binding.schema_version()
    }

    /// Number of Git object visits validated during ingestion.
    pub fn object_count(&self) -> u64 {
        self.object_count
    }

    /// Total retained payload bytes, including symlink targets and gitlink OID text.
    pub fn total_bytes(&self) -> u64 {
        self.manifest.entries.iter().map(|e| e.size).sum()
    }

    /// Immutable source completeness.
    pub fn status(&self) -> SourceStatus {
        if self.external.is_empty() {
            SourceStatus::Complete
        } else {
            SourceStatus::IncompleteExternalSource
        }
    }
}
