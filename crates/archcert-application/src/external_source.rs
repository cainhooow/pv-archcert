//! Controlled external-source resolution. Authority maps identities; candidate
//! URLs, .gitmodules and credentials never enter this port or execution inputs.
use archcert_domain::{
    Sha256Digest,
    materialization::SnapshotReference,
    source::{
        ExternalSource, ResolvedDependency, SourceError, SourceFile, SourceLimits, SourceManifest,
        SourceMode, SourcePath, SourceSnapshot, digest_bytes,
    },
};
use std::{io::Read, sync::Arc};

/// Authority-provisioned source acquisition only. Implementations hold ingress
/// credentials privately and return bounded readers/accepted immutable snapshots.
/// There is no URL argument and no fallback to candidate .gitmodules locations.
pub trait ExternalSourceAuthority {
    /// Retrieves an LFS object by declared digest through authority-selected storage.
    fn lfs_object(
        &self,
        parent: &SourceSnapshot,
        path: &SourcePath,
        digest: &Sha256Digest,
    ) -> Result<Box<dyn Read + '_>, SourceError>;
    /// Maps a top-level repository/path/gitlink to an exact allowed repository snapshot.
    /// Missing mappings deny acquisition, including all arbitrary candidate URLs.
    fn submodule(
        &self,
        parent: &SourceSnapshot,
        path: &SourcePath,
    ) -> Result<(SnapshotReference, Arc<SourceSnapshot>), SourceError>;
}

/// New immutable schema-2 resolved representation. The original schema-1 snapshot
/// remains unchanged. Its independently verifiable binding follows the new
/// snapshot through credential-free materialization and execution.
pub struct ResolvedSourceRepresentation {
    original: Arc<SourceSnapshot>,
    snapshot: SourceSnapshot,
    canonical: Vec<u8>,
}
impl ResolvedSourceRepresentation {
    /// Original accepted pointer/gitlink representation and immutable Git provenance.
    pub fn original(&self) -> &SourceSnapshot {
        &self.original
    }
    /// Exact resolved source bytes; never acquisition credentials.
    pub fn files(&self) -> &[SourceFile] {
        self.snapshot.files()
    }
    /// Canonical resolved content manifest.
    pub fn manifest(&self) -> &SourceManifest {
        self.snapshot.manifest()
    }
    /// Independently hashed schema-2 identity, separate from original schema 1.
    pub fn digest(&self) -> &Sha256Digest {
        &self.snapshot.identity().snapshot_sha256
    }
    /// Verified complete immutable snapshot, ready for separate source acceptance.
    pub fn snapshot(&self) -> &SourceSnapshot {
        &self.snapshot
    }
    /// Transfers the new snapshot without any acquisition authority.
    pub fn into_snapshot(self) -> SourceSnapshot {
        self.snapshot
    }
    /// Versioned binary provenance/manifest preimage; no audit time participates.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
/// Verifies controlled external acquisitions and constructs a new representation.
/// Resolution is one level; nested incomplete submodules reject. No mutable
/// snapshot, URL discovery, network credential, policy or execution handle escapes.
pub fn resolve_external_source(
    original: Arc<SourceSnapshot>,
    authority: &dyn ExternalSourceAuthority,
    limits: SourceLimits,
) -> Result<ResolvedSourceRepresentation, SourceError> {
    original.verify(&original.identity().snapshot_sha256)?;
    check_files(original.files(), limits)?;
    let mut files = original.files().to_vec();
    let mut bindings = Vec::new();
    for external in original.external() {
        match external {
            ExternalSource::Lfs {
                path,
                expected_sha256,
                expected_size,
            } => {
                if *expected_size > limits.max_blob_bytes || *expected_size > limits.max_total_bytes
                {
                    return Err(SourceError::IncompleteExternalSource);
                }
                let existing = files
                    .iter()
                    .find(|f| f.path() == path)
                    .ok_or(SourceError::InternalIntegrityFailure)?;
                let retained: u64 = files.iter().map(|f| f.bytes().len() as u64).sum();
                if retained
                    .saturating_sub(existing.bytes().len() as u64)
                    .saturating_add(*expected_size)
                    > limits.max_total_bytes
                {
                    return Err(SourceError::IncompleteExternalSource);
                }
                let mut reader = authority.lfs_object(&original, path, expected_sha256)?;
                let mut bytes = Vec::new();
                reader
                    .by_ref()
                    .take(expected_size.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|_| SourceError::IncompleteExternalSource)?;
                if bytes.len() as u64 != *expected_size || digest_bytes(&bytes) != *expected_sha256
                {
                    return Err(SourceError::SnapshotDigestMismatch);
                }
                let index = files
                    .iter()
                    .position(|f| f.path() == path)
                    .ok_or(SourceError::InternalIntegrityFailure)?;
                let mode = files[index].mode();
                files[index] = SourceFile::new(path.clone(), mode, bytes);
                bindings.push(ResolvedDependency::Lfs {
                    path: path.clone(),
                    sha256: expected_sha256.clone(),
                    size: *expected_size,
                });
            }
            ExternalSource::Submodule { path, commit } => {
                let (reference, snapshot) = authority.submodule(&original, path)?;
                if &reference.identity.commit != commit
                    || snapshot.project() != reference.project
                    || snapshot.repository() != &reference.repository
                    || snapshot.identity() != &reference.identity
                {
                    return Err(SourceError::SnapshotDigestMismatch);
                }
                snapshot.verify(&reference.identity.snapshot_sha256)?;
                snapshot.require_complete()?;
                check_files(snapshot.files(), limits)?;
                let retained_bytes: u64 = files
                    .iter()
                    .filter(|f| f.path() != path)
                    .map(|f| f.bytes().len() as u64)
                    .sum();
                if retained_bytes.saturating_add(snapshot.total_bytes()) > limits.max_total_bytes
                    || (files.len() as u64)
                        .saturating_sub(1)
                        .saturating_add(snapshot.files().len() as u64)
                        > limits.max_files
                {
                    return Err(SourceError::IncompleteExternalSource);
                }
                files.retain(|f| f.path() != path);
                for file in snapshot.files() {
                    if file.mode() == SourceMode::Submodule {
                        return Err(SourceError::IncompleteExternalSource);
                    }
                    files.push(SourceFile::new(
                        SourcePath::from_bytes(
                            format!("{}/{}", path.as_str(), file.path().as_str()).as_bytes(),
                        )?,
                        file.mode(),
                        file.bytes().to_vec(),
                    ));
                }
                bindings.push(ResolvedDependency::Submodule {
                    path: path.clone(),
                    project: reference.project,
                    repository: reference.repository,
                    identity: reference.identity,
                    binding: Box::new(snapshot.binding().clone()),
                });
            }
        }
        // Bound partial expansion before acquiring the next dependency.
        check_files(&files, limits)?;
    }
    check_files(&files, limits)?;
    files.sort_by(|a, b| a.path().cmp(b.path()));
    let snapshot =
        SourceSnapshot::seal_resolved(&original, files, bindings, original.created_at())?;
    snapshot.require_complete()?;
    let canonical = snapshot.binding().canonical_bytes(snapshot.manifest())?;
    Ok(ResolvedSourceRepresentation {
        original,
        snapshot,
        canonical,
    })
}
fn check_files(files: &[SourceFile], limits: SourceLimits) -> Result<(), SourceError> {
    let mut total = 0u64;
    if files.len() as u64 > limits.max_files {
        return Err(SourceError::IncompleteExternalSource);
    }
    for file in files {
        total = total
            .checked_add(file.bytes().len() as u64)
            .ok_or(SourceError::IncompleteExternalSource)?;
        if total > limits.max_total_bytes
            || file.bytes().len() as u64 > limits.max_blob_bytes
            || file.path().as_str().split('/').count() > limits.max_tree_depth as usize + 1
        {
            return Err(SourceError::IncompleteExternalSource);
        }
    }
    Ok(())
}
