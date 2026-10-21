//! Bounded development snapshot artifact, distinct from diagnostic JSON.

use archcert_domain::{
    ProjectId, SourceIdentity,
    source::{
        RepositoryId, SnapshotMetadata, SourceBinding, SourceError, SourceFile, SourceLimits,
        SourceMode, SourcePath, SourceSnapshot,
    },
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    project: ProjectId,
    repository: RepositoryId,
    identity: SourceIdentity,
    object_count: u64,
    created_at: u64,
    #[serde(default)]
    binding: SourceBinding,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: SourcePath,
    mode: u32,
    size: u64,
}

fn bad<E>(_: E) -> SourceError {
    SourceError::SnapshotDigestMismatch
}

const MAGIC: &[u8; 16] = b"ARCHCERT-DEV-S1\0";

/// Writes verified immutable bytes. This is a development storage codec, not a
/// signed artifact or a substitute for an authority-owned source store.
pub fn write_snapshot(snapshot: &SourceSnapshot, mut out: impl Write) -> Result<(), SourceError> {
    snapshot.verify(&snapshot.identity().snapshot_sha256)?;

    let metadata = Metadata {
        project: snapshot.project(),
        repository: snapshot.repository().clone(),
        identity: snapshot.identity().clone(),
        object_count: snapshot.object_count(),
        created_at: snapshot.created_at(),
        binding: snapshot.binding().clone(),
        entries: snapshot
            .files()
            .iter()
            .map(|f| Entry {
                path: f.path().clone(),
                mode: f.mode().git_mode(),
                size: f.bytes().len() as u64,
            })
            .collect(),
    };
    let header = serde_json::to_vec(&metadata).map_err(bad)?;

    if header.len() > 8 * 1024 * 1024 {
        return Err(SourceError::UnsupportedRepository);
    }

    out.write_all(MAGIC).map_err(bad)?;
    out.write_all(&(header.len() as u64).to_be_bytes())
        .map_err(bad)?;
    out.write_all(&header).map_err(bad)?;

    for file in snapshot.files() {
        out.write_all(file.bytes()).map_err(bad)?;
    }

    Ok(())
}

/// Reconstructs and independently rehashes retained bytes under finite budgets.
/// Callers must obtain the stream from an authority-controlled storage location.
pub fn read_snapshot(
    mut input: impl Read,
    limits: SourceLimits,
) -> Result<SourceSnapshot, SourceError> {
    let mut magic = [0; 16];
    input.read_exact(&mut magic).map_err(bad)?;

    if &magic != MAGIC {
        return Err(SourceError::SnapshotDigestMismatch);
    }

    let mut size = [0; 8];
    input.read_exact(&mut size).map_err(bad)?;
    let size = u64::from_be_bytes(size);

    if size > 8 * 1024 * 1024 {
        return Err(SourceError::SnapshotDigestMismatch);
    }

    let mut header = vec![0; size as usize];
    input.read_exact(&mut header).map_err(bad)?;
    let metadata: Metadata = serde_json::from_slice(&header).map_err(bad)?;

    if metadata.entries.len() as u64 > limits.max_files
        || metadata.object_count > limits.max_objects
    {
        return Err(SourceError::SnapshotDigestMismatch);
    }

    let mut total = 0u64;
    let mut files = Vec::new();

    for entry in metadata.entries {
        total = total
            .checked_add(entry.size)
            .ok_or(SourceError::SnapshotDigestMismatch)?;

        if total > limits.max_total_bytes
            || entry.size > limits.max_blob_bytes
            || entry.path.as_str().split('/').count() > limits.max_tree_depth as usize + 1
        {
            return Err(SourceError::SnapshotDigestMismatch);
        }

        let mut bytes = vec![0; entry.size as usize];
        input.read_exact(&mut bytes).map_err(bad)?;
        files.push(SourceFile::new(
            entry.path,
            match entry.mode {
                0o100644 => SourceMode::File,
                0o100755 => SourceMode::Executable,
                0o120000 => SourceMode::Symlink,
                0o160000 => SourceMode::Submodule,
                _ => return Err(SourceError::UnsupportedGitEntry),
            },
            bytes,
        ));
    }

    if input.read(&mut [0]).map_err(bad)? != 0 {
        return Err(SourceError::SnapshotDigestMismatch);
    }

    let snapshot = SourceSnapshot::seal_bound(
        SnapshotMetadata {
            project: metadata.project,
            repository: metadata.repository,
            commit: metadata.identity.commit.clone(),
            tree: metadata.identity.tree.clone(),
            object_count: metadata.object_count,
            created_at: metadata.created_at,
        },
        files,
        metadata.binding,
    )?;

    snapshot.verify(&metadata.identity.snapshot_sha256)?;

    Ok(snapshot)
}
