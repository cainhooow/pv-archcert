//! Versioned, credential-free source identity after controlled external resolution.

use super::*;

/// Verified external identity bound into a resolved source. This is metadata, not
/// acquisition authority; deserialization alone never constructs a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResolvedDependency {
    /// Exact acquired LFS bytes replace one original pointer.
    Lfs {
        /// Original pointer path.
        path: SourcePath,
        /// Independently verified content digest.
        sha256: Sha256Digest,
        /// Exact verified byte size.
        size: u64,
    },
    /// Complete child source expands one original gitlink, under its exact path.
    Submodule {
        /// Original gitlink path.
        path: SourcePath,
        /// Authority child project.
        project: ProjectId,
        /// Authority child repository, never a URL.
        repository: RepositoryId,
        /// Exact verified child Git and ArchCert identities.
        identity: SourceIdentity,
        /// Credential-free identity recipe for verifying the child manifest.
        binding: Box<SourceBinding>,
    },
}

impl ResolvedDependency {
    /// Original external source path.
    pub fn path(&self) -> &SourcePath {
        match self {
            Self::Lfs { path, .. } | Self::Submodule { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "schema",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
enum Binding {
    ManifestV1,
    ResolvedV2 {
        original: SourceIdentity,
        dependencies: Vec<ResolvedDependency>,
    },
}

/// Immutable identity recipe containing only original/dependency identities.
/// Verifiers combine this with an independently reconstructed content manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceBinding(Binding);

impl Default for SourceBinding {
    fn default() -> Self {
        Self(Binding::ManifestV1)
    }
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

struct Budget {
    entries: u64,
    bindings: u64,
    bytes: u64,
}

impl SourceBinding {
    /// Source canonicalization version. Schema 1 remains byte-for-byte unchanged.
    pub fn schema_version(&self) -> u32 {
        match self.0 {
            Binding::ManifestV1 => 1,
            Binding::ResolvedV2 { .. } => 2,
        }
    }

    /// Original pointer/gitlink source, absent for ordinary schema-1 source.
    pub fn original(&self) -> Option<&SourceIdentity> {
        match &self.0 {
            Binding::ManifestV1 => None,
            Binding::ResolvedV2 { original, .. } => Some(original),
        }
    }

    /// Verified external dependency metadata, never credentials or acquisition locators.
    pub fn dependencies(&self) -> &[ResolvedDependency] {
        match &self.0 {
            Binding::ManifestV1 => &[],
            Binding::ResolvedV2 { dependencies, .. } => dependencies,
        }
    }

    pub(super) fn resolved(
        original: &SourceSnapshot,
        mut dependencies: Vec<ResolvedDependency>,
        files: &[SourceFile],
    ) -> Result<Self, SourceError> {
        original.verify(&original.identity().snapshot_sha256)?;

        if original.external().is_empty() || dependencies.len() != original.external().len() {
            return Err(SourceError::IncompleteExternalSource);
        }

        dependencies.sort_by(|a, b| a.path().cmp(b.path()));

        for (external, dependency) in original.external().iter().zip(&dependencies) {
            let matches = match (external, dependency) {
                (
                    ExternalSource::Lfs {
                        path,
                        expected_sha256,
                        expected_size,
                    },
                    ResolvedDependency::Lfs {
                        path: p,
                        sha256,
                        size,
                    },
                ) => path == p && expected_sha256 == sha256 && expected_size == size,
                (
                    ExternalSource::Submodule { path, commit },
                    ResolvedDependency::Submodule {
                        path: p, identity, ..
                    },
                ) => path == p && commit == &identity.commit,
                _ => false,
            };

            if !matches {
                return Err(SourceError::SnapshotDigestMismatch);
            }
        }

        let replacement_paths: BTreeMap<_, _> = dependencies
            .iter()
            .map(|d| (d.path().as_str(), d))
            .collect();
        let original_files: BTreeMap<_, _> = original
            .files()
            .iter()
            .map(|f| (f.path().as_str(), f))
            .collect();

        for file in files {
            if file.path().as_str().match_indices('/').any(|(end, _)| {
                matches!(
                    replacement_paths.get(&file.path().as_str()[..end]),
                    Some(ResolvedDependency::Submodule { .. })
                )
            }) {
                continue;
            }

            let previous = original_files
                .get(file.path().as_str())
                .ok_or(SourceError::SnapshotDigestMismatch)?;

            if previous.mode() != file.mode()
                || (!replacement_paths.contains_key(file.path().as_str())
                    && previous.bytes() != file.bytes())
            {
                return Err(SourceError::SnapshotDigestMismatch);
            }
        }

        let final_paths: std::collections::BTreeSet<_> = files.iter().map(|f| f.path()).collect();

        for file in original.files() {
            if !replacement_paths.contains_key(file.path().as_str())
                && !final_paths.contains(file.path())
            {
                return Err(SourceError::SnapshotDigestMismatch);
            }
        }

        let binding = Self(Binding::ResolvedV2 {
            original: original.identity().clone(),
            dependencies,
        });
        binding.digest(&SourceManifest::new(
            files.iter().map(SourceFile::manifest_entry).collect(),
        )?)?;

        Ok(binding)
    }

    /// Reconstructs the canonical source preimage after validating dependency
    /// coverage, child manifests, path collisions and finite recursive work.
    pub fn canonical_bytes(&self, manifest: &SourceManifest) -> Result<Vec<u8>, SourceError> {
        self.digest(manifest)?;

        Ok(self.encode(manifest))
    }

    /// Hashes a freshly reconstructed manifest under the accepted source recipe.
    /// No timestamp, credential, mutable ref, endpoint or policy enters the hash.
    pub fn digest(&self, manifest: &SourceManifest) -> Result<Sha256Digest, SourceError> {
        self.verify_manifest(
            manifest,
            &mut Budget {
                entries: 0,
                bindings: 0,
                bytes: 0,
            },
            0,
        )
    }

    fn verify_manifest(
        &self,
        manifest: &SourceManifest,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<Sha256Digest, SourceError> {
        if depth > 32 {
            return Err(SourceError::LimitExceeded(ResourceLimit::TreeDepth));
        }

        budget.entries = budget
            .entries
            .saturating_add(manifest.entries().len() as u64);
        let bytes = manifest.canonical_bytes();
        budget.bytes = budget.bytes.saturating_add(bytes.len() as u64);

        if budget.entries > 25_000 || budget.bytes > 256 * 1024 * 1024 {
            return Err(SourceError::LimitExceeded(ResourceLimit::ObjectWorkBytes));
        }

        if let Binding::ResolvedV2 {
            original,
            dependencies,
        } = &self.0
        {
            if original.commit.as_str().len() != original.tree.as_str().len()
                || dependencies.is_empty()
            {
                return Err(SourceError::SnapshotDigestMismatch);
            }

            budget.bindings = budget.bindings.saturating_add(dependencies.len() as u64);

            if budget.bindings > 10_000 {
                return Err(SourceError::LimitExceeded(ResourceLimit::Files));
            }

            let mut prior = None;
            let mut names = Vec::new();

            for dependency in dependencies {
                let path = dependency.path();

                if prior.is_some_and(|p: &SourcePath| p >= path) {
                    return Err(SourceError::PathCollision);
                }

                prior = Some(path);
                names.push(ManifestEntry::new(
                    path.clone(),
                    SourceMode::File,
                    digest_bytes(b"binding"),
                    0,
                ));
            }

            SourceManifest::new(names)?;
            let entries: BTreeMap<_, _> = manifest
                .entries()
                .iter()
                .map(|e| (e.path().as_str(), e))
                .collect();

            if manifest
                .entries()
                .iter()
                .any(|e| e.mode() == SourceMode::Submodule)
            {
                return Err(SourceError::IncompleteExternalSource);
            }

            for dependency in dependencies {
                match dependency {
                    ResolvedDependency::Lfs { path, sha256, size } => {
                        let file = entries
                            .get(path.as_str())
                            .ok_or(SourceError::SnapshotDigestMismatch)?;

                        if !matches!(file.mode(), SourceMode::File | SourceMode::Executable)
                            || file.content_sha256() != sha256
                            || file.size() != *size
                        {
                            return Err(SourceError::SnapshotDigestMismatch);
                        }
                    }
                    ResolvedDependency::Submodule {
                        path,
                        identity,
                        binding,
                        ..
                    } => {
                        if entries.contains_key(path.as_str())
                            || identity.commit.as_str().len() != identity.tree.as_str().len()
                        {
                            return Err(SourceError::SnapshotDigestMismatch);
                        }

                        let prefix = format!("{}/", path.as_str());
                        let mut children = Vec::new();

                        for (_, entry) in entries.range(prefix.as_str()..) {
                            let Some(relative) = entry.path().as_str().strip_prefix(&prefix) else {
                                break;
                            };
                            children.push(ManifestEntry::new(
                                SourcePath::from_bytes(relative.as_bytes())?,
                                entry.mode(),
                                entry.content_sha256().clone(),
                                entry.size(),
                            ));
                        }

                        let child = SourceManifest::new(children)?;

                        if child
                            .entries()
                            .iter()
                            .any(|e| e.mode() == SourceMode::Submodule)
                            || binding.verify_manifest(&child, budget, depth + 1)?
                                != identity.snapshot_sha256
                        {
                            return Err(SourceError::SnapshotDigestMismatch);
                        }
                    }
                }
            }
        }

        Ok(digest_bytes(&self.encode(manifest)))
    }

    fn encode(&self, manifest: &SourceManifest) -> Vec<u8> {
        let Binding::ResolvedV2 {
            original,
            dependencies,
        } = &self.0
        else {
            return manifest.canonical_bytes();
        };
        let mut out = b"ARCHCERT-RESOLVED-SOURCE\0\0\0\0\x02".to_vec();
        field(&mut out, original.commit.as_str().as_bytes());
        field(&mut out, original.tree.as_str().as_bytes());
        field(&mut out, original.snapshot_sha256.as_str().as_bytes());
        let mut bindings = Vec::new();

        for dependency in dependencies {
            let mut binding = Vec::new();

            match dependency {
                ResolvedDependency::Lfs { path, sha256, size } => {
                    binding.push(1);
                    field(&mut binding, path.as_str().as_bytes());
                    field(&mut binding, sha256.as_str().as_bytes());
                    binding.extend_from_slice(&size.to_be_bytes());
                }
                ResolvedDependency::Submodule {
                    path,
                    project,
                    repository,
                    identity,
                    ..
                } => {
                    binding.push(2);
                    field(&mut binding, path.as_str().as_bytes());
                    field(&mut binding, project.to_string().as_bytes());
                    field(&mut binding, repository.as_str().as_bytes());
                    field(&mut binding, identity.commit.as_str().as_bytes());
                    field(&mut binding, identity.tree.as_str().as_bytes());
                    field(&mut binding, identity.snapshot_sha256.as_str().as_bytes());
                }
            }

            bindings.push(binding);
        }

        bindings.sort();
        out.extend_from_slice(&(bindings.len() as u64).to_be_bytes());

        for binding in bindings {
            field(&mut out, &binding);
        }

        field(&mut out, &manifest.canonical_bytes());
        out
    }

    pub(super) fn covers(&self, path: &SourcePath) -> bool {
        self.covers_text(path.as_str())
    }

    fn covers_text(&self, path: &str) -> bool {
        let dependencies = self.dependencies();

        if let Ok(index) = dependencies.binary_search_by(|d| d.path().as_str().cmp(path)) {
            return matches!(dependencies[index], ResolvedDependency::Lfs { .. });
        }

        for (end, _) in path.match_indices('/') {
            if let Ok(index) =
                dependencies.binary_search_by(|d| d.path().as_str().cmp(&path[..end]))
                && let ResolvedDependency::Submodule { binding, .. } = &dependencies[index]
            {
                // Expanding a child is not proof that every pointer inside it was
                // resolved. Only that child's own verified LFS binding covers bytes.
                return binding.covers_text(&path[end + 1..]);
            }
        }

        false
    }
}
