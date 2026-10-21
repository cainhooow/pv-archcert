//! Authority-provisioned external content. No candidate-selected network transport.

use crate::{
    DevelopmentSubmissionStore, IngressError, IngressEvent, IngressEvidence, StoredSubmission, now,
    rejected, store, unavailable,
};
use archcert_application::external_source::{ExternalSourceAuthority, resolve_external_source};
use archcert_domain::{
    ProjectId, Sha256Digest, SourceIdentity,
    ingress::{GitActorId, SourceSubmissionId},
    materialization::SnapshotReference,
    source::{
        RepositoryId, ResolvedDependency, SourceError, SourceLimits, SourcePath, SourceSnapshot,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Exact authority scope and immutable identity; display names never authorize.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionReference {
    /// Authority project.
    pub project: ProjectId,
    /// Authority repository.
    pub repository: RepositoryId,
    /// Expected immutable commit, tree and independent source identity.
    pub identity: SourceIdentity,
}

impl ResolutionReference {
    fn matches(&self, snapshot: &SourceSnapshot) -> bool {
        self.project == snapshot.project()
            && &self.repository == snapshot.repository()
            && &self.identity == snapshot.identity()
    }
}

/// One explicit path/content grant in a private authority LFS object directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LfsGrant {
    /// Original source path.
    pub path: SourcePath,
    /// Expected content digest; also the literal object filename.
    pub sha256: Sha256Digest,
    /// Expected byte length.
    pub size: u64,
}

/// One exact accepted child submission, not a mutable origin or branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmoduleGrant {
    /// Original gitlink path.
    pub path: SourcePath,
    /// Child submission acquired through authenticated ingress.
    pub submission: SourceSubmissionId,
    /// Explicitly permitted scoped immutable child source.
    pub source: ResolutionReference,
}

/// Private operator capability. Filesystem ownership authenticates its invocation;
/// it is never accepted by the SSH forced-command receive interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfiguration {
    /// Private bounded development store containing parent and child submissions.
    pub store: PathBuf,
    /// Authority attribution, configured outside candidate source.
    pub resolver_actor: GitActorId,
    /// Single permitted parent; configuration cannot resolve arbitrary submissions.
    pub parent_submission: SourceSubmissionId,
    /// Exact permitted original scope and immutable identity.
    pub parent: ResolutionReference,
    /// Private authority-provisioned digest-addressed LFS directory, if needed.
    pub lfs_root: Option<PathBuf>,
    /// Explicit per-path LFS grants; no candidate origin lookup.
    pub lfs: Vec<LfsGrant>,
    /// Explicit per-path scoped child grants; no .gitmodules lookup.
    pub submodules: Vec<SubmoduleGrant>,
}

/// Derivation audit data; operational attribution does not affect source identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionEvidence {
    /// Original immutable submission remains retained unchanged.
    pub parent_submission: SourceSubmissionId,
    /// Original source scope and identity.
    pub parent: ResolutionReference,
    /// Authority operator attribution, distinct from the source submitter.
    pub resolver_actor: GitActorId,
    /// Verified LFS replacements.
    pub lfs_resolved: u64,
    /// Verified complete child source expansions.
    pub submodules_resolved: u64,
}

/// Reads bounded, owner-only configuration without following links or ambient Git config.
pub fn read_resolution_configuration(path: &Path) -> Result<ResolutionConfiguration, IngressError> {
    let bytes = store::read_private_configuration(path)?;
    let config: ResolutionConfiguration = serde_json::from_slice(&bytes).map_err(unavailable)?;
    config.validate()?;

    Ok(config)
}

impl ResolutionConfiguration {
    fn validate(&self) -> Result<(), IngressError> {
        if !self.store.is_absolute()
            || self.lfs_root.as_ref().is_some_and(|p| !p.is_absolute())
            || self.lfs.len().saturating_add(self.submodules.len()) > 10_000
        {
            return Err(IngressError::Unavailable);
        }

        let mut paths = std::collections::BTreeSet::new();

        for grant in &self.lfs {
            if !paths.insert(&grant.path)
                || grant.size > SourceLimits::default().max_blob_bytes
                || self.lfs_root.is_none()
            {
                return Err(IngressError::Unavailable);
            }
        }

        for grant in &self.submodules {
            if !paths.insert(&grant.path) {
                return Err(IngressError::Unavailable);
            }
        }

        Ok(())
    }
}

struct Authority<'a> {
    config: &'a ResolutionConfiguration,
    store: &'a DevelopmentSubmissionStore,
}

impl ExternalSourceAuthority for Authority<'_> {
    fn lfs_object(
        &self,
        parent: &SourceSnapshot,
        path: &SourcePath,
        digest: &Sha256Digest,
    ) -> Result<Box<dyn Read + '_>, SourceError> {
        if !self.config.parent.matches(parent) {
            return Err(SourceError::IncompleteExternalSource);
        }

        let grant = self
            .config
            .lfs
            .iter()
            .find(|g| &g.path == path && &g.sha256 == digest)
            .ok_or(SourceError::IncompleteExternalSource)?;
        let root = store::private_root(
            self.config
                .lfs_root
                .as_deref()
                .ok_or(SourceError::IncompleteExternalSource)?,
        )
        .map_err(|_| SourceError::IncompleteExternalSource)?;
        let file = store::regular(&root, digest.as_str(), rustix::fs::OFlags::RDONLY)
            .map_err(|_| SourceError::IncompleteExternalSource)?;

        if file
            .metadata()
            .map_err(|_| SourceError::IncompleteExternalSource)?
            .len()
            != grant.size
        {
            return Err(SourceError::SnapshotDigestMismatch);
        }

        Ok(Box::new(file.take(grant.size.saturating_add(1))))
    }

    fn submodule(
        &self,
        parent: &SourceSnapshot,
        path: &SourcePath,
    ) -> Result<(SnapshotReference, Arc<SourceSnapshot>), SourceError> {
        if !self.config.parent.matches(parent) {
            return Err(SourceError::IncompleteExternalSource);
        }

        let grant = self
            .config
            .submodules
            .iter()
            .find(|g| &g.path == path)
            .ok_or(SourceError::IncompleteExternalSource)?;
        let child = self
            .store
            .load(&grant.submission)
            .map_err(|_| SourceError::IncompleteExternalSource)?;

        if !grant.source.matches(&child.snapshot) {
            return Err(SourceError::SnapshotDigestMismatch);
        }

        Ok((
            SnapshotReference {
                project: grant.source.project,
                repository: grant.source.repository.clone(),
                identity: grant.source.identity.clone(),
            },
            Arc::new(child.snapshot),
        ))
    }
}

/// Resolves one incomplete submission into a NEW complete immutable submission.
/// The parent is unchanged, source-only publication creates no execution request,
/// and all acquisition capabilities are dropped before this function returns.
pub fn resolve_submission(
    config: &ResolutionConfiguration,
    id: &SourceSubmissionId,
) -> Result<IngressEvidence, IngressError> {
    config.validate()?;

    if id != &config.parent_submission {
        return Err(IngressError::Authorization);
    }

    let mut store = DevelopmentSubmissionStore::open(&config.store, 32)?;
    let _reservation = store.quarantine()?;
    let StoredSubmission {
        snapshot: parent,
        mut evidence,
    } = store.load(id)?;

    if !config.parent.matches(&parent)
        || parent.require_complete().is_ok()
        || config.lfs.len() + config.submodules.len() != parent.external().len()
    {
        return Err(IngressError::Rejected);
    }

    let received_at = now()?;
    evidence.submission = SourceSubmissionId::new();
    evidence.transport = "AUTHORITY_PRIVATE_SOURCE_RESOLUTION".into();
    evidence.received_at = received_at;
    evidence.accepted_at = None;
    evidence.status = "VALIDATING".into();
    evidence.candidate = format!(
        "refs/archcert/candidates/{}/{}",
        evidence.project, evidence.submission
    );
    evidence.events = vec![IngressEvent::ExternalSourceResolutionStarted];
    evidence.resolution = Some(ResolutionEvidence {
        parent_submission: id.clone(),
        parent: config.parent.clone(),
        resolver_actor: config.resolver_actor.clone(),
        lfs_resolved: 0,
        submodules_resolved: 0,
    });

    let result = (|| {
        let source = resolve_external_source(
            Arc::new(parent),
            &Authority {
                config,
                store: &store,
            },
            SourceLimits::default(),
        )
        .map_err(rejected)?
        .into_snapshot();
        let mut metadata = source.metadata();
        metadata.created_at = now()?;
        let source =
            SourceSnapshot::seal_bound(metadata, source.files().to_vec(), source.binding().clone())
                .map_err(rejected)?;
        evidence.source = Some(source.identity().clone());
        evidence.completeness = Some(source.status());
        evidence.external_sources = Vec::new();
        evidence.lfs_unresolved = 0;
        evidence.submodules_unresolved = 0;
        evidence.source_schema = source.schema_version();
        let resolution = evidence
            .resolution
            .as_mut()
            .ok_or(IngressError::Unavailable)?;
        resolution.lfs_resolved = source
            .binding()
            .dependencies()
            .iter()
            .filter(|d| matches!(d, ResolvedDependency::Lfs { .. }))
            .count() as u64;
        resolution.submodules_resolved =
            source.binding().dependencies().len() as u64 - resolution.lfs_resolved;
        evidence.events.extend([
            IngressEvent::ExternalSourceResolved,
            IngressEvent::SourceSnapshotAccepted,
        ]);
        evidence.status = "ACCEPTED".into();
        evidence.accepted_at = Some(now()?);

        store.accept(&source, &evidence)?;

        Ok(())
    })();

    if result.is_err() {
        evidence.source = None;
        evidence.completeness = None;
        evidence.accepted_at = None;
        evidence.status = "REJECTED".into();
        evidence
            .events
            .retain(|e| !matches!(e, IngressEvent::SourceSnapshotAccepted));
        evidence.events.push(IngressEvent::GitSubmissionRejected);
        store.reject(&evidence)?;
    }

    result.map(|()| evidence)
}
