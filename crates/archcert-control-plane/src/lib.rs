//! Trusted admission/read composition. No execution or signing capability.

mod ironcrest;

use archcert_application::{jobs::*, worker::resolve_authority_plan};
use archcert_domain::{
    ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::*,
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};
use archcert_storage::{PostgresJobRepository, artifacts::FilesystemArtifactStore};
pub use ironcrest::PreparedIroncrestReview;

use serde::Deserialize;
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Operator configuration. No candidate-controlled path or authorization fallback.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfiguration {
    /// Existing private Northgate source root.
    pub source_store: PathBuf,
    /// Existing private development bulk artifact root.
    pub artifact_root: PathBuf,
    /// Explicit development principals and scope/authority mappings.
    pub grants: Vec<AuthorityGrant>,
}

/// Development authority provisioned outside source and target workspaces.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    /// Exact allowed project.
    pub project: ProjectId,
    /// Exact allowed repository.
    pub repository: RepositoryId,
    /// Authenticated authority actor.
    pub actor: GitActorId,
    /// SHA-256 of a high-entropy external bearer token, never its plaintext.
    pub token_sha256: archcert_domain::Sha256Digest,
    /// Fixed execution profile.
    pub profile: String,
    /// Pinned repository@sha256 image.
    pub image: String,
    /// Authority-owned mandatory command recipe, never loaded from target source.
    pub authority_toml: String,
    /// Maximum total attempts, authority-bounded to 1–3.
    pub maximum_attempts: u16,
    /// Explicit new-profile opt-in. Target requests cannot override this selection.
    #[serde(default)]
    pub ironcrest: bool,
    /// Authority-only lower request bound for Rust; exact policy/profile digest changes.
    #[serde(default)]
    pub semantic_request_bytes: Option<usize>,
    /// Authority-only accepted baseline. None explicitly requires full review.
    #[serde(default)]
    pub ironcrest_baseline: Option<SourceSubmissionId>,
}

/// Reads an existing private owned regular authority file without symlink following.
pub fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>, JobStoreError> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| JobStoreError::Invalid)? != path {
        return Err(JobStoreError::Invalid);
    }

    let parent = path.parent().ok_or(JobStoreError::Invalid)?;
    let p = std::fs::metadata(parent).map_err(|_| JobStoreError::Invalid)?;

    if p.uid() != rustix::process::geteuid().as_raw() || p.mode() & 0o077 != 0 {
        return Err(JobStoreError::Invalid);
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| JobStoreError::Invalid)?;
    let m = file.metadata().map_err(|_| JobStoreError::Invalid)?;

    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.len() > maximum
    {
        return Err(JobStoreError::Invalid);
    }

    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JobStoreError::Unavailable)?;

    if bytes.len() as u64 > maximum {
        return Err(JobStoreError::Invalid);
    }

    Ok(bytes)
}

impl ControlPlaneConfiguration {
    /// Loads strict bounded private operator JSON. Does not migrate or grant database rights.
    pub fn load(path: &Path) -> Result<Self, JobStoreError> {
        let config: Self = serde_json::from_slice(&read_private(path, 1024 * 1024)?)
            .map_err(|_| JobStoreError::Invalid)?;

        if config.grants.is_empty() || config.grants.len() > 128 {
            return Err(JobStoreError::Invalid);
        }

        for (index, g) in config.grants.iter().enumerate() {
            resolve_authority_plan(&g.profile, &g.image, &g.authority_toml)?;

            if (g.ironcrest && !["python", "rust-workspace-v1"].contains(&g.profile.as_str()))
                || (g.semantic_request_bytes.is_some()
                    && (!g.ironcrest || g.profile != "rust-workspace-v1"))
                || g.semantic_request_bytes
                    .is_some_and(|bytes| bytes == 0 || bytes > 1024 * 1024)
                || (!g.ironcrest && g.ironcrest_baseline.is_some())
                || !(1..=3).contains(&g.maximum_attempts)
                || config.grants[..index].iter().any(|p| {
                    p.project == g.project && p.repository == g.repository && p.actor == g.actor
                })
                || config
                    .grants
                    .iter()
                    .any(|p| p.token_sha256 == g.token_sha256 && p.actor != g.actor)
            {
                return Err(JobStoreError::Invalid);
            }
        }

        Ok(config)
    }

    /// Authenticates a development bearer token. Missing/unknown credentials reject.
    pub fn authenticate(&self, token: &str) -> Result<GitActorId, JobStoreError> {
        if token.len() < 32 || token.len() > 256 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(JobStoreError::Unauthorized);
        }

        let hash = digest_bytes(token.as_bytes());
        self.grants
            .iter()
            .find(|g| g.token_sha256 == hash)
            .map(|g| g.actor.clone())
            .ok_or(JobStoreError::Unauthorized)
    }

    /// Returns only an explicit actor/project/repository grant.
    pub fn grant_for(
        &self,
        actor: &GitActorId,
        project: ProjectId,
        repository: &RepositoryId,
    ) -> Result<&AuthorityGrant, JobStoreError> {
        self.grants
            .iter()
            .find(|g| &g.actor == actor && g.project == project && &g.repository == repository)
            .ok_or(JobStoreError::Unauthorized)
    }
}

/// Control-plane runtime composition, independently restartable from execution/signing.
pub struct ControlPlane {
    /// Transactional state adapter. Internal authority access only.
    pub repository: PostgresJobRepository,
    /// Bulk storage capability; never handed to target execution.
    pub artifacts: Arc<FilesystemArtifactStore>,
    /// Explicit development authority settings.
    pub configuration: ControlPlaneConfiguration,
}

impl ControlPlane {
    /// Connects existing migrated metadata and private storage; performs no DDL/provisioning.
    pub async fn connect(
        url: &str,
        configuration: ControlPlaneConfiguration,
    ) -> Result<Self, JobStoreError> {
        let repository = PostgresJobRepository::connect(url).await?;
        let artifacts = Arc::new(FilesystemArtifactStore::open_unencrypted_development(
            &configuration.artifact_root,
        )?);

        Ok(Self {
            repository,
            artifacts,
            configuration,
        })
    }

    /// Explicit operator provisioning of allowed scopes; never run from target/API requests.
    pub async fn provision(&self) -> Result<(), JobStoreError> {
        for grant in &self.configuration.grants {
            self.repository
                .grant(grant.project, &grant.repository, &grant.actor)
                .await?;
        }

        Ok(())
    }

    /// Loads an exact accepted source for a separately authorized artifact build.
    /// Repository scope is checked before opening source storage; no mutable ref.
    pub async fn release_source(
        &self,
        actor: &GitActorId,
        submission: &SourceSubmissionId,
        expected: &archcert_domain::release::CertifiedSourceIdentity,
    ) -> Result<SourceSnapshot, JobStoreError> {
        self.configuration
            .grant_for(actor, expected.project, &expected.repository)?;

        if !self
            .repository
            .authorized(expected.project, &expected.repository, actor)
            .await?
        {
            return Err(JobStoreError::Unauthorized);
        }

        let store =
            archcert_gateway::AcceptedSubmissionReader::open(&self.configuration.source_store)
                .map_err(|_| JobStoreError::Unavailable)?;
        let accepted = store.load(submission).map_err(|_| JobStoreError::Invalid)?;

        if accepted.snapshot.project() != expected.project
            || accepted.snapshot.repository() != &expected.repository
            || accepted.snapshot.identity() != &expected.source
        {
            return Err(JobStoreError::Precondition);
        }

        accepted
            .snapshot
            .require_complete()
            .map_err(|_| JobStoreError::Invalid)?;
        self.repository
            .register_source(submission, &accepted.snapshot)
            .await?;

        Ok(accepted.snapshot)
    }

    /// Loads independently checked accepted source under a known authority reference.
    pub fn source(&self, inputs: &JobInputs) -> Result<SourceSnapshot, JobStoreError> {
        let store =
            archcert_gateway::AcceptedSubmissionReader::open(&self.configuration.source_store)
                .map_err(|_| JobStoreError::Unavailable)?;
        let accepted = store
            .load(&inputs.submission)
            .map_err(|_| JobStoreError::Invalid)?;

        if accepted.snapshot.project() != inputs.project
            || accepted.snapshot.repository() != &inputs.repository
            || accepted.snapshot.identity() != &inputs.source
        {
            return Err(JobStoreError::Invalid);
        }

        accepted
            .snapshot
            .require_complete()
            .map_err(|_| JobStoreError::Invalid)?;

        Ok(accepted.snapshot)
    }

    /// Authorizes scope before source lookup, pins all inputs, then durably admits work.
    pub async fn submit(
        &self,
        actor: GitActorId,
        project: ProjectId,
        repository: RepositoryId,
        submission: SourceSubmissionId,
        key: IdempotencyKey,
    ) -> Result<CertificationJob, JobStoreError> {
        let grant = self.configuration.grant_for(&actor, project, &repository)?;

        if grant.ironcrest {
            return Err(JobStoreError::Precondition);
        }

        if !self
            .repository
            .authorized(project, &repository, &actor)
            .await?
        {
            return Err(JobStoreError::Unauthorized);
        }

        let accepted = {
            let store =
                archcert_gateway::AcceptedSubmissionReader::open(&self.configuration.source_store)
                    .map_err(|_| JobStoreError::Unavailable)?;
            store
                .load(&submission)
                .map_err(|_| JobStoreError::Invalid)?
        };

        if accepted.snapshot.project() != project || accepted.snapshot.repository() != &repository {
            return Err(JobStoreError::Unauthorized);
        }

        accepted
            .snapshot
            .require_complete()
            .map_err(|_| JobStoreError::Invalid)?;
        let policy = archcert_policy::development_bundle().map_err(|_| JobStoreError::Invalid)?;
        let p = policy.identity();
        let plan = resolve_authority_plan(&grant.profile, &grant.image, &grant.authority_toml)?;
        let inputs = JobInputs {
            project,
            repository,
            submission,
            source: accepted.snapshot.identity().clone(),
            actor,
            policy: PolicyPin {
                id: p.id.clone(),
                version: p.version.clone(),
                sha256: p.sha256.clone(),
            },
            profile: grant.profile.clone(),
            image: grant.image.clone(),
            plan_sha256: plan.digest().map_err(|_| JobStoreError::Invalid)?,
            authority_toml: grant.authority_toml.clone(),
            maximum_attempts: grant.maximum_attempts,
        };
        inputs.validate()?;
        self.repository
            .register_source(&inputs.submission, &accepted.snapshot)
            .await?;
        self.repository
            .create(CreateJob {
                inputs,
                idempotency: key,
            })
            .await
    }

    /// Reads durable state only after actor scope authorization. Existence alone grants nothing.
    pub async fn status(
        &self,
        actor: &GitActorId,
        id: JobId,
    ) -> Result<CertificationJob, JobStoreError> {
        let job = self.repository.get(id).await?;
        self.configuration
            .grant_for(actor, job.inputs.project, &job.inputs.repository)?;

        if !self
            .repository
            .authorized(job.inputs.project, &job.inputs.repository, actor)
            .await?
        {
            return Err(JobStoreError::Unauthorized);
        }

        Ok(job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_and_scope_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let token = "regression-only-public-token-value-00000001";
        let project = ProjectId::new();
        let repository = RepositoryId::parse("fixture/repository")?;
        let actor = GitActorId::parse(JobId::new().to_string())?;
        let configuration = ControlPlaneConfiguration {
            source_store: "/unused".into(),
            artifact_root: "/unused".into(),
            grants: vec![AuthorityGrant {
                project,
                repository: repository.clone(),
                actor: actor.clone(),
                token_sha256: digest_bytes(token.as_bytes()),
                profile: "python".into(),
                image: format!("python@sha256:{}", "a".repeat(64)),
                authority_toml: include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml")
                    .into(),
                maximum_attempts: 2,
                ironcrest: false,
                semantic_request_bytes: None,
                ironcrest_baseline: None,
            }],
        };

        assert_eq!(configuration.authenticate(token)?, actor);
        assert!(configuration.authenticate("").is_err());
        assert!(
            configuration
                .authenticate("unknown-public-token-value-00000001")
                .is_err()
        );
        assert!(
            configuration
                .grant_for(&actor, project, &repository)
                .is_ok()
        );
        assert!(
            configuration
                .grant_for(&actor, ProjectId::new(), &repository)
                .is_err()
        );

        let other = GitActorId::parse(JobId::new().to_string())?;

        assert!(
            configuration
                .grant_for(&other, project, &repository)
                .is_err()
        );

        Ok(())
    }

    #[test]
    fn authority_configuration_rejects_symlink_and_public_files()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let root = root.path().canonicalize()?;
        let file = root.join("authority.json");
        std::fs::write(&file, b"{}")?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))?;

        assert!(read_private(&file, 1024).is_err());

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;

        assert_eq!(read_private(&file, 1024)?, b"{}");

        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link)?;

        assert!(read_private(&link, 1024).is_err());
        assert!(ControlPlaneConfiguration::load(&file).is_err());

        Ok(())
    }
}
