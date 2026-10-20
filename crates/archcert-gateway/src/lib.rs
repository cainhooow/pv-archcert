//! Northgate source reception. OpenSSH authenticates possession; authority grants
//! authorize repositories. No execution, policy, certificate or signing dependency.
#![cfg(unix)]
mod git;
mod inspection;
mod protocol;
mod resolution;
mod store;
pub use resolution::{
    LfsGrant, ResolutionConfiguration, ResolutionEvidence, ResolutionReference, SubmoduleGrant,
    read_resolution_configuration, resolve_submission,
};
pub use store::{DevelopmentSubmissionStore, StoredSubmission};

use archcert_application::source::{GitGateway, SourceSubmission, ingest_source};
use archcert_domain::{
    ProjectId, Sha256Digest, SourceIdentity,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    source::{RepositoryId, SourceLimits, SourceStatus, digest_bytes},
};
use archcert_source::{
    GitObjectFormat, MemorySourceStore, PackLimits, PackedGitGateway, receive_pack,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

/// Loads only private owner-controlled authority configuration through anchored
/// no-follow directories/files. Never reads a target repository or ambient config.
pub fn read_configuration(path: &std::path::Path) -> Result<GatewayConfiguration, IngressError> {
    let bytes = store::read_private_configuration(path)?;
    let config: GatewayConfiguration = serde_json::from_slice(&bytes).map_err(unavailable)?;
    config.validate()?;
    Ok(config)
}

/// Bounded client-visible failure categories; no candidate bytes or OS diagnostics.
#[derive(Debug, Error)]
pub enum IngressError {
    /// Key is absent, disabled or not registered.
    #[error("AUTHENTICATION_DENIED")]
    Authentication,
    /// Authenticated key lacks the exact authority repository grant.
    #[error("REPOSITORY_DENIED")]
    Authorization,
    /// Only one literal Git receive command is supported.
    #[error("RECEIVE_COMMAND_DENIED")]
    Command,
    /// Protocol, ref or object validation failed.
    #[error("SOURCE_REJECTED")]
    Rejected,
    /// Capacity/deadline/admission exhausted.
    #[error("INGRESS_LIMIT_EXCEEDED")]
    Limit,
    /// Authority storage or configured adapter is unavailable.
    #[error("INGRESS_UNAVAILABLE")]
    Unavailable,
}
fn unavailable<E>(_: E) -> IngressError {
    IngressError::Unavailable
}
fn rejected<E>(_: E) -> IngressError {
    IngressError::Rejected
}
fn now() -> Result<u64, IngressError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(unavailable)?
        .as_secs())
}

/// Explicit actor-to-repository authorization; paths are only routing labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGrant {
    /// Authority project identity.
    pub project: ProjectId,
    /// Authority repository identity, separately scoped from project.
    pub repository: RepositoryId,
    /// Exact virtual Git route (for example company/project.git).
    pub route: String,
    /// Authority-selected Git object format.
    pub object_format: GitObjectFormat,
}
/// Public identity mapping corresponding to one restricted authorized_keys entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedDevice {
    /// Authority actor.
    pub actor: GitActorId,
    /// SHA-256 fingerprint of public SSH wire-key bytes.
    pub device: DeviceKeyId,
    /// Explicit development disable/revocation representation.
    pub enabled: bool,
    /// Explicit repository grants, not inferred from authenticated login.
    pub repositories: Vec<RepositoryGrant>,
}
/// Operator-owned gateway configuration; never loaded from target source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfiguration {
    /// Absolute observed system Git binary path; not cryptographically attested.
    pub git_executable: PathBuf,
    /// Private bounded development submission store.
    pub store: PathBuf,
    /// Public authentication mappings only.
    pub devices: Vec<AuthorizedDevice>,
    /// Finite pack budgets.
    pub pack_limits: PackLimits,
    /// Live-input and total acceptance deadline, also bounding Git subprocesses.
    pub session_seconds: u64,
    /// Retained attempts, including rejection records. No eviction by candidates.
    pub max_submissions: u32,
}
impl GatewayConfiguration {
    /// Validates trusted configuration and prevents ambiguous duplicate grants.
    pub fn validate(&self) -> Result<(), IngressError> {
        self.pack_limits.validate().map_err(unavailable)?;
        if !self.git_executable.is_absolute()
            || !self.store.is_absolute()
            || self.devices.len() > 256
            || !(1..=120).contains(&self.session_seconds)
            || !(1..=32).contains(&self.max_submissions)
        {
            return Err(IngressError::Unavailable);
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut namespace = std::collections::BTreeMap::new();
        for device in &self.devices {
            if !keys.insert(device.device.as_str()) || device.repositories.len() > 128 {
                return Err(IngressError::Unavailable);
            }
            let mut routes = std::collections::BTreeSet::new();
            for grant in &device.repositories {
                let target = (grant.project, grant.repository.clone(), grant.object_format);
                if let Some(prior) = namespace.insert(&grant.route, target.clone())
                    && prior != target
                {
                    return Err(IngressError::Unavailable);
                }
                if !protocol::valid_route(&grant.route) || !routes.insert(&grant.route) {
                    return Err(IngressError::Unavailable);
                }
            }
        }
        Ok(())
    }
    /// Maps an OpenSSH forced-command fingerprint and exact original command.
    /// This function does not itself authenticate SSH. Only the restricted account
    /// may invoke it, with a fingerprint fixed in authority-owned authorized_keys.
    pub fn authorize(
        &self,
        device: &DeviceKeyId,
        original: &str,
    ) -> Result<(&AuthorizedDevice, &RepositoryGrant), IngressError> {
        self.validate()?;
        let device = self
            .devices
            .iter()
            .find(|d| &d.device == device && d.enabled)
            .ok_or(IngressError::Authentication)?;
        let route = protocol::receive_route(original)?;
        let grant = device
            .repositories
            .iter()
            .find(|g| g.route == route)
            .ok_or(IngressError::Authorization)?;
        Ok((device, grant))
    }
}

/// Structural audit events, not a durable event-sourcing system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IngressEvent {
    /// OpenSSH public-key possession authenticated; authority mapping enabled.
    GitSessionAuthenticated,
    /// Authorized source session admitted.
    GitReceiveStarted,
    /// Bounded command names one immutable candidate OID.
    GitRefReceived,
    /// Raw pack retained only in this private session.
    GitObjectsQuarantined,
    /// Independent object/source validation begins.
    GitObjectValidationStarted,
    /// External dependencies remain separated from execution.
    ExternalSourceResolutionStarted,
    /// Controlled acquisition verified external bytes (never implied by a pointer).
    ExternalSourceResolved,
    /// No accepted artifact on this attempt.
    GitSubmissionRejected,
    /// Immutable source artifact published; no certification job created.
    SourceSnapshotAccepted,
}
/// Required external content, with explicit unresolved repository/location state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ExternalDependencyEvidence {
    /// Pointer claims retained for controlled verification; never final file bytes.
    Lfs {
        /// Source path containing the pointer.
        path: archcert_domain::source::SourcePath,
        /// Declared external SHA-256; not verified content evidence yet.
        expected_sha256: Sha256Digest,
        /// Declared external byte size.
        expected_size: u64,
        /// Explicit unresolved state.
        resolution: ExternalResolutionState,
    },
    /// Gitlink location is an authority mapping; .gitmodules never supplies it.
    Submodule {
        /// Gitlink path.
        path: archcert_domain::source::SourcePath,
        /// Required exact immutable child commit.
        commit: archcert_domain::GitObjectId,
        /// Authority repository mapping, absent in the initial receive endpoint.
        repository: Option<RepositoryId>,
        /// Explicit location/mapping state, without an attacker-selected URL.
        location: SubmoduleLocationState,
        /// Explicit unresolved state.
        resolution: ExternalResolutionState,
    },
}
/// Initial required dependencies remain unavailable to execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalResolutionState {
    /// No verified acquisition has completed for this snapshot.
    Unresolved,
}
/// A gitlink's origin must be assigned by authority before acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmoduleLocationState {
    /// No approved repository mapping exists in the receive session.
    AuthorityUnmapped,
}
fn schema_one() -> u32 {
    1
}
fn external_evidence(
    snapshot: &archcert_domain::source::SourceSnapshot,
) -> Vec<ExternalDependencyEvidence> {
    snapshot
        .external()
        .iter()
        .map(|e| match e {
            archcert_domain::source::ExternalSource::Lfs {
                path,
                expected_sha256,
                expected_size,
            } => ExternalDependencyEvidence::Lfs {
                path: path.clone(),
                expected_sha256: expected_sha256.clone(),
                expected_size: *expected_size,
                resolution: ExternalResolutionState::Unresolved,
            },
            archcert_domain::source::ExternalSource::Submodule { path, commit } => {
                ExternalDependencyEvidence::Submodule {
                    path: path.clone(),
                    commit: commit.clone(),
                    repository: None,
                    location: SubmoduleLocationState::AuthorityUnmapped,
                    resolution: ExternalResolutionState::Unresolved,
                }
            }
        })
        .collect()
}

/// Immutable source-ingress evidence. Audit metadata does not affect source digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressEvidence {
    /// Fresh reception identity, distinct across replay.
    pub submission: SourceSubmissionId,
    /// Authenticated actor.
    pub actor: GitActorId,
    /// Authenticated public-key identity.
    pub device: DeviceKeyId,
    /// Authority project scope.
    pub project: ProjectId,
    /// Authority repository scope.
    pub repository: RepositoryId,
    /// SSH public-key transport.
    pub transport: String,
    /// Exactly one received branch ref, provenance only.
    pub received_refs: Vec<String>,
    /// Exact requested commit OID, never a ref.
    pub requested_commit: Option<archcert_domain::GitObjectId>,
    /// Resolved exact commit/tree and independent source SHA-256.
    pub source: Option<SourceIdentity>,
    /// Authority object format.
    pub object_format: GitObjectFormat,
    /// SHA-256 of the complete raw received pack.
    pub pack_sha256: Option<Sha256Digest>,
    /// Received pack length.
    pub pack_bytes: u64,
    /// Advertised pack entry count.
    pub pack_objects: u32,
    /// Limits applied before any decoder allocation.
    pub pack_limits: PackLimits,
    /// Observed configured Git path and version (not binary attestation).
    pub git_adapter: Option<git::ObservedGit>,
    /// Required LFS pointers; no automatic remote acquisition.
    pub lfs_unresolved: u64,
    /// Required gitlinks; .gitmodules is untrusted source data.
    pub submodules_unresolved: u64,
    /// Paths and immutable external requirements; no candidate-controlled origins.
    #[serde(default)]
    pub external_sources: Vec<ExternalDependencyEvidence>,
    /// Identity canonicalization schema; historical source remains schema 1.
    #[serde(default = "schema_one")]
    pub source_schema: u32,
    /// New source derivation audit, absent on original Git submissions.
    #[serde(default)]
    pub resolution: Option<ResolutionEvidence>,
    /// Complete versus incomplete source; absent on rejection.
    pub completeness: Option<SourceStatus>,
    /// RECEIVED, INCOMPLETE_EXTERNAL_SOURCE, ACCEPTED or REJECTED.
    pub status: String,
    /// UTC reception time, excluded from source identity.
    pub received_at: u64,
    /// UTC immutable acceptance time, absent on rejection.
    pub accepted_at: Option<u64>,
    /// Ordered bounded structural events.
    pub events: Vec<IngressEvent>,
    /// Authority-generated candidate namespace; no normal branch is certification state.
    pub candidate: String,
}

/// Replaceable accepted-source/evidence storage port. Implementations must retain
/// immutable scoped bytes, rehash retrieval and never manufacture a job.
/// Admission/quarantine staging belong to the infrastructure composition.
pub trait SubmissionStore {
    /// Atomically publishes accepted immutable bytes with their ingress evidence.
    fn accept(
        &mut self,
        snapshot: &archcert_domain::source::SourceSnapshot,
        evidence: &IngressEvidence,
    ) -> Result<(), IngressError>;
    /// Records rejection without creating accepted source.
    fn reject(&mut self, evidence: &IngressEvidence) -> Result<(), IngressError>;
    /// Retrieves exact accepted source with integrity validation.
    fn load(&self, id: &SourceSubmissionId) -> Result<StoredSubmission, IngressError>;
}

/// Authenticated source receive. A successful return publishes only source state.
/// The caller must enforce a process deadline on live reads (the CLI does so).
pub fn receive(
    config: &GatewayConfiguration,
    device: &DeviceKeyId,
    original: &str,
    input: impl BufRead,
    mut output: impl Write,
) -> Result<IngressEvidence, IngressError> {
    let (actor, grant) = config.authorize(device, original)?;
    let mut store = DevelopmentSubmissionStore::open(&config.store, config.max_submissions)?;
    let id = SourceSubmissionId::new();
    let mut evidence = IngressEvidence {
        submission: id.clone(),
        actor: actor.actor.clone(),
        device: device.clone(),
        project: grant.project,
        repository: grant.repository.clone(),
        transport: "SSH_PUBLIC_KEY".into(),
        received_refs: Vec::new(),
        requested_commit: None,
        source: None,
        object_format: grant.object_format,
        pack_sha256: None,
        pack_bytes: 0,
        pack_objects: 0,
        pack_limits: config.pack_limits,
        git_adapter: None,
        lfs_unresolved: 0,
        submodules_unresolved: 0,
        external_sources: Vec::new(),
        source_schema: 1,
        resolution: None,
        completeness: None,
        status: "RECEIVED".into(),
        received_at: now()?,
        accepted_at: None,
        events: vec![
            IngressEvent::GitSessionAuthenticated,
            IngressEvent::GitReceiveStarted,
        ],
        candidate: format!("refs/archcert/candidates/{}/{}", grant.project, id),
    };
    let quarantine = store.quarantine()?;
    let result = receive_inner(
        config,
        grant,
        input,
        &mut output,
        &mut store,
        quarantine.path(),
        &mut evidence,
    );
    if result.is_err() && store.load(&id).is_err() {
        evidence.status = "REJECTED".into();
        evidence.accepted_at = None;
        evidence.source = None;
        evidence.completeness = None;
        evidence
            .events
            .retain(|e| !matches!(e, IngressEvent::SourceSnapshotAccepted));
        evidence.events.push(IngressEvent::GitSubmissionRejected);
        store.reject(&evidence)?;
    }
    result.map(|()| evidence)
}
fn receive_inner(
    config: &GatewayConfiguration,
    grant: &RepositoryGrant,
    mut input: impl BufRead,
    output: &mut impl Write,
    store: &mut dyn SubmissionStore,
    staging: &std::path::Path,
    evidence: &mut IngressEvidence,
) -> Result<(), IngressError> {
    let started = std::time::Instant::now();
    let deadline = || {
        if started.elapsed() > std::time::Duration::from_secs(config.session_seconds) {
            Err(IngressError::Limit)
        } else {
            Ok(())
        }
    };
    let git = git::SystemGit::new(&config.git_executable, staging, config.session_seconds)?;
    evidence.git_adapter = Some(git.observed().clone());
    git.init(grant.object_format)?;
    let advertisement = git.advertise()?;
    deadline()?;
    output.write_all(&advertisement).map_err(unavailable)?;
    output.flush().map_err(unavailable)?;
    let command = protocol::read_command(&mut input, grant.object_format)?;
    evidence.received_refs.push(command.reference.clone());
    evidence.requested_commit = Some(command.commit.clone());
    evidence.events.push(IngressEvent::GitRefReceived);
    let pack =
        receive_pack(&mut input, grant.object_format, config.pack_limits).map_err(rejected)?;
    evidence.pack_bytes = pack.len() as u64;
    evidence.pack_sha256 = Some(digest_bytes(&pack));
    evidence.pack_objects = u32::from_be_bytes(pack[8..12].try_into().map_err(rejected)?);
    evidence.events.extend([
        IngressEvent::GitObjectsQuarantined,
        IngressEvent::GitObjectValidationStarted,
    ]);
    let gateway = PackedGitGateway::new(
        grant.repository.clone(),
        &pack,
        grant.object_format,
        config.pack_limits,
    )
    .map_err(rejected)?;
    // ArchCert validates before Git's second decoder can observe the buffered pack.
    gateway
        .quarantine(&grant.repository)
        .map_err(rejected)?
        .validate(&command.commit, SourceLimits::default())
        .map_err(rejected)?;
    deadline()?;
    let response = git.receive(&command.raw, &pack, &command.reference, &command.commit)?;
    let source = ingest_source(
        &gateway,
        &mut MemorySourceStore::default(),
        SourceSubmission {
            project: grant.project,
            repository: grant.repository.clone(),
            requested_commit: command.commit,
        },
        SourceLimits::default(),
    )
    .map_err(rejected)?;
    evidence.source = Some(source.snapshot.identity().clone());
    evidence.completeness = Some(source.snapshot.status());
    evidence.external_sources = external_evidence(&source.snapshot);
    for external in source.snapshot.external() {
        match external {
            archcert_domain::source::ExternalSource::Lfs { .. } => evidence.lfs_unresolved += 1,
            archcert_domain::source::ExternalSource::Submodule { .. } => {
                evidence.submodules_unresolved += 1
            }
        }
    }
    evidence.status = if source.snapshot.require_complete().is_ok() {
        "ACCEPTED"
    } else {
        "INCOMPLETE_EXTERNAL_SOURCE"
    }
    .into();
    deadline()?;
    evidence.accepted_at = Some(now()?);
    evidence.events.push(IngressEvent::SourceSnapshotAccepted);
    store.accept(&source.snapshot, evidence)?;
    // Git's report-status is withheld until immutable source storage succeeds.
    output.write_all(&response).map_err(unavailable)?;
    output.flush().map_err(unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Result<GatewayConfiguration, Box<dyn std::error::Error>> {
        Ok(GatewayConfiguration {
            git_executable: "/usr/bin/git".into(),
            store: "/authority/source-store".into(),
            devices: vec![AuthorizedDevice {
                actor: GitActorId::parse("00000000-0000-4000-8000-000000000001".into())?,
                device: DeviceKeyId::parse("1".repeat(64))?,
                enabled: true,
                repositories: vec![RepositoryGrant {
                    project: ProjectId::new(),
                    repository: RepositoryId::parse("authority/one")?,
                    route: "company/one.git".into(),
                    object_format: GitObjectFormat::Sha1,
                }],
            }],
            pack_limits: PackLimits::default(),
            session_seconds: 10,
            max_submissions: 2,
        })
    }
    #[test]
    fn authentication_repository_authorization_and_namespace_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = config()?;
        let key = config.devices[0].device.clone();
        assert!(
            config
                .authorize(&key, "git-receive-pack 'company/one.git'")
                .is_ok()
        );
        assert!(matches!(
            config.authorize(&key, "git-receive-pack 'company/two.git'"),
            Err(IngressError::Authorization)
        ));
        assert!(matches!(
            config.authorize(
                &DeviceKeyId::parse("2".repeat(64))?,
                "git-receive-pack 'company/one.git'"
            ),
            Err(IngressError::Authentication)
        ));
        config.devices[0].enabled = false;
        assert!(matches!(
            config.authorize(&key, "git-receive-pack 'company/one.git'"),
            Err(IngressError::Authentication)
        ));
        config.devices[0].enabled = true;
        let mut conflicting = config.devices[0].clone();
        conflicting.device = DeviceKeyId::parse("2".repeat(64))?;
        conflicting.repositories[0].project = ProjectId::new();
        config.devices.push(conflicting);
        assert!(config.validate().is_err());
        Ok(())
    }
    #[test]
    fn authority_configuration_cannot_disable_resource_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = config()?;
        for mutation in 0..5 {
            let mut config = original.clone();
            match mutation {
                0 => config.session_seconds = 0,
                1 => config.max_submissions = 0,
                2 => config.pack_limits.max_pack_bytes = u64::MAX,
                3 => config.pack_limits.max_delta_depth = u32::MAX,
                _ => config.git_executable = "git".into(),
            }
            assert!(config.validate().is_err());
        }
        Ok(())
    }
}
