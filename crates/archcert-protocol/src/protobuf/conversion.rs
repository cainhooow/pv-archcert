use super::{CONTRACT_VERSION, common::v1 as c, source::v1 as p};
use archcert_application::ingress as app;
use archcert_domain::{
    GitObjectId, ProjectId, Sha256Digest, SourceIdentity,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    source::{RepositoryId, SourceStatus},
};
use prost::Message;
use prost_types::Timestamp;

/// Maximum encoded source-inspection message accepted by this adapter.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Last whole second representable by google.protobuf.Timestamp (year 9999).
const MAX_TIMESTAMP_SECONDS: u64 = 253_402_300_799;

/// Fail-closed conversion failure, deliberately excluding hostile field contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid source protocol value: {0}")]
pub struct ConversionError(pub &'static str);

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, ConversionError> {
    value.ok_or(ConversionError(field))
}
fn bytes(value: &str) -> Result<Vec<u8>, ConversionError> {
    hex::decode(value).map_err(|_| ConversionError("domain digest"))
}
fn sha256(value: Vec<u8>) -> Result<Sha256Digest, ConversionError> {
    if value.len() != 32 {
        return Err(ConversionError("SHA-256 length"));
    }
    Sha256Digest::parse(hex::encode(value)).map_err(|_| ConversionError("SHA-256"))
}

impl TryFrom<c::ProjectId> for ProjectId {
    type Error = ConversionError;
    fn try_from(value: c::ProjectId) -> Result<Self, Self::Error> {
        let id: Self = value
            .value
            .parse()
            .map_err(|_| ConversionError("project ID"))?;
        if id.to_string() != value.value {
            return Err(ConversionError("project ID"));
        }
        Ok(id)
    }
}
impl From<&ProjectId> for c::ProjectId {
    fn from(value: &ProjectId) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}
impl TryFrom<c::RepositoryId> for RepositoryId {
    type Error = ConversionError;
    fn try_from(value: c::RepositoryId) -> Result<Self, Self::Error> {
        Self::parse(value.value).map_err(|_| ConversionError("repository ID"))
    }
}
impl From<&RepositoryId> for c::RepositoryId {
    fn from(value: &RepositoryId) -> Self {
        Self {
            value: value.as_str().into(),
        }
    }
}
impl TryFrom<c::SourceSubmissionId> for SourceSubmissionId {
    type Error = ConversionError;
    fn try_from(value: c::SourceSubmissionId) -> Result<Self, Self::Error> {
        Self::parse(&value.value).map_err(|_| ConversionError("submission ID"))
    }
}
impl From<&SourceSubmissionId> for c::SourceSubmissionId {
    fn from(value: &SourceSubmissionId) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}
impl TryFrom<c::GitActorId> for GitActorId {
    type Error = ConversionError;
    fn try_from(value: c::GitActorId) -> Result<Self, Self::Error> {
        Self::parse(value.value).map_err(|_| ConversionError("actor ID"))
    }
}
impl From<&GitActorId> for c::GitActorId {
    fn from(value: &GitActorId) -> Self {
        Self {
            value: value.as_str().into(),
        }
    }
}
impl TryFrom<c::DeviceKeyId> for DeviceKeyId {
    type Error = ConversionError;
    fn try_from(value: c::DeviceKeyId) -> Result<Self, Self::Error> {
        let digest = sha256(value.sha256)?;
        Self::parse(digest.as_str().into()).map_err(|_| ConversionError("device key ID"))
    }
}
impl TryFrom<&DeviceKeyId> for c::DeviceKeyId {
    type Error = ConversionError;
    fn try_from(value: &DeviceKeyId) -> Result<Self, Self::Error> {
        Ok(Self {
            sha256: bytes(value.as_str())?,
        })
    }
}
impl TryFrom<c::Sha256Digest> for Sha256Digest {
    type Error = ConversionError;
    fn try_from(value: c::Sha256Digest) -> Result<Self, Self::Error> {
        sha256(value.sha256)
    }
}
impl TryFrom<&Sha256Digest> for c::Sha256Digest {
    type Error = ConversionError;
    fn try_from(value: &Sha256Digest) -> Result<Self, Self::Error> {
        Ok(Self {
            sha256: bytes(value.as_str())?,
        })
    }
}
impl TryFrom<c::GitObjectId> for GitObjectId {
    type Error = ConversionError;
    fn try_from(value: c::GitObjectId) -> Result<Self, Self::Error> {
        let length = match algorithm(value.algorithm)? {
            app::GitObjectAlgorithm::Sha1 => 20,
            app::GitObjectAlgorithm::Sha256 => 32,
        };
        if value.digest.len() != length {
            return Err(ConversionError("Git OID length"));
        }
        Self::parse(hex::encode(value.digest)).map_err(|_| ConversionError("Git OID"))
    }
}
impl TryFrom<&GitObjectId> for c::GitObjectId {
    type Error = ConversionError;
    fn try_from(value: &GitObjectId) -> Result<Self, Self::Error> {
        Ok(Self {
            algorithm: match value.as_str().len() {
                40 => c::GitObjectAlgorithm::Sha1 as i32,
                64 => c::GitObjectAlgorithm::Sha256 as i32,
                _ => return Err(ConversionError("Git OID length")),
            },
            digest: bytes(value.as_str())?,
        })
    }
}
impl TryFrom<c::SourceIdentity> for SourceIdentity {
    type Error = ConversionError;
    fn try_from(value: c::SourceIdentity) -> Result<Self, Self::Error> {
        let commit: GitObjectId = required(value.commit, "commit")?.try_into()?;
        let tree: GitObjectId = required(value.tree, "tree")?.try_into()?;
        if commit.as_str().len() != tree.as_str().len() {
            return Err(ConversionError("mixed Git object algorithms"));
        }
        Ok(Self {
            commit,
            tree,
            snapshot_sha256: required(value.snapshot, "source SHA-256")?.try_into()?,
        })
    }
}
impl TryFrom<&SourceIdentity> for c::SourceIdentity {
    type Error = ConversionError;
    fn try_from(value: &SourceIdentity) -> Result<Self, Self::Error> {
        let result = Self {
            commit: Some((&value.commit).try_into()?),
            tree: Some((&value.tree).try_into()?),
            snapshot: Some((&value.snapshot_sha256).try_into()?),
        };
        // Public domain identity fields may be composed with mixed algorithms.
        SourceIdentity::try_from(result.clone())?;
        Ok(result)
    }
}

fn algorithm(value: i32) -> Result<app::GitObjectAlgorithm, ConversionError> {
    match c::GitObjectAlgorithm::try_from(value) {
        Ok(c::GitObjectAlgorithm::Sha1) => Ok(app::GitObjectAlgorithm::Sha1),
        Ok(c::GitObjectAlgorithm::Sha256) => Ok(app::GitObjectAlgorithm::Sha256),
        _ => Err(ConversionError("object algorithm")),
    }
}
fn transport(value: i32) -> Result<app::SourceTransport, ConversionError> {
    match p::SourceTransport::try_from(value) {
        Ok(p::SourceTransport::SshPublicKey) => Ok(app::SourceTransport::SshPublicKey),
        Ok(p::SourceTransport::AuthorityPrivateSourceResolution) => {
            Ok(app::SourceTransport::AuthorityPrivateSourceResolution)
        }
        _ => Err(ConversionError("transport")),
    }
}
fn status(value: i32) -> Result<app::SubmissionStatus, ConversionError> {
    match p::SubmissionStatus::try_from(value) {
        Ok(p::SubmissionStatus::Received) => Ok(app::SubmissionStatus::Received),
        Ok(p::SubmissionStatus::Quarantined) => Ok(app::SubmissionStatus::Quarantined),
        Ok(p::SubmissionStatus::Validating) => Ok(app::SubmissionStatus::Validating),
        Ok(p::SubmissionStatus::IncompleteExternalSource) => {
            Ok(app::SubmissionStatus::IncompleteExternalSource)
        }
        Ok(p::SubmissionStatus::Accepted) => Ok(app::SubmissionStatus::Accepted),
        Ok(p::SubmissionStatus::Rejected) => Ok(app::SubmissionStatus::Rejected),
        _ => Err(ConversionError("submission status")),
    }
}
fn timestamp(value: Timestamp) -> Result<u64, ConversionError> {
    let seconds = u64::try_from(value.seconds).map_err(|_| ConversionError("timestamp"))?;
    // Northgate's existing model has whole, nonnegative Unix seconds. Never
    // silently discard fractional precision or normalize an invalid timestamp.
    if value.nanos != 0 || seconds > MAX_TIMESTAMP_SECONDS {
        return Err(ConversionError("timestamp"));
    }
    Ok(seconds)
}
fn wire_timestamp(value: u64) -> Result<Timestamp, ConversionError> {
    if value > MAX_TIMESTAMP_SECONDS {
        return Err(ConversionError("timestamp"));
    }
    Ok(Timestamp {
        seconds: value as i64,
        nanos: 0,
    })
}

impl TryFrom<p::SourceResolutionSummary> for app::SourceResolutionSummary {
    type Error = ConversionError;
    fn try_from(value: p::SourceResolutionSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_submission: required(value.parent_submission, "parent submission")?
                .try_into()?,
            original: required(value.original, "original source")?.try_into()?,
            resolver_actor: required(value.resolver_actor, "resolver actor")?.try_into()?,
            lfs_resolved: value.lfs_resolved,
            submodules_resolved: value.submodules_resolved,
        })
    }
}
impl TryFrom<&app::SourceResolutionSummary> for p::SourceResolutionSummary {
    type Error = ConversionError;
    fn try_from(value: &app::SourceResolutionSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_submission: Some((&value.parent_submission).into()),
            original: Some((&value.original).try_into()?),
            resolver_actor: Some((&value.resolver_actor).into()),
            lfs_resolved: value.lfs_resolved,
            submodules_resolved: value.submodules_resolved,
        })
    }
}
impl TryFrom<p::SourceState> for app::SourceState {
    type Error = ConversionError;
    fn try_from(value: p::SourceState) -> Result<Self, Self::Error> {
        if ![1, 2].contains(&value.schema_version) {
            return Err(ConversionError("source schema"));
        }
        let state = Self {
            identity: required(value.identity, "source identity")?.try_into()?,
            schema_version: value.schema_version,
            completeness: match p::SourceCompleteness::try_from(value.completeness) {
                Ok(p::SourceCompleteness::Complete) => SourceStatus::Complete,
                Ok(p::SourceCompleteness::IncompleteExternalSource) => {
                    SourceStatus::IncompleteExternalSource
                }
                _ => return Err(ConversionError("source completeness")),
            },
            lfs_unresolved: value.lfs_unresolved,
            submodules_unresolved: value.submodules_unresolved,
            resolution: value.resolution.map(TryInto::try_into).transpose()?,
        };
        state
            .validate()
            .map_err(|_| ConversionError("inconsistent source state"))?;
        Ok(state)
    }
}
impl TryFrom<&app::SourceState> for p::SourceState {
    type Error = ConversionError;
    fn try_from(value: &app::SourceState) -> Result<Self, Self::Error> {
        value
            .validate()
            .map_err(|_| ConversionError("inconsistent source state"))?;
        Ok(Self {
            identity: Some((&value.identity).try_into()?),
            schema_version: value.schema_version,
            completeness: match value.completeness {
                SourceStatus::Complete => p::SourceCompleteness::Complete,
                SourceStatus::IncompleteExternalSource => {
                    p::SourceCompleteness::IncompleteExternalSource
                }
            } as i32,
            lfs_unresolved: value.lfs_unresolved,
            submodules_unresolved: value.submodules_unresolved,
            resolution: value
                .resolution
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}
impl TryFrom<p::SourceSubmission> for app::SourceSubmissionState {
    type Error = ConversionError;
    fn try_from(value: p::SourceSubmission) -> Result<Self, Self::Error> {
        if value.contract_version != CONTRACT_VERSION {
            return Err(ConversionError("contract version"));
        }
        let actor = required(value.actor, "actor identity")?;
        let git = required(value.git, "Git provenance")?;
        let state = Self {
            submission: required(value.submission, "submission ID")?.try_into()?,
            project: required(value.project, "project ID")?.try_into()?,
            repository: required(value.repository, "repository ID")?.try_into()?,
            actor: required(actor.actor, "actor ID")?.try_into()?,
            device: required(actor.device, "device key ID")?.try_into()?,
            transport: transport(git.transport)?,
            submitted_refs: git.submitted_refs,
            requested_commit: git.requested_commit.map(TryInto::try_into).transpose()?,
            object_algorithm: algorithm(git.object_algorithm)?,
            source: value.source.map(TryInto::try_into).transpose()?,
            status: status(value.status)?,
            received_at: timestamp(required(value.received_at, "received timestamp")?)?,
            accepted_at: value.accepted_at.map(timestamp).transpose()?,
        };
        state
            .validate()
            .map_err(|_| ConversionError("inconsistent ingress state"))?;
        Ok(state)
    }
}
impl TryFrom<&app::SourceSubmissionState> for p::SourceSubmission {
    type Error = ConversionError;
    fn try_from(value: &app::SourceSubmissionState) -> Result<Self, Self::Error> {
        value
            .validate()
            .map_err(|_| ConversionError("inconsistent ingress state"))?;
        Ok(Self {
            contract_version: CONTRACT_VERSION,
            submission: Some((&value.submission).into()),
            project: Some((&value.project).into()),
            repository: Some((&value.repository).into()),
            actor: Some(p::ActorIdentity {
                actor: Some((&value.actor).into()),
                device: Some((&value.device).try_into()?),
            }),
            git: Some(p::GitSubmission {
                submitted_refs: value.submitted_refs.clone(),
                requested_commit: value
                    .requested_commit
                    .as_ref()
                    .map(TryInto::try_into)
                    .transpose()?,
                object_algorithm: match value.object_algorithm {
                    app::GitObjectAlgorithm::Sha1 => c::GitObjectAlgorithm::Sha1,
                    app::GitObjectAlgorithm::Sha256 => c::GitObjectAlgorithm::Sha256,
                } as i32,
                transport: match value.transport {
                    app::SourceTransport::SshPublicKey => p::SourceTransport::SshPublicKey,
                    app::SourceTransport::AuthorityPrivateSourceResolution => {
                        p::SourceTransport::AuthorityPrivateSourceResolution
                    }
                } as i32,
            }),
            source: value.source.as_ref().map(TryInto::try_into).transpose()?,
            status: match value.status {
                app::SubmissionStatus::Received => p::SubmissionStatus::Received,
                app::SubmissionStatus::Quarantined => p::SubmissionStatus::Quarantined,
                app::SubmissionStatus::Validating => p::SubmissionStatus::Validating,
                app::SubmissionStatus::IncompleteExternalSource => {
                    p::SubmissionStatus::IncompleteExternalSource
                }
                app::SubmissionStatus::Accepted => p::SubmissionStatus::Accepted,
                app::SubmissionStatus::Rejected => p::SubmissionStatus::Rejected,
            } as i32,
            received_at: Some(wire_timestamp(value.received_at)?),
            accepted_at: value.accepted_at.map(wire_timestamp).transpose()?,
        })
    }
}

/// Encodes validated ingress observations. These bytes are not canonical semantic
/// identity, and must never replace existing source/policy/certificate encodings.
pub fn encode_submission(state: &app::SourceSubmissionState) -> Result<Vec<u8>, ConversionError> {
    let dto = p::SourceSubmission::try_from(state)?;
    if dto.encoded_len() > MAX_MESSAGE_BYTES {
        return Err(ConversionError("message size"));
    }
    Ok(dto.encode_to_vec())
}
/// Decodes a bounded message and validates every known required semantic value.
/// Unknown additive fields are ignored; they cannot supply positive authority.
pub fn decode_submission(bytes: &[u8]) -> Result<app::SourceSubmissionState, ConversionError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ConversionError("message size"));
    }
    p::SourceSubmission::decode(bytes)
        .map_err(|_| ConversionError("Protobuf encoding"))?
        .try_into()
}
