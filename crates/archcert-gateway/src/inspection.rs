//! Credential-free projection of existing ingress evidence for protocol adapters.
use crate::{IngressError, IngressEvidence};
use archcert_application::ingress::{
    GitObjectAlgorithm, SourceResolutionSummary, SourceState, SourceSubmissionState,
    SourceTransport, SubmissionStatus,
};
use archcert_source::GitObjectFormat;

impl IngressEvidence {
    /// Projects source-only observations into an application read model. Callers
    /// must authenticate transport separately; this does not admit source bytes.
    pub fn source_submission_state(&self) -> Result<SourceSubmissionState, IngressError> {
        let status = match self.status.as_str() {
            "RECEIVED" => SubmissionStatus::Received,
            "QUARANTINED" => SubmissionStatus::Quarantined,
            "VALIDATING" => SubmissionStatus::Validating,
            "INCOMPLETE_EXTERNAL_SOURCE" => SubmissionStatus::IncompleteExternalSource,
            "ACCEPTED" => SubmissionStatus::Accepted,
            "REJECTED" => SubmissionStatus::Rejected,
            _ => return Err(IngressError::Unavailable),
        };
        let transport = match self.transport.as_str() {
            "SSH_PUBLIC_KEY" => SourceTransport::SshPublicKey,
            "AUTHORITY_PRIVATE_SOURCE_RESOLUTION" => {
                SourceTransport::AuthorityPrivateSourceResolution
            }
            _ => return Err(IngressError::Unavailable),
        };
        let source = self
            .source
            .as_ref()
            .map(|identity| {
                Ok::<_, IngressError>(SourceState {
                    identity: identity.clone(),
                    schema_version: self.source_schema,
                    completeness: self.completeness.ok_or(IngressError::Unavailable)?,
                    lfs_unresolved: self.lfs_unresolved,
                    submodules_unresolved: self.submodules_unresolved,
                    resolution: self.resolution.as_ref().map(|resolution| {
                        SourceResolutionSummary {
                            parent_submission: resolution.parent_submission.clone(),
                            original: resolution.parent.identity.clone(),
                            resolver_actor: resolution.resolver_actor.clone(),
                            lfs_resolved: resolution.lfs_resolved,
                            submodules_resolved: resolution.submodules_resolved,
                        }
                    }),
                })
            })
            .transpose()?;
        let state = SourceSubmissionState {
            submission: self.submission.clone(),
            project: self.project,
            repository: self.repository.clone(),
            actor: self.actor.clone(),
            device: self.device.clone(),
            transport,
            submitted_refs: self.received_refs.clone(),
            requested_commit: self.requested_commit.clone(),
            object_algorithm: match self.object_format {
                GitObjectFormat::Sha1 => GitObjectAlgorithm::Sha1,
                GitObjectFormat::Sha256 => GitObjectAlgorithm::Sha256,
            },
            source,
            status,
            received_at: self.received_at,
            accepted_at: self.accepted_at,
        };
        state.validate().map_err(|_| IngressError::Unavailable)?;
        Ok(state)
    }
}
