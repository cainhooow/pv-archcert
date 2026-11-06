//! Independently verified, sealed release admission; no execution or signing capability.

use super::*;
use crate::{artifacts::ImmutableArtifactStore, release::BuildInputManifest};

/// Public-key verification of the frozen M6 input and original certificate envelope.
/// Trusted composition selects the exact supported recipe and public keys separately.
pub trait ReleaseBuildSourceVerifier: Send + Sync {
    /// Apply the existing M6 source/recipe/policy/key checks. Failure cannot seal admission.
    fn verify(&self, input: &BuildInputManifest, certificate: &[u8]) -> Result<(), JobStoreError>;
}

/// Non-deserializable capability for one independently checked command generation.
/// It conveys admission only, never an M6 execution claim or release authorization.
pub struct PreparedReleaseBuild {
    command: ControlCommandId,
    request_sha256: Sha256Digest,
    dispatches: u32,
}

impl PreparedReleaseBuild {
    /// Reject substitution across commands, frozen inputs and coordination generations.
    pub fn validate(&self, record: &ControlCommandRecord) -> Result<(), JobStoreError> {
        if self.command != record.id
            || self.request_sha256 != record.request_sha256
            || self.request_sha256 != record.command.digest()?
            || self.dispatches != record.dispatches
            || record.state != ControlCommandState::Processing
            || !matches!(
                record.command.action,
                ResolvedControlAction::RequestReleaseBuild { .. }
            )
        {
            return Err(JobStoreError::Precondition);
        }

        Ok(())
    }
}

/// Read and verify outside the short admission transaction, after current authorization.
pub struct ReleaseBuildRequestPreparer<'a> {
    /// Existing project/repository/operation grants and immutable command journal.
    pub commands: &'a dyn ControlCommandRepository,
    /// Bounded project-scoped reads of the registered original certificate bytes.
    pub artifacts: &'a dyn ImmutableArtifactStore,
    /// Explicit public-verification capability; never a signer or runtime adapter.
    pub verifier: &'a dyn ReleaseBuildSourceVerifier,
}

impl ReleaseBuildRequestPreparer<'_> {
    /// Seal only this exact processing generation and frozen authority context.
    /// The executor must recheck current grants, object binding and lease ownership.
    pub async fn prepare(
        &self,
        assignment: &ControlCommandAssignment,
        selected_context: &Sha256Digest,
    ) -> Result<PreparedReleaseBuild, JobStoreError> {
        if assignment.record.id != assignment.lease.command {
            return Err(JobStoreError::Invalid);
        }

        let record = self
            .commands
            .get(&assignment.record.command.scope, assignment.lease.command)
            .await?;
        let ResolvedControlAction::RequestReleaseBuild {
            admission,
            source_certificate,
        } = &record.command.action
        else {
            return Err(JobStoreError::Invalid);
        };
        if record.state != ControlCommandState::Processing
            || record.dispatches != assignment.record.dispatches
            || record.request_sha256 != assignment.record.request_sha256
            || record.command.authority_context != *selected_context
        {
            return Err(JobStoreError::Precondition);
        }

        // M6's original certificate decoder has a 64 KiB bound. Do not first read
        // the larger generic artifact allowance or accept a browser size assertion.
        if source_certificate.size == 0 || source_certificate.size > 65_536 {
            return Err(JobStoreError::Invalid);
        }
        let certificate = self
            .artifacts
            .get(record.command.scope.project, source_certificate)
            .await?;
        if certificate.len() as u64 != source_certificate.size
            || digest_bytes(&certificate) != source_certificate.sha256
        {
            return Err(JobStoreError::Precondition);
        }

        self.verifier.verify(&admission.input, &certificate)?;

        Ok(PreparedReleaseBuild {
            command: record.id,
            request_sha256: record.request_sha256,
            dispatches: record.dispatches,
        })
    }
}

/// Atomic M6 workflow admission and command publication. Owns no build/signing port.
#[async_trait]
pub trait ControlReleaseCommandExecutor: Send + Sync {
    /// Recheck the sealed request, grants, object scope and original live fence;
    /// commit the existing immutable M6 admission, both audits and receipt together.
    async fn apply_release_build(
        &self,
        lease: &ControlCommandLease,
        selected_context: &Sha256Digest,
        prepared: &PreparedReleaseBuild,
    ) -> Result<ControlCommandOutcome, JobStoreError>;
}
