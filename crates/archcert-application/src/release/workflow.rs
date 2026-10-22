//! Create-only publication and conservative execution recovery for release inputs.

use super::*;
use crate::{artifacts::ImmutableArtifactStore, jobs::JobStoreError};
use archcert_domain::{
    ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::JobId,
};
use async_trait::async_trait;

/// Fixed roles. Existing source-certification artifact kinds are not reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseRole {
    /// Frozen admitted build input manifest.
    Input,
    /// Source certificate envelope, verified separately before admission and signing.
    SourceCertificate,
    /// First independently collected file.
    ArtifactA,
    /// First canonical build result.
    ResultA,
    /// Second independently collected file.
    ArtifactB,
    /// Second canonical build result.
    ResultB,
    /// Deterministic three-state comparison.
    Reproducibility,
    /// Exact signable message, persisted before signing.
    PermitPayload,
    /// Verified signed envelope, accepted at most once.
    PermitEnvelope,
}

/// Scoped immutable release admission, provided only by authority composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAdmission {
    /// Exact immutable inputs, including project/repository/source.
    pub input: BuildInputManifest,
    /// Accepted source submission; no mutable Git lookup during recovery.
    pub submission: SourceSubmissionId,
    /// Authenticated actor requiring an independent repository grant.
    pub actor: GitActorId,
    /// Exact retained input bytes.
    pub input_reference: ArtifactReference,
}

/// Create-only staged/accepted evidence reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseReference {
    /// One fixed role.
    pub role: ReleaseRole,
    /// Exact immutable bytes and producer/schema.
    pub artifact: ArtifactReference,
    /// True only after verified object-store readback.
    pub available: bool,
}

/// Durable state. Status is derived from the accepted immutable checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRecord {
    /// Immutable admitted invocation.
    pub admission: ReleaseAdmission,
    /// Independently claimed A; no expiry or takeover.
    pub claimed_a: bool,
    /// Independently claimed B; no expiry or takeover.
    pub claimed_b: bool,
    /// Retained evidence including staged publication intent.
    pub references: Vec<ReleaseReference>,
}

/// Exclusive non-expiring execution claim. Never send it into a target sandbox.
pub struct BuildClaim {
    /// Exact repetition.
    pub ordinal: BuildOrdinal,
    /// Opaque fencing capability, never exposed in ordinary read models.
    pub token: JobId,
}

/// Durable coordination port. Implementations use short transactions; no lock is
/// held across execution, object-store operations or signature creation.
#[async_trait]
pub trait ReleaseRepository: Send + Sync {
    /// Rechecks grant and accepted source, creates one immutable invocation.
    async fn open(&self, admission: &ReleaseAdmission) -> Result<ReleaseRecord, JobStoreError>;

    /// Project-scoped read; database existence does not establish artifact availability.
    async fn get(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
    ) -> Result<ReleaseRecord, JobStoreError>;

    /// At most one execution grant for each ordinal. An existing claim is never reclaimed.
    async fn claim(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
        ordinal: BuildOrdinal,
    ) -> Result<Option<BuildClaim>, JobStoreError>;

    /// Freeze a role's exact publication intent. Initial build publication requires
    /// its claim; recovery may only accept the already frozen identical reference.
    async fn stage(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
        role: ReleaseRole,
        reference: &ArtifactReference,
        claim: Option<&BuildClaim>,
    ) -> Result<(), JobStoreError>;

    /// Accept only the existing exact staged reference after verified readback.
    async fn available(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
        role: ReleaseRole,
        reference: &ArtifactReference,
    ) -> Result<(), JobStoreError>;
}

/// Output of a trusted execution adapter. Target bytes themselves remain hostile.
pub struct BuildOutput {
    /// Runner-derived classification and exact input/output bindings.
    pub result: BuildResult,
    /// Bytes actually collected by the authority adapter; absent on failure.
    pub artifact: Option<Vec<u8>>,
}

/// Executes only the fixed authority recipe, on fresh isolated instances and
/// fresh materialized source for every call. No signing or metadata port crosses it.
pub trait ReleaseBuilder {
    /// Returns classified evidence even for infrastructure failure.
    fn build(&self, input: &BuildInputManifest, ordinal: BuildOrdinal) -> BuildOutput;
}

/// Stateless orchestrator; accepted state and bytes live behind separate ports.
pub struct ReleaseWorkflow<'a> {
    /// Durable metadata authority.
    pub repository: &'a dyn ReleaseRepository,
    /// Project-scoped immutable bytes authority.
    pub artifacts: &'a dyn ImmutableArtifactStore,
}

fn roles(ordinal: BuildOrdinal) -> (ReleaseRole, ReleaseRole) {
    match ordinal {
        BuildOrdinal::A => (ReleaseRole::ResultA, ReleaseRole::ArtifactA),
        BuildOrdinal::B => (ReleaseRole::ResultB, ReleaseRole::ArtifactB),
    }
}

impl ReleaseWorkflow<'_> {
    /// Idempotent create-only upload, followed by independent exact readback.
    pub async fn publish(
        &self,
        input: &BuildInputManifest,
        role: ReleaseRole,
        bytes: &[u8],
        claim: Option<&BuildClaim>,
    ) -> Result<ArtifactReference, JobStoreError> {
        let invocation = input.identity()?;
        let reference = release_reference(bytes);
        self.repository
            .stage(
                input.certified_source.project,
                &invocation,
                role,
                &reference,
                claim,
            )
            .await?;
        self.artifacts
            .put(input.certified_source.project, &reference, bytes)
            .await?;
        let readback = self
            .artifacts
            .get(input.certified_source.project, &reference)
            .await?;

        if readback != bytes {
            return Err(JobStoreError::Precondition);
        }

        self.repository
            .available(
                input.certified_source.project,
                &invocation,
                role,
                &reference,
            )
            .await?;

        Ok(reference)
    }

    /// Verified bytes, including staged objects recoverable after process death.
    pub async fn read(
        &self,
        input: &BuildInputManifest,
        role: ReleaseRole,
    ) -> Result<Option<Vec<u8>>, JobStoreError> {
        let record = self
            .repository
            .get(input.certified_source.project, &input.identity()?)
            .await?;
        let Some(reference) = record.references.iter().find(|r| r.role == role) else {
            return Ok(None);
        };
        let bytes = self
            .artifacts
            .get(input.certified_source.project, &reference.artifact)
            .await?;

        if release_reference(&bytes) != reference.artifact {
            return Err(JobStoreError::Precondition);
        }

        Ok(Some(bytes))
    }

    /// Persists frozen inputs before either claim. Source certificate verification
    /// is a prerequisite of the authority caller and is repeated by permit preparation.
    pub async fn admit(
        &self,
        admission: &ReleaseAdmission,
        recipe: &RustReleaseRecipe,
        source_certificate: &[u8],
    ) -> Result<(), JobStoreError> {
        admission.input.validate(recipe)?;
        let bytes = release_bytes(&admission.input)?;

        if admission.input_reference != release_reference(&bytes) {
            return Err(JobStoreError::Precondition);
        }

        self.repository.open(admission).await?;
        self.publish(&admission.input, ReleaseRole::Input, &bytes, None)
            .await?;
        self.publish(
            &admission.input,
            ReleaseRole::SourceCertificate,
            source_certificate,
            None,
        )
        .await?;

        Ok(())
    }

    /// Restores the exact canonical result, independently reads output, and
    /// completes interrupted acceptance without executing a target again.
    pub async fn restore_build(
        &self,
        input: &BuildInputManifest,
        ordinal: BuildOrdinal,
    ) -> Result<Option<BuildResult>, JobStoreError> {
        let (result_role, artifact_role) = roles(ordinal);
        let Some(bytes) = self.read(input, result_role).await? else {
            return Ok(None);
        };
        let result: BuildResult =
            serde_json::from_slice(&bytes).map_err(|_| JobStoreError::Invalid)?;
        result.validate(input, ordinal)?;

        if release_bytes(&result)? != bytes {
            return Err(JobStoreError::Precondition);
        }

        if let Some(expected) = &result.artifact {
            let artifact = self
                .read(input, artifact_role)
                .await?
                .ok_or(JobStoreError::Precondition)?;

            if artifact_identity(&artifact)? != *expected {
                return Err(JobStoreError::Precondition);
            }

            self.publish(input, artifact_role, &artifact, None).await?;
        }

        self.publish(input, result_role, &bytes, None).await?;

        Ok(Some(result))
    }

    /// Claims once, executes once, and freezes result bytes before output
    /// publication. A crash after output acceptance can therefore restore its result.
    pub async fn run_build(
        &self,
        input: &BuildInputManifest,
        ordinal: BuildOrdinal,
        builder: &dyn ReleaseBuilder,
    ) -> Result<BuildResult, JobStoreError> {
        if let Some(result) = self.restore_build(input, ordinal).await? {
            return Ok(result);
        }

        if ordinal == BuildOrdinal::B {
            let first = self
                .restore_build(input, BuildOrdinal::A)
                .await?
                .ok_or(JobStoreError::Precondition)?;

            if !first.cleanup_complete {
                return Err(JobStoreError::Precondition);
            }
        }

        if self.read(input, ReleaseRole::Input).await? != Some(release_bytes(input)?)
            || self
                .read(input, ReleaseRole::SourceCertificate)
                .await?
                .is_none()
        {
            return Err(JobStoreError::Precondition);
        }

        let claim = self
            .repository
            .claim(input.certified_source.project, &input.identity()?, ordinal)
            .await?
            .ok_or(JobStoreError::Precondition)?;
        let output = builder.build(input, ordinal);
        output.result.validate(input, ordinal)?;

        match (&output.result.artifact, &output.artifact) {
            (Some(identity), Some(bytes)) if artifact_identity(bytes)? == *identity => {}
            (None, None) => {}
            _ => return Err(JobStoreError::Precondition),
        }

        let (result_role, artifact_role) = roles(ordinal);
        let bytes = release_bytes(&output.result)?;
        let reference = release_reference(&bytes);
        self.repository
            .stage(
                input.certified_source.project,
                &input.identity()?,
                result_role,
                &reference,
                Some(&claim),
            )
            .await?;
        self.artifacts
            .put(input.certified_source.project, &reference, &bytes)
            .await?;

        if self
            .artifacts
            .get(input.certified_source.project, &reference)
            .await?
            != bytes
        {
            return Err(JobStoreError::Precondition);
        }

        if let Some(artifact) = &output.artifact {
            self.publish(input, artifact_role, artifact, Some(&claim))
                .await?;
        }

        self.publish(input, result_role, &bytes, Some(&claim))
            .await?;

        Ok(output.result)
    }

    /// Re-derives the comparison from retained independent outputs on every call.
    pub async fn compare(
        &self,
        input: &BuildInputManifest,
    ) -> Result<ReproducibilityEvidence, JobStoreError> {
        let a = self
            .restore_build(input, BuildOrdinal::A)
            .await?
            .ok_or(JobStoreError::Precondition)?;
        let b = self
            .restore_build(input, BuildOrdinal::B)
            .await?
            .ok_or(JobStoreError::Precondition)?;
        let evidence = compare_builds(input, &a, &b)?;
        self.publish(
            input,
            ReleaseRole::Reproducibility,
            &release_bytes(&evidence)?,
            None,
        )
        .await?;

        Ok(evidence)
    }
}

/// Durable exact-message capability. No public constructor or deserialization;
/// only verified publication under the release workflow creates it.
pub struct PersistedReleasePayload {
    invocation: BuildInvocationIdentity,
    digest: Sha256Digest,
}

impl PersistedReleasePayload {
    /// Exact invocation for which this message was frozen.
    pub fn invocation(&self) -> &BuildInvocationIdentity {
        &self.invocation
    }

    /// Identity of the exact persisted canonical message.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

impl ReleaseWorkflow<'_> {
    /// Revalidates retained build/output availability and freezes one exact message
    /// before authority composition can issue it. Message semantics are checked
    /// independently by the permit constructor.
    pub async fn prepare_payload(
        &self,
        input: &BuildInputManifest,
        bytes: &[u8],
    ) -> Result<PersistedReleasePayload, JobStoreError> {
        if self.read(input, ReleaseRole::Input).await? != Some(release_bytes(input)?)
            || self
                .read(input, ReleaseRole::SourceCertificate)
                .await?
                .is_none()
            || self.compare(input).await?.verdict != ReproducibilityVerdict::Reproducible
        {
            return Err(JobStoreError::Precondition);
        }

        let reference = self
            .publish(input, ReleaseRole::PermitPayload, bytes, None)
            .await?;

        Ok(PersistedReleasePayload {
            invocation: input.identity()?,
            digest: reference.sha256,
        })
    }
}
