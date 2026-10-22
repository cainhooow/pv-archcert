//! A release permit authenticates exact deployable bytes, separately from source.

use super::*;
use archcert_application::release::*;
use archcert_domain::{ProjectId, release::*, source::RepositoryId};

/// Release failures do not create authorization, even with a valid source certificate.
#[derive(Debug, Error)]
pub enum ReleaseError {
    /// Source certificate, authority pins or release evidence disagree.
    #[error("release evidence or authority binding invalid")]
    Binding,
    /// Byte-equal independent complete outputs are required.
    #[error("release is not reproducible; PERMIT NOT ISSUED")]
    NotEligible,
    /// Malformed, unknown, duplicate, oversized or noncanonical payload.
    #[error("invalid release permit encoding or structure")]
    Encoding,
    /// Signature, permit ID or explicit trust key failed verification.
    #[error("release permit verification failed")]
    Verification,
    /// Actual deployable bytes do not match the permit and requested scope.
    #[error("deployment artifact or scope mismatch")]
    Artifact,
    /// Isolated development signer failure.
    #[error(transparent)]
    Signing(#[from] SigningFailure),
}

impl From<archcert_application::jobs::JobStoreError> for ReleaseError {
    fn from(_: archcert_application::jobs::JobStoreError) -> Self {
        Self::Binding
    }
}

/// Independently checks existing schema-1 semantics, exact scope/source and
/// selected source authority/policy before build admission and again at issuance.
pub fn verify_source(
    input: &BuildInputManifest,
    recipe: &RustReleaseRecipe,
    certificate: &CertificateEnvelope,
    source_key: &PublicKey,
    release_key: &PublicKey,
) -> Result<(), ReleaseError> {
    input.validate(recipe)?;
    certificate
        .verify(source_key)
        .map_err(|_| ReleaseError::Verification)?;
    let p = &certificate.payload;
    let source = &input.certified_source;

    if p.project != source.project.to_string()
        || p.repository != source.repository.as_str()
        || p.source.commit != source.source.commit.as_str()
        || p.source.tree != source.source.tree.as_str()
        || p.source.snapshot_sha256 != source.source.snapshot_sha256.as_str()
        || certificate.certificate_sha256 != source.certificate_sha256.as_str()
        || p.policy.sha256 != input.source_policy_sha256.as_str()
        || p.signing_key_id != input.source_authority_key_sha256.as_str()
        || release_key.key_id().as_str() != input.release_authority_key_sha256.as_str()
    {
        return Err(ReleaseError::Binding);
    }

    Ok(())
}

/// Returns exact scope/source only after existing offline certificate verification.
/// This is source certification identity, never artifact release authorization.
pub fn certified_source(
    certificate: &CertificateEnvelope,
    trusted_key: &PublicKey,
) -> Result<CertifiedSourceIdentity, ReleaseError> {
    certificate
        .verify(trusted_key)
        .map_err(|_| ReleaseError::Verification)?;
    let p = &certificate.payload;

    Ok(CertifiedSourceIdentity {
        project: p.project.parse().map_err(|_| ReleaseError::Binding)?,
        repository: RepositoryId::parse(p.repository.clone()).map_err(|_| ReleaseError::Binding)?,
        source: archcert_domain::SourceIdentity {
            commit: archcert_domain::GitObjectId::parse(p.source.commit.clone())
                .map_err(|_| ReleaseError::Binding)?,
            tree: archcert_domain::GitObjectId::parse(p.source.tree.clone())
                .map_err(|_| ReleaseError::Binding)?,
            snapshot_sha256: Sha256Digest::parse(p.source.snapshot_sha256.clone())
                .map_err(|_| ReleaseError::Binding)?,
        },
        certificate_sha256: Sha256Digest::parse(certificate.certificate_sha256.clone())
            .map_err(|_| ReleaseError::Binding)?,
    })
}

/// Only these frozen fields are signed. Detailed logs/results remain external.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitPayload {
    schema: u32,
    kind: String,
    authority: String,
    scope: String,
    source: CertifiedSourceIdentity,
    invocation: BuildInvocationIdentity,
    recipe: BuildRecipeIdentity,
    environment: BuildEnvironmentIdentity,
    reproducibility: ReproducibilityIdentity,
    artifact: ReleaseArtifactIdentity,
    policy: String,
    policy_sha256: Sha256Digest,
    signature_algorithm: String,
    signing_key_id: String,
    expiration: String,
    revocation: String,
}

impl PermitPayload {
    fn validate(&self) -> Result<(), ReleaseError> {
        validate_artifact(&self.artifact)?;

        if self.schema != 1
            || self.kind != "ARCHCERT_RELEASE_PERMIT"
            || self.authority != "DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY"
            || self.scope != "EXACT_ARTIFACT_FROM_EXACT_SOURCE"
            || self.policy != RELEASE_POLICY
            || self.policy_sha256 != release_policy_digest()
            || self.signature_algorithm != "Ed25519"
            || !lower_hex(&self.signing_key_id, 64)
            || self.expiration != "NO EXPIRATION SEMANTICS YET"
            || self.revocation != "NOT IMPLEMENTED"
        {
            return Err(ReleaseError::Encoding);
        }

        Ok(())
    }
}

/// Trusted retained inputs, revalidated independently of any eligibility flag.
pub struct ReleasePermitContext<'a> {
    /// Frozen admitted build input.
    pub input: &'a BuildInputManifest,
    /// Independently selected authority recipe.
    pub recipe: &'a RustReleaseRecipe,
    /// Existing source certificate, not an existence assertion.
    pub source_certificate: &'a CertificateEnvelope,
    /// Explicit source authority trust key.
    pub source_key: &'a PublicKey,
    /// Explicit release authority trust key.
    pub release_key: &'a PublicKey,
    /// Accepted A result with actual runtime evidence.
    pub a: &'a BuildResult,
    /// Accepted B result from a different execution/workspace.
    pub b: &'a BuildResult,
    /// Retained comparison, independently recomputed here.
    pub reproducibility: &'a ReproducibilityEvidence,
    /// Artifact read back from immutable storage, not target path text.
    pub artifact: &'a [u8],
}

/// Owned exact canonical message. No target, policy flag or JSON can create it.
pub struct ReleasePermitDraft {
    payload: PermitPayload,
    bytes: Vec<u8>,
    identity: ReleasePermitIdentity,
    public_key: PublicKey,
}

impl ReleasePermitDraft {
    /// Requires valid exact-source certification and deterministic release evidence.
    pub fn prepare(context: ReleasePermitContext<'_>) -> Result<Self, ReleaseError> {
        let c = context;
        verify_source(
            c.input,
            c.recipe,
            c.source_certificate,
            c.source_key,
            c.release_key,
        )?;
        let comparison = compare_builds(c.input, c.a, c.b)?;

        if comparison != *c.reproducibility {
            return Err(ReleaseError::Binding);
        }

        if comparison.verdict != ReproducibilityVerdict::Reproducible {
            return Err(ReleaseError::NotEligible);
        }

        let artifact = artifact_identity(c.artifact)?;

        if c.a.artifact.as_ref() != Some(&artifact) || c.b.artifact.as_ref() != Some(&artifact) {
            return Err(ReleaseError::Binding);
        }

        let payload = PermitPayload {
            schema: 1,
            kind: "ARCHCERT_RELEASE_PERMIT".into(),
            authority: "DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY".into(),
            scope: "EXACT_ARTIFACT_FROM_EXACT_SOURCE".into(),
            source: c.input.certified_source.clone(),
            invocation: c.input.identity()?,
            recipe: c.input.recipe_identity.clone(),
            environment: c.input.environment_identity.clone(),
            reproducibility: ReproducibilityIdentity(digest_bytes(&release_bytes(&comparison)?)),
            artifact,
            policy: RELEASE_POLICY.into(),
            policy_sha256: release_policy_digest(),
            signature_algorithm: "Ed25519".into(),
            signing_key_id: c.release_key.key_id().as_str().into(),
            expiration: "NO EXPIRATION SEMANTICS YET".into(),
            revocation: "NOT IMPLEMENTED".into(),
        };
        payload.validate()?;
        let bytes = release_bytes(&payload)?;
        let identity = ReleasePermitIdentity(digest_bytes(&bytes));

        Ok(Self {
            payload,
            bytes,
            identity,
            public_key: c.release_key.clone(),
        })
    }

    /// Exact message to persist before calling the signer.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the complete canonical payload.
    pub fn identity(&self) -> &ReleasePermitIdentity {
        &self.identity
    }

    /// Requires a verified exact-message durable checkpoint. Deterministic same-
    /// message signing may repeat after a crash, but cannot select a new payload.
    pub fn issue(
        self,
        durable: &PersistedReleasePayload,
        signer: &dyn CertificateSigner,
    ) -> Result<ReleasePermitEnvelope, ReleaseError> {
        if durable.invocation() != &self.payload.invocation
            || durable.digest() != &self.identity.0
            || signer.key_id() != self.public_key.key_id()
        {
            return Err(ReleaseError::Binding);
        }

        let signature = signer.sign(&self.bytes)?;
        let envelope = ReleasePermitEnvelope {
            payload: self.payload,
            permit_sha256: self.identity.0,
            signature: signature.to_hex(),
            public_key: self.public_key.to_hex(),
        };
        envelope.verify(&self.public_key)?;

        Ok(envelope)
    }
}

/// Strict envelope. Read/verify never treats an embedded public key as authority.
#[derive(Debug, Serialize)]
pub struct ReleasePermitEnvelope {
    payload: PermitPayload,
    permit_sha256: Sha256Digest,
    signature: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedPermit {
    payload: PermitPayload,
    permit_sha256: Sha256Digest,
    signature: String,
    public_key: String,
}

impl ReleasePermitEnvelope {
    /// Bounded strict decoding; duplicate and unknown fields reject before hashing.
    pub fn read(reader: impl Read) -> Result<Self, ReleaseError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_CERTIFICATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseError::Encoding)?;

        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(ReleaseError::Encoding);
        }

        let parsed: ParsedPermit =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Encoding)?;
        parsed.payload.validate()?;
        DetachedSignature::from_hex(&parsed.signature).map_err(|_| ReleaseError::Encoding)?;
        PublicKey::from_hex(&parsed.public_key).map_err(|_| ReleaseError::Encoding)?;

        let envelope = Self {
            payload: parsed.payload,
            permit_sha256: parsed.permit_sha256,
            signature: parsed.signature,
            public_key: parsed.public_key,
        };

        // Imported historical identity types keep their existing parsers. Require
        // exact structural round-trip here so ignored nested fields or normalized
        // hexadecimal/UUID spellings cannot enter the new signed grammar.
        let original: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Encoding)?;
        let retained = serde_json::to_value(&envelope).map_err(|_| ReleaseError::Encoding)?;

        if original != retained {
            return Err(ReleaseError::Encoding);
        }

        Ok(envelope)
    }

    /// Authenticates the recorded release authorization, not actual artifact bytes.
    /// Use authorize_artifact to gate deployment of a file.
    pub fn verify(&self, trusted_key: &PublicKey) -> Result<ReleasePermitIdentity, ReleaseError> {
        self.payload.validate()?;
        let bytes = release_bytes(&self.payload)?;

        if digest_bytes(&bytes) != self.permit_sha256
            || self.public_key != trusted_key.to_hex()
            || self.payload.signing_key_id != trusted_key.key_id().as_str()
        {
            return Err(ReleaseError::Verification);
        }

        trusted_key
            .verify(
                &bytes,
                &DetachedSignature::from_hex(&self.signature)
                    .map_err(|_| ReleaseError::Verification)?,
            )
            .map_err(|_| ReleaseError::Verification)?;

        Ok(ReleasePermitIdentity(self.permit_sha256.clone()))
    }

    /// Local offline deployment gate: verify the permit and exact actual bounded
    /// bytes under explicit scope and trust. Caller must deploy these same bytes.
    pub fn authorize_artifact(
        &self,
        trusted_key: &PublicKey,
        project: ProjectId,
        repository: &RepositoryId,
        artifact: &[u8],
    ) -> Result<ReleasePermitIdentity, ReleaseError> {
        let identity = self.verify(trusted_key)?;

        if self.payload.source.project != project
            || self.payload.source.repository != *repository
            || artifact_identity(artifact)? != self.payload.artifact
        {
            return Err(ReleaseError::Artifact);
        }

        Ok(identity)
    }

    /// Canonical envelope for immutable publication; the payload is the signed message.
    pub fn to_json(&self) -> Result<Vec<u8>, ReleaseError> {
        Ok(release_bytes(self)?)
    }
}
