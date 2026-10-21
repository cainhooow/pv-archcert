//! Eldermark issuance and independent offline verification.
//!
//! Eligibility is not certification. Only successful construction, signing and
//! strict verification can create an IssuedCertificate. No target execution lives here.
use archcert_application::validation::{ValidationObservation, ValidationPlan};
use archcert_crypto::{CertificateSigner, DetachedSignature, PublicKey, SigningFailure};
use archcert_domain::{
    Sha256Digest,
    source::{SourceSnapshot, digest_bytes},
};
use archcert_evidence::{
    EvidenceBundle, EvidenceError, EvidenceManifest, canonical_bytes, evaluation_digest,
};
use archcert_policy::{
    CertificationEligibility, EvaluationInput, ExpectedExecution, PolicyBundle, PolicyBundleRef,
    PolicyEvaluation,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use thiserror::Error;

/// Maximum envelope bytes before decoding, including one sentinel byte on reads.
pub const MAX_CERTIFICATE_BYTES: usize = 65_536;
/// Explicit fail-closed construction/signing/verification failures.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// No evaluation was supplied.
    #[error("missing evaluation")]
    MissingEvaluation,
    /// Only ELIGIBLE_FOR_CERTIFICATION can reach signing.
    #[error("evaluation not eligible; CERTIFICATE NOT ISSUED")]
    EvaluationNotEligible,
    /// Evaluation schema/evaluator semantics are unknown.
    #[error("unsupported evaluation schema")]
    UnsupportedEvaluationSchema,
    /// Incomplete required external source cannot reach certificate construction.
    #[error("source contains unresolved external material")]
    IncompleteSource,
    /// Source identity differs from the accepted snapshot.
    #[error("source identity mismatch")]
    SourceIdentityMismatch,
    /// Plan identity differs from the authority-resolved plan.
    #[error("plan identity mismatch")]
    PlanIdentityMismatch,
    /// Policy ID/version/digest differs from the authority selection.
    #[error("policy identity mismatch")]
    PolicyIdentityMismatch,
    /// References do not resolve to original trusted payloads.
    #[error("evidence binding mismatch")]
    EvidenceBindingMismatch,
    /// Re-evaluation disagrees with the supplied result.
    #[error("internal evaluation integrity failure")]
    InternalIntegrityFailure,
    /// Canonical representation was not constructible.
    #[error("canonicalization failed")]
    CanonicalizationFailed,
    /// Invalid field values or invariants.
    #[error("certificate construction or structure invalid")]
    CertificateConstructionFailed,
    /// Certificate schema is not explicitly supported.
    #[error("unsupported certificate schema")]
    UnsupportedCertificateSchema,
    /// Malformed, unknown, duplicate, or oversized JSON.
    #[error("invalid or oversized certificate encoding")]
    InvalidCertificateEncoding,
    /// Signing key is unavailable or signing failed.
    #[error(transparent)]
    Signing(#[from] SigningFailure),
    /// Certificate key identity differs from signer or pinned public key.
    #[error("signing key mismatch")]
    SigningKeyMismatch,
    /// Recomputed canonical SHA-256 differs from recorded identity.
    #[error("certificate digest mismatch")]
    CertificateDigestMismatch,
    /// Ed25519 verification failed; no CERTIFIED state exists.
    #[error("signature verification failed")]
    VerificationFailed,
}
impl From<EvidenceError> for CertificateError {
    fn from(e: EvidenceError) -> Self {
        match e {
            EvidenceError::EvidenceBindingMismatch => Self::EvidenceBindingMismatch,
            EvidenceError::CanonicalizationFailed => Self::CanonicalizationFailed,
        }
    }
}
/// Signed development issuance metadata. No expiration or revocation semantics.
pub struct IssuanceMetadata {
    /// Positive Unix seconds, signed audit metadata; not evaluation/source identity.
    pub issued_at: u64,
    /// Authority-controlled certifier identity, never obtained from target config.
    pub certifier: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyIdentity {
    id: String,
    version: String,
    sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    commit: String,
    tree: String,
    snapshot_sha256: String,
}
/// Every field in this payload is signed. The envelope digest and signature are
/// derived verification data, not additional authority claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema: u32,
    kind: String,
    authority: String,
    scope: String,
    project: String,
    repository: String,
    source: SourceIdentity,
    policy: PolicyIdentity,
    plan_sha256: String,
    evaluation_sha256: String,
    evidence_manifest_sha256: String,
    findings: Vec<String>,
    archcert_version: String,
    evaluator_version: String,
    certifier: String,
    runner: String,
    isolation_level: String,
    issued_at: u64,
    expiration: String,
    revocation: String,
    signature_algorithm: String,
    signing_key_id: String,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
}
fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Payload {
    fn validate(&self) -> Result<(), CertificateError> {
        if self.schema != 1 {
            return Err(CertificateError::UnsupportedCertificateSchema);
        }
        let project: archcert_domain::ProjectId =
            serde_json::from_value(serde_json::Value::String(self.project.clone()))
                .map_err(|_| CertificateError::CertificateConstructionFailed)?;
        let repository = archcert_domain::source::RepositoryId::parse(self.repository.clone())
            .map_err(|_| CertificateError::CertificateConstructionFailed)?;
        if self.kind != "ARCHCERT_CERTIFICATE"
            || self.authority != "DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY"
            || self.scope != "EXACT_SOURCE"
            || self.signature_algorithm != "Ed25519"
            || self.expiration != "NO EXPIRATION SEMANTICS YET"
            || self.revocation != "NOT IMPLEMENTED"
            || self.isolation_level != "ROOTLESS_OCI_SHARED_KERNEL"
            || self.runner != "archcert-docker-cli-v1/0.1.0"
            || self.evaluator_version != "archcert-policy-evaluator-v1/0.1.0"
            || !identifier(&self.archcert_version)
            || !identifier(&self.certifier)
            || !identifier(&self.policy.id)
            || !identifier(&self.policy.version)
            || project.to_string() != self.project
            || repository.as_str() != self.repository
            || self.repository.len() > 128
            || self.source.commit.len() != self.source.tree.len()
            || ![40, 64].contains(&self.source.commit.len())
            || !lower_hex(&self.source.commit, self.source.commit.len())
            || !lower_hex(&self.source.tree, self.source.tree.len())
            || self.issued_at == 0
            || self.issued_at > 9_007_199_254_740_991
            || self.findings.len() > 32
            || self.findings.windows(2).any(|w| w[0] >= w[1])
            || self.findings.iter().any(|s| !lower_hex(s, 64))
            || [
                &self.source.snapshot_sha256,
                &self.policy.sha256,
                &self.plan_sha256,
                &self.evaluation_sha256,
                &self.evidence_manifest_sha256,
                &self.signing_key_id,
            ]
            .iter()
            .any(|s| !lower_hex(s, 64))
        {
            return Err(CertificateError::CertificateConstructionFailed);
        }
        Ok(())
    }
}
/// Frozen owned signable payload and its computed identity. No mutable access.
#[derive(Debug)]
pub struct CanonicalCertificate {
    payload: Payload,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}
impl CanonicalCertificate {
    fn new(payload: Payload) -> Result<Self, CertificateError> {
        payload.validate()?;
        let bytes = canonical_bytes(&payload)?;
        let digest = digest_bytes(&bytes);
        Ok(Self {
            payload,
            bytes,
            digest,
        })
    }
    /// Exactly these bytes, rather than JSON presentation or the digest, are signed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Certificate instance identity: SHA-256 of all signed payload fields.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}
/// Trusted original inputs; neither project configuration nor deserialized reports
/// can construct source snapshots or authority plans. Borrowing ends at preparation.
pub struct IssuanceContext<'a> {
    /// Accepted immutable snapshot.
    pub source: &'a SourceSnapshot,
    /// Authority-resolved immutable plan.
    pub plan: &'a ValidationPlan,
    /// Independent controller-dispatched execution identities.
    pub executions: &'a [ExpectedExecution],
    /// Controller observations, after target execution and cleanup.
    pub observations: &'a [ValidationObservation],
    /// Detailed records from the same controller executions, retained separately.
    pub execution_records: &'a [archcert_domain::execution::ExecutionEvidence],
    /// Immutable authority policy.
    pub bundle: &'a PolicyBundle,
    /// Separately selected authority identity.
    pub selected: &'a PolicyBundleRef,
}
/// Owned immutable pre-signing result. No source, runner, or mutable references
/// survive preparation. Mutating the caller's originals cannot change these bytes.
#[derive(Debug)]
pub struct CertificateDraft {
    certificate: CanonicalCertificate,
    manifest: EvidenceManifest,
    bundle: EvidenceBundle,
    key: PublicKey,
}
impl CertificateDraft {
    /// Rejects ineligibility and mismatches before any signer call. Recomputes the
    /// exact evaluation to detect stale/edited findings, eligibility and references.
    pub fn prepare(
        context: IssuanceContext<'_>,
        evaluation: Option<PolicyEvaluation>,
        metadata: IssuanceMetadata,
        key: PublicKey,
    ) -> Result<Self, CertificateError> {
        Self::prepare_inner(context, evaluation, metadata, key, None)
    }
    /// Ironcrest preparation requires the accepted review/challenge evidence in
    /// addition to independently recomputing all deterministic requirements.
    pub fn prepare_ironcrest(
        context: IssuanceContext<'_>,
        evaluation: Option<PolicyEvaluation>,
        metadata: IssuanceMetadata,
        key: PublicKey,
        ironcrest: &archcert_application::ironcrest::IroncrestIssuanceEvidence,
    ) -> Result<Self, CertificateError> {
        Self::prepare_inner(context, evaluation, metadata, key, Some(ironcrest))
    }
    fn prepare_inner(
        context: IssuanceContext<'_>,
        evaluation: Option<PolicyEvaluation>,
        metadata: IssuanceMetadata,
        key: PublicKey,
        ironcrest: Option<&archcert_application::ironcrest::IroncrestIssuanceEvidence>,
    ) -> Result<Self, CertificateError> {
        if context.bundle.identity().id == archcert_policy::IRONCREST_CONTROLLED_POLICY_ID
            && ironcrest.is_none()
        {
            return Err(CertificateError::EvidenceBindingMismatch);
        }
        let e = evaluation.ok_or(CertificateError::MissingEvaluation)?;
        if e.schema != 1 || e.evaluator_version != "archcert-policy-evaluator-v1/0.1.0" {
            return Err(CertificateError::UnsupportedEvaluationSchema);
        }
        if e.eligibility != CertificationEligibility::EligibleForCertification {
            return Err(CertificateError::EvaluationNotEligible);
        }
        context
            .source
            .require_complete()
            .map_err(|_| CertificateError::IncompleteSource)?;
        if e.source != *context.source.identity() {
            return Err(CertificateError::SourceIdentityMismatch);
        }
        if e.plan_sha256
            != context
                .plan
                .digest()
                .map_err(|_| CertificateError::CanonicalizationFailed)?
        {
            return Err(CertificateError::PlanIdentityMismatch);
        }
        if &e.policy != context.bundle.identity() || context.selected != context.bundle.identity() {
            return Err(CertificateError::PolicyIdentityMismatch);
        }
        // Resolve references before re-evaluation; no large execution payload is
        // duplicated in the signable certificate.
        EvidenceManifest::build(&e, context.observations)?;
        let recomputed = archcert_policy::evaluate(
            context.bundle,
            context.selected,
            EvaluationInput {
                source: context.source,
                plan: context.plan,
                executions: context.executions,
                observations: context.observations,
                evaluated_at: e.evaluated_at,
            },
        )
        .map_err(|_| CertificateError::InternalIntegrityFailure)?;
        if canonical_bytes(&e)? != canonical_bytes(&recomputed)? {
            return Err(CertificateError::InternalIntegrityFailure);
        }
        // This schema may claim ROOTLESS_OCI_SHARED_KERNEL only with an actual
        // nonempty, completely bound controller execution set and established
        // environment facts, even if a future authority policy omits that rule.
        use archcert_application::validation::{ObservationFact, ObservationKind};
        if context.plan.steps().is_empty() || context.executions.len() != context.plan.steps().len()
        {
            return Err(CertificateError::EvidenceBindingMismatch);
        }
        for o in context.observations {
            let step = context
                .plan
                .steps()
                .iter()
                .find(|s| s.id() == o.id.step)
                .ok_or(CertificateError::EvidenceBindingMismatch)?;
            let kind = match &o.fact {
                ObservationFact::SourceIdentityMatched => ObservationKind::SourceIdentityMatched,
                ObservationFact::NetworkDenied => ObservationKind::NetworkDenied,
                ObservationFact::EnvironmentEstablished { .. } => {
                    ObservationKind::EnvironmentEstablished
                }
                ObservationFact::ExecutionFinished { category, .. } => {
                    if *category != step.evidence_category() {
                        return Err(CertificateError::EvidenceBindingMismatch);
                    }
                    ObservationKind::ExecutionFinished
                }
            };
            if o.producer != "archcert-docker-cli-v1/0.1.0"
                || o.profile != step.profile().name()
                || kind != o.id.kind
                || !context
                    .executions
                    .iter()
                    .any(|e| e.step == o.id.step && e.execution == o.id.execution)
            {
                return Err(CertificateError::EvidenceBindingMismatch);
            }
        }
        for step in context.plan.steps() {
            if !context.observations.iter().any(|o| {
                o.id.step == step.id()
                    && matches!(o.fact, ObservationFact::EnvironmentEstablished { .. })
            }) {
                return Err(CertificateError::EvidenceBindingMismatch);
            }
        }
        if context.execution_records.len() != context.executions.len() {
            return Err(CertificateError::EvidenceBindingMismatch);
        }
        let mut record_executions = std::collections::BTreeSet::new();
        let mut record_observations = std::collections::BTreeSet::new();
        for record in context.execution_records {
            if !record_executions.insert(record.execution.to_string()) || record.source != e.source
            {
                return Err(CertificateError::EvidenceBindingMismatch);
            }
            let expected = context
                .executions
                .iter()
                .find(|x| x.execution == record.execution)
                .ok_or(CertificateError::EvidenceBindingMismatch)?;
            let step = context
                .plan
                .steps()
                .iter()
                .find(|s| s.id() == expected.step)
                .ok_or(CertificateError::EvidenceBindingMismatch)?;
            for o in ValidationObservation::from_execution(context.plan, step, record)
                .map_err(|_| CertificateError::EvidenceBindingMismatch)?
            {
                record_observations.insert(canonical_bytes(&o)?);
            }
        }
        let supplied_observations = context
            .observations
            .iter()
            .map(canonical_bytes)
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        if record_observations != supplied_observations {
            return Err(CertificateError::EvidenceBindingMismatch);
        }
        let bundle = EvidenceBundle::build(&e, context.observations, context.execution_records)?;
        let manifest =
            EvidenceManifest::build_with_bundle(&e, context.observations, Some(&bundle))?;
        let manifest = if let Some(ironcrest) = ironcrest {
            let binding = ironcrest.binding();
            if binding.pin.project != context.source.project()
                || binding.pin.repository != *context.source.repository()
                || binding.pin.source != *context.source.identity()
                || binding.plan_sha256 != e.plan_sha256
                || binding.pin.policy.id != e.policy.id
                || binding.pin.policy.version != e.policy.version
                || binding.pin.policy.sha256 != e.policy.sha256
            {
                return Err(CertificateError::EvidenceBindingMismatch);
            }
            manifest.with_ironcrest(binding)?
        } else {
            manifest
        };
        let mut findings: Vec<_> = e
            .findings
            .iter()
            .map(|f| f.id.as_str().to_owned())
            .collect();
        findings.sort();
        let payload = Payload {
            schema: 1,
            kind: "ARCHCERT_CERTIFICATE".into(),
            authority: "DEVELOPMENT ONLY / NOT PRODUCTION AUTHORITY".into(),
            scope: "EXACT_SOURCE".into(),
            project: context.source.project().to_string(),
            repository: context.source.repository().as_str().into(),
            source: SourceIdentity {
                commit: e.source.commit.as_str().into(),
                tree: e.source.tree.as_str().into(),
                snapshot_sha256: e.source.snapshot_sha256.as_str().into(),
            },
            policy: PolicyIdentity {
                id: e.policy.id,
                version: e.policy.version,
                sha256: e.policy.sha256.as_str().into(),
            },
            plan_sha256: e.plan_sha256.as_str().into(),
            evaluation_sha256: evaluation_digest(&recomputed)?.as_str().into(),
            evidence_manifest_sha256: manifest.digest().as_str().into(),
            findings,
            archcert_version: env!("CARGO_PKG_VERSION").into(),
            evaluator_version: e.evaluator_version.into(),
            certifier: metadata.certifier,
            runner: "archcert-docker-cli-v1/0.1.0".into(),
            isolation_level: "ROOTLESS_OCI_SHARED_KERNEL".into(),
            issued_at: metadata.issued_at,
            expiration: "NO EXPIRATION SEMANTICS YET".into(),
            revocation: "NOT IMPLEMENTED".into(),
            signature_algorithm: "Ed25519".into(),
            signing_key_id: key.key_id().as_str().into(),
        };
        Ok(Self {
            certificate: CanonicalCertificate::new(payload)?,
            manifest,
            bundle,
            key,
        })
    }
    /// Immutable canonical payload for inspection/retention before authority use.
    pub fn certificate(&self) -> &CanonicalCertificate {
        &self.certificate
    }
    /// Separate manifest; detailed observations/logs remain in the evidence bundle.
    pub fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }
    /// Detailed immutable bundle; the manifest binds its digest.
    pub fn evidence_bundle(&self) -> &EvidenceBundle {
        &self.bundle
    }
    /// Signs only the frozen canonical payload and independently verifies the result
    /// under the selected public key before constructing a CERTIFIED capability.
    pub fn issue(
        self,
        signer: &impl CertificateSigner,
    ) -> Result<IssuedCertificate, CertificateError> {
        if signer.key_id() != self.key.key_id() {
            return Err(CertificateError::SigningKeyMismatch);
        }
        let signature = signer.sign(self.certificate.bytes())?;
        let envelope = CertificateEnvelope {
            payload: self.certificate.payload,
            certificate_sha256: self.certificate.digest.as_str().into(),
            signature: signature.to_hex(),
            public_key: self.key.to_hex(),
        };
        let verified = envelope.verify(&self.key)?;
        Ok(IssuedCertificate { envelope, verified })
    }
}
/// Strict signed envelope. Parsing creates no certification state. Embedded public
/// material is convenience data; callers must provide an independently trusted key.
#[derive(Debug, Serialize)]
pub struct CertificateEnvelope {
    payload: Payload,
    certificate_sha256: String,
    signature: String,
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedEnvelope {
    payload: Payload,
    certificate_sha256: String,
    signature: String,
    public_key: String,
}
impl CertificateEnvelope {
    /// Reads bounded strict JSON directly into typed structs: duplicate known fields
    /// and unknown fields at every object depth reject before canonicalization.
    pub fn read(reader: impl Read) -> Result<Self, CertificateError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_CERTIFICATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CertificateError::InvalidCertificateEncoding)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(CertificateError::InvalidCertificateEncoding);
        }
        let parsed: ParsedEnvelope = serde_json::from_slice(&bytes)
            .map_err(|_| CertificateError::InvalidCertificateEncoding)?;
        let envelope = Self {
            payload: parsed.payload,
            certificate_sha256: parsed.certificate_sha256,
            signature: parsed.signature,
            public_key: parsed.public_key,
        };
        envelope.payload.validate()?;
        if !lower_hex(&envelope.certificate_sha256, 64)
            || DetachedSignature::from_hex(&envelope.signature).is_err()
            || PublicKey::from_hex(&envelope.public_key).is_err()
        {
            return Err(CertificateError::InvalidCertificateEncoding);
        }
        Ok(envelope)
    }
    /// Offline verification needs no Git, Docker, workspace, network, database or
    /// private key. No embedded-key trust fallback is provided.
    pub fn verify(&self, trusted_key: &PublicKey) -> Result<VerifiedCertificate, CertificateError> {
        let certificate = CanonicalCertificate::new(self.payload.clone())?;
        if certificate.digest.as_str() != self.certificate_sha256 {
            return Err(CertificateError::CertificateDigestMismatch);
        }
        if self.public_key != trusted_key.to_hex()
            || self.payload.signing_key_id != trusted_key.key_id().as_str()
        {
            return Err(CertificateError::SigningKeyMismatch);
        }
        let signature = DetachedSignature::from_hex(&self.signature)
            .map_err(|_| CertificateError::VerificationFailed)?;
        trusted_key
            .verify(certificate.bytes(), &signature)
            .map_err(|_| CertificateError::VerificationFailed)?;
        Ok(VerifiedCertificate {
            certificate_sha256: self.certificate_sha256.clone(),
            source: self.payload.source.clone(),
            policy: self.payload.policy.clone(),
            certifier: self.payload.certifier.clone(),
            signing_key_id: self.payload.signing_key_id.clone(),
        })
    }
    /// Small reviewable JSON presentation; this representation is never signed.
    pub fn to_json(&self) -> Result<Vec<u8>, CertificateError> {
        serde_json::to_vec_pretty(self).map_err(|_| CertificateError::CanonicalizationFailed)
    }
}
/// Successful verification proof. Private construction prevents parsing or signer
/// attempts from manufacturing CERTIFIED. This authenticates claims, not universal security.
#[derive(Debug, Serialize)]
pub struct VerifiedCertificate {
    certificate_sha256: String,
    source: SourceIdentity,
    policy: PolicyIdentity,
    certifier: String,
    signing_key_id: String,
}
impl VerifiedCertificate {
    /// Structured public verification output with explicit governance limitations.
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({"status":"CERTIFIED","signature":"SIGNATURE VALID","structure":"CERTIFICATE STRUCTURE VALID",
            "certificate_sha256":self.certificate_sha256,"source":self.source,"policy":self.policy,
            "certifier":self.certifier,"signing_key_id":self.signing_key_id,"scope":"EXACT_SOURCE",
            "notice":"DEVELOPMENT CERTIFICATE / NOT PRODUCTION AUTHORITY", "revocation":"NOT IMPLEMENTED",
            "expiration":"NO EXPIRATION SEMANTICS YET", "meaning":"Signed ArchCert claims are authentic under the selected trusted key."})
    }
}
/// Only construction + signing + verification creates this real certification result.
#[derive(Debug)]
pub struct IssuedCertificate {
    envelope: CertificateEnvelope,
    verified: VerifiedCertificate,
}
impl IssuedCertificate {
    /// Verified certificate suitable for offline retention.
    pub fn envelope(&self) -> &CertificateEnvelope {
        &self.envelope
    }
    /// Proof-backed certification report.
    pub fn verification(&self) -> &VerifiedCertificate {
        &self.verified
    }
}
