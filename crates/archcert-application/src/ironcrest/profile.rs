//! Versioned authority controls, provisioned outside accepted repository data.
use super::*;
use crate::{
    challenges::{AuthorityChallengeRegistry, IDEMPOTENCY_TEMPLATE},
    knowledge::{CanonicalArtifact, KnowledgeError, KnowledgeLimits},
    semantic::{ReviewerSelection, SemanticLimits, SemanticReviewRequest},
};

/// Fixed gate algorithm. Changing its semantics requires a new profile version.
pub const IRONCREST_GATE_ALGORITHM: &str = "archcert-semantic-gate-v1/1.0.0";
/// Separately versioned authority profile; historical policies do not opt in.
pub const IRONCREST_PROFILE_ID: &str = "ironcrest-controlled-v1";

/// Immutable authority capability. There is no target parser or deserializer.
/// The initial profile supports local exact replay and denies external disclosure.
#[derive(Debug)]
pub struct IroncrestAuthorityProfile {
    artifact: CanonicalArtifact,
    policy: PolicyPin,
    extractor_registry: Sha256Digest,
    authority_bundles: Vec<Sha256Digest>,
    challenge_registry: Sha256Digest,
}
impl IroncrestAuthorityProfile {
    /// Authority composition supplies the deterministic policy and scoped knowledge
    /// identities. All semantic/challenge behavior belongs to this fixed version.
    pub fn controlled(
        policy: PolicyPin,
        extractor_registry: Sha256Digest,
        authority_bundles: Vec<Sha256Digest>,
        registry: &AuthorityChallengeRegistry,
    ) -> Result<Self, KnowledgeError> {
        if policy.id.is_empty()
            || policy.version.is_empty()
            || authority_bundles.len() > 16
            || authority_bundles
                .windows(2)
                .any(|w| w[0].as_str() >= w[1].as_str())
        {
            return Err(KnowledgeError::Invalid);
        }
        let challenge_registry = registry.artifact().digest().clone();
        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({
                "schema":1,"kind":"ARCHCERT_IRONCREST_AUTHORITY_PROFILE",
                "id":IRONCREST_PROFILE_ID,"version":"1.0.0","policy":policy,
                "semantic_required":true,"reviewer":ReviewerSelection::replay(),
                "extractor_registry_sha256":extractor_registry,"authority_bundles":authority_bundles,
                "challenge_registry_sha256":challenge_registry,
                "gate_algorithm":IRONCREST_GATE_ALGORITHM,
                "gate_behavior":{"block":"VETO_ADMISSION_AND_ISSUANCE",
                    "require_more_evidence":"BLOCK_UNRESOLVED_CONTEXT",
                    "continue":"NO_DETERMINISTIC_PROOF"},
                "required_challenges":[{"template_id":IDEMPOTENCY_TEMPLATE,"minimum_repetitions":3}],
                "knowledge_limits":KnowledgeLimits::default(),"semantic_limits":SemanticLimits::default(),
                "external_disclosure":"DENIED"
            }),
            65536,
        )?;
        Ok(Self {
            artifact,
            policy,
            extractor_registry,
            authority_bundles,
            challenge_registry,
        })
    }
    /// Canonical profile bytes and identity, retained as immutable evidence.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
    /// Fixed mandatory semantic bounds.
    pub fn semantic_limits(&self) -> SemanticLimits {
        SemanticLimits::default()
    }
    /// Fixed passive knowledge bounds.
    pub fn knowledge_limits(&self) -> KnowledgeLimits {
        KnowledgeLimits::default()
    }
    /// Only supported local provider identity. This grants no invocation claim.
    pub fn reviewer(&self) -> ReviewerSelection {
        ReviewerSelection::replay()
    }
    /// Reject weaker, foreign or stale session authority pins.
    pub fn validate_pin(&self, pin: &IroncrestSessionPin) -> Result<(), JobStoreError> {
        pin.validate()?;
        if pin.policy != self.policy
            || pin.authority_profile_sha256 != *self.artifact.digest()
            || pin.extractor_registry_sha256 != self.extractor_registry
            || pin.authority_bundles != self.authority_bundles
            || pin.challenge_registry_sha256 != self.challenge_registry
        {
            return Err(JobStoreError::Precondition);
        }
        Ok(())
    }
    /// A request cannot weaken mandatory review, limits, disclosure or provider.
    pub fn validate_request(&self, request: &SemanticReviewRequest) -> Result<(), JobStoreError> {
        let b = request.binding();
        if b.policy != self.policy
            || b.authority_profile_sha256 != *self.artifact.digest()
            || b.authority_bundles != self.authority_bundles
            || request.selection() != &self.reviewer()
            || crate::knowledge::canonical_bytes(&request.limits())
                .map_err(|_| JobStoreError::Invalid)?
                != crate::knowledge::canonical_bytes(&self.semantic_limits())
                    .map_err(|_| JobStoreError::Invalid)?
        {
            return Err(JobStoreError::Precondition);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::{GitObjectId, source::digest_bytes};
    fn pin() -> Result<IroncrestSessionPin, Box<dyn std::error::Error>> {
        Ok(IroncrestSessionPin {
            project: ProjectId::new(),
            repository: RepositoryId::parse("fixture/source")?,
            actor: GitActorId::parse(JobId::new().to_string())?,
            submission: SourceSubmissionId::new(),
            source: SourceIdentity {
                commit: GitObjectId::parse("a".repeat(40))?,
                tree: GitObjectId::parse("b".repeat(40))?,
                snapshot_sha256: digest_bytes(b"source"),
            },
            baseline: None,
            policy: PolicyPin {
                id: "fixture-policy-v1".into(),
                version: "1.0.0".into(),
                sha256: digest_bytes(b"policy"),
            },
            base_plan_sha256: digest_bytes(b"base"),
            authority_profile_sha256: digest_bytes(b"unselected"),
            extractor_registry_sha256: digest_bytes(b"extractors"),
            challenge_registry_sha256: digest_bytes(b"unselected"),
            authority_bundles: vec![],
        })
    }
    #[test]
    fn profile_is_versioned_and_binds_every_authority_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = AuthorityChallengeRegistry::controlled()?;
        let mut pin = pin()?;
        let profile = IroncrestAuthorityProfile::controlled(
            pin.policy.clone(),
            pin.extractor_registry_sha256.clone(),
            vec![],
            &registry,
        )?;
        pin.authority_profile_sha256 = profile.artifact().digest().clone();
        pin.challenge_registry_sha256 = registry.artifact().digest().clone();
        profile.validate_pin(&pin)?;
        for field in 0..5 {
            let mut other = pin.clone();
            match field {
                0 => other.policy.sha256 = digest_bytes(b"other"),
                1 => other.authority_profile_sha256 = digest_bytes(b"other"),
                2 => other.extractor_registry_sha256 = digest_bytes(b"other"),
                3 => other.authority_bundles.push(digest_bytes(b"other")),
                _ => other.challenge_registry_sha256 = digest_bytes(b"other"),
            }
            assert!(profile.validate_pin(&other).is_err());
        }
        let body: serde_json::Value = serde_json::from_slice(profile.artifact().bytes())?;
        assert_eq!(body["semantic_required"], true);
        assert_eq!(body["external_disclosure"], "DENIED");
        assert_eq!(body["id"], IRONCREST_PROFILE_ID);
        Ok(())
    }
}
