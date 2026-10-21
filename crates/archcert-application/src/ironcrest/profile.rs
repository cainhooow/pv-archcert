//! Versioned authority controls, provisioned outside accepted repository data.

use super::*;
use crate::{
    challenges::{AuthorityChallengeRegistry, IDEMPOTENCY_TEMPLATE},
    knowledge::{CanonicalArtifact, KnowledgeError, KnowledgeLimits},
    semantic::{ReviewerSelection, SemanticLimits, SemanticReviewRequest},
};

/// Separately selected deterministic bundle for the controlled Ironcrest lifecycle.
pub const IRONCREST_CONTROLLED_POLICY_ID: &str = "archcert-ironcrest-controlled-v1";

/// Fixed gate algorithm. Changing its semantics requires a new profile version.
pub const IRONCREST_GATE_ALGORITHM: &str = "archcert-ironcrest-gate-v1/1.0.0";

/// Separately versioned authority profile; historical policies do not opt in.
pub const IRONCREST_PROFILE_ID: &str = "ironcrest-controlled-v1";

/// Explicit pending-challenge gate semantics; the earlier admission-only 1.0.0
/// profile is not silently reinterpreted or selected on recovery.
pub const IRONCREST_PROFILE_VERSION: &str = "1.1.0";

/// Immutable authority capability. There is no target parser or deserializer.
/// The initial profile supports local exact replay and denies external disclosure.
#[derive(Debug)]
pub struct IroncrestAuthorityProfile {
    artifact: CanonicalArtifact,
    packaging: Option<crate::semantic::SemanticPackagingPolicy>,
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
                "schema": 1,
                "kind": "ARCHCERT_IRONCREST_AUTHORITY_PROFILE",
                "id": IRONCREST_PROFILE_ID,
                "version": IRONCREST_PROFILE_VERSION,
                "policy": policy,
                "semantic_required": true,
                "reviewer": ReviewerSelection::replay(),
                "extractor_registry_sha256": extractor_registry,
                "authority_bundles": authority_bundles,
                "challenge_registry_sha256": challenge_registry,
                "gate_algorithm": IRONCREST_GATE_ALGORITHM,
                "gate_behavior": {
                    "block": "VETO_ADMISSION_AND_ISSUANCE",
                    "require_more_evidence": "EXECUTE_FROZEN_CHALLENGES_OR_BLOCK_UNRESOLVED_CONTEXT",
                    "continue": "NO_DETERMINISTIC_PROOF"
                },
                "required_challenges": [
                    {
                        "template_id": IDEMPOTENCY_TEMPLATE,
                        "minimum_repetitions": 3
                    }
                ],
                "knowledge_limits": KnowledgeLimits::default(),
                "semantic_limits": SemanticLimits::default(),
                "external_disclosure": "DENIED"
            }),
            65536,
        )?;

        Ok(Self {
            artifact,
            packaging: None,
            policy,
            extractor_registry,
            authority_bundles,
            challenge_registry,
        })
    }

    /// Separate Rust authority identity; the fixture-specific Python profile is unchanged.
    pub fn rust_workspace(
        policy: PolicyPin,
        extractor_registry: Sha256Digest,
        authority_bundles: Vec<Sha256Digest>,
        registry: &AuthorityChallengeRegistry,
    ) -> Result<Self, KnowledgeError> {
        Self::rust_workspace_with_packaging(
            policy,
            extractor_registry,
            authority_bundles,
            registry,
            crate::semantic::SemanticPackagingPolicy::rust_controlled(),
        )
    }

    /// Authority may provision a stricter packaging budget; its exact identity is pinned.
    pub fn rust_workspace_with_packaging(
        policy: PolicyPin,
        extractor_registry: Sha256Digest,
        authority_bundles: Vec<Sha256Digest>,
        registry: &AuthorityChallengeRegistry,
        packaging: crate::semantic::SemanticPackagingPolicy,
    ) -> Result<Self, KnowledgeError> {
        if policy.id != RUST_CONTROLLED_POLICY_ID
            || registry.artifact().digest()
                != AuthorityChallengeRegistry::rust_workspace()?
                    .artifact()
                    .digest()
        {
            return Err(KnowledgeError::BindingMismatch);
        }

        let challenge_registry = registry.artifact().digest().clone();
        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({
                "schema": 1,
                "kind": "ARCHCERT_RUST_AUTHORITY_PROFILE",
                "id": RUST_PROFILE_ID,
                "version": "1.0.0",
                "language": "rust",
                "policy": policy,
                "semantic_required": true,
                "reviewer": ReviewerSelection::replay(),
                "extractor_registry_sha256": extractor_registry,
                "authority_bundles": authority_bundles,
                "packager_version": crate::semantic::PACKAGER_VERSION,
                "packaging_policy": packaging,
                "packaging_policy_sha256": packaging.digest()?,
                "challenge_registry_sha256": challenge_registry,
                "gate_algorithm": IRONCREST_GATE_ALGORITHM,
                "required_challenges": [
                    {
                        "template_id": crate::challenges::RUST_ARCHITECTURE_TEMPLATE,
                        "minimum_repetitions": 1
                    }
                ],
                "execution_profile": "rust-workspace-v1",
                "resource_limits": crate::validation::rust_workspace_limits(),
                "network": "DENIED",
                "external_disclosure": "DENIED",
                "knowledge_limits": KnowledgeLimits::default(),
                "semantic_limits": SemanticLimits {
                    request_bytes: packaging.request_limit(),
                    ..SemanticLimits::default()
                },
                "coverage_acceptance": "EXPLICIT_PARTIAL_ENGINEERING_REVIEW_NO_COMPLETE_SOURCE_CLAIM"
            }),
            65536,
        )?;

        Ok(Self {
            artifact,
            packaging: Some(packaging),
            policy,
            extractor_registry,
            authority_bundles,
            challenge_registry,
        })
    }

    /// New explicit packaging policy, absent for historical Python profiles.
    pub fn packaging_policy(&self) -> Option<&crate::semantic::SemanticPackagingPolicy> {
        self.packaging.as_ref()
    }

    /// Canonical profile bytes and identity, retained as immutable evidence.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }

    /// Fixed mandatory semantic bounds.
    pub fn semantic_limits(&self) -> SemanticLimits {
        SemanticLimits {
            request_bytes: self
                .packaging
                .as_ref()
                .map_or(SemanticLimits::default().request_bytes, |p| {
                    p.request_limit()
                }),
            ..SemanticLimits::default()
        }
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

        match (&self.packaging, request.package()) {
            (Some(policy), Some(package))
                if policy.digest().map_err(|_| JobStoreError::Invalid)?
                    == *package.policy_digest() => {}
            (None, None) => {}
            _ => return Err(JobStoreError::Precondition),
        }

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

/// Fixed project-scoped controlled settlement invariant, selected by the authority
/// composition before source extraction. Targets have no bundle-selection field.
pub fn controlled_settlement_knowledge(
    project: ProjectId,
    policy: Sha256Digest,
) -> Result<crate::knowledge::AuthorityKnowledgeBundle, KnowledgeError> {
    use archcert_domain::knowledge::*;

    crate::knowledge::AuthorityKnowledgeBundle::approve(
        "ironcrest-controlled-settlement".into(),
        "1.0.0".into(),
        KnowledgeScope::Project(project),
        vec![AuthorityKnowledgeEntry {
            id: "SETTLEMENT-IDEMPOTENCY-001".into(),
            version: "1.0.0".into(),
            kind: AuthorityEntryKind::Invariant,
            scope: KnowledgeScope::Project(project),
            severity: KnowledgeSeverity::High,
            authority: "archcert-controlled-authority".into(),
            description: "Repeated settlement with an identical idempotency key must retain exactly one ledger entry with the original amount. Review is bounded and does not prove general correctness.".into(),
            origin: "ArchCert controlled settlement contract v1".into(),
            approval: ApprovalState::Approved,
            supersedes: None,
            paths: vec![
                archcert_domain::source::SourcePath::from_bytes(b"settlement.py")
                    .map_err(|_| KnowledgeError::Invalid)?
            ],
            policy_sha256: vec![policy],
        }],
    )
}

/// Distinct Rust authority profile, never a historical profile reinterpretation.
pub const RUST_PROFILE_ID: &str = "rust-workspace-review-v1";

/// Separate Rust deterministic policy requires the Rust trust challenge.
pub const RUST_CONTROLLED_POLICY_ID: &str = "archcert-rust-controlled-v1";

/// Policies requiring the durable reviewed chain in addition to deterministic evaluation.
pub fn requires_reviewed_chain(id: &str) -> bool {
    [IRONCREST_CONTROLLED_POLICY_ID, RUST_CONTROLLED_POLICY_ID].contains(&id)
}

/// Authority-scoped Rust trust invariant. No repository text can select or edit it.
pub fn controlled_rust_knowledge(
    project: ProjectId,
    policy: Sha256Digest,
) -> Result<crate::knowledge::AuthorityKnowledgeBundle, KnowledgeError> {
    use archcert_domain::knowledge::*;

    crate::knowledge::AuthorityKnowledgeBundle::approve(
        "rust-trust-boundaries".into(),
        "1.0.0".into(),
        KnowledgeScope::Project(project),
        vec![AuthorityKnowledgeEntry {
            id: "RUST-INWARD-TRUST-001".into(),
            version: "1.0.0".into(),
            kind: AuthorityEntryKind::Invariant,
            scope: KnowledgeScope::Project(project),
            severity: KnowledgeSeverity::Critical,
            authority: "archcert-controlled-authority".into(),
            description: "Named domain/application layers exclude generated transport/provider/signing dependencies; semantic packages exclude signing authority. Source remains read-only. Cargo metadata closure is bounded structural evidence, not proof of arbitrary behavior.".into(),
            origin: "Rust authority trust contract v1".into(),
            approval: ApprovalState::Approved,
            supersedes: None,
            paths: vec![],
            policy_sha256: vec![policy],
        }]
    )
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
    fn rust_profile_has_distinct_authority_limits_registry_and_packaging()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut pin = pin()?;
        pin.policy.id = RUST_CONTROLLED_POLICY_ID.into();
        let registry = AuthorityChallengeRegistry::rust_workspace()?;
        let profile = IroncrestAuthorityProfile::rust_workspace(
            pin.policy.clone(),
            pin.extractor_registry_sha256.clone(),
            vec![],
            &registry,
        )?;
        pin.authority_profile_sha256 = profile.artifact().digest().clone();
        pin.challenge_registry_sha256 = registry.artifact().digest().clone();
        profile.validate_pin(&pin)?;
        let body: serde_json::Value = serde_json::from_slice(profile.artifact().bytes())?;

        assert_eq!(body["id"], RUST_PROFILE_ID);
        assert_eq!(body["external_disclosure"], "DENIED");
        assert_eq!(body["network"], "DENIED");
        assert_eq!(body["semantic_required"], true);
        assert_eq!(
            body["packaging_policy"]["maximum_request_bytes"],
            1024 * 1024
        );
        assert!(profile.packaging_policy().is_some());
        assert!(
            IroncrestAuthorityProfile::rust_workspace(
                pin.policy.clone(),
                pin.extractor_registry_sha256.clone(),
                vec![],
                &AuthorityChallengeRegistry::controlled()?
            )
            .is_err()
        );
        assert!(requires_reviewed_chain(RUST_CONTROLLED_POLICY_ID));

        Ok(())
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
        assert_eq!(body["version"], IRONCREST_PROFILE_VERSION);

        Ok(())
    }
}
