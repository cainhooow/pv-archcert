//! Bounded authority challenge selection. Model proposals never become commands.
use crate::{knowledge::*, semantic::*, validation::*};
use archcert_domain::{Sha256Digest, execution::ExecutionCommand, source::digest_bytes};
use serde::Serialize;

/// Authority-owned controlled fixture test. Target code may observe or interfere
/// with same-process test state; this does not promise test-source confidentiality.
const IDEMPOTENCY_TEST: &str = include_str!("challenges/idempotency.py");
/// Stable registry template, independent of project or reviewer spelling.
pub const IDEMPOTENCY_TEMPLATE: &str = "idempotency-replay-v1";
/// Fixed appended authority step; collision with a target/base step rejects.
pub const IDEMPOTENCY_STEP: &str = "ironcrest-idempotency";

/// Registry categories are vocabulary, not a promise of generic executability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeKind {
    /// Concurrent final-state checks; not implemented by the initial template.
    Concurrency,
    /// Bounded replay with an authority final-state assertion.
    IdempotencyReplay,
    /// Fault injection; requires a separately approved domain-specific template.
    FaultInjection,
    /// Time-of-check/time-of-use scrutiny; not generically executable.
    Toctou,
    /// Authorization boundary; requires an approved domain-specific template.
    AuthorizationBoundary,
    /// Migration invariant; requires supported domain/database knowledge.
    MigrationInvariant,
}
/// A genuine bounded command selected exclusively by the authority registry.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeChallenge {
    template_id: String,
    version: String,
    kind: ChallengeKind,
    parameters: ChallengeParameters,
    private_test_sha256: Sha256Digest,
    profile: String,
    image: String,
    command: ExecutionCommand,
}
impl RuntimeChallenge {
    /// New mandatory authority step, constrained by the existing execution profile.
    pub fn required_step(&self) -> AuthorityRequiredStep {
        AuthorityRequiredStep {
            id: IDEMPOTENCY_STEP.into(),
            profile: self.profile.clone(),
            command: self.command.clone(),
            evidence: EvidenceCategory::Test,
        }
    }
    /// Exact authority test identity, included in plan identity/evidence.
    pub fn private_test_digest(&self) -> &Sha256Digest {
        &self.private_test_sha256
    }
}
/// Explicit initial registry. Only idempotency replay against the controlled
/// settlement.py API is implemented; other categories remain unsupported.
#[derive(Debug)]
pub struct AuthorityChallengeRegistry {
    artifact: CanonicalArtifact,
}
impl AuthorityChallengeRegistry {
    /// Operator-selected versioned registry; not loaded from a target filename.
    pub fn controlled() -> Result<Self, KnowledgeError> {
        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({"schema":1,"kind":"ARCHCERT_CHALLENGE_REGISTRY",
            "id":"ironcrest-controlled-v1","version":"1.0.0","templates":[{"id":IDEMPOTENCY_TEMPLATE,"version":"1.0.0",
                "kind":ChallengeKind::IdempotencyReplay,"profile":"python","program":"python3","private_test_sha256":digest_bytes(IDEMPOTENCY_TEST.as_bytes()),
                "minimum_repetitions":2,"maximum_repetitions":8,"default_required_repetitions":3,
                "contract":"/source/settlement.py: settle(database_path, idempotency_key, amount); ledger(key TEXT, amount INTEGER)"}]}),
            65536,
        )?;
        Ok(Self { artifact })
    }
    /// Canonical authority registry identity, never an AI-selected runtime identity.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
    /// Resolve non-executable proposals after a valid semantic gate. At least one
    /// authority-required replay runs even if the reviewer proposes no challenge.
    pub fn plan(
        &self,
        request: &SemanticReviewRequest,
        review: &SemanticReviewArtifact,
        profile: &AuthorityExecutionProfile,
    ) -> Result<ChallengePlan, KnowledgeError> {
        if semantic_gate(request, Some(review)) != SemanticGateDecision::Continue
            || profile.id() != "python"
        {
            return Err(KnowledgeError::Invalid);
        }
        let response = review.response().ok_or(KnowledgeError::Invalid)?;
        let mut repetitions = 3;
        for proposal in &response.proposed_challenges {
            if proposal.challenge_template_id != IDEMPOTENCY_TEMPLATE
                || !(2..=8).contains(&proposal.parameters.repetitions)
            {
                return Err(KnowledgeError::Invalid);
            }
            repetitions = repetitions.max(proposal.parameters.repetitions);
        }
        let command = ExecutionCommand::new(
            "python3".into(),
            vec![
                "-I".into(),
                "-c".into(),
                IDEMPOTENCY_TEST.into(),
                repetitions.to_string(),
            ],
            "/work".into(),
        )
        .map_err(|_| KnowledgeError::Invalid)?;
        let challenge = RuntimeChallenge {
            template_id: IDEMPOTENCY_TEMPLATE.into(),
            version: "1.0.0".into(),
            kind: ChallengeKind::IdempotencyReplay,
            parameters: ChallengeParameters { repetitions },
            private_test_sha256: digest_bytes(IDEMPOTENCY_TEST.as_bytes()),
            profile: profile.id().into(),
            image: profile.image().into(),
            command,
        };
        let artifact = CanonicalArtifact::freeze(
            &serde_json::json!({"schema":1,"kind":"ARCHCERT_CHALLENGE_PLAN",
            "binding":request.binding(),"request_sha256":request.artifact().digest(),"review_sha256":review.artifact().digest(),
            "registry_sha256":self.artifact.digest(),"challenges":[challenge]}),
            65536,
        )?;
        Ok(ChallengePlan {
            challenges: vec![challenge],
            artifact,
        })
    }
}
/// Immutable challenge plan, bound to exact semantic and source inputs.
#[derive(Debug)]
pub struct ChallengePlan {
    challenges: Vec<RuntimeChallenge>,
    artifact: CanonicalArtifact,
}
impl ChallengePlan {
    /// Canonical evidence of authority selection and private-test identities.
    pub fn artifact(&self) -> &CanonicalArtifact {
        &self.artifact
    }
    /// Read-only validated challenges.
    pub fn challenges(&self) -> &[RuntimeChallenge] {
        &self.challenges
    }
    /// Add checks without dropping or reclassifying any existing mandatory step.
    /// Project-requested base steps reject rather than acquiring authority provenance.
    /// This creates a NEW plan identity; an admitted pinned job cannot be mutated.
    pub fn extend_authority_plan(
        &self,
        base: &ValidationPlan,
    ) -> Result<ValidationPlan, KnowledgeError> {
        if base.steps().is_empty()
            || base
                .steps()
                .iter()
                .any(|s| s.origin() != StepOrigin::AuthorityRequired)
        {
            return Err(KnowledgeError::Invalid);
        }
        let mut profiles = std::collections::BTreeMap::new();
        let mut steps = Vec::new();
        for s in base.steps() {
            if let Some(existing) = profiles.get(s.profile().name()) {
                if canonical_bytes(existing)? != canonical_bytes(s.profile())? {
                    return Err(KnowledgeError::BindingMismatch);
                }
            } else {
                profiles.insert(s.profile().name().to_owned(), s.profile().clone());
            }
            steps.push(AuthorityRequiredStep {
                id: s.id().into(),
                profile: s.profile().name().into(),
                command: s.command().clone(),
                evidence: s.evidence_category(),
            });
        }
        for c in &self.challenges {
            if profiles
                .get(&c.profile)
                .is_none_or(|p| p.image() != c.image)
            {
                return Err(KnowledgeError::BindingMismatch);
            }
            steps.push(c.required_step());
        }
        let profiles = profiles
            .into_values()
            .map(|p| {
                let limits = p.limits();
                AuthorityExecutionProfile::new(p, limits).map_err(|_| KnowledgeError::Invalid)
            })
            .collect::<Result<_, _>>()?;
        AuthorityConfiguration::new(profiles, steps)
            .map_err(|_| KnowledgeError::Invalid)?
            .resolve(None)
            .map_err(|_| KnowledgeError::Invalid)
    }
}
