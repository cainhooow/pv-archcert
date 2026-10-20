//! Pure evaluation with explicit audit time and independently supplied execution bindings.
use crate::{
    Applicability, PolicyBundle, PolicyBundleRef, PolicyError, Property, PropertyId, Rule, Severity,
};
use archcert_application::validation::{
    ObservationFact, ObservationId, ObservationKind, StepOrigin, ValidationObservation,
    ValidationPlan,
};
use archcert_domain::{
    PropertyVerdict, Sha256Digest, SourceIdentity,
    execution::{ExecutionId, ExecutionOutcome},
    source::{SourceSnapshot, SourceStatus, digest_bytes},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Authority/controller expectation, obtained from dispatch/result identity, never inferred
/// by finding a convenient observation. Schema 1 allows at most one execution per step.
#[derive(Debug, Clone, Serialize)]
pub struct ExpectedExecution {
    /// Resolved plan step ID.
    pub step: String,
    /// Exact expected execution identity for this evaluation/job.
    pub execution: ExecutionId,
}
/// Trusted process-local input boundary; no deserialization API or output text.
pub struct EvaluationInput<'a> {
    /// Accepted immutable source, including existing completeness evidence.
    pub source: &'a SourceSnapshot,
    /// Exact authority-resolved immutable plan.
    pub plan: &'a ValidationPlan,
    /// Independent expected controller execution identities.
    pub executions: &'a [ExpectedExecution],
    /// Typed controller observations; hostile target output has no field here.
    pub observations: &'a [ValidationObservation],
    /// Explicit audit timestamp in Unix seconds. Never enters a decision or ID.
    pub evaluated_at: u64,
}
/// Pre-signing disposition; this enum cannot issue CERTIFIED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificationEligibility {
    /// All blocking requirements satisfied; certificate construction/signing still required.
    EligibleForCertification,
    /// A blocking property failed, lacks evidence, or has disallowed non-applicability.
    NotEligible,
    /// No definite blocker, but at least one blocking conclusion is unreliable.
    Inconclusive,
}
/// Stable explanation codes, independent of prose or observation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// Every required fact positively established the property.
    EvidenceEstablished,
    /// Existing snapshot evidence records unresolved external source.
    SourceIncomplete,
    /// Required authority step is absent or not authority-designated with matching category.
    RequiredAuthorityStepMissing,
    /// Required execution/observation was never received.
    RequiredEvidenceMissing,
    /// Source, plan, step, execution, profile or fact discriminator did not bind.
    EvidenceBindingMismatch,
    /// Unknown producer or schema cannot be interpreted.
    UnsupportedEvidenceVersion,
    /// Two different facts for the same expected observation contradict.
    ContradictoryEvidence,
    /// Runtime/setup/transport evidence cannot establish a reliable target outcome.
    InfrastructureFailure,
    /// Completed target exit is nonzero.
    TargetExitNonzero,
    /// Bounded command was terminated by timeout/resource limit.
    ExecutionLimit,
    /// Completed result has an absent or invalid exit code.
    AmbiguousExecution,
    /// Explicit authority applicability excludes this plan's profiles.
    PolicyNotApplicable,
}
/// Explicit applicability decision; never inferred from absent evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyApplicability {
    /// Authority conditions match.
    Applicable,
    /// Authority conditions explicitly exclude this plan.
    NotApplicable,
}
/// Selector of required evidence, kept separate from actual payload references.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredEvidenceRef {
    /// Existing immutable snapshot completeness.
    SourceSnapshot,
    /// Required named step and factual kind; missing execution remains visibly absent.
    Observation {
        /// Expected authority step.
        step: String,
        /// Required factual discriminator.
        fact: ObservationKind,
        /// Independent execution binding, if dispatched.
        execution: Option<ExecutionId>,
    },
    /// The all-planned-executions rule requires at least one step.
    NonemptyPlan,
}
/// Stable content-bound reference; detailed evidence remains outside policy results.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceRef {
    /// Exact immutable source snapshot.
    SourceSnapshot {
        /// Independent source identity digest.
        sha256: Sha256Digest,
    },
    /// Typed observation identity plus canonical payload digest, disambiguating contradictions.
    Observation {
        /// Controller identity of the fact.
        id: ObservationId,
        /// SHA-256 of compact key-sorted JSON of the complete typed observation.
        sha256: Sha256Digest,
    },
}
/// One authority interpretation; never a copy of entire execution evidence.
#[derive(Debug, Clone, Serialize)]
pub struct PropertyEvaluation {
    /// Authority property identifier.
    pub property: PropertyId,
    /// Included policy description/reference.
    pub description: String,
    /// Explicit applicability conclusion.
    pub applicability: PropertyApplicability,
    /// First-class five-state verdict.
    pub verdict: PropertyVerdict,
    /// Authority severity.
    pub severity: Severity,
    /// Whether the result blocks the selected profile.
    pub blocking: bool,
    /// Required selectors, including absent facts.
    pub required_evidence: Vec<RequiredEvidenceRef>,
    /// Actual retained fact references, sorted/deduplicated by content digest.
    pub actual_evidence: Vec<EvidenceRef>,
    /// Stable explanation for this conclusion.
    pub reason: ReasonCode,
}
/// Structured authority finding for an unsatisfied property.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Deterministic correlation digest; excludes audit time and execution UUIDs.
    pub id: Sha256Digest,
    /// Property responsible for this finding.
    pub property: PropertyId,
    /// Authority priority.
    pub severity: Severity,
    /// Evaluated status, including NOT_PROVEN.
    pub status: PropertyVerdict,
    /// Whether this finding prevents eligibility.
    pub blocking: bool,
    /// Stable explanation code.
    pub reason: ReasonCode,
    /// References to evidence, without payload copies.
    pub observations: Vec<EvidenceRef>,
}
/// Unsigned deterministic evaluation, expressly not a certificate.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    /// Explicit evaluation schema; unsupported versions cannot reach issuance.
    pub schema: u32,
    /// Exact source revision.
    pub source: SourceIdentity,
    /// Exact immutable validation plan identity.
    pub plan_sha256: Sha256Digest,
    /// Authority bundle ID/version/canonical SHA-256.
    pub policy: PolicyBundleRef,
    /// Canonically ordered property results.
    pub properties: Vec<PropertyEvaluation>,
    /// Structured findings, in property order.
    pub findings: Vec<Finding>,
    /// Stable IDs of blocking findings.
    pub blocking_findings: Vec<Sha256Digest>,
    /// Pre-signing decision only.
    pub eligibility: CertificationEligibility,
    /// Evaluator semantic version.
    pub evaluator_version: &'static str,
    /// Audit metadata only, Unix seconds.
    pub evaluated_at: u64,
}
#[derive(Clone, Copy)]
struct Conclusion(PropertyVerdict, ReasonCode);
fn combine(items: &[Conclusion]) -> Conclusion {
    // Reliability uncertainty dominates a target failure within a property. Eligibility
    // separately prefers definite blockers across properties. Both orders are explicit.
    fn rank(v: PropertyVerdict) -> u8 {
        match v {
            PropertyVerdict::Inconclusive => 0,
            PropertyVerdict::Failed => 1,
            PropertyVerdict::NotProven => 2,
            PropertyVerdict::NotApplicable => 3,
            PropertyVerdict::Proven => 4,
        }
    }
    items
        .iter()
        .min_by_key(|c| (rank(c.0), c.1))
        .copied()
        .unwrap_or(Conclusion(
            PropertyVerdict::NotProven,
            ReasonCode::RequiredEvidenceMissing,
        ))
}
fn fact_kind(f: &ObservationFact) -> ObservationKind {
    match f {
        ObservationFact::ExecutionFinished { .. } => ObservationKind::ExecutionFinished,
        ObservationFact::SourceIdentityMatched => ObservationKind::SourceIdentityMatched,
        ObservationFact::NetworkDenied => ObservationKind::NetworkDenied,
        ObservationFact::EnvironmentEstablished { .. } => ObservationKind::EnvironmentEstablished,
    }
}
fn fact_conclusion(f: &ObservationFact) -> Conclusion {
    use PropertyVerdict::*;
    use ReasonCode::*;
    match f {
        ObservationFact::ExecutionFinished {
            outcome, exit_code, ..
        } => match (outcome, exit_code) {
            (ExecutionOutcome::Completed, Some(0)) => Conclusion(Proven, EvidenceEstablished),
            (ExecutionOutcome::Completed, Some(1..=255)) => Conclusion(Failed, TargetExitNonzero),
            (ExecutionOutcome::Completed, _) => Conclusion(Inconclusive, AmbiguousExecution),
            (ExecutionOutcome::TimedOut | ExecutionOutcome::ResourceLimit, _) => {
                Conclusion(Failed, ExecutionLimit)
            }
            _ => Conclusion(Inconclusive, InfrastructureFailure),
        },
        _ => Conclusion(Proven, EvidenceEstablished),
    }
}
struct EvaluationContext<'a> {
    input: &'a EvaluationInput<'a>,
    bundle: &'a PolicyBundle,
    plan_digest: Sha256Digest,
}
impl EvaluationContext<'_> {
    fn slot(
        &self,
        step_id: &str,
        kind: ObservationKind,
        refs: &mut BTreeMap<String, EvidenceRef>,
    ) -> Result<Conclusion, PolicyError> {
        let step = self.input.plan.steps().iter().find(|s| s.id() == step_id);
        let execution = self.input.executions.iter().find(|e| e.step == step_id);
        let mut facts = BTreeMap::new();
        let mut errors = Vec::new();
        for o in self
            .input
            .observations
            .iter()
            .filter(|o| o.id.step == step_id && o.id.kind == kind)
        {
            let bytes = crate::model::canonical_json(o)?;
            let digest = digest_bytes(&bytes);
            refs.insert(
                digest.as_str().into(),
                EvidenceRef::Observation {
                    id: o.id.clone(),
                    sha256: digest,
                },
            );
            if o.schema != 1
                || !self.bundle.supports_producer(&o.producer)
                || (o.producer == "archcert-controller-v1/0.1.0"
                    && !matches!(
                        o.fact,
                        ObservationFact::ExecutionFinished {
                            outcome: ExecutionOutcome::SandboxFailure,
                            exit_code: None,
                            ..
                        }
                    ))
            {
                errors.push(Conclusion(
                    PropertyVerdict::Inconclusive,
                    ReasonCode::UnsupportedEvidenceVersion,
                ));
                continue;
            }
            if o.source != *self.input.source.identity()
                || o.plan_sha256 != self.plan_digest
                || execution.is_none_or(|e| e.execution != o.id.execution)
                || step.is_none_or(|s| s.profile().name() != o.profile)
                || fact_kind(&o.fact) != kind
                || matches!(&o.fact, ObservationFact::ExecutionFinished { category, .. }
                    if step.is_none_or(|s| s.evidence_category() != *category))
            {
                errors.push(Conclusion(
                    PropertyVerdict::NotProven,
                    ReasonCode::EvidenceBindingMismatch,
                ));
                continue;
            }
            facts.insert(crate::model::canonical_json(&o.fact)?, &o.fact);
        }
        if facts.len() > 1 {
            errors.push(Conclusion(
                PropertyVerdict::Inconclusive,
                ReasonCode::ContradictoryEvidence,
            ));
        }
        if !errors.is_empty() {
            return Ok(combine(&errors));
        }
        Ok(facts.values().next().map_or(
            Conclusion(
                PropertyVerdict::NotProven,
                ReasonCode::RequiredEvidenceMissing,
            ),
            |f| fact_conclusion(f),
        ))
    }
    fn property(&self, p: &Property) -> Result<PropertyEvaluation, PolicyError> {
        let applicable = match &p.applicability {
            Applicability::Always {} => true,
            Applicability::PolicyProfiles { profiles } => {
                profiles.iter().any(|p| p == &self.bundle.identity().id)
            }
        };
        let mut required = Vec::new();
        let mut refs = BTreeMap::new();
        let conclusion = if !applicable {
            Conclusion(
                PropertyVerdict::NotApplicable,
                ReasonCode::PolicyNotApplicable,
            )
        } else if p.rule == (Rule::SourceComplete {}) {
            required.push(RequiredEvidenceRef::SourceSnapshot);
            refs.insert(
                "snapshot".into(),
                EvidenceRef::SourceSnapshot {
                    sha256: self.input.source.identity().snapshot_sha256.clone(),
                },
            );
            if self.input.source.status() == SourceStatus::Complete {
                Conclusion(PropertyVerdict::Proven, ReasonCode::EvidenceEstablished)
            } else {
                Conclusion(PropertyVerdict::Failed, ReasonCode::SourceIncomplete)
            }
        } else {
            let (steps, kind) = match &p.rule {
                Rule::Command { steps, .. } => (steps.clone(), ObservationKind::ExecutionFinished),
                Rule::SourceIdentity {} => (
                    self.input
                        .plan
                        .steps()
                        .iter()
                        .map(|s| s.id().into())
                        .collect(),
                    ObservationKind::SourceIdentityMatched,
                ),
                Rule::Sandbox {} => (
                    self.input
                        .plan
                        .steps()
                        .iter()
                        .map(|s| s.id().into())
                        .collect(),
                    ObservationKind::EnvironmentEstablished,
                ),
                Rule::Network {} => (
                    self.input
                        .plan
                        .steps()
                        .iter()
                        .map(|s| s.id().into())
                        .collect(),
                    ObservationKind::NetworkDenied,
                ),
                Rule::SourceComplete {} => return Err(PolicyError::InvalidPolicy),
            };
            let mut steps = steps;
            steps.sort();
            let mut results = Vec::new();
            if steps.is_empty() {
                required.push(RequiredEvidenceRef::NonemptyPlan);
            }
            for id in steps {
                required.push(RequiredEvidenceRef::Observation {
                    step: id.clone(),
                    fact: kind,
                    execution: self
                        .input
                        .executions
                        .iter()
                        .find(|e| e.step == id)
                        .map(|e| e.execution),
                });
                if let Rule::Command { category, .. } = &p.rule
                    && !self.input.plan.steps().iter().any(|s| {
                        s.id() == id
                            && s.origin() == StepOrigin::AuthorityRequired
                            && s.evidence_category() == *category
                    })
                {
                    results.push(Conclusion(
                        PropertyVerdict::NotProven,
                        ReasonCode::RequiredAuthorityStepMissing,
                    ));
                    continue;
                }
                results.push(self.slot(&id, kind, &mut refs)?);
            }
            combine(&results)
        };
        let satisfied = conclusion.0 == PropertyVerdict::Proven
            || (conclusion.0 == PropertyVerdict::NotApplicable && p.allow_not_applicable);
        Ok(PropertyEvaluation {
            property: p.id,
            description: p.description.clone(),
            applicability: if applicable {
                PropertyApplicability::Applicable
            } else {
                PropertyApplicability::NotApplicable
            },
            verdict: conclusion.0,
            severity: p.severity,
            blocking: !satisfied
                && (p.mandatory || matches!(p.severity, Severity::P0 | Severity::P1)),
            required_evidence: required,
            actual_evidence: refs.into_values().collect(),
            reason: conclusion.1,
        })
    }
}
/// Evaluates an immutable authority bundle against exact process-local inputs.
/// Input errors return no evaluation/eligibility. No ambient time or random value is read.
pub fn evaluate(
    bundle: &PolicyBundle,
    selected: &PolicyBundleRef,
    input: EvaluationInput<'_>,
) -> Result<PolicyEvaluation, PolicyError> {
    if selected != bundle.identity() {
        return Err(PolicyError::SelectionMismatch);
    }
    if input.executions.len() > 160 || input.observations.len() > 4096 {
        return Err(PolicyError::InvalidInputs);
    }
    let mut steps = BTreeSet::new();
    let mut executions = BTreeSet::new();
    for e in input.executions {
        if !input.plan.steps().iter().any(|s| s.id() == e.step)
            || !steps.insert(e.step.clone())
            || !executions.insert(e.execution.to_string())
        {
            return Err(PolicyError::InvalidInputs);
        }
    }
    // Bound mutable public observation strings before any canonicalization or repeated scan.
    if input
        .observations
        .iter()
        .any(|o| o.id.step.len() > 128 || o.profile.len() > 128 || o.producer.len() > 128)
    {
        return Err(PolicyError::InvalidInputs);
    }
    let plan_digest = input.plan.digest()?;
    let context = EvaluationContext {
        input: &input,
        bundle,
        plan_digest: plan_digest.clone(),
    };
    let properties = bundle
        .properties()
        .iter()
        .map(|p| context.property(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut findings = Vec::new();
    for p in &properties {
        if p.verdict == PropertyVerdict::Proven
            || (p.verdict == PropertyVerdict::NotApplicable && !p.blocking)
        {
            continue;
        }
        let id = digest_bytes(&crate::model::canonical_json(&serde_json::json!({
            "schema":1,"source":input.source.identity(),"plan":plan_digest,"policy":selected,
            "property":p.property,"verdict":p.verdict,"reason":p.reason,
        }))?);
        findings.push(Finding {
            id,
            property: p.property,
            severity: p.severity,
            status: p.verdict,
            blocking: p.blocking,
            reason: p.reason,
            observations: p.actual_evidence.clone(),
        });
    }
    let blockers: Vec<_> = properties.iter().filter(|p| p.blocking).collect();
    // Source completeness is an ingress safety floor, independent of an
    // authority profile omitting or excluding a source-completeness property.
    let eligibility = if input.source.status() != SourceStatus::Complete {
        CertificationEligibility::NotEligible
    } else if blockers.is_empty() {
        CertificationEligibility::EligibleForCertification
    } else if blockers
        .iter()
        .any(|p| p.verdict != PropertyVerdict::Inconclusive)
    {
        CertificationEligibility::NotEligible
    } else {
        CertificationEligibility::Inconclusive
    };
    Ok(PolicyEvaluation {
        schema: 1,
        source: input.source.identity().clone(),
        plan_sha256: plan_digest,
        policy: selected.clone(),
        properties,
        blocking_findings: findings
            .iter()
            .filter(|f| f.blocking)
            .map(|f| f.id.clone())
            .collect(),
        findings,
        eligibility,
        evaluator_version: "archcert-policy-evaluator-v1/0.1.0",
        evaluated_at: input.evaluated_at,
    })
}
