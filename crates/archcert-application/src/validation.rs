//! Execution plans and observations, without policy evaluation or certification verdicts.

use crate::{
    configuration::valid_step_id,
    execution::ExecutionRequest,
    materialization::{MaterializedSource, RunnerInput},
};
use archcert_domain::execution::{
    ExecutionCommand, ExecutionError, ExecutionLimits, ExecutionProfile, NetworkPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Requested meaning of collected execution evidence; a label, never a passed check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCategory {
    /// General engineering execution evidence.
    #[default]
    Execution,
    /// Requested typecheck command evidence.
    Typecheck,
    /// Requested test command evidence.
    Test,
    /// Requested build command evidence.
    Build,
}
/// Project requests cannot select their provenance.
#[derive(Debug, Clone)]
pub struct RequestedStep {
    /// Validated stable step name.
    pub id: String,
    /// Structural literal command, with sandbox cwd.
    pub command: ExecutionCommand,
    /// Requested evidence label, no semantic success assertion.
    pub evidence: EvidenceCategory,
}
/// Project-owned request; contains no runtime, image, limits, network or environment.
#[derive(Debug, Clone)]
pub struct ProjectExecutionRequest {
    profile: String,
    steps: Vec<RequestedStep>,
}
impl ProjectExecutionRequest {
    /// Programmatic request follows the same checks during authority resolution.
    pub fn new(profile: String, steps: Vec<RequestedStep>) -> Self {
        Self { profile, steps }
    }
    /// Requested authority profile identifier.
    pub fn profile(&self) -> &str {
        &self.profile
    }
    /// Project-requested execution steps.
    pub fn steps(&self) -> &[RequestedStep] {
        &self.steps
    }
}
/// Immutable provenance assigned by authority composition, never project TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepOrigin {
    /// Project request, unable to replace mandatory steps.
    ProjectRequested,
    /// Mandatory authority step, always composed first.
    AuthorityRequired,
}
/// Only supported environment policy; no ambient host inheritance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentPolicy {
    /// Construct the fixed five-key sandbox environment.
    FixedSandbox,
}
/// Authority-owned approved image/executables/default and maximum budgets.
#[derive(Debug, Clone)]
pub struct AuthorityExecutionProfile {
    execution: ExecutionProfile,
    maximum: ExecutionLimits,
}
impl AuthorityExecutionProfile {
    /// Trusted policy construction, deliberately not Deserialize.
    pub fn new(execution: ExecutionProfile, maximum: ExecutionLimits) -> Result<Self, PlanError> {
        maximum.validate()?;
        if !within(execution.limits(), maximum) {
            return Err(PlanError::MaximumExceeded);
        }
        Ok(Self { execution, maximum })
    }
    /// Authority profile identifier.
    pub fn id(&self) -> &str {
        self.execution.name()
    }
    /// Immutable OCI image identity.
    pub fn image(&self) -> &str {
        self.execution.image()
    }
    /// Default finite limits.
    pub fn default_limits(&self) -> ExecutionLimits {
        self.execution.limits()
    }
    /// Maximum finite limits, not project-controlled.
    pub fn maximum_limits(&self) -> ExecutionLimits {
        self.maximum
    }
    /// Network enablement has no representation in the current policy.
    pub fn network_policy(&self) -> NetworkPolicy {
        NetworkPolicy::Denied
    }
    /// Fixed authority environment, with private HOME.
    pub fn environment_policy(&self) -> EnvironmentPolicy {
        EnvironmentPolicy::FixedSandbox
    }
    /// Selects bounded authority limits; callers are trusted, never project deserialization.
    pub fn with_limits(&self, limits: ExecutionLimits) -> Result<Self, PlanError> {
        limits.validate()?;
        if !within(limits, self.maximum) {
            return Err(PlanError::MaximumExceeded);
        }
        Self::new(self.execution.with_limits(limits)?, self.maximum)
    }
}
fn within(l: ExecutionLimits, m: ExecutionLimits) -> bool {
    l.timeout_ms <= m.timeout_ms
        && l.cpu_millis <= m.cpu_millis
        && l.memory_bytes <= m.memory_bytes
        && l.pids <= m.pids
        && l.stdout_bytes <= m.stdout_bytes
        && l.stderr_bytes <= m.stderr_bytes
        && l.excerpt_bytes <= m.excerpt_bytes
        && l.scratch_bytes <= m.scratch_bytes
        && l.output_bytes <= m.output_bytes
}
/// Mandatory authority input, separate from any project-requested step.
#[derive(Debug, Clone)]
pub struct AuthorityRequiredStep {
    /// Stable step identifier.
    pub id: String,
    /// Authority-selected profile ID.
    pub profile: String,
    /// Mandatory command.
    pub command: ExecutionCommand,
    /// Authority evidence category.
    pub evidence: EvidenceCategory,
}
/// In-memory registry and mandatory plan composition. No persistence/plugin machinery.
#[derive(Debug)]
pub struct AuthorityConfiguration {
    profiles: BTreeMap<String, AuthorityExecutionProfile>,
    mandatory: Vec<AuthorityRequiredStep>,
}
/// Explicit composition errors; no silent fallback to another image/profile/step.
#[derive(Debug, Error)]
pub enum PlanError {
    /// Unregistered profile IDs reject at authority resolution.
    #[error("unknown authority execution profile: {0}")]
    UnknownProfile(String),
    /// Ambiguous IDs or malformed/oversized plans reject.
    #[error("invalid or duplicate validation step/profile ID")]
    InvalidPlan,
    /// Caller tried to exceed a profile ceiling.
    #[error("execution limits exceed authority maximum")]
    MaximumExceeded,
    /// Authority command/image/limit validation failed.
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}
/// Static development catalog: names identify executable families, never observed versions.
fn development_programs(id: &str) -> Result<Vec<String>, PlanError> {
    let programs: &[&str] = match id {
        "python" => &["python3"],
        "rust" => &["cargo", "rustc"],
        "rust-workspace-v1" => &["cargo", "rustc", "python3"],
        "node" => &["node", "npm", "pnpm", "corepack"],
        _ => return Err(PlanError::UnknownProfile(id.into())),
    };
    Ok(programs.iter().map(|s| (*s).into()).collect())
}
/// Config-check authority boundary using the same development catalog as run.
/// No image/runtime is selected and no execution is performed.
pub fn check_development_request(request: &ProjectExecutionRequest) -> Result<(), PlanError> {
    let programs = development_programs(request.profile())?;
    validate_requested_steps(request)?;
    for step in request.steps() {
        if !programs.iter().any(|p| p == step.command.program()) {
            return Err(ExecutionError::CommandNotAllowed.into());
        }
    }
    Ok(())
}
fn validate_requested_steps(request: &ProjectExecutionRequest) -> Result<(), PlanError> {
    if !valid_step_id(request.profile()) || request.steps.is_empty() || request.steps.len() > 32 {
        return Err(PlanError::InvalidPlan);
    }
    let mut ids = std::collections::BTreeSet::new();
    for step in request.steps() {
        if !valid_step_id(&step.id) || !ids.insert(&step.id) {
            return Err(PlanError::InvalidPlan);
        }
    }
    Ok(())
}
impl AuthorityConfiguration {
    /// Validates all profiles and mandatory steps before any project request.
    pub fn new(
        profiles: Vec<AuthorityExecutionProfile>,
        mandatory: Vec<AuthorityRequiredStep>,
    ) -> Result<Self, PlanError> {
        let mut registry = BTreeMap::new();
        for profile in profiles {
            if registry.insert(profile.id().into(), profile).is_some() {
                return Err(PlanError::InvalidPlan);
            }
        }
        let authority = Self {
            profiles: registry,
            mandatory,
        };
        authority.resolve(None)?;
        Ok(authority)
    }
    /// Operator provisions approved immutable images into a static executable catalog.
    /// This is trusted development setup, never populated by project configuration.
    pub fn development(images: Vec<(String, String)>) -> Result<Self, PlanError> {
        let mut profiles = Vec::new();
        for (id, image) in images {
            let programs = development_programs(&id)?;
            let limits = if id == "rust-workspace-v1" {
                rust_workspace_limits()
            } else {
                ExecutionLimits::default()
            };
            profiles.push(AuthorityExecutionProfile::new(
                ExecutionProfile::new(id, image, programs, limits)?,
                limits,
            )?);
        }
        Self::new(profiles, vec![])
    }
    /// Adds operator-owned mandatory commands; never populated from target configuration.
    pub fn with_required_steps(
        self,
        mandatory: Vec<AuthorityRequiredStep>,
    ) -> Result<Self, PlanError> {
        Self::new(self.profiles.into_values().collect(), mandatory)
    }
    /// Only registered authority profiles may enter the resolved plan.
    pub fn profile(&self, id: &str) -> Result<&AuthorityExecutionProfile, PlanError> {
        self.profiles
            .get(id)
            .ok_or_else(|| PlanError::UnknownProfile(id.into()))
    }
    /// Additive composition. Projects cannot omit/replace mandatory steps; collisions reject.
    pub fn resolve(
        &self,
        request: Option<&ProjectExecutionRequest>,
    ) -> Result<ValidationPlan, PlanError> {
        if self.mandatory.len() > 128 {
            return Err(PlanError::InvalidPlan);
        }
        let mut steps = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for required in &self.mandatory {
            if !valid_step_id(&required.id) || !ids.insert(required.id.clone()) {
                return Err(PlanError::InvalidPlan);
            }
            let profile = self.profile(&required.profile)?.execution.clone();
            profile.authorize(&required.command)?;
            steps.push(ValidatedExecutionStep {
                id: required.id.clone(),
                command: required.command.clone(),
                profile,
                evidence: required.evidence,
                origin: StepOrigin::AuthorityRequired,
            });
        }
        if let Some(request) = request {
            validate_requested_steps(request)?;
            let profile = self.profile(request.profile())?;
            for step in request.steps() {
                if !ids.insert(step.id.clone()) {
                    return Err(PlanError::InvalidPlan);
                }
                profile.execution.authorize(&step.command)?;
                steps.push(ValidatedExecutionStep {
                    id: step.id.clone(),
                    command: step.command.clone(),
                    profile: profile.execution.clone(),
                    evidence: step.evidence,
                    origin: StepOrigin::ProjectRequested,
                });
            }
        }
        Ok(ValidationPlan { steps })
    }
}
/// Resolved controlled steps. No removal/mutation/deserialization API or policy verdict.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationPlan {
    steps: Vec<ValidatedExecutionStep>,
}
impl ValidationPlan {
    /// Schema-1 plan identity: SHA-256 of compact recursively key-sorted JSON.
    /// All fields, step order, resolved profiles and provenance are included.
    pub fn digest(&self) -> Result<archcert_domain::Sha256Digest, serde_json::Error> {
        let mut value =
            serde_json::json!({"schema":1,"kind":"ARCHCERT_VALIDATION_PLAN","plan":self});
        value.sort_all_objects();
        Ok(archcert_domain::source::digest_bytes(&serde_json::to_vec(
            &value,
        )?))
    }
    /// Mandatory and project-requested steps in deterministic execution order.
    pub fn steps(&self) -> &[ValidatedExecutionStep] {
        &self.steps
    }
}
/// Authority-validated literal execution step, ready for source-bound execution.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatedExecutionStep {
    id: String,
    command: ExecutionCommand,
    profile: ExecutionProfile,
    evidence: EvidenceCategory,
    origin: StepOrigin,
}
impl ValidatedExecutionStep {
    /// Stable step identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Provenance assigned by authority, not project input.
    pub fn origin(&self) -> StepOrigin {
        self.origin
    }
    /// Requested evidence category, no verdict.
    pub fn evidence_category(&self) -> EvidenceCategory {
        self.evidence
    }
    /// Authorized literal command and sandbox cwd.
    pub fn command(&self) -> &ExecutionCommand {
        &self.command
    }
    /// Resolved approved execution profile.
    pub fn profile(&self) -> &ExecutionProfile {
        &self.profile
    }
    /// Binds a validated step to an actual sealed source capability.
    pub fn execution_request<S: MaterializedSource>(
        &self,
        source: RunnerInput<S>,
    ) -> Result<ExecutionRequest<S>, ExecutionError> {
        ExecutionRequest::new(source, self.profile.clone(), self.command.clone())
    }
}

/// Typed identity of an observation within an execution, stable across serialization.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationId {
    /// Producer execution identity.
    pub execution: archcert_domain::execution::ExecutionId,
    /// Resolved plan step identity.
    pub step: String,
    /// Distinguishes facts within the same execution/step.
    pub kind: ObservationKind,
}
/// Fact discriminator, not a policy check or verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ObservationKind {
    /// Runtime-observed execution termination.
    ExecutionFinished,
    /// Isolated source view matched accepted source before execution.
    SourceIdentityMatched,
    /// Runtime denied external network.
    NetworkDenied,
    /// Authority sandbox environment/configuration was established.
    EnvironmentEstablished,
}
/// Facts available to a future policy evaluator without importing Docker structures.
#[derive(Debug, Clone, Serialize)]
pub enum ObservationFact {
    /// Completion includes nonzero exits; category labels do not prove semantic tests/builds.
    ExecutionFinished {
        /// Operational execution outcome.
        outcome: archcert_domain::execution::ExecutionOutcome,
        /// Actual observed exit code, if available.
        exit_code: Option<i64>,
        /// Requested category, not interpretation of output or argv.
        category: EvidenceCategory,
    },
    /// Actual source-view reconstruction matched the expected source identity.
    SourceIdentityMatched,
    /// Configured denied-network policy was verified before target start.
    NetworkDenied,
    /// Sandbox prerequisites/configuration established; no toolchain-version assertion.
    EnvironmentEstablished {
        /// Absence of toolchain probing remains explicit.
        toolchain: archcert_domain::execution::ToolchainObservation,
    },
}
/// Source/execution/producer-bound structured observation. No PASS boolean or verdict.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationObservation {
    /// Typed observation schema, independent of backend version.
    pub schema: u32,
    /// Exact whole-plan identity, including step provenance and resolved profiles.
    pub plan_sha256: archcert_domain::Sha256Digest,
    /// Resolved authority execution profile ID.
    pub profile: String,
    /// Stable typed identity.
    pub id: ObservationId,
    /// Exact accepted source.
    pub source: archcert_domain::SourceIdentity,
    /// Controller adapter and producer version.
    pub producer: String,
    /// Structured fact, never hostile output interpretation.
    pub fact: ObservationFact,
}
impl ValidationObservation {
    /// Converts trusted completed runner evidence, including operational failures/nonzero exits.
    /// Missing setup evidence must remain absent, never fabricated as an observation.
    pub fn from_execution(
        plan: &ValidationPlan,
        step: &ValidatedExecutionStep,
        evidence: &archcert_domain::execution::ExecutionEvidence,
    ) -> Result<Vec<Self>, ExecutionError> {
        // Refuse accidental cross-plan evidence attribution.
        let resolved = plan
            .steps()
            .iter()
            .find(|s| s.id() == step.id())
            .ok_or(ExecutionError::SourceIntegrity)?;
        let resolved =
            serde_json::to_value(resolved).map_err(|_| ExecutionError::SourceIntegrity)?;
        let supplied = serde_json::to_value(step).map_err(|_| ExecutionError::SourceIntegrity)?;
        if resolved != supplied
            || evidence.command != *step.command()
            || evidence.profile != step.profile().name()
            || evidence.image_digest != step.profile().image()
            || evidence.limits != step.profile().limits()
        {
            return Err(ExecutionError::SourceIntegrity);
        }
        let plan_sha256 = plan.digest().map_err(|_| ExecutionError::SourceIntegrity)?;
        Ok([
            (
                ObservationKind::ExecutionFinished,
                ObservationFact::ExecutionFinished {
                    outcome: evidence.outcome,
                    exit_code: evidence.exit_code,
                    category: step.evidence_category(),
                },
            ),
            (
                ObservationKind::SourceIdentityMatched,
                ObservationFact::SourceIdentityMatched,
            ),
            (
                ObservationKind::NetworkDenied,
                ObservationFact::NetworkDenied,
            ),
            (
                ObservationKind::EnvironmentEstablished,
                ObservationFact::EnvironmentEstablished {
                    toolchain: evidence.toolchain,
                },
            ),
        ]
        .into_iter()
        .map(|(kind, fact)| Self {
            schema: 1,
            plan_sha256: plan_sha256.clone(),
            profile: step.profile().name().into(),
            id: ObservationId {
                execution: evidence.execution,
                step: step.id().into(),
                kind,
            },
            source: evidence.source.clone(),
            producer: format!("{}/{}", evidence.backend_version, evidence.producer_version),
            fact,
        })
        .collect())
    }
}

/// Versioned authority Rust workspace budgets; historical catalog limits are unchanged.
pub fn rust_workspace_limits() -> ExecutionLimits {
    ExecutionLimits {
        timeout_ms: 900_000,
        cpu_millis: 2000,
        memory_bytes: 8 * 1024 * 1024 * 1024,
        pids: 256,
        scratch_bytes: 6 * 1024 * 1024 * 1024,
        ..ExecutionLimits::default()
    }
}
