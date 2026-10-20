//! Credential-free worker process models; decoding never grants a lease or trust.
use crate::{
    jobs::JobStoreError,
    validation::{AuthorityConfiguration, AuthorityRequiredStep, ValidationPlan},
};
use archcert_domain::{
    Sha256Digest, SourceIdentity,
    execution::{ExecutionEvidence, ExecutionId},
    jobs::*,
};
use serde::{Deserialize, Serialize};
/// Maximum assignment including a bounded Northgate source artifact.
pub const MAX_ASSIGNMENT_BYTES: usize = 80 * 1024 * 1024;
/// Maximum result including bounded captured stream prefixes.
pub const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
/// One process assignment, authenticated by the authority-owned private stdio channel.
#[derive(Clone)]
pub struct WorkerAssignment {
    /// Leased job identity.
    pub job: JobId,
    /// Exact attempt identity.
    pub attempt: AttemptId,
    /// Frozen source/authority inputs; no database/object-store/signing credential.
    pub inputs: JobInputs,
    /// Independently verified Northgate snapshot artifact; worker must rehash/recheck it.
    pub source_artifact: Vec<u8>,
}
/// One observed execution, including independently confirmed cleanup outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepResult {
    /// Exact authority plan step.
    pub step: String,
    /// Fresh execution identity, even if infrastructure fails before target start.
    pub execution: ExecutionId,
    /// Operational evidence only; missing evidence cannot fabricate positive observations.
    pub evidence: Option<ExecutionEvidence>,
    /// Materialization cleanup confirmed.
    pub source_cleaned: bool,
    /// Runtime target/job-image destruction confirmed.
    pub sandbox_cleaned: bool,
}
/// Result from one actual worker process, before policy interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResult {
    /// Wire/artifact schema.
    pub schema: u32,
    /// Exact leased job.
    pub job: JobId,
    /// Exact leased attempt.
    pub attempt: AttemptId,
    /// Immutable source identity.
    pub source: SourceIdentity,
    /// Frozen authority plan.
    pub plan_sha256: Sha256Digest,
    /// Controller implementation, not target text.
    pub producer: String,
    /// Full plan step results, in plan order.
    pub steps: Vec<StepResult>,
}
/// Reconstructs only the pinned bounded authority configuration, then checks its digest.
pub fn pinned_plan(inputs: &JobInputs) -> Result<ValidationPlan, JobStoreError> {
    inputs.validate()?;
    let plan = resolve_authority_plan(&inputs.profile, &inputs.image, &inputs.authority_toml)?;
    if plan.digest().map_err(|_| JobStoreError::Invalid)? != inputs.plan_sha256 {
        return Err(JobStoreError::Invalid);
    }
    Ok(plan)
}
/// Resolves a bounded operator-owned mandatory command recipe before job admission.
/// Candidate request data must never call this as an authority provisioning path.
pub fn resolve_authority_plan(
    profile: &str,
    image: &str,
    authority_toml: &str,
) -> Result<ValidationPlan, JobStoreError> {
    if authority_toml.len() > 65536 {
        return Err(JobStoreError::Invalid);
    }
    let config = crate::configuration::ProjectConfiguration::parse(authority_toml)
        .map_err(|_| JobStoreError::Invalid)?;
    let requested = config.execution_request().ok_or(JobStoreError::Invalid)?;
    if requested.profile() != profile {
        return Err(JobStoreError::Invalid);
    }
    let authority =
        AuthorityConfiguration::development(vec![(profile.to_owned(), image.to_owned())])
            .map_err(|_| JobStoreError::Invalid)?
            .with_required_steps(
                requested
                    .steps()
                    .iter()
                    .map(|s| AuthorityRequiredStep {
                        id: s.id.clone(),
                        profile: profile.to_owned(),
                        command: s.command.clone(),
                        evidence: s.evidence,
                    })
                    .collect(),
            )
            .map_err(|_| JobStoreError::Invalid)?;
    let plan = authority
        .resolve(None)
        .map_err(|_| JobStoreError::Invalid)?;
    if plan.steps().is_empty() {
        return Err(JobStoreError::Invalid);
    }
    Ok(plan)
}

impl WorkerResult {
    /// Verifies structural source/plan/attempt/execution binding before evidence persistence.
    /// The private authenticated worker channel is still required; structure is not attestation.
    pub fn validate(
        &self,
        job: JobId,
        attempt: AttemptId,
        inputs: &JobInputs,
    ) -> Result<(), JobStoreError> {
        let plan = pinned_plan(inputs)?;
        if self.schema != 1
            || self.job != job
            || self.attempt != attempt
            || self.source != inputs.source
            || self.plan_sha256 != inputs.plan_sha256
            || self.producer != "archcert-worker-v1/0.1.0"
            || self.steps.len() != plan.steps().len()
        {
            return Err(JobStoreError::Invalid);
        }
        let mut executions = std::collections::BTreeSet::new();
        for (record, step) in self.steps.iter().zip(plan.steps()) {
            if record.step != step.id() || !executions.insert(record.execution.to_string()) {
                return Err(JobStoreError::Invalid);
            }
            if let Some(e) = &record.evidence {
                if e.execution != record.execution
                    || e.source != inputs.source
                    || e.backend_version != "archcert-docker-cli-v1"
                    || e.producer_version != "0.1.0"
                    || e.started_at_ms > e.ended_at_ms
                    || e.environment_keys
                        != archcert_domain::execution::sandbox_environment()
                            .into_keys()
                            .collect::<Vec<_>>()
                    || e.container_user != "10001:10001"
                {
                    return Err(JobStoreError::Invalid);
                }
                e.limits.validate().map_err(|_| JobStoreError::Invalid)?;
                for stream in [&e.stdout, &e.stderr] {
                    if stream.excerpt.len() as u64 > e.limits.excerpt_bytes
                        || stream.excerpt.len() as u64 > stream.observed_bytes
                        || (stream.complete
                            && !stream.truncated
                            && (stream.observed_bytes != stream.excerpt.len() as u64
                                || archcert_domain::source::digest_bytes(&stream.excerpt)
                                    != stream.sha256))
                    {
                        return Err(JobStoreError::Invalid);
                    }
                }
                crate::validation::ValidationObservation::from_execution(&plan, step, e)
                    .map_err(|_| JobStoreError::Invalid)?;
            }
        }
        Ok(())
    }
}
