//! Bounded worker wire adapters. Transport parsing creates no execution authority.

use super::{ConversionError as E, execution::v1 as p};
use archcert_application::worker as a;
use archcert_domain::jobs::*;
use prost::Message;
fn required<T>(v: Option<T>) -> Result<T, E> {
    v.ok_or(E("worker required field"))
}

fn invalid(_: impl std::fmt::Debug) -> E {
    E("worker contract")
}

impl TryFrom<p::WorkerAssignment> for a::WorkerAssignment {
    type Error = E;

    fn try_from(w: p::WorkerAssignment) -> Result<Self, E> {
        if w.contract_version != 1
            || w.source_artifact.is_empty()
            || w.source_artifact.len() > 72 * 1024 * 1024
        {
            return Err(E("worker version/size"));
        }

        let inputs = JobInputs {
            project: required(w.project)?.try_into()?,
            repository: required(w.repository)?.try_into()?,
            submission: required(w.submission)?.try_into()?,
            source: required(w.source)?.try_into()?,
            actor: required(w.actor)?.try_into()?,
            policy: PolicyPin {
                id: w.policy_id,
                version: w.policy_version,
                sha256: required(w.policy_sha256)?.try_into()?,
            },
            profile: w.profile,
            image: w.image,
            plan_sha256: required(w.plan_sha256)?.try_into()?,
            authority_toml: w.authority_toml,
            maximum_attempts: u16::try_from(w.maximum_attempts).map_err(invalid)?,
        };
        a::pinned_plan(&inputs).map_err(invalid)?;

        Ok(Self {
            job: JobId::parse(&w.job_id).map_err(invalid)?,
            attempt: AttemptId::parse(&w.attempt_id).map_err(invalid)?,
            inputs,
            source_artifact: w.source_artifact,
        })
    }
}

impl TryFrom<&a::WorkerAssignment> for p::WorkerAssignment {
    type Error = E;

    fn try_from(w: &a::WorkerAssignment) -> Result<Self, E> {
        let i = &w.inputs;
        a::pinned_plan(i).map_err(invalid)?;

        Ok(Self {
            contract_version: 1,
            job_id: w.job.to_string(),
            attempt_id: w.attempt.to_string(),
            project: Some((&i.project).into()),
            repository: Some((&i.repository).into()),
            submission: Some((&i.submission).into()),
            source: Some((&i.source).try_into()?),
            actor: Some((&i.actor).into()),
            policy_id: i.policy.id.clone(),
            policy_version: i.policy.version.clone(),
            policy_sha256: Some((&i.policy.sha256).try_into()?),
            profile: i.profile.clone(),
            image: i.image.clone(),
            plan_sha256: Some((&i.plan_sha256).try_into()?),
            authority_toml: i.authority_toml.clone(),
            maximum_attempts: u32::from(i.maximum_attempts),
            source_artifact: w.source_artifact.clone(),
        })
    }
}

/// Encodes checked pinned work for a private authority-owned process pipe.
pub fn encode_assignment(w: &a::WorkerAssignment) -> Result<Vec<u8>, E> {
    let bytes = p::WorkerAssignment::try_from(w)?.encode_to_vec();

    if bytes.len() > a::MAX_ASSIGNMENT_BYTES {
        return Err(E("assignment size"));
    }

    Ok(bytes)
}

/// Decodes bounded pinned work. Source artifact validation remains independently required.
pub fn decode_assignment(bytes: &[u8]) -> Result<a::WorkerAssignment, E> {
    if bytes.len() > a::MAX_ASSIGNMENT_BYTES {
        return Err(E("assignment size"));
    }

    p::WorkerAssignment::decode(bytes)
        .map_err(invalid)?
        .try_into()
}

/// Serializes existing operational evidence in a typed, versioned worker envelope.
pub fn encode_result(w: &a::WorkerResult) -> Result<Vec<u8>, E> {
    let executions = w
        .steps
        .iter()
        .map(|s| {
            Ok(p::CompletedExecution {
                step_id: s.step.clone(),
                execution_id: s.execution.to_string(),
                execution_evidence_json: s
                    .evidence
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()
                    .map_err(invalid)?,
                source_cleanup_confirmed: s.source_cleaned,
                sandbox_cleanup_confirmed: s.sandbox_cleaned,
            })
        })
        .collect::<Result<Vec<_>, E>>()?;
    let bytes = p::WorkerResult {
        contract_version: w.schema,
        job_id: w.job.to_string(),
        attempt_id: w.attempt.to_string(),
        source: Some((&w.source).try_into()?),
        plan_sha256: Some((&w.plan_sha256).try_into()?),
        producer: w.producer.clone(),
        executions,
    }
    .encode_to_vec();

    if bytes.len() > a::MAX_RESULT_BYTES {
        return Err(E("result size"));
    }

    Ok(bytes)
}

/// Decodes bounded operational records. Caller must validate against the actual leased job.
pub fn decode_result(bytes: &[u8]) -> Result<a::WorkerResult, E> {
    if bytes.len() > a::MAX_RESULT_BYTES {
        return Err(E("result size"));
    }

    let w = p::WorkerResult::decode(bytes).map_err(invalid)?;

    if w.contract_version != 1
        || w.executions.len() > 160
        || w.producer != "archcert-worker-v1/0.1.0"
    {
        return Err(E("result version/producer"));
    }

    let steps = w
        .executions
        .into_iter()
        .map(|s| {
            if s.step_id.is_empty() || s.step_id.len() > 128 {
                return Err(E("step ID"));
            }

            Ok(a::StepResult {
                step: s.step_id,
                execution: s.execution_id.try_into().map_err(invalid)?,
                evidence: s
                    .execution_evidence_json
                    .map(|b| serde_json::from_slice(&b))
                    .transpose()
                    .map_err(invalid)?,
                source_cleaned: s.source_cleanup_confirmed,
                sandbox_cleaned: s.sandbox_cleanup_confirmed,
            })
        })
        .collect::<Result<Vec<_>, E>>()?;

    Ok(a::WorkerResult {
        schema: 1,
        job: JobId::parse(&w.job_id).map_err(invalid)?,
        attempt: AttemptId::parse(&w.attempt_id).map_err(invalid)?,
        source: required(w.source)?.try_into()?,
        plan_sha256: required(w.plan_sha256)?.try_into()?,
        producer: w.producer,
        steps,
    })
}
