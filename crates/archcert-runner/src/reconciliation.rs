//! Runtime-only ownership checks. Durable DB decisions belong to trusted orchestration.
use crate::{DockerRuntime, ExecutionGateLease};
use archcert_application::jobs::RuntimeCleanupState;
use archcert_domain::{
    execution::{ExecutionError, ExecutionId},
    jobs::{AttemptId, JobId},
};
use serde::Serialize;
use serde_json::Value;

/// Runtime object class; no arbitrary prune operation exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RuntimeObjectKind {
    /// Preparation or target container.
    Container,
    /// Job-local committed preparation image.
    Image,
}
/// Bounded inspection result. Labels are correlation, not attestation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeObject {
    /// Object class.
    pub kind: RuntimeObjectKind,
    /// Full immutable runtime object identity.
    pub id: String,
    /// Parsed durable job identity, if valid.
    pub job: Option<JobId>,
    /// Parsed attempt identity, if valid.
    pub attempt: Option<AttemptId>,
    /// Parsed execution identity, if valid.
    pub execution: Option<ExecutionId>,
    /// Owner/version, all identities and exact name/tag agree.
    pub owned: bool,
}
fn object(kind: RuntimeObjectKind, id: &str, v: &Value) -> RuntimeObject {
    let labels = &v["Config"]["Labels"];
    let job = labels["archcert.certification-job"]
        .as_str()
        .and_then(|s| JobId::parse(s).ok());
    let attempt = labels["archcert.attempt"]
        .as_str()
        .and_then(|s| AttemptId::parse(s).ok());
    let execution = labels["archcert.execution"]
        .as_str()
        .and_then(|s| ExecutionId::try_from(s.to_owned()).ok());
    let owned = execution.is_some_and(|execution| {
        let named = match kind {
            RuntimeObjectKind::Container => {
                v["Name"] == format!("/archcert-{execution}")
                    || v["Name"] == format!("/archcert-{execution}-prepare")
            }
            RuntimeObjectKind::Image => {
                v["RepoTags"] == serde_json::json!([format!("archcert-job:{execution}")])
            }
        };
        v["Id"] == id
            && job.is_some()
            && attempt.is_some()
            && named
            && labels["archcert.job"] == execution.to_string()
            && labels["archcert.owner"] == "execution-v1"
            && labels["archcert.ownership"] == "2"
    });
    RuntimeObject {
        kind,
        id: id.into(),
        job,
        attempt,
        execution,
        owned,
    }
}
impl DockerRuntime {
    fn inspect_owned(
        &self,
        kind: RuntimeObjectKind,
        id: &str,
    ) -> Result<RuntimeObject, ExecutionError> {
        let group = match kind {
            RuntimeObjectKind::Container => "container",
            RuntimeObjectKind::Image => "image",
        };
        let inspection = self.json(&[group, "inspect", id])?;
        let first = inspection
            .as_array()
            .filter(|a| a.len() == 1)
            .and_then(|a| a.first())
            .ok_or(ExecutionError::RuntimeFailure)?;
        Ok(object(kind, id, first))
    }
    /// Lists only objects with the owner label on a validated rootless daemon, with bounded count.
    /// Unknown/legacy/malformed ownership is retained for operator inspection.
    pub fn inventory(&self) -> Result<Vec<RuntimeObject>, ExecutionError> {
        self.preflight()?;
        let mut objects = Vec::new();
        for (kind, group) in [
            (RuntimeObjectKind::Container, "container"),
            (RuntimeObjectKind::Image, "image"),
        ] {
            let mut args = vec![
                group.into(),
                "ls".into(),
                "--quiet".into(),
                "--no-trunc".into(),
                "--filter".into(),
                "label=archcert.owner=execution-v1".into(),
            ];
            if kind == RuntimeObjectKind::Container {
                args.push("--all".into());
            }
            let out = self.call(&args, &[], 256 * 1024)?;
            let text = std::str::from_utf8(&out.stdout.excerpt)
                .map_err(|_| ExecutionError::RuntimeFailure)?;
            let ids: std::collections::BTreeSet<_> = text.lines().collect();
            for id in ids {
                let hash = id.strip_prefix("sha256:").unwrap_or(id);
                if hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || objects.len() >= 256
                {
                    return Err(ExecutionError::EnvironmentNotProven);
                }
                objects.push(self.inspect_owned(kind, id)?);
            }
        }
        Ok(objects)
    }
    /// Removes only exact-attempt owned objects while its revoked exclusive gate is held.
    /// The controller must durably fence DB authority first; uncertain creates stay blocked.
    pub fn reconcile_attempt(
        &self,
        job: JobId,
        attempt: AttemptId,
        gate: &ExecutionGateLease,
    ) -> Result<RuntimeCleanupState, ExecutionError> {
        if !gate.revoked() || !gate.matches(job, attempt) {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        let observed = self.preflight()?;
        if observed.runtime_information.get("authority/endpoint") != Some(&gate.binding().endpoint)
            || observed.runtime_information.get("ID") != Some(&gate.binding().daemon_id)
        {
            return Err(ExecutionError::EnvironmentNotProven);
        }
        let objects = self.inventory()?;
        let owned: Vec<_> = objects
            .into_iter()
            .filter(|o| o.job == Some(job) && o.attempt == Some(attempt))
            .collect();
        if owned.iter().any(|o| !o.owned) {
            return Ok(RuntimeCleanupState::Blocked);
        }
        // Inventory orders containers before images. Reinspect immutable identity and labels.
        for expected in owned {
            if self.inspect_owned(expected.kind, &expected.id)? != expected {
                return Ok(RuntimeCleanupState::Blocked);
            }
            let args = match expected.kind {
                RuntimeObjectKind::Container => {
                    vec!["container", "rm", "--force", "--volumes", &expected.id]
                }
                RuntimeObjectKind::Image => vec!["image", "rm", &expected.id],
            };
            self.call(
                &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                &[],
                256 * 1024,
            )?;
        }
        if self
            .inventory()?
            .iter()
            .any(|o| o.job == Some(job) && o.attempt == Some(attempt))
        {
            return Ok(RuntimeCleanupState::Failed);
        }
        Ok(if gate.uncertain_creation() {
            RuntimeCleanupState::Blocked
        } else {
            RuntimeCleanupState::Succeeded
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_requires_job_attempt_execution_version_and_exact_resource_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = JobId::new();
        let attempt = AttemptId::new();
        let execution = ExecutionId::new();
        let id = "a".repeat(64);
        let v = serde_json::json!({"Id":id,"Name":format!("/archcert-{execution}"),"Config":{"Labels":{
            "archcert.owner":"execution-v1","archcert.ownership":"2","archcert.job":execution.to_string(),
            "archcert.execution":execution.to_string(),"archcert.certification-job":job.to_string(),"archcert.attempt":attempt.to_string()}}});
        assert!(object(RuntimeObjectKind::Container, &id, &v).owned);
        for key in [
            "archcert.owner",
            "archcert.ownership",
            "archcert.job",
            "archcert.execution",
            "archcert.certification-job",
            "archcert.attempt",
        ] {
            let mut invalid = v.clone();
            invalid["Config"]["Labels"][key] = Value::Null;
            assert!(
                !object(RuntimeObjectKind::Container, &id, &invalid).owned,
                "{key}"
            );
        }
        let mut invalid = v.clone();
        invalid["Name"] = serde_json::json!("/unrelated");
        assert!(!object(RuntimeObjectKind::Container, &id, &invalid).owned);
        assert!(!object(RuntimeObjectKind::Container, &"b".repeat(64), &v).owned);
        let mut image = v;
        image["RepoTags"] = serde_json::json!([format!("archcert-job:{execution}")]);
        assert!(object(RuntimeObjectKind::Image, &id, &image).owned);
        image["RepoTags"] =
            serde_json::json!([format!("archcert-job:{execution}"), "unrelated:tag"]);
        assert!(!object(RuntimeObjectKind::Image, &id, &image).owned);
        Ok(())
    }
}
