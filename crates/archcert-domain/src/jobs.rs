//! Durable job language. Operational state is separate from cryptographic validity.

use crate::{
    ProjectId, Sha256Digest, SourceIdentity,
    ingress::{GitActorId, SourceSubmissionId},
    source::RepositoryId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Invalid durable input or state transition; diagnostics never include secrets.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid durable job input or transition")]
pub struct JobError;

macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new immutable authority identity.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Checks canonical RFC 4122 UUID v4 text.
            pub fn parse(text: &str) -> Result<Self, JobError> {
                let id = Uuid::parse_str(text).map_err(|_| JobError)?;

                if id.get_version_num() != 4
                    || id.get_variant() != uuid::Variant::RFC4122
                    || id.to_string() != text
                {
                    return Err(JobError);
                }

                Ok(Self(id))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl TryFrom<String> for $name {
            type Error = JobError;

            fn try_from(v: String) -> Result<Self, JobError> {
                Self::parse(&v)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.to_string()
            }
        }
    };
}

identity!(JobId, "Immutable certification job identity.");

identity!(
    AttemptId,
    "Fresh identity for exactly one execution attempt."
);

identity!(
    LeaseToken,
    "Unpredictable fencing capability, never passed into target execution."
);

/// Client key, scoped by authenticated actor, project and repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Accepts 1–128 ASCII identifier characters, excluding whitespace/control data.
    pub fn parse(text: String) -> Result<Self, JobError> {
        if text.is_empty()
            || text.len() > 128
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            return Err(JobError);
        }

        Ok(Self(text))
    }

    /// Exact scoped key; never a filesystem path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = JobError;

    fn try_from(v: String) -> Result<Self, JobError> {
        Self::parse(v)
    }
}

impl From<IdempotencyKey> for String {
    fn from(v: IdempotencyKey) -> String {
        v.0
    }
}

/// Authority-owned policy pin; no lookup of a mutable default is allowed on restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPin {
    /// Authority policy name.
    pub id: String,
    /// Exact version.
    pub version: String,
    /// Canonical policy digest.
    pub sha256: Sha256Digest,
}

/// All immutable job inputs. Deserialization conveys no acceptance or authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobInputs {
    /// Authority project scope.
    pub project: ProjectId,
    /// Authority repository scope.
    pub repository: RepositoryId,
    /// Already accepted Northgate submission.
    pub submission: SourceSubmissionId,
    /// Full immutable source binding; no ref or HEAD.
    pub source: SourceIdentity,
    /// Authenticated requesting actor.
    pub actor: GitActorId,
    /// Pinned authority policy.
    pub policy: PolicyPin,
    /// Pinned authority execution profile.
    pub profile: String,
    /// Exact image repository@sha256 digest.
    pub image: String,
    /// Exact resolved authority plan digest.
    pub plan_sha256: Sha256Digest,
    /// Bounded authority command configuration retained for deterministic reconstruction.
    pub authority_toml: String,
    /// Authority maximum total attempts (including the initial attempt).
    pub maximum_attempts: u16,
}

impl JobInputs {
    /// Checks structural bounds; application must independently verify source/policy/plan.
    pub fn validate(&self) -> Result<(), JobError> {
        let (_, hash) = self.image.rsplit_once("@sha256:").ok_or(JobError)?;

        if Sha256Digest::parse(hash).is_err()
            || self.image.len() > 512
            || self.image.bytes().any(|b| b.is_ascii_whitespace())
            || self.profile.is_empty()
            || self.profile.len() > 64
            || self.policy.id.is_empty()
            || self.policy.id.len() > 128
            || self.policy.version.is_empty()
            || self.policy.version.len() > 64
            || self.authority_toml.len() > 65536
            || self.authority_toml.is_empty()
            || !(1..=3).contains(&self.maximum_attempts)
            || self.source.commit.as_str().len() != self.source.tree.as_str().len()
        {
            return Err(JobError);
        }

        Ok(())
    }
}

/// Durable job state; terminal states never become active again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    /// Waiting for a fresh attempt.
    Queued,
    /// One leased attempt owns execution.
    Running,
    /// Validated durable evidence is ready for controller evaluation.
    Evaluating,
    /// Eligibility and exact issuance payload are durable before signing.
    Signing,
    /// Verified immutable certificate metadata was committed.
    Completed,
    /// Policy evidence is insufficient or failed; never automatically retried.
    NotEligible,
    /// Infrastructure uncertainty exhausted safe recovery.
    Inconclusive,
}

impl JobState {
    /// True only for states that cannot transition again.
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::NotEligible | Self::Inconclusive
        )
    }

    /// Checks the state graph. RUNNING -> QUEUED additionally requires repository retry/cleanup checks.
    pub fn transition(self, next: Self) -> Result<Self, JobError> {
        if matches!(
            (self, next),
            (Self::Queued, Self::Running)
                | (
                    Self::Running,
                    Self::Queued | Self::Evaluating | Self::Inconclusive
                )
                | (
                    Self::Evaluating,
                    Self::Signing | Self::NotEligible | Self::Inconclusive
                )
                | (Self::Signing, Self::Completed | Self::Inconclusive)
        ) {
            Ok(next)
        } else {
            Err(JobError)
        }
    }
}

/// Attempt history; evidence-ready closes worker execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptState {
    /// Claimed but target execution has not started.
    Leased,
    /// Target execution started.
    Running,
    /// Bound evidence durably accepted; worker lease is closed.
    EvidenceReady,
    /// Job completed with this attempt's evidence.
    Completed,
    /// Explicit classified infrastructure failure.
    Failed,
    /// Lease expired; no target failure is inferred.
    Lost,
}

/// Persisted failure category, separate from policy eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCategory {
    /// Target command failed; no retry until pass.
    TargetFailure,
    /// Authority policy did not permit issuance.
    PolicyFailure,
    /// Explicit infrastructure impairment.
    InfrastructureFailure,
    /// Worker lease expired.
    WorkerLoss,
    /// Artifact/database persistence could not be established.
    PersistenceFailure,
    /// Signer failed for the frozen issuance payload.
    SigningFailure,
    /// Cryptographic verification failed.
    VerificationFailure,
    /// Authorized operator canceled work.
    OperatorCancellation,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_states_and_invalid_transitions_fail_closed() {
        for state in [
            JobState::Completed,
            JobState::NotEligible,
            JobState::Inconclusive,
        ] {
            for next in [
                JobState::Queued,
                JobState::Running,
                JobState::Evaluating,
                JobState::Signing,
                JobState::Completed,
            ] {
                assert!(state.transition(next).is_err());
            }
        }

        assert!(JobState::Queued.transition(JobState::Completed).is_err());
        assert!(JobState::Running.transition(JobState::Signing).is_err());
        assert!(JobState::Running.transition(JobState::Evaluating).is_ok());
        assert!(IdempotencyKey::parse("../candidate key".into()).is_err());
        assert!(AttemptId::parse("latest").is_err());
        assert_ne!(AttemptId::new(), AttemptId::new());
    }
}
