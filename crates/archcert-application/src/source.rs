//! Source submission orchestration and ports. Adapters cannot select policy or sign.

use archcert_domain::{
    GitObjectId, ProjectId, SourceIdentity,
    source::{
        ExternalSource, RepositoryId, SourceError, SourceFile, SourceLimits, SourceSnapshot,
        SourceStatus,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Exact source request suitable for a future authenticated Git push/API flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSubmission {
    /// Authority project identity, never read from target configuration.
    pub project: ProjectId,
    /// Authority repository identity mapped to transport by the gateway.
    pub repository: RepositoryId,
    /// Full object ID; symbolic references and abbreviations are not accepted.
    pub requested_commit: GitObjectId,
}

/// Bounded, verified selected-commit closure transferred out of quarantine.
pub struct ValidatedSource {
    /// Exact commit verified against received bytes.
    pub commit: GitObjectId,
    /// Tree parsed from the verified commit.
    pub tree: GitObjectId,
    /// Owned bytes; no paths into the target filesystem survive acceptance.
    pub files: Vec<SourceFile>,
    /// Object visits, including repeated objects, used against the resource budget.
    pub object_count: u64,
}

/// Untrusted reception boundary. Implementations must not execute repository code.
pub trait GitGateway {
    /// Opens a quarantined source without interpreting target configuration or refs.
    fn quarantine(
        &self,
        repository: &RepositoryId,
    ) -> Result<Box<dyn SourceQuarantine>, SourceError>;
}

/// A received source is not accepted until the entire selected closure validates.
pub trait SourceQuarantine {
    /// Validates object identity, grammar, paths and resource limits before returning bytes.
    fn validate(
        &mut self,
        commit: &GitObjectId,
        limits: SourceLimits,
    ) -> Result<ValidatedSource, SourceError>;
}

/// Authority-owned immutable source storage, distinct from repository storage.
pub trait SourceStore {
    /// Retains an immutable snapshot and rechecks its independent identity.
    fn retain(&mut self, snapshot: SourceSnapshot) -> Result<Arc<SourceSnapshot>, SourceError>;
    /// Retrieves only an exact authority-scoped accepted source; no transport lookup occurs.
    fn load(
        &self,
        reference: &archcert_domain::materialization::SnapshotReference,
    ) -> Result<Arc<SourceSnapshot>, SourceError>;
}

pub use crate::materialization::SourceMaterializer;

/// Structural source evidence, independently generated during this invocation.
#[derive(Debug, Clone, Serialize)]
pub struct SourceEvidence {
    /// Original authority-scoped request.
    pub submission: SourceSubmission,
    /// Resolved Git and ArchCert identities.
    pub identity: SourceIdentity,
    /// Manifest leaves processed, including gitlinks.
    pub entry_count: u64,
    /// Validated Git object visits.
    pub object_count: u64,
    /// Retained canonical payload bytes.
    pub total_bytes: u64,
    /// LFS and submodule dependencies, all unresolved in validator version 1.
    pub unresolved: Vec<ExternalSource>,
    /// Completeness, independent of certification policy.
    pub status: SourceStatus,
    /// Validator semantics, versioned separately from human-readable logs.
    pub validation_version: String,
    /// Canonical source schema version.
    pub schema_version: u32,
    /// Authority UTC Unix creation seconds.
    pub created_at: u64,
    /// Authority resource budgets applied to this attempt.
    pub limits: SourceLimits,
}

/// Structured transitions for a future append-only audit sink.
#[derive(Debug, Clone, Serialize)]
pub enum SourceEvent {
    /// Authority request was received.
    Received(SourceSubmission),
    /// Reception succeeded but source remains untrusted.
    Quarantined,
    /// Bounded independent validation is starting.
    ValidationStarted,
    /// Acceptance failed; no source is released.
    Rejected(SourceError),
    /// Validation succeeded; completeness remains explicit.
    Accepted(SourceStatus),
    /// Immutable retained source is now available.
    SnapshotCreated(SourceIdentity),
}

/// Rejected attempt retains its typed failure and structural audit evidence.
#[derive(Debug)]
pub struct SourceRejection {
    /// Input/access/integrity failure; callers must not flatten it to a success state.
    pub error: SourceError,
    /// Ordered events through rejection.
    pub events: Vec<SourceEvent>,
}

impl std::fmt::Display for SourceRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for SourceRejection {}

/// Successful immutable source result; incomplete source is never runner-ready.
pub struct SourceIngestion {
    /// Authority-retained bytes, exposed through read-only APIs.
    pub snapshot: Arc<SourceSnapshot>,
    /// Authoritative structured evidence, suitable for future persistence.
    pub evidence: SourceEvidence,
    /// Ordered transitions; these do not claim durable audit storage.
    pub events: Vec<SourceEvent>,
}

/// Receives, validates, seals and retains source without running target code.
pub fn ingest_source(
    gateway: &dyn GitGateway,
    store: &mut dyn SourceStore,
    submission: SourceSubmission,
    limits: SourceLimits,
) -> Result<SourceIngestion, SourceRejection> {
    let mut events = vec![SourceEvent::Received(submission.clone())];
    let result = (|| {
        let mut quarantine = gateway.quarantine(&submission.repository)?;
        events.push(SourceEvent::Quarantined);
        events.push(SourceEvent::ValidationStarted);
        let validated = quarantine.validate(&submission.requested_commit, limits)?;
        if validated.commit != submission.requested_commit {
            return Err(SourceError::InternalIntegrityFailure);
        }
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SourceError::InternalIntegrityFailure)?
            .as_secs();
        let snapshot = SourceSnapshot::seal(
            submission.project,
            submission.repository.clone(),
            validated.commit,
            validated.tree,
            validated.files,
            validated.object_count,
            created_at,
        )?;
        let expected_identity = snapshot.identity().clone();
        let snapshot = store.retain(snapshot)?;
        snapshot.verify(&expected_identity.snapshot_sha256)?;
        if snapshot.identity() != &expected_identity
            || snapshot.project() != submission.project
            || snapshot.repository() != &submission.repository
        {
            return Err(SourceError::InternalIntegrityFailure);
        }
        events.push(SourceEvent::Accepted(snapshot.status()));
        events.push(SourceEvent::SnapshotCreated(snapshot.identity().clone()));
        let evidence = SourceEvidence {
            submission,
            identity: snapshot.identity().clone(),
            entry_count: snapshot.manifest().entries().len() as u64,
            object_count: snapshot.object_count(),
            total_bytes: snapshot.total_bytes(),
            unresolved: snapshot.external().to_vec(),
            status: snapshot.status(),
            validation_version: "archcert-loose-v1".to_owned(),
            schema_version: snapshot.schema_version(),
            created_at: snapshot.created_at(),
            limits,
        };
        Ok((snapshot, evidence))
    })();
    match result {
        Ok((snapshot, evidence)) => Ok(SourceIngestion {
            snapshot,
            evidence,
            events,
        }),
        Err(error) => {
            events.push(SourceEvent::Rejected(error.clone()));
            Err(SourceRejection { error, events })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use archcert_domain::source::{SourceMode, SourcePath};

    struct Gateway {
        wrong_commit: bool,
    }
    struct Quarantine {
        wrong_commit: bool,
    }
    impl GitGateway for Gateway {
        fn quarantine(&self, _: &RepositoryId) -> Result<Box<dyn SourceQuarantine>, SourceError> {
            Ok(Box::new(Quarantine {
                wrong_commit: self.wrong_commit,
            }))
        }
    }
    impl SourceQuarantine for Quarantine {
        fn validate(
            &mut self,
            commit: &GitObjectId,
            _: SourceLimits,
        ) -> Result<ValidatedSource, SourceError> {
            Ok(ValidatedSource {
                commit: if self.wrong_commit {
                    oid('b')?
                } else {
                    commit.clone()
                },
                tree: oid('a')?,
                files: vec![file(b"original")?],
                object_count: 3,
            })
        }
    }

    struct SubstitutingStore {
        change_bytes: bool,
    }
    impl SourceStore for SubstitutingStore {
        fn load(
            &self,
            _: &archcert_domain::materialization::SnapshotReference,
        ) -> Result<Arc<SourceSnapshot>, SourceError> {
            Err(SourceError::SnapshotUnavailable)
        }
        fn retain(&mut self, snapshot: SourceSnapshot) -> Result<Arc<SourceSnapshot>, SourceError> {
            Ok(Arc::new(SourceSnapshot::seal(
                snapshot.project(),
                snapshot.repository().clone(),
                if self.change_bytes {
                    snapshot.identity().commit.clone()
                } else {
                    oid('c')?
                },
                snapshot.identity().tree.clone(),
                vec![file(if self.change_bytes {
                    b"substituted"
                } else {
                    b"original"
                })?],
                snapshot.object_count(),
                snapshot.created_at(),
            )?))
        }
    }
    fn oid(c: char) -> Result<GitObjectId, SourceError> {
        GitObjectId::parse(c.to_string().repeat(40))
            .map_err(|_| SourceError::InternalIntegrityFailure)
    }
    fn file(bytes: &[u8]) -> Result<SourceFile, SourceError> {
        Ok(SourceFile::new(
            SourcePath::from_bytes(b"a")?,
            SourceMode::File,
            bytes.to_vec(),
        ))
    }
    fn submission() -> Result<SourceSubmission, SourceError> {
        Ok(SourceSubmission {
            project: ProjectId::new(),
            repository: RepositoryId::parse("test/source")?,
            requested_commit: oid('1')?,
        })
    }

    #[test]
    fn source_store_substitution_cannot_change_expected_identity() -> Result<(), SourceError> {
        for change_bytes in [true, false] {
            let result = ingest_source(
                &Gateway {
                    wrong_commit: false,
                },
                &mut SubstitutingStore { change_bytes },
                submission()?,
                SourceLimits::default(),
            );
            let Err(rejection) = result else {
                return Err(SourceError::InternalIntegrityFailure);
            };
            assert_eq!(
                rejection.error,
                if change_bytes {
                    SourceError::SnapshotDigestMismatch
                } else {
                    SourceError::InternalIntegrityFailure
                }
            );
            assert!(matches!(
                rejection.events.last(),
                Some(SourceEvent::Rejected(_))
            ));
            assert!(!rejection.events.iter().any(|e| matches!(
                e,
                SourceEvent::Accepted(_) | SourceEvent::SnapshotCreated(_)
            )));
        }
        Ok(())
    }

    #[test]
    fn gateway_cannot_resolve_a_different_commit_than_requested() -> Result<(), SourceError> {
        let result = ingest_source(
            &Gateway { wrong_commit: true },
            &mut SubstitutingStore {
                change_bytes: false,
            },
            submission()?,
            SourceLimits::default(),
        );
        let Err(rejection) = result else {
            return Err(SourceError::InternalIntegrityFailure);
        };
        assert_eq!(rejection.error, SourceError::InternalIntegrityFailure);
        assert_eq!(rejection.events.len(), 4);
        Ok(())
    }
}
