//! Stable authority-generated diagnostics. Candidate text never enters messages.

use crate::IngressError;
use archcert_domain::source::{ResourceLimit, SourceError, SourceLimits};
use archcert_source::PackLimits;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Bounded public failure vocabulary, also retained in ingress evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngressCode {
    /// The fixed OpenSSH device mapping was absent or disabled.
    AuthenticationDenied,
    /// The authenticated device lacked the exact repository grant.
    RepositoryDenied,
    /// The forced command was outside the literal receive contract.
    ReceiveCommandDenied,
    /// Trusted configuration is malformed or violates implementation ceilings.
    IngressConfigurationInvalid,
    /// Incoming pack exceeded its byte budget.
    IngressPackTooLarge,
    /// Advertised pack entry count exceeded its budget.
    IngressObjectCountExceeded,
    /// Aggregate decoder or selected-closure work exceeded its budget.
    IngressObjectWorkExceeded,
    /// Selected snapshot exceeded retained content bytes.
    SourceSnapshotTooLarge,
    /// Selected snapshot contained too many leaves.
    SourceFileCountExceeded,
    /// An individual source blob exceeded its budget.
    SourceBlobTooLarge,
    /// A path or portable alias was rejected.
    SourcePathRejected,
    /// Selected source tree nesting exceeded its budget.
    SourceTreeDepthExceeded,
    /// Selected source required too many object reads.
    SourceObjectVisitsExceeded,
    /// An individual Git object exceeded its decoder budget.
    IngressObjectTooLarge,
    /// Delta ancestry or expansion exceeded its independent safety budget.
    IngressDeltaLimitExceeded,
    /// Object grammar, identity, representation or checksum was rejected.
    SourceObjectInvalid,
    /// Required objects were absent; no content is fabricated.
    SourceIncomplete,
    /// Session wall time expired.
    IngressSessionTimeout,
    /// Concurrent admission or retained-attempt capacity was exhausted.
    IngressCapacityExhausted,
    /// Authority storage or an infrastructure adapter was unavailable.
    IngressStorageUnavailable,
    /// Input or binding was rejected without a more specific established cause.
    SourceRejected,
    /// The supported receive protocol was rejected.
    IngressProtocolRejected,
    /// A bounded internal operation could not complete.
    IngressInternalError,
}

/// Safe actionable details; all values originate in authority checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressFailure {
    /// Stable machine-readable classification.
    pub code: IngressCode,
    /// Applied authority budget, when the check identifies one.
    pub configured: Option<u64>,
    /// Measured value, absent when no measurement is available.
    pub observed: Option<u64>,
}

impl fmt::Display for IngressFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serialization of a closed enum supplies only fixed ASCII identifiers.
        let code = serde_json::to_string(&self.code).map_err(|_| fmt::Error)?;
        write!(f, "{}", code.trim_matches('"'))?;

        if let Some(limit) = self.configured {
            write!(f, "; configured={limit}")?;
        }

        if let Some(observed) = self.observed {
            write!(f, "; observed={observed}")?;
        }

        let action = match self.code {
            IngressCode::IngressSessionTimeout => {
                "source admission exceeded the configured deadline"
            }
            IngressCode::IngressPackTooLarge
            | IngressCode::IngressObjectWorkExceeded
            | IngressCode::SourceSnapshotTooLarge => {
                "authority budget exceeded; request operator capacity review"
            }
            IngressCode::IngressCapacityExhausted => {
                "receive lease busy or retained capacity exhausted; contact the operator"
            }
            IngressCode::IngressStorageUnavailable => {
                "operator must inspect private storage and Git adapter readiness"
            }
            IngressCode::IngressConfigurationInvalid => {
                "operator must correct private host configuration"
            }
            _ => "source admission did not complete; inspect retained ingress evidence",
        };

        write!(f, "; {action}")
    }
}

impl IngressFailure {
    pub(crate) fn new(code: IngressCode) -> Self {
        Self {
            code,
            configured: None,
            observed: None,
        }
    }

    pub(crate) fn source(
        error: SourceError,
        source: SourceLimits,
        pack: Option<PackLimits>,
    ) -> Self {
        use IngressCode as C;
        use ResourceLimit as R;

        let (code, configured) = match error {
            SourceError::LimitExceeded(kind) => match kind {
                R::PackBytes => (C::IngressPackTooLarge, pack.map(|p| p.max_pack_bytes)),
                R::Files => (C::SourceFileCountExceeded, Some(source.max_files)),
                R::TotalBytes => (C::SourceSnapshotTooLarge, Some(source.max_total_bytes)),
                R::BlobBytes => (C::SourceBlobTooLarge, Some(source.max_blob_bytes)),
                R::TreeDepth => (
                    C::SourceTreeDepthExceeded,
                    Some(u64::from(source.max_tree_depth)),
                ),
                R::Objects => match pack {
                    Some(p) => (
                        C::IngressObjectCountExceeded,
                        Some(u64::from(p.max_objects)),
                    ),
                    None => (C::SourceObjectVisitsExceeded, Some(source.max_objects)),
                },
                R::ObjectBytes => (
                    C::IngressObjectTooLarge,
                    Some(pack.map_or(source.max_object_bytes, |p| p.max_object_bytes)),
                ),
                R::ObjectWorkBytes => (
                    C::IngressObjectWorkExceeded,
                    Some(pack.map_or(source.max_object_work_bytes, |p| p.max_decoded_bytes)),
                ),
                R::DeltaDepth | R::DeltaExpansion => (C::IngressDeltaLimitExceeded, None),
            },
            SourceError::SessionTimeout => (C::IngressSessionTimeout, None),
            SourceError::InvalidSourcePath | SourceError::PathCollision => {
                (C::SourcePathRejected, None)
            }
            SourceError::CommitNotFound
            | SourceError::MissingTree
            | SourceError::MissingBlob
            | SourceError::IncompleteExternalSource => (C::SourceIncomplete, None),
            SourceError::RepositoryAccessFailure | SourceError::SnapshotUnavailable => {
                (C::IngressStorageUnavailable, None)
            }
            SourceError::InternalIntegrityFailure => (C::IngressInternalError, None),
            _ => (C::SourceObjectInvalid, None),
        };

        Self {
            code,
            configured,
            observed: None,
        }
    }
}

impl IngressError {
    /// Safe classification without filesystem paths, raw subprocess output or source text.
    pub fn diagnostic(&self) -> IngressFailure {
        use IngressCode as C;

        match self {
            Self::Failure(failure) => failure.clone(),
            Self::Configuration => IngressFailure::new(C::IngressConfigurationInvalid),
            Self::Rejected => IngressFailure::new(C::SourceRejected),
            Self::Protocol => IngressFailure::new(C::IngressProtocolRejected),
            Self::Command => IngressFailure::new(C::ReceiveCommandDenied),
            Self::Limit => IngressFailure::new(C::IngressCapacityExhausted),
            Self::Unavailable => IngressFailure::new(C::IngressStorageUnavailable),
            Self::Authentication => IngressFailure::new(C::AuthenticationDenied),
            Self::Authorization => IngressFailure::new(C::RepositoryDenied),
        }
    }
}

/// Operational evidence, separate from canonical source identity. Historical records
/// deserialize with absent measurements rather than invented values.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressDiagnostics {
    /// Exact authority capacity at admission, absent on historical records.
    #[serde(default)]
    pub capacity: Option<crate::IngressCapacity>,
    /// Last authority-controlled phase reached.
    pub stage: Option<String>,
    /// Monotonic wall time through validation/publication or rejection.
    pub elapsed_ms: Option<u64>,
    /// Classified reason, absent on acceptance and historical opaque rejections.
    pub failure: Option<IngressFailure>,
    /// Bounded pack prefix measurements, retained on early rejection too.
    pub reception: Option<archcert_source::PackReception>,
    /// Conservative pack decoder work, including progress on rejection.
    #[serde(default)]
    pub decoding: Option<archcert_source::PackDecoding>,
    /// Retained source content bytes, available after selected-source validation.
    pub source_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_follow_the_check_and_never_include_hostile_details() {
        let source = SourceLimits::default();
        let pack = PackLimits::default();
        let cases = [
            (
                ResourceLimit::PackBytes,
                Some(pack),
                IngressCode::IngressPackTooLarge,
            ),
            (
                ResourceLimit::Objects,
                Some(pack),
                IngressCode::IngressObjectCountExceeded,
            ),
            (
                ResourceLimit::Objects,
                None,
                IngressCode::SourceObjectVisitsExceeded,
            ),
            (
                ResourceLimit::TotalBytes,
                None,
                IngressCode::SourceSnapshotTooLarge,
            ),
            (
                ResourceLimit::Files,
                None,
                IngressCode::SourceFileCountExceeded,
            ),
            (
                ResourceLimit::BlobBytes,
                None,
                IngressCode::SourceBlobTooLarge,
            ),
            (
                ResourceLimit::ObjectWorkBytes,
                Some(pack),
                IngressCode::IngressObjectWorkExceeded,
            ),
            (
                ResourceLimit::TreeDepth,
                None,
                IngressCode::SourceTreeDepthExceeded,
            ),
        ];

        for (kind, pack, code) in cases {
            let failure = IngressFailure::source(SourceError::LimitExceeded(kind), source, pack);

            assert_eq!(failure.code, code);
            assert!(failure.configured.is_some());
            assert_eq!(failure.observed, None);
        }

        assert_eq!(
            IngressFailure::source(SourceError::MalformedGitObject, source, Some(pack)).code,
            IngressCode::SourceObjectInvalid
        );
        assert_eq!(
            IngressFailure::source(SourceError::SessionTimeout, source, Some(pack)).code,
            IngressCode::IngressSessionTimeout
        );
        assert_eq!(
            IngressError::Unavailable.diagnostic().code,
            IngressCode::IngressStorageUnavailable
        );
        assert_eq!(
            IngressError::Limit.diagnostic().code,
            IngressCode::IngressCapacityExhausted
        );
        assert!(
            !crate::input_error(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "/private/secret"
            ))
            .diagnostic()
            .to_string()
            .contains("secret")
        );
    }
}
