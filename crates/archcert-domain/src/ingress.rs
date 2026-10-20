//! Authenticated submission identity, independent of certification jobs.
use crate::{Sha256Digest, source::SourceError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable authority actor identity; a display name is not authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct GitActorId(String);
impl GitActorId {
    /// Returns the canonical authority-assigned actor UUID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accepts a canonical UUID v4 assigned by the authority.
    pub fn parse(value: String) -> Result<Self, SourceError> {
        let id = Uuid::parse_str(&value).map_err(|_| SourceError::UnsupportedRepository)?;
        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != value
        {
            return Err(SourceError::UnsupportedRepository);
        }
        Ok(Self(value))
    }
}
impl TryFrom<String> for GitActorId {
    type Error = SourceError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// SHA-256 of the public SSH wire-key blob, never a private key or filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceKeyId(Sha256Digest);
impl DeviceKeyId {
    /// Validates a public-material fingerprint.
    pub fn parse(value: String) -> Result<Self, SourceError> {
        Ok(Self(
            Sha256Digest::parse(value).map_err(|_| SourceError::UnsupportedRepository)?,
        ))
    }
    /// Canonical fingerprint for the restricted OpenSSH command mapping.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Fresh authority-generated submission identity; replay gets a different ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SourceSubmissionId(Uuid);
impl SourceSubmissionId {
    /// Creates a random UUID v4 unrelated to source identity.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    /// Validates canonical UUID v4 text before any storage lookup.
    pub fn parse(value: &str) -> Result<Self, SourceError> {
        let id = Uuid::parse_str(value).map_err(|_| SourceError::SnapshotUnavailable)?;
        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != value
        {
            return Err(SourceError::SnapshotUnavailable);
        }
        Ok(Self(id))
    }
}
impl Default for SourceSubmissionId {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Display for SourceSubmissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl TryFrom<String> for SourceSubmissionId {
    type Error = SourceError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<SourceSubmissionId> for String {
    fn from(value: SourceSubmissionId) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ingress_identifiers_reject_path_syntax_and_submission_replay_is_distinct() {
        for value in [
            "",
            "../project",
            "actor",
            "00000000-0000-4000-0000-000000000001",
        ] {
            assert!(GitActorId::parse(value.into()).is_err());
            assert!(SourceSubmissionId::parse(value).is_err());
        }
        assert!(DeviceKeyId::parse("private-key".into()).is_err());
        assert_ne!(SourceSubmissionId::new(), SourceSubmissionId::new());
    }
}
