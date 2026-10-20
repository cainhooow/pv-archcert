//! Core domain model for ArchCert.
//!
//! This crate intentionally has no infrastructure dependencies. It models the
//! certification language used by the rest of the system.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;
use uuid::Uuid;

pub mod execution;
pub mod ingress;
pub mod jobs;
pub mod materialization;
pub mod source;
/// Unique identifier of a registered project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(Uuid);

impl ProjectId {
    /// Creates a new project identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::str::FromStr for ProjectId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

impl Display for ProjectId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Unique identifier of a certification job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationId(Uuid);

impl CertificationId {
    /// Creates a new certification identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CertificationId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for CertificationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Errors raised while constructing immutable source identities.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SourceIdentityError {
    /// A Git object id must be hexadecimal and use a supported length.
    #[error("invalid Git object id")]
    InvalidGitObjectId,
    /// A digest must be a lowercase or uppercase hexadecimal SHA-256 value.
    #[error("invalid SHA-256 digest")]
    InvalidSha256,
}

/// Validated Git object identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct GitObjectId(String);

impl GitObjectId {
    /// Accepts SHA-1 (40 hex chars) and SHA-256 (64 hex chars) Git object ids.
    pub fn parse(value: impl Into<String>) -> Result<Self, SourceIdentityError> {
        let value = value.into();
        let valid_len = value.len() == 40 || value.len() == 64;
        let valid_hex = value.bytes().all(|b| b.is_ascii_hexdigit());
        if valid_len && valid_hex {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(SourceIdentityError::InvalidGitObjectId)
        }
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GitObjectId {
    type Error = SourceIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// SHA-256 digest represented as lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates a SHA-256 hexadecimal digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, SourceIdentityError> {
        let value = value.into();
        if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(SourceIdentityError::InvalidSha256)
        }
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = SourceIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Immutable source identity accepted by ArchCert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    /// Exact Git commit object id.
    pub commit: GitObjectId,
    /// Exact Git tree object id referenced by the commit.
    pub tree: GitObjectId,
    /// ArchCert-owned digest of the normalized source manifest.
    pub snapshot_sha256: Sha256Digest,
}

/// Lifecycle state of a certification job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificationStatus {
    /// Request exists but source has not been accepted yet.
    Pending,
    /// Immutable source identity has been established.
    SourceAccepted,
    /// Independent checks are executing.
    Running,
    /// At least one blocking policy failed.
    Rejected,
    /// The system could not establish a safe final verdict.
    Inconclusive,
}

/// Result of an individual property or policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyVerdict {
    /// Required authoritative evidence positively establishes the property under the selected policy.
    Proven,
    /// Authoritative evidence establishes that the property is false.
    Failed,
    /// Required evidence is absent or insufficient; this is not equivalent to failure or success.
    NotProven,
    /// Authority policy explicitly excludes this target/profile; absence of evidence never suffices.
    NotApplicable,
    /// Evidence exists but infrastructure failure, ambiguity, contradiction or unsupported versions prevent a reliable deterministic conclusion.
    Inconclusive,
}

#[cfg(test)]
mod tests {
    use super::{GitObjectId, Sha256Digest, SourceIdentityError};

    #[test]
    fn accepts_git_sha1_and_sha256_object_ids() {
        assert!(GitObjectId::parse("a".repeat(40)).is_ok());
        assert!(GitObjectId::parse("B".repeat(64)).is_ok());
    }

    #[test]
    fn rejects_invalid_git_object_id() {
        assert_eq!(
            GitObjectId::parse("not-a-sha"),
            Err(SourceIdentityError::InvalidGitObjectId)
        );
    }

    #[test]
    fn validates_sha256_digest() {
        assert!(Sha256Digest::parse("c".repeat(64)).is_ok());
        assert_eq!(
            Sha256Digest::parse("d".repeat(63)),
            Err(SourceIdentityError::InvalidSha256)
        );
    }
}
