//! Strict authoring model and immutable canonical policy identity.

use archcert_domain::{Sha256Digest, source::digest_bytes};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Read};
use thiserror::Error;

/// Maximum authoring bytes, enforced before parsing.
pub const MAX_POLICY_BYTES: usize = 65_536;

/// Only supported authority profile, embedded in the development CLI.
pub const DEVELOPMENT_POLICY: &str = include_str!("../../../policies/archcert-development-v1.toml");

/// Independently reproduced schema-1 development policy digest. Updates require authority review.
pub const DEVELOPMENT_POLICY_SHA256: &str =
    "e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae";

/// Loads the embedded authority profile and checks its independent fixed identity.
pub fn development_bundle() -> Result<PolicyBundle, PolicyError> {
    let bundle = PolicyBundle::read(DEVELOPMENT_POLICY.as_bytes())?;

    if bundle.identity().id != "archcert-development-v1"
        || bundle.identity().version != "1.0.0"
        || bundle.identity().sha256.as_str() != DEVELOPMENT_POLICY_SHA256
    {
        return Err(PolicyError::SelectionMismatch);
    }

    Ok(bundle)
}

/// Separately versioned Ironcrest deterministic requirements. Historical bundles
/// retain their original rule set and canonical identity.
pub use archcert_application::ironcrest::IRONCREST_CONTROLLED_POLICY_ID;

/// Embedded authority bundle, never discovered in a target repository.
pub const IRONCREST_CONTROLLED_POLICY: &str =
    include_str!("../../../policies/archcert-ironcrest-controlled-v1.toml");

/// Independently re-canonicalized SHA-256 of the controlled policy.
pub const IRONCREST_CONTROLLED_POLICY_SHA256: &str =
    "2f0101fffb230caf6957065e91ba0655c25893dbee2f6105f44ce3e62cafef4e";

/// Loads the explicit controlled Ironcrest policy with required challenge evidence.
pub fn ironcrest_controlled_bundle() -> Result<PolicyBundle, PolicyError> {
    let bundle = PolicyBundle::read(IRONCREST_CONTROLLED_POLICY.as_bytes())?;

    if bundle.identity().id != IRONCREST_CONTROLLED_POLICY_ID
        || bundle.identity().version != "1.0.0"
        || bundle.identity().sha256.as_str() != IRONCREST_CONTROLLED_POLICY_SHA256
    {
        return Err(PolicyError::SelectionMismatch);
    }

    Ok(bundle)
}

/// Distinct Rust policy identity requiring the reviewed bounded context chain.
pub use archcert_application::ironcrest::RUST_CONTROLLED_POLICY_ID;

/// Independently canonicalized Rust policy SHA-256.
pub const RUST_CONTROLLED_POLICY_SHA256: &str =
    "7d62950af054c3eb6a12585153a7fb7e5f2ec6850b683c6d4e56098eda0e691e";

/// Loads explicit Rust workspace requirements without altering historical policies.
pub fn rust_controlled_bundle() -> Result<PolicyBundle, PolicyError> {
    let bundle = PolicyBundle::read(
        include_str!("../../../policies/archcert-rust-controlled-v1.toml").as_bytes(),
    )?;

    if bundle.identity().id != RUST_CONTROLLED_POLICY_ID
        || bundle.identity().version != "1.0.0"
        || bundle.identity().sha256.as_str() != RUST_CONTROLLED_POLICY_SHA256
    {
        return Err(PolicyError::SelectionMismatch);
    }

    Ok(bundle)
}

/// Policy input or authority-selection error. Errors never yield eligibility.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// I/O failed while reading the bounded policy.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Strict TOML parsing failed.
    #[error(transparent)]
    Parse(#[from] toml::de::Error),
    /// Invalid schema, bounds, duplicate or inconsistent rule.
    #[error("invalid or oversized authority policy")]
    InvalidPolicy,
    /// Selected authority identity did not match the supplied bundle.
    #[error("authority policy ID, version or digest mismatch")]
    SelectionMismatch,
    /// Input observation/execution count exceeds schema limits or bindings are ambiguous.
    #[error("invalid or oversized evaluation inputs")]
    InvalidInputs,
    /// Canonical representation could not be encoded.
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

/// Generic engineering properties. These IDs have fixed rule semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyId {
    /// Isolated source view matches exact accepted identity before execution.
    SourceIdentityVerified,
    /// No unresolved required external source remains in the snapshot.
    SourceComplete,
    /// Authority sandbox prerequisites were established for every planned execution.
    SandboxEnvironmentEstablished,
    /// Denied-network configuration was established for every planned execution.
    NetworkIsolationEstablished,
    /// Authority-designated typecheck commands exit zero; no soundness claim.
    TypecheckCompletes,
    /// Authority-designated test commands exit zero; no coverage/defect claim.
    TestSuiteCompletes,
    /// Authority-designated build commands exit zero; no artifact security claim.
    BuildCompletes,
}

impl PropertyId {
    /// Stable schema-1 spelling, also the canonical property sort key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceIdentityVerified => "SOURCE_IDENTITY_VERIFIED",
            Self::SourceComplete => "SOURCE_COMPLETE",
            Self::SandboxEnvironmentEstablished => "SANDBOX_ENVIRONMENT_ESTABLISHED",
            Self::NetworkIsolationEstablished => "NETWORK_ISOLATION_ESTABLISHED",
            Self::TypecheckCompletes => "TYPECHECK_COMPLETES",
            Self::TestSuiteCompletes => "TEST_SUITE_COMPLETES",
            Self::BuildCompletes => "BUILD_COMPLETES",
        }
    }
}

/// Severity prioritizes findings; mandatory requirements always block at every severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Critical authority/evidence or isolation requirement. Always blocking.
    P0,
    /// Essential engineering requirement. Always blocking.
    P1,
    /// Additional engineering requirement; blocking when mandatory.
    P2,
    /// Informational engineering requirement; blocking when mandatory.
    P3,
}

/// Fixed non-recursive rule set; no scripts, expressions or plugins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Rule {
    /// Consume immutable snapshot completeness, without reparsing source.
    SourceComplete {},
    /// Require source match on all planned executions.
    SourceIdentity {},
    /// Require sandbox configuration on all planned executions.
    Sandbox {},
    /// Require denied network on all planned executions.
    Network {},
    /// Require these exact authority-required plan steps and matching category.
    Command {
        /// Stable authority step IDs, treated as a set and sorted canonically.
        steps: Vec<String>,
        /// TYPECHECK, TEST or BUILD only, fixed by property ID.
        category: archcert_application::validation::EvidenceCategory,
    },
}

/// Applicability is entirely authority authored. Missing steps never imply non-applicability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Applicability {
    /// Applies even when there are no matching observations or planned steps.
    Always {},
    /// Applies only to these separately selected authority policy bundle/profile IDs.
    PolicyProfiles {
        /// Authority policy profile IDs; never derived from project-selected execution profiles.
        profiles: Vec<String>,
    },
}

/// Strict authority property definition. Project configuration cannot construct a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Property {
    /// Fixed property identifier and semantics.
    pub id: PropertyId,
    /// Human reference; bounded and included in policy identity.
    pub description: String,
    /// Authority severity.
    pub severity: Severity,
    /// Explicit requirement; P0/P1 block even if this is false.
    pub mandatory: bool,
    /// Explicit permission for NOT_APPLICABLE to satisfy this requirement.
    pub allow_not_applicable: bool,
    /// Bounded deterministic applicability.
    pub applicability: Applicability,
    /// Typed rule; must match the fixed property semantics.
    pub rule: Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoringBundle {
    schema: u32,
    id: String,
    version: String,
    producers: Vec<String>,
    properties: Vec<Property>,
}

/// Full independent authority identity. Caller pins this separately from supplied policy bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBundleRef {
    /// Bundle/profile identifier.
    pub id: String,
    /// Authority version, never inferred from a filename.
    pub version: String,
    /// Independent canonical SHA-256, not authoring-file digest.
    pub sha256: Sha256Digest,
}

/// Immutable parsed bundle with normalized schema-1 canonical JSON and SHA-256.
#[derive(Debug, Clone)]
pub struct PolicyBundle {
    authoring: AuthoringBundle,
    canonical: Vec<u8>,
    identity: PolicyBundleRef,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
}

fn normalize_set(items: &mut [String], max: usize) -> bool {
    items.sort();
    !items.is_empty()
        && items.len() <= max
        && items.iter().all(|s| identifier(s))
        && items.windows(2).all(|p| p[0] != p[1])
}

impl PolicyBundle {
    /// Reads at most 64 KiB plus one sentinel byte, rejecting unknown fields and schemas.
    pub fn read(reader: impl Read) -> Result<Self, PolicyError> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;

        if bytes.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::InvalidPolicy);
        }

        let text = std::str::from_utf8(&bytes).map_err(|_| PolicyError::InvalidPolicy)?;
        let mut a: AuthoringBundle = toml::from_str(text)?;

        if a.schema != 1
            || !identifier(&a.id)
            || !identifier(&a.version)
            || !normalize_set(&mut a.producers, 16)
            || a.properties.is_empty()
            || a.properties.len() > 32
        {
            return Err(PolicyError::InvalidPolicy);
        }

        let mut seen = BTreeSet::new();

        for p in &mut a.properties {
            if !seen.insert(p.id) || p.description.is_empty() || p.description.len() > 2048 {
                return Err(PolicyError::InvalidPolicy);
            }

            if let Applicability::PolicyProfiles { profiles } = &mut p.applicability
                && !normalize_set(profiles, 16)
            {
                return Err(PolicyError::InvalidPolicy);
            }

            use archcert_application::validation::EvidenceCategory as C;
            let valid = match (&p.id, &mut p.rule) {
                (PropertyId::SourceComplete, Rule::SourceComplete {})
                | (PropertyId::SourceIdentityVerified, Rule::SourceIdentity {})
                | (PropertyId::SandboxEnvironmentEstablished, Rule::Sandbox {})
                | (PropertyId::NetworkIsolationEstablished, Rule::Network {}) => true,
                (id, Rule::Command { steps, category }) => {
                    let matches = matches!(
                        (id, category),
                        (PropertyId::TypecheckCompletes, C::Typecheck)
                            | (PropertyId::TestSuiteCompletes, C::Test)
                            | (PropertyId::BuildCompletes, C::Build)
                    );
                    normalize_set(steps, 32) && matches
                }
                _ => false,
            };

            if !valid {
                return Err(PolicyError::InvalidPolicy);
            }
        }

        // Fixed IDs have ASCII canonical names; sorting by serialized spelling is explicit.
        a.properties.sort_by_key(|p| p.id.as_str());
        let canonical = canonical_json(&a)?;
        let identity = PolicyBundleRef {
            id: a.id.clone(),
            version: a.version.clone(),
            sha256: digest_bytes(&canonical),
        };

        Ok(Self {
            authoring: a,
            canonical,
            identity,
        })
    }

    /// Canonical compact JSON bytes; sorted object keys and set-valued arrays, no timestamp.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Immutable ID/version/digest.
    pub fn identity(&self) -> &PolicyBundleRef {
        &self.identity
    }

    /// Normalized authority property definitions.
    pub fn properties(&self) -> &[Property] {
        &self.authoring.properties
    }

    pub(crate) fn supports_producer(&self, producer: &str) -> bool {
        matches!(
            producer,
            "archcert-docker-cli-v1/0.1.0" | "archcert-controller-v1/0.1.0"
        ) && self.authoring.producers.iter().any(|p| p == producer)
    }
}

// Schema-scoped JSON encoding, with explicit ordering even if another workspace
// consumer enables serde_json/preserve_order through feature unification.
pub(crate) fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(value)?;
    value.sort_all_objects();
    serde_json::to_vec(&value)
}

#[cfg(test)]
mod ironcrest_tests {
    use super::*;
    #[test]
    fn ironcrest_policy_retains_historical_policy_identity() -> Result<(), PolicyError> {
        let historical = development_bundle()?;
        let current = ironcrest_controlled_bundle()?;

        assert_eq!(
            historical.identity().sha256.as_str(),
            DEVELOPMENT_POLICY_SHA256
        );
        assert_ne!(historical.identity(), current.identity());
        assert_eq!(current.identity().id, IRONCREST_CONTROLLED_POLICY_ID);
        assert_eq!(
            current.identity().sha256.as_str(),
            IRONCREST_CONTROLLED_POLICY_SHA256
        );

        Ok(())
    }
}

#[cfg(test)]
mod rust_profile_tests {
    use super::*;
    #[test]
    fn rust_policy_has_a_distinct_fixed_identity_and_preserves_historical_policy()
    -> Result<(), PolicyError> {
        let rust = rust_controlled_bundle()?;

        assert_eq!(rust.identity().id, RUST_CONTROLLED_POLICY_ID);
        assert_eq!(
            rust.identity().sha256.as_str(),
            RUST_CONTROLLED_POLICY_SHA256
        );
        assert_ne!(
            rust.identity().sha256,
            ironcrest_controlled_bundle()?.identity().sha256
        );

        Ok(())
    }
}
