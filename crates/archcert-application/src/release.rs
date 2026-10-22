//! Canonical M6: authority build inputs, independent output evidence and release policy.
//!
//! These services own no runtime, transport, database or signing capability.

mod workflow;

pub use workflow::*;

use crate::{
    jobs::{ArtifactReference, JobStoreError},
    knowledge::canonical_bytes,
};
use archcert_domain::{
    Sha256Digest,
    execution::{
        ExecutionCommand, ExecutionEvidence, ExecutionLimits, ExecutionOutcome, ExecutionProfile,
    },
    release::*,
    source::digest_bytes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Fixed authority collector source. It returns hostile bytes only and is
/// executed exclusively through the isolated runner, never on the host.
pub const FILE_COLLECTOR: &str = include_str!("release/collect.py");

/// Separate unprivileged sandbox identity, preventing target access to collector FDs.
pub const FILE_COLLECTOR_USER: &str = "10002:10002";

/// Finite artifact bound shared by collection, storage and deployment verification.
pub const MAX_RELEASE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Versioned producer for new release evidence; historical Ironcrest is untouched.
pub const RELEASE_PRODUCER: &str = "archcert-release-v1/0.1.0";

/// Fixed pure release policy. No target or semantic response may alter it.
pub const RELEASE_POLICY: &str = "archcert-release-strict-v1/1.0.0";

/// Content identity of the fixed release requirements, including algorithm version.
pub fn release_policy_digest() -> Sha256Digest {
    digest_bytes(b"ARCHCERT-RELEASE-POLICY\0v1\0exact-source-certificate;approved-recipe;two-independent-complete-builds;confirmed-cleanup;immutable-artifact-readback;sha256-and-size-equality;all-bound-evidence;persisted-payload-before-signing")
}

/// Canonical identity helper for the restricted JSON rules in ADR 0048.
pub fn release_bytes(value: &impl Serialize) -> Result<Vec<u8>, JobStoreError> {
    canonical_bytes(value).map_err(|_| JobStoreError::Invalid)
}

/// Digest and exact size of immutable evidence bytes.
pub fn release_reference(bytes: &[u8]) -> ArtifactReference {
    ArtifactReference {
        sha256: digest_bytes(bytes),
        size: bytes.len() as u64,
        schema: 1,
        producer: RELEASE_PRODUCER.into(),
    }
}

/// Authority-provisioned immutable build environment. Inventories are assertions
/// from provisioning, not target output or independent runtime attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnvironment {
    /// Immutable authority-approved OCI reference.
    pub image: String,
    /// SHA-256 of the public dependency inventory prepared outside target execution.
    pub dependency_bundle_sha256: Sha256Digest,
    /// SHA-256 of the toolchain inventory, including versions and target triple.
    pub toolchain_sha256: Sha256Digest,
}

/// Frozen recipe description. Deserializing this data grants no authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipeDescription {
    /// Exact algorithm name.
    pub id: String,
    /// Exact recipe version; incompatible recipes need a new version.
    pub version: String,
    /// Versioned execution family, separately identified from source checks.
    pub profile: String,
    /// Authority image and provisioning inventories.
    pub environment: BuildEnvironment,
    /// Literal command including the fixed authority launcher.
    pub command: ExecutionCommand,
    /// Fixed finite runtime budgets.
    pub limits: ExecutionLimits,
    /// Exact launcher environment in addition to the runner's fixed environment.
    pub environment_variables: BTreeMap<String, String>,
    /// Known output selector; never received from target output.
    pub output: String,
    /// Exact source mode.
    pub source_mode: String,
    /// Only DENIED is supported.
    pub network: String,
    /// Only NONE is supported.
    pub normalization: String,
    /// Explicit large-offline-image-v1 control operation deadline.
    pub control_timeout_ms: u64,
    /// Exact authority file reader, part of the frozen output contract.
    pub collector_sha256: Sha256Digest,
    /// Separate non-target sandbox UID/GID used by the authority reader.
    pub collector_user: String,
}

/// Explicit authority capability. Construction is an operator decision, never
/// project configuration discovery or deserialization of a target-provided recipe.
#[derive(Debug, Clone)]
pub struct RustReleaseRecipe {
    description: BuildRecipeDescription,
}

impl RustReleaseRecipe {
    /// Pins a fixed Rust recipe to independently provisioned inputs and binary.
    /// The binary is an authority parameter, not a target execution instruction.
    pub fn new(environment: BuildEnvironment, binary: &str) -> Result<Self, JobStoreError> {
        if binary.is_empty()
            || binary.len() > 64
            || !binary
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(JobStoreError::Invalid);
        }

        let limits = ExecutionLimits {
            timeout_ms: 900_000,
            cpu_millis: 2000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            pids: 256,
            stdout_bytes: 1024,
            stderr_bytes: 16 * 1024 * 1024,
            excerpt_bytes: 1024,
            scratch_bytes: 6 * 1024 * 1024 * 1024,
            output_bytes: MAX_RELEASE_ARTIFACT_BYTES,
        };
        let environment_variables = BTreeMap::from([
            ("CARGO_HOME".into(), "/home/archcert/.cargo".into()),
            ("CARGO_TARGET_DIR".into(), "/work/target".into()),
            ("CARGO_NET_OFFLINE".into(), "true".into()),
            ("CARGO_INCREMENTAL".into(), "0".into()),
            ("CARGO_BUILD_JOBS".into(), "2".into()),
            ("RUSTUP_HOME".into(), "/usr/local/rustup".into()),
            (
                "RUSTUP_TOOLCHAIN".into(),
                "1.99.1-x86_64-unknown-linux-gnu".into(),
            ),
            ("RUSTC".into(), "/usr/local/cargo/bin/rustc".into()),
            ("RUSTDOC".into(), "/usr/local/cargo/bin/rustdoc".into()),
            (
                "PATH".into(),
                "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin".into(),
            ),
            ("SOURCE_DATE_EPOCH".into(), "1".into()),
        ]);
        let command = ExecutionCommand::new(
            "/usr/bin/python3".into(),
            vec![
                "-I".into(),
                "-c".into(),
                include_str!("release/build.py").into(),
                binary.into(),
                serde_json::to_string(&environment_variables)
                    .map_err(|_| JobStoreError::Invalid)?,
            ],
            "/source".into(),
        )
        .map_err(|_| JobStoreError::Invalid)?;
        let description = BuildRecipeDescription {
            id: "rust-single-file-release-v1".into(),
            version: "1.0.2".into(),
            profile: "rust-release-build-v1".into(),
            environment,
            command,
            limits,
            environment_variables,
            output: "/output/artifact".into(),
            source_mode: "EXACT_SNAPSHOT_READ_ONLY".into(),
            network: "DENIED".into(),
            normalization: "NONE".into(),
            control_timeout_ms: 60_000,
            collector_sha256: digest_bytes(FILE_COLLECTOR.as_bytes()),
            collector_user: FILE_COLLECTOR_USER.into(),
        };
        let recipe = Self { description };
        recipe.execution_profile()?;

        Ok(recipe)
    }

    /// Complete immutable authority recipe, suitable for retention as evidence.
    pub fn description(&self) -> &BuildRecipeDescription {
        &self.description
    }

    /// Content identity of every executable and security-relevant recipe field.
    pub fn identity(&self) -> Result<BuildRecipeIdentity, JobStoreError> {
        Ok(BuildRecipeIdentity(digest_bytes(&release_bytes(
            &self.description,
        )?)))
    }

    /// Image, dependency and toolchain binding.
    pub fn environment_identity(&self) -> Result<BuildEnvironmentIdentity, JobStoreError> {
        Ok(BuildEnvironmentIdentity(digest_bytes(&release_bytes(
            &self.description.environment,
        )?)))
    }

    /// Reconstructs exact runtime authority without target-selected settings.
    pub fn execution_profile(&self) -> Result<ExecutionProfile, JobStoreError> {
        ExecutionProfile::new(
            self.description.profile.clone(),
            self.description.environment.image.clone(),
            vec!["/usr/bin/python3".into()],
            self.description.limits,
        )
        .map_err(|_| JobStoreError::Invalid)
    }
}

/// Immutable manifest persisted before either build may be claimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInputManifest {
    /// Schema 1.
    pub schema: u32,
    /// ARCHCERT_BUILD_INPUT.
    pub kind: String,
    /// Exact source and separately verified source certificate.
    pub certified_source: CertifiedSourceIdentity,
    /// Complete fixed recipe description, retained for audit and recovery.
    pub recipe: BuildRecipeDescription,
    /// Exact recipe identity.
    pub recipe_identity: BuildRecipeIdentity,
    /// Exact image/toolchain/dependency identity.
    pub environment_identity: BuildEnvironmentIdentity,
    /// Selected source certification policy digest.
    pub source_policy_sha256: Sha256Digest,
    /// Explicit trusted source certificate key digest.
    pub source_authority_key_sha256: Sha256Digest,
    /// Selected release authority key digest; no key material.
    pub release_authority_key_sha256: Sha256Digest,
    /// Exact deterministic release policy identifier.
    pub release_policy: String,
    /// Exact authority requirements, separately pinned from the source policy.
    pub release_policy_sha256: Sha256Digest,
}

impl BuildInputManifest {
    /// Validates against an independently selected authority capability. Never
    /// trusts a deserialized recipe to approve itself.
    pub fn validate(&self, recipe: &RustReleaseRecipe) -> Result<(), JobStoreError> {
        if self.schema != 1
            || self.kind != "ARCHCERT_BUILD_INPUT"
            || self.release_policy != RELEASE_POLICY
            || self.release_policy_sha256 != release_policy_digest()
            || self.recipe_identity != recipe.identity()?
            || self.environment_identity != recipe.environment_identity()?
            || release_bytes(&self.recipe)? != release_bytes(recipe.description())?
        {
            return Err(JobStoreError::Precondition);
        }

        Ok(())
    }

    /// Deterministic admitted invocation, distinct from its source/recipe/output.
    pub fn identity(&self) -> Result<BuildInvocationIdentity, JobStoreError> {
        Ok(BuildInvocationIdentity(digest_bytes(&release_bytes(self)?)))
    }
}

/// Canonical result of one independently claimed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildResult {
    /// Schema 1.
    pub schema: u32,
    /// ARCHCERT_BUILD_RESULT.
    pub kind: String,
    /// Exact frozen build inputs.
    pub invocation: BuildInvocationIdentity,
    /// A or B.
    pub ordinal: BuildOrdinal,
    /// Full scoped source/certificate.
    pub source: CertifiedSourceIdentity,
    /// Authority recipe identity.
    pub recipe: BuildRecipeIdentity,
    /// Authority environment identity.
    pub environment: BuildEnvironmentIdentity,
    /// Controller classification, separate from byte equality.
    pub completion: BuildCompletion,
    /// Actual runner evidence; absent for pre-execution infrastructure failure.
    pub execution: Option<ExecutionEvidence>,
    /// Confirmed source and sandbox destruction.
    pub cleanup_complete: bool,
    /// Authority-selected output content; only valid for COMPLETE.
    pub artifact: Option<ReleaseArtifactIdentity>,
}

impl BuildResult {
    /// Exact canonical result identity.
    pub fn identity(&self) -> Result<BuildResultIdentity, JobStoreError> {
        Ok(BuildResultIdentity(digest_bytes(&release_bytes(self)?)))
    }

    /// Checks retained evidence against the admitted contract, including the
    /// actual runner command, profile, image, source, budgets and cleanup.
    pub fn validate(
        &self,
        input: &BuildInputManifest,
        ordinal: BuildOrdinal,
    ) -> Result<(), JobStoreError> {
        if self.schema != 1
            || self.kind != "ARCHCERT_BUILD_RESULT"
            || self.invocation != input.identity()?
            || self.ordinal != ordinal
            || self.source != input.certified_source
            || self.recipe != input.recipe_identity
            || self.environment != input.environment_identity
        {
            return Err(JobStoreError::Precondition);
        }

        if let Some(e) = &self.execution
            && (e.source != input.certified_source.source
                || e.image_digest != input.recipe.environment.image
                || e.profile != input.recipe.profile
                || release_bytes(&e.command)? != release_bytes(&input.recipe.command)?
                || release_bytes(&e.limits)? != release_bytes(&input.recipe.limits)?
                || e.backend_version != "archcert-docker-release-v1"
                || e.observed_runtime
                    .runtime_information
                    .get("authority/control-profile")
                    .map(String::as_str)
                    != Some("large-offline-image-v1/60s"))
        {
            return Err(JobStoreError::Precondition);
        }

        if self.completion == BuildCompletion::Complete {
            let e = self.execution.as_ref().ok_or(JobStoreError::Precondition)?;
            let artifact = self.artifact.as_ref().ok_or(JobStoreError::Precondition)?;
            validate_artifact(artifact)?;

            if !self.cleanup_complete
                || e.outcome != ExecutionOutcome::Completed
                || e.exit_code != Some(0)
                || !e.stdout.complete
                || !e.stderr.complete
                || e.termination != archcert_domain::execution::TerminationReason::Exit
                || e.container_user != "10001:10001"
                || e.environment_keys
                    != archcert_domain::execution::sandbox_environment()
                        .into_keys()
                        .collect::<Vec<_>>()
                || e.stdout.truncated
                || e.stdout.observed_bytes != b"ARCHCERT_BUILD_READY_V1\n".len() as u64
                || e.stdout.sha256 != digest_bytes(b"ARCHCERT_BUILD_READY_V1\n")
                || e.stdout.excerpt != b"ARCHCERT_BUILD_READY_V1\n"
            {
                return Err(JobStoreError::Precondition);
            }
        } else if self.artifact.is_some() {
            return Err(JobStoreError::Precondition);
        }

        Ok(())
    }
}

/// Checks the exact supported single-file identity contract.
pub fn validate_artifact(a: &ReleaseArtifactIdentity) -> Result<(), JobStoreError> {
    if a.kind != "REGULAR_FILE"
        || a.algorithm != "SHA-256"
        || a.media_type != "application/octet-stream"
        || a.role != "RUST_EXECUTABLE"
        || a.size == 0
        || a.size > MAX_RELEASE_ARTIFACT_BYTES
    {
        return Err(JobStoreError::Invalid);
    }

    Ok(())
}

/// Derives identity from authority-collected bytes, never target labels.
pub fn artifact_identity(bytes: &[u8]) -> Result<ReleaseArtifactIdentity, JobStoreError> {
    let artifact = ReleaseArtifactIdentity {
        kind: "REGULAR_FILE".into(),
        algorithm: "SHA-256".into(),
        sha256: digest_bytes(bytes),
        size: bytes.len() as u64,
        media_type: "application/octet-stream".into(),
        role: "RUST_EXECUTABLE".into(),
    };
    validate_artifact(&artifact)?;

    Ok(artifact)
}

/// Canonical deterministic comparison; full results/logs remain separate artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproducibilityEvidence {
    /// Schema 1.
    pub schema: u32,
    /// ARCHCERT_REPRODUCIBILITY.
    pub kind: String,
    /// Exact source and certificate binding.
    pub source: CertifiedSourceIdentity,
    /// Exact admitted inputs.
    pub invocation: BuildInvocationIdentity,
    /// Accepted A result identity.
    pub attempt_a: BuildResultIdentity,
    /// Accepted B result identity.
    pub attempt_b: BuildResultIdentity,
    /// A's independently collected output, if any.
    pub artifact_a: Option<ReleaseArtifactIdentity>,
    /// B's independently collected output, if any.
    pub artifact_b: Option<ReleaseArtifactIdentity>,
    /// SHA-256-AND-SIZE-EXACT-V1; no normalization.
    pub comparison: String,
    /// Three-state outcome; infrastructure failure cannot mean a byte difference.
    pub verdict: ReproducibilityVerdict,
    /// Exact authority policy.
    pub policy: String,
}

/// Validates both results and derives equality without semantic interpretation.
pub fn compare_builds(
    input: &BuildInputManifest,
    a: &BuildResult,
    b: &BuildResult,
) -> Result<ReproducibilityEvidence, JobStoreError> {
    a.validate(input, BuildOrdinal::A)?;
    b.validate(input, BuildOrdinal::B)?;

    let independent = match (&a.execution, &b.execution) {
        (Some(a), Some(b)) => a.execution != b.execution && a.workspace != b.workspace,
        _ => false,
    };
    let verdict = if a.completion != BuildCompletion::Complete
        || b.completion != BuildCompletion::Complete
        || !independent
    {
        ReproducibilityVerdict::Inconclusive
    } else if a.artifact == b.artifact {
        ReproducibilityVerdict::Reproducible
    } else {
        ReproducibilityVerdict::NonReproducible
    };

    Ok(ReproducibilityEvidence {
        schema: 1,
        kind: "ARCHCERT_REPRODUCIBILITY".into(),
        source: input.certified_source.clone(),
        invocation: input.identity()?,
        attempt_a: a.identity()?,
        attempt_b: b.identity()?,
        artifact_a: a.artifact.clone(),
        artifact_b: b.artifact.clone(),
        comparison: "SHA-256-AND-SIZE-EXACT-V1".into(),
        verdict,
        policy: RELEASE_POLICY.into(),
    })
}
