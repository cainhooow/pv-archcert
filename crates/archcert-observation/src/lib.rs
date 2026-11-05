//! Edge adapter: public verifier composition, never a signer or runtime controller.

use archcert_application::{
    glassmere::*,
    jobs::{ArtifactReference, JobStoreError},
    release::*,
};
use archcert_certificate::observation::{ReleaseObservationContext, observe_release};
use archcert_crypto::PublicKey;
use archcert_domain::{ProjectId, source::digest_bytes};
use archcert_storage::{
    artifacts::ReadOnlyFilesystemArtifactStore, glassmere::ObservationRepository,
};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, JobStoreError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeProvision {
    environment: BuildEnvironment,
    binary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    artifact_root: PathBuf,
    source_public_keys: Vec<String>,
    release_public_keys: Vec<String>,
    recipes: Vec<RecipeProvision>,
}

/// Bounded SELECT-only observations and existing selected-public-key verification.
pub struct QueryService {
    repository: ObservationRepository,
    artifacts: ReadOnlyFilesystemArtifactStore,
    source_keys: Vec<PublicKey>,
    release_keys: Vec<PublicKey>,
    recipes: Vec<RustReleaseRecipe>,
    verification_budget: tokio::sync::Semaphore,
}

impl QueryService {
    /// Load explicit private trust selection and reject writable observation storage.
    pub async fn connect(url: &str, path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                rustix::fs::OFlags::NOFOLLOW.bits() as i32
                    | rustix::fs::OFlags::NONBLOCK.bits() as i32,
            )
            .open(path)
            .map_err(|_| JobStoreError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| JobStoreError::Unavailable)?;
        let link = std::fs::symlink_metadata(path).map_err(|_| JobStoreError::Unavailable)?;
        if !metadata.is_file()
            || link.file_type().is_symlink()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(JobStoreError::Invalid);
        }
        let mut bytes = Vec::new();
        file.take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| JobStoreError::Unavailable)?;
        if bytes.len() > 128 * 1024 {
            return Err(JobStoreError::Invalid);
        }
        let config: Configuration =
            serde_json::from_slice(&bytes).map_err(|_| JobStoreError::Invalid)?;
        if config.schema != 1
            || config.source_public_keys.len() > 32
            || config.release_public_keys.len() > 32
            || config.recipes.len() > 32
        {
            return Err(JobStoreError::Invalid);
        }
        let source_keys = config
            .source_public_keys
            .iter()
            .map(|key| PublicKey::from_hex(key).map_err(|_| JobStoreError::Invalid))
            .collect::<Result<Vec<_>>>()?;
        let release_keys = config
            .release_public_keys
            .iter()
            .map(|key| PublicKey::from_hex(key).map_err(|_| JobStoreError::Invalid))
            .collect::<Result<Vec<_>>>()?;
        let recipes = config
            .recipes
            .into_iter()
            .map(|r| RustReleaseRecipe::new(r.environment, &r.binary))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            repository: ObservationRepository::connect(url).await?,
            artifacts: ReadOnlyFilesystemArtifactStore::open_unencrypted_development(
                &config.artifact_root,
            )?,
            source_keys,
            release_keys,
            recipes,
            verification_budget: tokio::sync::Semaphore::new(2),
        })
    }
}

#[async_trait]
impl GlassmereQuery for QueryService {
    async fn search(
        &self,
        project: ProjectId,
        query: &search::SearchQuery,
    ) -> Result<search::SearchPage> {
        self.repository.search(project, query).await
    }

    async fn projects(
        &self,
        allowed: &[ProjectId],
        after: Option<ProjectId>,
    ) -> Result<Vec<ProjectObservation>> {
        self.repository.projects(allowed, after).await
    }

    async fn snapshot(&self, project: ProjectId, offset: u32) -> Result<ProjectSnapshot> {
        self.repository.snapshot(project, offset).await
    }

    async fn entity(
        &self,
        project: ProjectId,
        entity: &str,
        offset: u32,
    ) -> Result<ProjectSnapshot> {
        self.repository.entity(project, entity, offset).await
    }

    async fn readiness(&self, project: ProjectId, invocation: &str) -> Result<ReleaseReadiness> {
        let _permit = self
            .verification_budget
            .try_acquire()
            .map_err(|_| JobStoreError::Unavailable)?;
        let record = self.repository.release(project, invocation).await?;
        let input = &record.admission.input;
        let source_key = self
            .source_keys
            .iter()
            .find(|k| k.key_id().as_str() == input.source_authority_key_sha256.as_str());
        let release_key = self
            .release_keys
            .iter()
            .find(|k| k.key_id().as_str() == input.release_authority_key_sha256.as_str());
        let recipe = self
            .recipes
            .iter()
            .find(|r| r.identity().is_ok_and(|id| id == input.recipe_identity));
        let mut evidence = Vec::new();
        let mut unavailable = false;

        for reference in &record.references {
            if !reference.available {
                continue;
            }
            let max = if [ReleaseRole::ArtifactA, ReleaseRole::ArtifactB].contains(&reference.role)
            {
                MAX_RELEASE_ARTIFACT_BYTES
            } else {
                4 * 1024 * 1024
            };
            if reference.artifact.size > max {
                unavailable = true;
                continue;
            }
            match self.artifacts.get(project, &reference.artifact) {
                Ok(bytes) => evidence.push((reference.role, bytes)),
                Err(_) => unavailable = true,
            }
        }

        let mut checks = match (source_key, release_key, recipe) {
            (Some(source_key), Some(release_key), Some(recipe)) => {
                observe_release(ReleaseObservationContext {
                    input,
                    recipe,
                    source_key,
                    release_key,
                    evidence: &evidence,
                })
            }
            _ => ReadinessChecks {
                subject: ReleaseSubject {
                    project,
                    repository: input.certified_source.repository.as_str().into(),
                    source: input.certified_source.source.clone(),
                    certificate: Some(input.certified_source.certificate_sha256.as_str().into()),
                    invocation: invocation.into(),
                    artifact: None,
                    permit: None,
                },
                certificate: Err(BlockerCode::CertificateInvalid),
                reproducibility: Err(BlockerCode::MandatoryEvidenceMissing),
                artifact: Err(BlockerCode::MandatoryEvidenceMissing),
                permit: Err(BlockerCode::ReleasePermitInvalid),
                policy: Err(BlockerCode::MandatoryEvidenceMissing),
                review: Err(BlockerCode::ReviewInconclusive),
                environment: Err(BlockerCode::EnvironmentNotQualified),
                freshness: Ok(()),
            },
        };
        if unavailable {
            checks.freshness = Err(BlockerCode::InfrastructureUncertain);
        }

        // Revision binds the exact verified result, metadata and independently
        // provisioned public trust selection. Time/MVCC allocation is not order.
        let mut result = checks.evaluate(String::new(), 0);
        let revision_bytes = serde_json::to_vec(&serde_json::json!({
            "observation":result,
            "references":record.references,
            "source_keys":self.source_keys.iter().map(|k|k.key_id().as_str().to_owned()).collect::<Vec<_>>(),
            "release_keys":self.release_keys.iter().map(|k|k.key_id().as_str().to_owned()).collect::<Vec<_>>(),
        })).map_err(|_|JobStoreError::Invalid)?;
        result.revision = digest_bytes(&revision_bytes).as_str().into();
        result.evaluated_at = record.evaluated_at;

        Ok(result)
    }

    async fn evidence(
        &self,
        project: ProjectId,
        entity: &str,
        digest: &str,
    ) -> Result<(EvidenceObservation, Vec<u8>)> {
        let mut observation = self.repository.evidence(project, entity, digest).await?;
        if observation.state != "AVAILABLE" {
            return Err(JobStoreError::Unavailable);
        }
        let reference = ArtifactReference {
            sha256: archcert_domain::Sha256Digest::parse(&observation.sha256)
                .map_err(|_| JobStoreError::Invalid)?,
            size: observation.size,
            schema: observation.schema,
            producer: observation.producer.clone(),
        };
        let bytes = self.artifacts.get(project, &reference)?;

        observation.verification = match observation.role.as_str() {
            "CERTIFICATE" | "SOURCE_CERTIFICATE" => certificate_facts(&bytes, &self.source_keys),
            "PERMIT_ENVELOPE" => permit_facts(&bytes, &self.release_keys),
            _ => Vec::new(),
        };

        Ok((observation, bytes))
    }

    async fn healthy(&self) -> bool {
        self.repository.healthy().await && self.artifacts.healthy()
    }
}

#[async_trait]
impl archcert_application::glassmere::commands::ReleaseReadinessObserver for QueryService {
    async fn observe(
        &self,
        project: ProjectId,
        invocation: &archcert_domain::release::BuildInvocationIdentity,
    ) -> Result<ReleaseReadiness> {
        GlassmereQuery::readiness(self, project, invocation.0.as_str()).await
    }
}

fn verification_failure(state: &str, provenance: &str) -> Vec<ObservationField> {
    vec![ObservationField {
        label: "Signature verification".into(),
        value: state.into(),
        provenance: provenance.into(),
    }]
}

fn certificate_facts(bytes: &[u8], keys: &[PublicKey]) -> Vec<ObservationField> {
    use archcert_certificate::{CertificateEnvelope, CertificateError};

    let certificate = match CertificateEnvelope::read(bytes) {
        Ok(certificate) => certificate,
        Err(CertificateError::UnsupportedCertificateSchema) => {
            return verification_failure("UNSUPPORTED_SCHEMA", "Existing certificate verifier");
        }
        Err(_) => return verification_failure("INVALID", "Existing certificate verifier"),
    };
    let mut recognized_key = false;

    for key in keys {
        match certificate.verify(key) {
            Ok(verified) => {
                return vec![
                    ObservationField {
                        label: "Signature verification".into(),
                        value: "VALID under explicitly selected public key; EXACT_SOURCE scope"
                            .into(),
                        provenance: "Existing certificate verifier".into(),
                    },
                    ObservationField {
                        label: "Verification key SHA256".into(),
                        value: key.key_id().as_str().into(),
                        provenance: "Operator-provisioned public key".into(),
                    },
                    ObservationField {
                        label: "Verified source and policy".into(),
                        value: verified.report().to_string(),
                        provenance: "Existing certificate verifier; DEVELOPMENT signing".into(),
                    },
                ];
            }
            Err(CertificateError::SigningKeyMismatch) => {}
            Err(_) => recognized_key = true,
        }
    }

    verification_failure(
        if recognized_key {
            "INVALID"
        } else {
            "UNKNOWN_KEY"
        },
        "Existing certificate verifier",
    )
}

fn permit_facts(bytes: &[u8], keys: &[PublicKey]) -> Vec<ObservationField> {
    use archcert_certificate::release::ReleasePermitEnvelope;

    let permit = match ReleasePermitEnvelope::read(bytes) {
        Ok(permit) => permit,
        Err(_) => {
            return verification_failure(
                "INVALID / UNSUPPORTED_SCHEMA",
                "Existing Release Permit verifier",
            );
        }
    };

    for key in keys {
        if let Ok(identity) = permit.verify(key) {
            return vec![
                ObservationField {
                    label: "Signature verification".into(),
                    value: "VALID permit signature; actual artifact authorization requires the Release Readiness view".into(),
                    provenance: "Existing Release Permit verifier".into(),
                },
                ObservationField {
                    label: "Permit payload identity".into(),
                    value: identity.0.as_str().into(),
                    provenance: "Existing Release Permit verifier".into(),
                },
                ObservationField {
                    label: "Verification key SHA256".into(),
                    value: key.key_id().as_str().into(),
                    provenance: "Operator-provisioned public key".into(),
                },
            ];
        }
    }

    verification_failure("INVALID / UNKNOWN_KEY", "Existing Release Permit verifier")
}
