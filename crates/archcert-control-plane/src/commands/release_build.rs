//! Fixed operator-owned build selection and passive, identifier-only request resolution.

use super::*;
use archcert_application::release::{
    BuildEnvironment, BuildInputManifest, RELEASE_POLICY, ReleaseAdmission, RustReleaseRecipe,
    release_policy_digest, release_reference,
};
use archcert_domain::release::CertifiedSourceIdentity;
use serde::{Deserialize, Serialize};

/// Private provisioning only. Repository requests cannot construct authority selection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBuildAuthority {
    /// First explicit private selection grammar.
    pub schema: u32,
    /// Exact supported M6 implementation version; never a recovery default.
    pub recipe_version: String,
    /// Pinned image and externally provisioned public dependency/toolchain inventories.
    pub environment: BuildEnvironment,
    /// One fixed Rust binary, selected outside the target.
    pub binary: String,
    /// Approved source certification policy identity.
    pub source_policy_sha256: Sha256Digest,
    /// Explicit trusted source public-key identity; no key material.
    pub source_authority_key_sha256: Sha256Digest,
    /// Explicit release public-key identity; never a signing capability.
    pub release_authority_key_sha256: Sha256Digest,
}

impl ReleaseBuildAuthority {
    /// Construct only the fixed supported recipe and reject a different retained version.
    pub fn recipe(&self) -> Result<RustReleaseRecipe, JobStoreError> {
        if self.schema != 1 {
            return Err(JobStoreError::Invalid);
        }

        let recipe = RustReleaseRecipe::new(self.environment.clone(), &self.binary)?;
        if self.recipe_version != recipe.description().version {
            return Err(JobStoreError::Precondition);
        }

        Ok(recipe)
    }
}

impl AuthorityGrant {
    /// Preserve existing contexts; build requests require distinct explicit provisioning.
    pub fn command_context_for(
        &self,
        operation: ControlOperation,
    ) -> Result<Sha256Digest, JobStoreError> {
        if operation != ControlOperation::RequestReleaseBuild {
            return self.command_context();
        }

        let selection = self
            .release_build
            .as_ref()
            .ok_or(JobStoreError::Precondition)?;
        let recipe = selection.recipe()?;
        let bytes = release_bytes(&serde_json::json!({
            "schema": 1,
            "kind": "GLASSMERE_RELEASE_BUILD_AUTHORITY_CONTEXT",
            "base_context_sha256": self.command_context()?,
            "selection": selection,
            "recipe_sha256": recipe.identity()?,
            "environment_sha256": recipe.environment_identity()?,
            "release_policy": RELEASE_POLICY,
            "release_policy_sha256": release_policy_digest(),
        }))?;

        Ok(digest_bytes(&bytes))
    }
}

impl ControlPlane {
    /// Freeze a requested build from an owned certification and fixed private selection.
    /// This accepts a journal request only; independent verification precedes M6 admission.
    pub async fn request_release_build(
        &self,
        authorization: &CommandAuthorization,
        job: JobId,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        let scope = self
            .authorize_command(authorization, ControlOperation::RequestReleaseBuild)
            .await?;
        self.repository
            .check_control_operation(
                scope,
                authorization.context(),
                ControlOperation::RequestReleaseBuild,
            )
            .await?;

        let grant = self
            .configuration
            .grant_for(&scope.actor, scope.project, &scope.repository)?;
        let selection = grant
            .release_build
            .as_ref()
            .ok_or(JobStoreError::Precondition)?;
        let recipe = selection.recipe()?;
        let job = JobRepository::get(&self.repository, job).await?;

        if job.inputs.project != scope.project
            || job.inputs.repository != scope.repository
            || job.inputs.actor != scope.actor
        {
            return Err(JobStoreError::Unauthorized);
        }

        let certificate = job
            .certificate
            .as_ref()
            .ok_or(JobStoreError::Precondition)?;
        if job.state != JobState::Completed
            || job.failure.is_some()
            || !certificate.verified
            || job.issuance.as_ref() != Some(&certificate.issuance)
            || certificate.issuance.signing_key_id != selection.source_authority_key_sha256.as_str()
            || job.inputs.policy.sha256 != selection.source_policy_sha256
            || certificate.artifact.schema != 1
            || certificate.artifact.size == 0
            || certificate.artifact.size > 65_536
        {
            return Err(JobStoreError::Precondition);
        }

        // Reload complete accepted bytes only after exact object authorization.
        // The reader is passive and compares the original submission/source identity.
        let source = self.source(&job.inputs)?;
        let input = BuildInputManifest {
            schema: 1,
            kind: "ARCHCERT_BUILD_INPUT".into(),
            certified_source: CertifiedSourceIdentity {
                project: scope.project,
                repository: scope.repository.clone(),
                source: source.identity().clone(),
                certificate_sha256: certificate.issuance.certificate_sha256.clone(),
            },
            recipe: recipe.description().clone(),
            recipe_identity: recipe.identity()?,
            environment_identity: recipe.environment_identity()?,
            source_policy_sha256: selection.source_policy_sha256.clone(),
            source_authority_key_sha256: selection.source_authority_key_sha256.clone(),
            release_authority_key_sha256: selection.release_authority_key_sha256.clone(),
            release_policy: RELEASE_POLICY.into(),
            release_policy_sha256: release_policy_digest(),
        };
        let admission = ReleaseAdmission {
            input_reference: release_reference(&release_bytes(&input)?),
            input,
            submission: job.inputs.submission,
            actor: scope.actor.clone(),
        };
        let command = ResolvedControlCommand {
            schema: CONTROL_COMMAND_SCHEMA,
            scope: scope.clone(),
            authority_context: authorization.context().clone(),
            action: ResolvedControlAction::RequestReleaseBuild {
                admission: Box::new(admission),
                source_certificate: certificate.artifact.clone(),
            },
        };

        self.repository.accept(&command, key).await
    }
}
