//! Command-only authentication and passive request resolution.
//! No target execution, signing, review-provider invocation or browser roles.

mod credentials;
mod release_build;

pub use credentials::{CommandAuthorization, CommandCredentials};
pub use release_build::ReleaseBuildAuthority;

use super::*;
use archcert_application::{
    glassmere::commands::*, ironcrest::IroncrestRepository, release::release_bytes,
};
use archcert_domain::Sha256Digest;

impl AuthorityGrant {
    /// Identity of the exact authority selection, excluding credential hashes.
    /// This identity grants no capability without independent provisioning.
    pub fn command_context(&self) -> Result<Sha256Digest, JobStoreError> {
        let plan = resolve_authority_plan(&self.profile, &self.image, &self.authority_toml)?;
        let (policy, review_profile) = if self.ironcrest {
            let rust = self.profile == "rust-workspace-v1";
            let policy = ironcrest::policy_pin(rust)?;
            let (_, _, _, profile) = ironcrest::authority(
                self.project,
                &policy,
                rust,
                self.semantic_request_bytes,
                self.greywatch,
            )?;
            (policy, Some(profile.artifact().digest().clone()))
        } else {
            let bundle =
                archcert_policy::development_bundle().map_err(|_| JobStoreError::Invalid)?;
            let identity = bundle.identity();
            (
                PolicyPin {
                    id: identity.id.clone(),
                    version: identity.version.clone(),
                    sha256: identity.sha256.clone(),
                },
                None,
            )
        };

        let bytes = release_bytes(&serde_json::json!({
            "schema": 1,
            "kind": "GLASSMERE_AUTHORITY_CONTEXT",
            "project": self.project,
            "repository": self.repository,
            "actor": self.actor,
            "profile": self.profile,
            "image": self.image,
            "plan_sha256": plan.digest().map_err(|_| JobStoreError::Invalid)?,
            "policy": policy,
            "maximum_attempts": self.maximum_attempts,
            "ironcrest": self.ironcrest,
            "greywatch": self.greywatch,
            "semantic_request_bytes": self.semantic_request_bytes,
            "baseline": self.ironcrest_baseline,
            "review_profile_sha256": review_profile,
        }))?;

        Ok(digest_bytes(&bytes))
    }
}

impl ControlPlane {
    /// Recheck current scope before exposing selection identity. This creates no
    /// command and grants no execution or signature capability.
    pub async fn command_context(
        &self,
        authorization: &CommandAuthorization,
    ) -> Result<Sha256Digest, JobStoreError> {
        self.authorize_command(authorization, authorization.operation())
            .await?;

        Ok(authorization.context().clone())
    }

    /// Explicit operator provisioning only. Repository authorization remains separate.
    /// Calling this does not revoke older grants or apply database migrations.
    pub async fn provision_commands(
        &self,
        credentials: &CommandCredentials,
    ) -> Result<(), JobStoreError> {
        credentials.validate(&self.configuration)?;
        let mut selections = Vec::new();

        for principal in credentials.principals() {
            if !self
                .repository
                .authorized(
                    principal.scope.project,
                    &principal.scope.repository,
                    &principal.scope.actor,
                )
                .await?
            {
                return Err(JobStoreError::Unauthorized);
            }

            let grant = self.configuration.grant_for(
                &principal.scope.actor,
                principal.scope.project,
                &principal.scope.repository,
            )?;

            for operation in &principal.operations {
                selections.push((
                    principal.scope.clone(),
                    grant.command_context_for(*operation)?,
                    *operation,
                ));
            }
        }

        // Invalid scope or an unsupported selection must fail before provisioning
        // any requested grant. Database availability remains independently required.
        for (scope, context, operation) in selections {
            self.repository
                .grant_control_operation(&scope, &context, operation)
                .await?;
        }

        Ok(())
    }

    async fn authorize_command<'a>(
        &self,
        authorization: &'a CommandAuthorization,
        operation: ControlOperation,
    ) -> Result<&'a CommandScope, JobStoreError> {
        authorization.require(operation)?;
        let scope = authorization.scope();
        let grant = self
            .configuration
            .grant_for(&scope.actor, scope.project, &scope.repository)?;

        if grant.command_context_for(operation)? != *authorization.context() {
            return Err(JobStoreError::Precondition);
        }

        if !self
            .repository
            .authorized(scope.project, &scope.repository, &scope.actor)
            .await?
        {
            return Err(JobStoreError::Unauthorized);
        }

        Ok(scope)
    }

    /// Resolve original source/authority inputs and accept the journal request.
    /// No job is created here; the atomic dispatcher mediates admission later.
    pub async fn request_certification(
        &self,
        authorization: &CommandAuthorization,
        submission: SourceSubmissionId,
        reviewed_session: Option<JobId>,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        let scope = self
            .authorize_command(authorization, ControlOperation::RequestCertification)
            .await?;
        let grant = self
            .configuration
            .grant_for(&scope.actor, scope.project, &scope.repository)?;

        let inputs = match (grant.ironcrest, reviewed_session) {
            (true, Some(id)) => {
                // Authorize ownership before loading private source or knowledge.
                let session = self.repository.review_session(scope.project, id).await?;
                if session.pin.actor != scope.actor
                    || session.pin.repository != scope.repository
                    || session.pin.submission != submission
                {
                    return Err(JobStoreError::Unauthorized);
                }

                self.prepare_ironcrest(scope.project, id).await?.base_inputs
            }
            (false, None) => {
                self.resolve_certification_inputs(
                    scope.actor.clone(),
                    scope.project,
                    scope.repository.clone(),
                    submission,
                )
                .await?
            }
            _ => return Err(JobStoreError::Precondition),
        };

        let command = ResolvedControlCommand {
            schema: CONTROL_COMMAND_SCHEMA,
            scope: scope.clone(),
            authority_context: authorization.context().clone(),
            action: ResolvedControlAction::RequestCertification {
                inputs: Box::new(inputs),
                reviewed_session,
            },
        };
        self.repository.accept(&command, key).await
    }

    /// Request a fresh historical readiness observation for one exact owned invocation.
    pub async fn request_readiness(
        &self,
        authorization: &CommandAuthorization,
        invocation: archcert_domain::release::BuildInvocationIdentity,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        self.request_object_action(
            authorization,
            ResolvedControlAction::RequestReleaseReadinessEvaluation { invocation },
            key,
        )
        .await
    }

    /// Accept an exact owned job cancellation; eligibility is checked atomically at dispatch.
    pub async fn request_cancellation(
        &self,
        authorization: &CommandAuthorization,
        job: JobId,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        self.request_object_action(
            authorization,
            ResolvedControlAction::CancelEligibleJob { job },
            key,
        )
        .await
    }

    /// Accept exact-attempt infrastructure recovery; no browser cleanup assertion is accepted.
    pub async fn request_recovery(
        &self,
        authorization: &CommandAuthorization,
        job: JobId,
        attempt: AttemptId,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        self.request_object_action(
            authorization,
            ResolvedControlAction::RetryEligibleJob { job, attempt },
            key,
        )
        .await
    }

    async fn request_object_action(
        &self,
        authorization: &CommandAuthorization,
        action: ResolvedControlAction,
        key: &IdempotencyKey,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        let scope = self
            .authorize_command(authorization, action.operation())
            .await?;
        let command = ResolvedControlCommand {
            schema: CONTROL_COMMAND_SCHEMA,
            scope: scope.clone(),
            authority_context: authorization.context().clone(),
            action,
        };

        // The repository scopes the object in SQL before acceptance and audit.
        self.repository.accept(&command, key).await
    }

    /// Read a scoped receipt without serializing private authority inputs.
    pub async fn command_status(
        &self,
        authorization: &CommandAuthorization,
        id: ControlCommandId,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        self.historical_command_status(authorization, id, authorization.context())
            .await
    }

    /// Inspect an original receipt under current scope/operation authorization.
    /// The context must match that retained record; it cannot select execution inputs.
    pub async fn historical_command_status(
        &self,
        authorization: &CommandAuthorization,
        id: ControlCommandId,
        original_context: &Sha256Digest,
    ) -> Result<ControlCommandRecord, JobStoreError> {
        let scope = self
            .authorize_command(authorization, authorization.operation())
            .await?;
        let record = ControlCommandRepository::get(&self.repository, scope, id).await?;

        if record.command.action.operation() != authorization.operation()
            || record.command.authority_context != *original_context
        {
            return Err(JobStoreError::Unauthorized);
        }

        Ok(record)
    }
}
