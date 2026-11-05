//! Strict private command credentials; never accepted by legacy job submission.

use super::*;
use serde::Deserialize;

#[cfg(test)]
mod tests;

/// External command-only credential mappings. Load afresh at each authenticated
/// request so removal or operation revocation invalidates subsequent requests.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCredentials {
    schema: u32,
    principals: Vec<CommandPrincipal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandPrincipal {
    pub(super) scope: CommandScope,
    token_sha256: Sha256Digest,
    pub(super) operations: Vec<ControlOperation>,
}

/// Short-lived authenticated selection, constructed only by credential validation.
/// It is not a wire type, durable grant or capability for target execution.
pub struct CommandAuthorization {
    scope: CommandScope,
    context: Sha256Digest,
    operation: ControlOperation,
}

impl CommandAuthorization {
    /// Exact actor/scope derived from the command credential.
    pub fn scope(&self) -> &CommandScope {
        &self.scope
    }

    /// Exact current authority selection, excluding credential material.
    pub fn context(&self) -> &Sha256Digest {
        &self.context
    }

    /// The single operation authorized for this request.
    pub fn operation(&self) -> ControlOperation {
        self.operation
    }

    pub(super) fn require(&self, operation: ControlOperation) -> Result<(), JobStoreError> {
        if self.operation != operation {
            return Err(JobStoreError::Unauthorized);
        }

        Ok(())
    }
}

impl CommandCredentials {
    /// Load bounded owned private JSON. This creates no database grants.
    pub fn load(path: &Path, authority: &ControlPlaneConfiguration) -> Result<Self, JobStoreError> {
        let credentials: Self = serde_json::from_slice(&read_private(path, 256 * 1024)?)
            .map_err(|_| JobStoreError::Invalid)?;
        credentials.validate(authority)?;

        Ok(credentials)
    }

    pub(super) fn principals(&self) -> &[CommandPrincipal] {
        &self.principals
    }

    pub(super) fn validate(
        &self,
        authority: &ControlPlaneConfiguration,
    ) -> Result<(), JobStoreError> {
        if self.schema != 1 || self.principals.is_empty() || self.principals.len() > 128 {
            return Err(JobStoreError::Invalid);
        }

        for (index, principal) in self.principals.iter().enumerate() {
            authority.grant_for(
                &principal.scope.actor,
                principal.scope.project,
                &principal.scope.repository,
            )?;

            if principal.operations.is_empty()
                || principal.operations.len() > 5
                || principal
                    .operations
                    .iter()
                    .enumerate()
                    .any(|(index, operation)| principal.operations[..index].contains(operation))
                || authority
                    .grants
                    .iter()
                    .any(|grant| grant.token_sha256 == principal.token_sha256)
                || self.principals[..index].iter().any(|previous| {
                    previous.scope == principal.scope
                        || (previous.token_sha256 == principal.token_sha256
                            && previous.scope.actor != principal.scope.actor)
                })
            {
                return Err(JobStoreError::Invalid);
            }
        }

        Ok(())
    }

    /// Authenticate exact scope and operation before any object or source lookup.
    /// Expected context is an identity check, never a way to select authority inputs.
    pub fn authorize(
        &self,
        authority: &ControlPlaneConfiguration,
        token: &str,
        project: ProjectId,
        repository: &RepositoryId,
        operation: ControlOperation,
        expected_context: Option<&Sha256Digest>,
    ) -> Result<CommandAuthorization, JobStoreError> {
        self.validate(authority)?;

        if !(32..=256).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(JobStoreError::Unauthorized);
        }

        let token_sha256 = digest_bytes(token.as_bytes());
        let principal = self
            .principals
            .iter()
            .find(|principal| {
                principal.token_sha256 == token_sha256
                    && principal.scope.project == project
                    && principal.scope.repository == *repository
                    && principal.operations.contains(&operation)
            })
            .ok_or(JobStoreError::Unauthorized)?;
        let grant = authority.grant_for(&principal.scope.actor, project, repository)?;
        let context = grant.command_context()?;

        if expected_context.is_some_and(|expected| expected != &context) {
            return Err(JobStoreError::Precondition);
        }

        Ok(CommandAuthorization {
            scope: principal.scope.clone(),
            context,
            operation,
        })
    }
}
