//! Command DTO rejection and private-to-public projection regressions.

use archcert_application::glassmere::commands::*;
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{ControlCommandId, JobInputs, PolicyPin},
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};
use archcert_protocol::commands::{ControlCommandResponse, CreateControlCommandRequest};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn request() -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "project": ProjectId::new(),
        "repository": "fixture/commands",
        "authority_context": digest_bytes(b"explicit authority selection"),
        "action": {
            "kind": "REQUEST_CERTIFICATION",
            "source_submission": SourceSubmissionId::new(),
            "reviewed_session": null,
        },
    })
}

#[test]
fn command_requests_cannot_carry_authority_overrides_or_direct_effects() -> Result {
    let original = request();
    let parsed: CreateControlCommandRequest = serde_json::from_value(original.clone())?;
    assert_eq!(
        parsed.action.operation(),
        ControlOperation::RequestCertification
    );

    for field in [
        "actor",
        "role",
        "authority_toml",
        "policy",
        "image",
        "limits",
        "signing_key",
        "shell",
        "verdict",
        "cleanup_complete",
    ] {
        for nested in [false, true] {
            let mut forged = original.clone();
            let object = if nested {
                &mut forged["action"]
            } else {
                &mut forged
            };
            object[field] = serde_json::json!("forged authority");

            assert!(serde_json::from_value::<CreateControlCommandRequest>(forged).is_err());
        }
    }
    for kind in [
        "SIGN_CERTIFICATE",
        "SIGN_RELEASE_PERMIT",
        "EXECUTE_DOCKER",
        "REVIEW_DISPOSITION",
        "REQUEST_RELEASE_BUILD",
        "REQUEST_RELEASE_READINESS_EVALUATION",
    ] {
        let mut forged = original.clone();
        forged["action"]["kind"] = serde_json::json!(kind);
        assert!(serde_json::from_value::<CreateControlCommandRequest>(forged).is_err());
    }
    for field in ["project", "repository", "authority_context", "action"] {
        let mut missing = original.clone();
        missing
            .as_object_mut()
            .ok_or("not an object")?
            .remove(field);
        assert!(serde_json::from_value::<CreateControlCommandRequest>(missing).is_err());
    }

    Ok(())
}

#[test]
fn public_receipt_omits_frozen_recipe_actor_intent_and_dispatch_capabilities() -> Result {
    let scope = CommandScope {
        project: ProjectId::new(),
        repository: RepositoryId::parse("fixture/commands")?,
        actor: GitActorId::parse(ControlCommandId::new().to_string())?,
    };
    let source = SourceSnapshot::seal(
        scope.project,
        scope.repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1_700_000_000,
    )?;
    let command = ResolvedControlCommand {
        schema: 1,
        authority_context: digest_bytes(b"selected authority"),
        action: ResolvedControlAction::RequestCertification {
            inputs: Box::new(JobInputs {
                project: scope.project,
                repository: scope.repository.clone(),
                actor: scope.actor.clone(),
                submission: SourceSubmissionId::new(),
                source: source.identity().clone(),
                policy: PolicyPin {
                    id: "development".into(),
                    version: "1.0.0".into(),
                    sha256: digest_bytes(b"policy"),
                },
                profile: "python".into(),
                image: format!("python@sha256:{}", "a".repeat(64)),
                plan_sha256: digest_bytes(b"plan"),
                authority_toml: "PRIVATE_RECIPE_CANARY".into(),
                maximum_attempts: 2,
            }),
            reviewed_session: None,
        },
        scope,
    };
    command.validate()?;
    let record = ControlCommandRecord {
        id: ControlCommandId::new(),
        request_sha256: command.digest()?,
        intent_sha256: digest_bytes(b"private semantic intent"),
        command,
        state: ControlCommandState::Rejected,
        created_at: 1_700_000_000,
        dispatches: 2,
        outcome: Some(ControlCommandOutcome::Rejected {
            reason: CommandFailure::DomainPrecondition,
        }),
    };
    let id = record.id;

    let value = serde_json::to_value(ControlCommandResponse::from(record))?;
    assert_eq!(value["command_id"], id.to_string());
    assert_eq!(value["state"], "REJECTED");
    assert_eq!(value["operation"], "REQUEST_CERTIFICATION");
    assert_eq!(value["outcome"]["reason"], "DOMAIN_PRECONDITION");
    let encoded = serde_json::to_string(&value)?;
    for excluded in [
        "PRIVATE_RECIPE_CANARY",
        "authority_toml",
        "actor",
        "intent_sha256",
        "dispatches",
        "dispatcher",
        "lease",
        "inputs",
        "maximum_attempts",
    ] {
        assert!(
            !encoded.contains(excluded),
            "private field leaked: {excluded}"
        );
    }
    let decoded: ControlCommandResponse = serde_json::from_value(value)?;
    assert_eq!(decoded.command_id, id);
    assert_eq!(decoded.state, ControlCommandState::Rejected);

    Ok(())
}
