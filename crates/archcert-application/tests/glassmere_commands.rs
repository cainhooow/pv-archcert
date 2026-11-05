//! Private request identity and receipt boundaries, not browser authorization tests.

use archcert_application::{
    glassmere::{
        BlockerCode, ReleaseBlocker, ReleaseReadiness, ReleaseState, ReleaseSubject, commands::*,
    },
    jobs::{
        AttemptRuntime, CertificationAttempt, CertificationJob, JobStoreError, RuntimeBinding,
        RuntimeCleanupState,
    },
};
use archcert_domain::{
    GitObjectId, ProjectId,
    ingress::{GitActorId, SourceSubmissionId},
    jobs::{
        AttemptId, AttemptState, FailureCategory, IdempotencyKey, JobId, JobInputs, JobState,
        PolicyPin,
    },
    release::BuildInvocationIdentity,
    source::{RepositoryId, SourceSnapshot, digest_bytes},
};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn command() -> R<ResolvedControlCommand> {
    let project = ProjectId::new();
    let repository = RepositoryId::parse("fixture/source")?;
    let actor = GitActorId::parse("11111111-1111-4111-8111-111111111111".into())?;
    let source = SourceSnapshot::seal(
        project,
        repository.clone(),
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1_700_000_000,
    )?;

    Ok(ResolvedControlCommand {
        schema: CONTROL_COMMAND_SCHEMA,
        scope: CommandScope {
            project,
            repository: repository.clone(),
            actor: actor.clone(),
        },
        authority_context: digest_bytes(b"explicit trusted selection"),
        action: ResolvedControlAction::RequestCertification {
            inputs: Box::new(JobInputs {
                project,
                repository,
                actor,
                submission: SourceSubmissionId::new(),
                source: source.identity().clone(),
                policy: PolicyPin {
                    id: "development".into(),
                    version: "1.0.0".into(),
                    sha256: digest_bytes(b"fixed policy"),
                },
                profile: "python".into(),
                image: format!("python@sha256:{}", "d".repeat(64)),
                plan_sha256: digest_bytes(b"fixed plan"),
                authority_toml: "schema = 1".into(),
                maximum_attempts: 2,
            }),
            reviewed_session: None,
        },
    })
}

#[test]
fn frozen_request_roundtrip_preserves_canonical_identity() -> R {
    let command = command()?;
    command.validate()?;
    let value = serde_json::to_value(&command)?;
    let reconstructed: ResolvedControlCommand = serde_json::from_value(value)?;

    assert_eq!(command.bytes()?, reconstructed.bytes()?);
    assert_eq!(command.digest()?, reconstructed.digest()?);

    let mut changed = reconstructed;
    changed.authority_context = digest_bytes(b"different authority selection");
    assert_ne!(command.digest()?, changed.digest()?);

    Ok(())
}

#[test]
fn schema_one_request_retains_its_fixed_canonical_identity() -> R {
    let request = ResolvedControlCommand {
        schema: CONTROL_COMMAND_SCHEMA,
        scope: CommandScope {
            project: "33333333-3333-4333-8333-333333333333".parse()?,
            repository: RepositoryId::parse("fixture/source")?,
            actor: GitActorId::parse("11111111-1111-4111-8111-111111111111".into())?,
        },
        authority_context: digest_bytes(b"fixed context"),
        action: ResolvedControlAction::RequestReleaseReadinessEvaluation {
            invocation: BuildInvocationIdentity(digest_bytes(b"fixed invocation")),
        },
    };
    request.validate()?;

    // Fixed version-1 vector, independently calculated with sorted restricted JSON
    // and SHA-256. Recovery cannot silently reinterpret a retained request identity.
    assert_eq!(
        request.digest()?.as_str(),
        "c315ce9a5968387726eae0f57b83eed9b59190e5d790f42c8a3ecfc64e4081d7",
    );

    Ok(())
}

#[test]
fn frozen_request_rejects_scope_substitution_and_unknown_grammar() -> R {
    let command = command()?;
    for change in 0..5 {
        let mut changed = command.clone();
        match change {
            0 => changed.scope.project = ProjectId::new(),
            1 => changed.scope.repository = RepositoryId::parse("other/source")?,
            2 => {
                changed.scope.actor =
                    GitActorId::parse("22222222-2222-4222-8222-222222222222".into())?;
            }
            3 => changed.schema = 2,
            _ => {
                if let ResolvedControlAction::RequestCertification { inputs, .. } =
                    &mut changed.action
                {
                    inputs.authority_toml = "x".repeat(MAX_CONTROL_COMMAND_BYTES + 1);
                }
            }
        }

        assert!(matches!(changed.validate(), Err(JobStoreError::Invalid)));
    }

    let mut unknown = serde_json::to_value(&command)?;
    unknown["posted_role"] = "ADMINISTRATOR".into();
    assert!(serde_json::from_value::<ResolvedControlCommand>(unknown).is_err());
    let mut unknown = serde_json::to_value(&command)?;
    unknown["action"] = serde_json::json!({
        "kind": "REVIEW_DISPOSITION",
        "verdict": "PROVEN",
    });
    assert!(serde_json::from_value::<ResolvedControlCommand>(unknown).is_err());

    Ok(())
}

#[test]
fn different_client_keys_share_workflow_intent_but_not_fresh_observations() -> R {
    let mut command = command()?;
    let first = IdempotencyKey::parse("tab-one".into())?;
    let second = IdempotencyKey::parse("tab-two".into())?;

    assert_eq!(command.intent(&first)?, command.intent(&second)?);
    command.action = ResolvedControlAction::RequestReleaseReadinessEvaluation {
        invocation: BuildInvocationIdentity(digest_bytes(b"exact invocation")),
    };
    assert_eq!(command.intent(&first)?, command.intent(&first)?);
    assert_ne!(command.intent(&first)?, command.intent(&second)?);

    Ok(())
}

#[test]
fn receipt_kind_and_exact_review_identity_cannot_be_substituted() -> R {
    let mut command = command()?;
    let job = JobId::new();
    let effect = |job, session| ControlCommandOutcome::Applied {
        effect: Box::new(CommandEffect::CertificationRequested { job, session }),
    };

    command.validate_outcome(&effect(Some(job), None))?;
    assert!(command.validate_outcome(&effect(None, None)).is_err());
    assert!(
        command
            .validate_outcome(&effect(Some(job), Some(job)))
            .is_err()
    );
    assert!(
        command
            .validate_outcome(&ControlCommandOutcome::Applied {
                effect: Box::new(CommandEffect::JobCanceled { job }),
            })
            .is_err()
    );

    if let ResolvedControlAction::RequestCertification {
        reviewed_session, ..
    } = &mut command.action
    {
        *reviewed_session = Some(job);
    }
    command.validate_outcome(&effect(None, Some(job)))?;
    command.validate_outcome(&effect(Some(job), Some(job)))?;
    assert!(
        command
            .validate_outcome(&effect(Some(JobId::new()), Some(job)))
            .is_err()
    );

    Ok(())
}

#[test]
fn readiness_receipt_cannot_change_subject_or_hide_denial() -> R {
    let mut command = command()?;
    let ResolvedControlAction::RequestCertification { inputs, .. } = &command.action else {
        return Err("wrong fixture action".into());
    };
    let invocation = digest_bytes(b"exact invocation");
    let observation = ReleaseReadiness {
        schema: 1,
        subject: ReleaseSubject {
            project: command.scope.project,
            repository: command.scope.repository.as_str().into(),
            source: inputs.source.clone(),
            certificate: None,
            invocation: invocation.as_str().into(),
            artifact: None,
            permit: None,
        },
        state: ReleaseState::ReleaseDenied,
        blockers: vec![ReleaseBlocker {
            code: BlockerCode::NoSourceCertificate,
            summary: "Source certificate bytes are missing.".into(),
            affected_identity: invocation.as_str().into(),
            evidence_reference: None,
            remediation_category: "AUTHORITY_EVIDENCE_REQUIRED".into(),
        }],
        revision: digest_bytes(b"observation revision").as_str().into(),
        evaluated_at: 1_700_000_000,
        provenance: "Test observation; no signature or runtime proof".into(),
    };
    command.action = ResolvedControlAction::RequestReleaseReadinessEvaluation {
        invocation: BuildInvocationIdentity(invocation),
    };
    let outcome = |observation| ControlCommandOutcome::Applied {
        effect: Box::new(CommandEffect::ReadinessEvaluated {
            observation: Box::new(observation),
        }),
    };
    command.validate_outcome(&outcome(observation.clone()))?;

    for change in 0..5 {
        let mut substituted = observation.clone();
        match change {
            0 => substituted.subject.project = ProjectId::new(),
            1 => substituted.subject.repository = "other/source".into(),
            2 => substituted.subject.invocation = digest_bytes(b"other invocation").as_str().into(),
            3 => substituted.state = ReleaseState::ReleaseAllowed,
            _ => substituted.schema = 2,
        }
        assert!(command.validate_outcome(&outcome(substituted)).is_err());
    }

    Ok(())
}

#[test]
fn queued_cancellation_denies_active_or_uncertain_attempts_and_positive_checkpoints() -> R {
    let command = command()?;
    let ResolvedControlAction::RequestCertification { inputs, .. } = command.action else {
        return Err("wrong fixture action".into());
    };
    let mut job = CertificationJob {
        id: JobId::new(),
        inputs: *inputs,
        created_at: 1_700_000_000,
        evaluation_at: None,
        failure: None,
        state: JobState::Queued,
        attempts: vec![],
        evaluation: None,
        issuance: None,
        certificate: None,
    };
    assert_eq!(queued_cancellation_state(&job)?, JobState::Inconclusive);

    for state in [
        JobState::Running,
        JobState::Evaluating,
        JobState::Signing,
        JobState::Completed,
        JobState::NotEligible,
        JobState::Inconclusive,
    ] {
        job.state = state;
        assert!(queued_cancellation_state(&job).is_err());
        assert!(state.cancel_queued().is_err());
    }
    job.state = JobState::Queued;
    job.failure = Some(FailureCategory::PolicyFailure);
    assert!(queued_cancellation_state(&job).is_err());
    job.failure = None;
    job.evaluation = Some(archcert_application::release::release_reference(
        b"evaluation",
    ));
    assert!(queued_cancellation_state(&job).is_err());
    job.evaluation = None;

    job.attempts.push(CertificationAttempt {
        id: AttemptId::new(),
        ordinal: 1,
        worker: "fixture-worker".into(),
        state: AttemptState::Lost,
        leased_at: 1_700_000_000,
        lease_until: 1_700_000_005,
        ended_at: Some(1_700_000_006),
        failure: Some(FailureCategory::WorkerLoss),
        evidence: None,
        runtime: Some(AttemptRuntime {
            binding: RuntimeBinding {
                endpoint: "unix:///fixture/runtime.sock".into(),
                daemon_id: "fixture-runtime".into(),
                gate_root: "/fixture/gates".into(),
            },
            fenced: true,
            cleanup: RuntimeCleanupState::Succeeded,
        }),
    });
    assert_eq!(queued_cancellation_state(&job)?, JobState::Inconclusive);

    let retained = job.attempts[0].runtime.take();
    assert!(queued_cancellation_state(&job).is_err());
    job.attempts[0].runtime = retained;

    for state in [
        AttemptState::Leased,
        AttemptState::Running,
        AttemptState::EvidenceReady,
        AttemptState::Completed,
        AttemptState::Failed,
    ] {
        job.attempts[0].state = state;
        assert!(queued_cancellation_state(&job).is_err());
    }
    job.attempts[0].state = AttemptState::Lost;
    for cleanup in [
        RuntimeCleanupState::NotRequired,
        RuntimeCleanupState::Pending,
        RuntimeCleanupState::InProgress,
        RuntimeCleanupState::Failed,
        RuntimeCleanupState::Blocked,
    ] {
        job.attempts[0]
            .runtime
            .as_mut()
            .ok_or("missing runtime")?
            .cleanup = cleanup;
        assert!(queued_cancellation_state(&job).is_err());
    }
    let runtime = job.attempts[0].runtime.as_mut().ok_or("missing runtime")?;
    runtime.cleanup = RuntimeCleanupState::Succeeded;
    runtime.fenced = false;
    assert!(queued_cancellation_state(&job).is_err());

    Ok(())
}
