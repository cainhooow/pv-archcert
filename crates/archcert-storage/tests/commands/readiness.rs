//! Real journal grants, binding, fencing and historical publication.
//! The observer is a metadata fixture, not cryptographic or runtime qualification.

use super::*;
use archcert_application::{glassmere::*, release::*};
use archcert_domain::release::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn readiness_fixture() -> R<(
    PostgresJobRepository,
    PgPool,
    ResolvedControlCommand,
    ReleaseSubject,
)> {
    let (repo, pool, mut command) = fixture().await?;
    let ResolvedControlAction::RequestCertification { inputs, .. } = &command.action else {
        return Err("source fixture".into());
    };
    let recipe = RustReleaseRecipe::new(
        BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"metadata fixture dependencies"),
            toolchain_sha256: digest_bytes(b"metadata fixture toolchain"),
        },
        "fixture",
    )?;
    let input = BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: CertifiedSourceIdentity {
            project: command.scope.project,
            repository: command.scope.repository.clone(),
            source: inputs.source.clone(),
            certificate_sha256: digest_bytes(b"metadata fixture source certificate"),
        },
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: inputs.policy.sha256.clone(),
        source_authority_key_sha256: digest_bytes(b"metadata fixture source key"),
        release_authority_key_sha256: digest_bytes(b"metadata fixture release key"),
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    };
    let admission = ReleaseAdmission {
        input_reference: release_reference(&release_bytes(&input)?),
        input,
        submission: inputs.submission.clone(),
        actor: command.scope.actor.clone(),
    };
    ReleaseRepository::open(&repo, &admission).await?;
    let invocation = admission.input.identity()?;
    let subject = ReleaseSubject {
        project: command.scope.project,
        repository: command.scope.repository.as_str().into(),
        source: admission.input.certified_source.source.clone(),
        certificate: Some(
            admission
                .input
                .certified_source
                .certificate_sha256
                .as_str()
                .into(),
        ),
        invocation: invocation.0.as_str().into(),
        artifact: None,
        permit: None,
    };
    command.action = ResolvedControlAction::RequestReleaseReadinessEvaluation { invocation };
    enable(&repo, &command).await?;

    Ok((repo, pool, command, subject))
}

#[derive(Clone, Copy)]
enum Mode {
    Allowed,
    Denied,
    Unavailable,
    UnsupportedSchema,
    WrongProject,
    WrongSource,
    ContradictoryState,
}

struct Observer {
    subject: ReleaseSubject,
    mode: Mode,
    calls: AtomicUsize,
}

impl Observer {
    fn new(subject: &ReleaseSubject, mode: Mode) -> Self {
        Self {
            subject: subject.clone(),
            mode,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ReleaseReadinessObserver for Observer {
    async fn observe(
        &self,
        project: ProjectId,
        invocation: &BuildInvocationIdentity,
    ) -> Result<ReleaseReadiness, JobStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if project != self.subject.project || invocation.0.as_str() != self.subject.invocation {
            return Err(JobStoreError::Precondition);
        }
        if matches!(self.mode, Mode::Unavailable) {
            return Err(JobStoreError::Unavailable);
        }

        let mut checks = ReadinessChecks {
            subject: self.subject.clone(),
            certificate: Ok(()),
            reproducibility: Ok(()),
            artifact: Ok(()),
            permit: Ok(()),
            policy: Ok(()),
            review: Ok(()),
            environment: Ok(()),
            freshness: Ok(()),
        };
        if matches!(self.mode, Mode::Denied | Mode::ContradictoryState) {
            checks.policy = Err(BlockerCode::PolicyFailed);
        }

        let mut observation = checks.evaluate("metadata-fixture-revision".into(), 1_700_000_000);
        observation.provenance =
            "METADATA FIXTURE / NOT CRYPTOGRAPHIC OR RUNTIME VALIDATION".into();
        match self.mode {
            Mode::UnsupportedSchema => observation.schema = 99,
            Mode::WrongProject => observation.subject.project = ProjectId::new(),
            Mode::WrongSource => {
                observation.subject.source.snapshot_sha256 = digest_bytes(b"wrong source")
            }
            Mode::ContradictoryState => observation.state = ReleaseState::ReleaseAllowed,
            _ => {}
        }

        Ok(observation)
    }
}

async fn next_assignment(
    repo: &PostgresJobRepository,
    command: &ResolvedControlCommand,
    key_text: &str,
) -> R<ControlCommandAssignment> {
    repo.accept(command, &key(key_text)?).await?;
    Ok(
        ControlCommandRepository::claim(repo, "readiness-dispatcher", 30)
            .await?
            .ok_or("readiness claim")?,
    )
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_receipts_are_historical_same_key_replays_and_new_keys_observe_again() -> R {
    let (repo, pool, command, subject) = readiness_fixture().await?;
    for (ordinal, mode) in [Mode::Allowed, Mode::Denied].into_iter().enumerate() {
        let key_text = format!("explicit-observation-{ordinal}");
        let assignment = next_assignment(&repo, &command, &key_text).await?;
        let observer = Observer::new(&subject, mode);
        let evaluator = ReadinessRequestEvaluator {
            commands: &repo,
            observer: Some(&observer),
        };

        let outcome = evaluator
            .evaluate(&assignment, &command.authority_context)
            .await?;
        let ControlCommandOutcome::Applied { effect } = outcome else {
            return Err("observation not published".into());
        };
        let CommandEffect::ReadinessEvaluated { observation } = *effect else {
            return Err("wrong observation effect".into());
        };
        assert_eq!(observation.subject, subject);
        assert_eq!(
            observation.state,
            if ordinal == 0 {
                ReleaseState::ReleaseAllowed
            } else {
                ReleaseState::ReleaseDenied
            }
        );
        assert_eq!(
            observation
                .blockers
                .iter()
                .map(|blocker| blocker.code)
                .collect::<Vec<_>>(),
            if ordinal == 0 {
                vec![]
            } else {
                vec![BlockerCode::PolicyFailed]
            }
        );

        let replay = repo.accept(&command, &key(&key_text)?).await?;
        assert_eq!(replay.id, assignment.record.id);
        assert_eq!(replay.state, ControlCommandState::Applied);
        assert_eq!(observer.calls.load(Ordering::Relaxed), 1);
    }

    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_commands),
                (SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'),
                (SELECT count(*) FROM release_invocations),
                (SELECT count(*) FROM release_audit),
                (SELECT count(*) FROM release_invocations WHERE claim_a IS NOT NULL OR claim_b IS NOT NULL)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (2, 2, 1, 1, 0));

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_unavailable_or_invalid_observations_never_publish_allowed() -> R {
    let (repo, _, command, subject) = readiness_fixture().await?;
    for (ordinal, (mode, expected)) in [
        (None, CommandFailure::InfrastructureUnavailable),
        (
            Some(Mode::Unavailable),
            CommandFailure::InfrastructureUnavailable,
        ),
        (
            Some(Mode::UnsupportedSchema),
            CommandFailure::UnsupportedAuthorityContext,
        ),
        (Some(Mode::WrongProject), CommandFailure::IdentityMismatch),
        (
            Some(Mode::ContradictoryState),
            CommandFailure::IdentityMismatch,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let assignment = next_assignment(&repo, &command, &format!("unproven-{ordinal}")).await?;
        let observer = mode.map(|mode| Observer::new(&subject, mode));
        let evaluator = ReadinessRequestEvaluator {
            commands: &repo,
            observer: observer
                .as_ref()
                .map(|observer| observer as &dyn ReleaseReadinessObserver),
        };

        let outcome = evaluator
            .evaluate(&assignment, &command.authority_context)
            .await?;
        assert!(matches!(
            outcome,
            ControlCommandOutcome::Inconclusive { reason } if reason == expected
        ));
        let retained =
            ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
        assert_eq!(retained.state, ControlCommandState::Inconclusive);
        assert!(matches!(
            retained.outcome,
            Some(ControlCommandOutcome::Inconclusive { reason }) if reason == expected
        ));
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_changed_authority_and_revoked_grant_deny_before_observation() -> R {
    let (repo, pool, command, subject) = readiness_fixture().await?;
    let observer = Observer::new(&subject, Mode::Allowed);
    let evaluator = ReadinessRequestEvaluator {
        commands: &repo,
        observer: Some(&observer),
    };
    let first = next_assignment(&repo, &command, "old-context").await?;

    let outcome = evaluator
        .evaluate(&first, &digest_bytes(b"different selected authority"))
        .await?;
    assert!(matches!(
        outcome,
        ControlCommandOutcome::Rejected {
            reason: CommandFailure::UnsupportedAuthorityContext
        }
    ));
    assert_eq!(observer.calls.load(Ordering::Relaxed), 0);

    let second = next_assignment(&repo, &command, "revoked-context").await?;
    sqlx::query("DELETE FROM control_command_grants WHERE project=$1")
        .bind(command.scope.project.to_string())
        .execute(&pool)
        .await?;
    assert!(matches!(
        evaluator
            .evaluate(&second, &command.authority_context)
            .await,
        Err(JobStoreError::Unauthorized)
    ));
    assert_eq!(observer.calls.load(Ordering::Relaxed), 0);
    let applied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(applied, 0);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_wrong_source_cannot_publish_and_retains_the_request() -> R {
    let (repo, pool, command, subject) = readiness_fixture().await?;
    let assignment = next_assignment(&repo, &command, "wrong-source").await?;
    let observer = Observer::new(&subject, Mode::WrongSource);
    let evaluator = ReadinessRequestEvaluator {
        commands: &repo,
        observer: Some(&observer),
    };

    assert!(matches!(
        evaluator
            .evaluate(&assignment, &command.authority_context)
            .await,
        Err(JobStoreError::Precondition)
    ));
    let retained =
        ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
    assert_eq!(retained.state, ControlCommandState::Processing);
    assert!(retained.outcome.is_none());
    let applied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(applied, 0);

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; scripts/test-ravenport"]
async fn readiness_expired_dispatch_cannot_publish_a_positive_observation() -> R {
    let (repo, pool, command, subject) = readiness_fixture().await?;
    repo.accept(&command, &key("expired-readiness")?).await?;
    let assignment = ControlCommandRepository::claim(&repo, "expired-readiness-dispatcher", 5)
        .await?
        .ok_or("claim")?;
    let observer = Observer::new(&subject, Mode::Allowed);
    let evaluator = ReadinessRequestEvaluator {
        commands: &repo,
        observer: Some(&observer),
    };
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    assert!(matches!(
        evaluator
            .evaluate(&assignment, &command.authority_context)
            .await,
        Err(JobStoreError::Precondition)
    ));
    let retained =
        ControlCommandRepository::get(&repo, &command.scope, assignment.record.id).await?;
    assert_eq!(retained.state, ControlCommandState::Processing);
    assert!(retained.outcome.is_none());
    let applied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_command_audit WHERE event='CommandApplied'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(applied, 0);

    Ok(())
}
