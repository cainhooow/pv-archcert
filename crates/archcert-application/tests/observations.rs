//! Evidence facts are usable without Docker DTOs or a policy verdict.
use archcert_application::validation::*;
use archcert_domain::{
    GitObjectId, SourceIdentity, execution::*, materialization::WorkspaceId, source::digest_bytes,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<(ValidationPlan, ExecutionEvidence), Box<dyn std::error::Error>> {
    let authority = AuthorityConfiguration::development(vec![(
        "node".into(),
        format!("python-image@sha256:{}", "a".repeat(64)),
    )])?;
    let command = ExecutionCommand::new("node".into(), vec!["tests.js".into()], "/source".into())?;
    let plan = authority.resolve(Some(&ProjectExecutionRequest::new(
        "node".into(),
        vec![RequestedStep {
            id: "tests".into(),
            command: command.clone(),
            evidence: EvidenceCategory::Test,
        }],
    )))?;
    let empty = CapturedStream {
        sha256: digest_bytes(b""),
        observed_bytes: 0,
        excerpt: vec![],
        truncated: false,
        complete: true,
    };
    let evidence = ExecutionEvidence {
        execution: ExecutionId::new(),
        source: SourceIdentity {
            commit: GitObjectId::parse("a".repeat(40))?,
            tree: GitObjectId::parse("b".repeat(40))?,
            snapshot_sha256: digest_bytes(b"source"),
        },
        workspace: WorkspaceId::new(),
        backend: "test-controller".into(),
        backend_version: "test-v1".into(),
        producer_version: "0.1.0".into(),
        observed_runtime: ObservedRuntimeIdentity {
            client_path: "/trusted/runtime".into(),
            client_version: "test-client".into(),
            server_version: "test-server".into(),
            runtime_information: Default::default(),
        },
        toolchain: ToolchainObservation::NotObserved,
        image_digest: plan.steps()[0].profile().image().into(),
        base_image_id: format!("sha256:{}", "c".repeat(64)),
        execution_image_id: format!("sha256:{}", "d".repeat(64)),
        profile: "node".into(),
        command,
        network: NetworkPolicy::Denied,
        limits: ExecutionLimits::default(),
        environment_keys: sandbox_environment().into_keys().collect(),
        container_user: "10001:10001".into(),
        started_at_ms: 1,
        ended_at_ms: 2,
        duration_ms: 1,
        exit_code: Some(0),
        termination: TerminationReason::Exit,
        stdout: empty.clone(),
        stderr: empty,
        outcome: ExecutionOutcome::Completed,
    };
    Ok((plan, evidence))
}
#[test]
fn toolchain_profile_image_mismatch_is_never_silently_represented_as_proven() -> TestResult {
    let (plan, evidence) = fixture()?;
    // An authority operator can associate a misleading image with a catalog ID.
    // Names/digests do not prove that Node exists inside this Python-named image.
    let observations = ValidationObservation::from_execution(&plan, &plan.steps()[0], &evidence)?;
    assert!(observations.iter().any(|o| matches!(
        o.fact,
        ObservationFact::EnvironmentEstablished {
            toolchain: ToolchainObservation::NotObserved
        }
    )));
    let encoded = serde_json::to_string(&observations)?;
    assert!(!encoded.contains("Proven"));
    assert!(!encoded.contains("PASS"));
    assert!(!encoded.contains("CERTIFIED"));
    Ok(())
}
#[test]
fn zero_and_nonzero_exits_remain_observations_bound_to_source_execution_and_producer() -> TestResult
{
    let (plan, mut evidence) = fixture()?;
    for exit in [0, 7] {
        evidence.exit_code = Some(exit);
        let observations =
            ValidationObservation::from_execution(&plan, &plan.steps()[0], &evidence)?;
        let observed = observations.first().ok_or("missing observation")?;
        assert_eq!(observed.id.execution, evidence.execution);
        assert_eq!(observed.id.step, "tests");
        assert_eq!(observed.source, evidence.source);
        assert_eq!(observed.producer, "test-v1/0.1.0");
        assert!(
            matches!(observed.fact, ObservationFact::ExecutionFinished { outcome:ExecutionOutcome::Completed, exit_code:Some(code), category:EvidenceCategory::Test } if code == exit)
        );
    }
    Ok(())
}
#[test]
fn observations_reject_cross_plan_evidence_attribution() -> TestResult {
    let (plan, mut evidence) = fixture()?;
    evidence.profile = "other".into();
    assert!(ValidationObservation::from_execution(&plan, &plan.steps()[0], &evidence).is_err());
    Ok(())
}

#[test]
fn whole_plan_identity_includes_authority_provenance_and_rejects_cross_plan_step() -> TestResult {
    let (plan, evidence) = fixture()?;
    let original = plan.steps().first().ok_or("step")?;
    let authority = AuthorityConfiguration::development(vec![(
        "node".into(),
        original.profile().image().into(),
    )])?
    .with_required_steps(vec![AuthorityRequiredStep {
        id: original.id().into(),
        profile: "node".into(),
        command: original.command().clone(),
        evidence: original.evidence_category(),
    }])?;
    let changed = authority.resolve(None)?;
    assert_ne!(plan.digest()?, changed.digest()?);
    assert_eq!(plan.digest()?, plan.clone().digest()?);
    assert!(ValidationObservation::from_execution(&changed, original, &evidence).is_err());
    let observations = ValidationObservation::from_execution(&plan, original, &evidence)?;
    let digest = plan.digest()?;
    assert!(observations.iter().all(|o| o.plan_sha256 == digest));
    Ok(())
}
