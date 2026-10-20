//! Deterministic policy regression and exhaustive finite permutation tests.
use archcert_application::{configuration::ProjectConfiguration, validation::*};
use archcert_domain::{
    GitObjectId, ProjectId, PropertyVerdict as V, execution::*, materialization::WorkspaceId,
    source::*,
};
use archcert_policy::*;
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    snapshot: SourceSnapshot,
    plan: ValidationPlan,
    evidence: ExecutionEvidence,
}
fn fixture() -> R<Fixture> {
    let snapshot = SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("fixture/policy")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![],
        1,
        1,
    )?;
    let authority = AuthorityConfiguration::development(vec![(
        "python".into(),
        format!("approved@sha256:{}", "a".repeat(64)),
    )])?;
    let command = ExecutionCommand::new(
        "python3".into(),
        vec!["-c".into(), "print('TESTS PASSED')".into()],
        "/source".into(),
    )?;
    let mandatory = [
        ("typecheck", EvidenceCategory::Typecheck),
        ("test", EvidenceCategory::Test),
        ("build", EvidenceCategory::Build),
    ]
    .into_iter()
    .map(|(id, evidence)| AuthorityRequiredStep {
        id: id.into(),
        profile: "python".into(),
        command: command.clone(),
        evidence,
    })
    .collect();
    let plan = authority.with_required_steps(mandatory)?.resolve(None)?;
    let empty = CapturedStream {
        sha256: digest_bytes(b""),
        observed_bytes: 0,
        excerpt: vec![],
        truncated: false,
        complete: true,
    };
    let evidence = ExecutionEvidence {
        execution: ExecutionId::new(),
        source: snapshot.identity().clone(),
        workspace: WorkspaceId::new(),
        backend: "test-controller".into(),
        backend_version: "archcert-docker-cli-v1".into(),
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
        profile: "python".into(),
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
    Ok(Fixture {
        snapshot,
        plan,
        evidence,
    })
}
fn bundle() -> R<PolicyBundle> {
    Ok(PolicyBundle::read(DEVELOPMENT_POLICY.as_bytes())?)
}
fn observations(f: &Fixture) -> R<(Vec<ExpectedExecution>, Vec<ValidationObservation>)> {
    let mut expected = vec![];
    let mut observations = vec![];
    for step in f.plan.steps() {
        let mut evidence = f.evidence.clone();
        evidence.execution = ExecutionId::new();
        expected.push(ExpectedExecution {
            step: step.id().into(),
            execution: evidence.execution,
        });
        observations.extend(ValidationObservation::from_execution(
            &f.plan, step, &evidence,
        )?);
    }
    Ok((expected, observations))
}
fn run(
    f: &Fixture,
    b: &PolicyBundle,
    expected: &[ExpectedExecution],
    obs: &[ValidationObservation],
    time: u64,
) -> R<PolicyEvaluation> {
    Ok(evaluate(
        b,
        b.identity(),
        EvaluationInput {
            source: &f.snapshot,
            plan: &f.plan,
            executions: expected,
            observations: obs,
            evaluated_at: time,
        },
    )?)
}
fn property(e: &PolicyEvaluation, id: PropertyId) -> R<&PropertyEvaluation> {
    e.properties
        .iter()
        .find(|p| p.property == id)
        .ok_or_else(|| "property missing".into())
}
fn test_fact(obs: &mut [ValidationObservation], outcome: ExecutionOutcome, exit_code: Option<i64>) {
    for o in obs
        .iter_mut()
        .filter(|o| o.id.step == "test" && o.id.kind == ObservationKind::ExecutionFinished)
    {
        o.fact = ObservationFact::ExecutionFinished {
            outcome,
            exit_code,
            category: EvidenceCategory::Test,
        };
    }
}
#[test]
fn all_proven_is_eligible_but_never_a_certificate() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert!(e.properties.iter().all(|p| p.verdict == V::Proven));
    assert_eq!(
        e.eligibility,
        CertificationEligibility::EligibleForCertification
    );
    assert!(e.findings.is_empty());
    let json = serde_json::to_string(&e)?;
    assert!(!json.contains("CERTIFIED"));
    assert!(!json.contains("signature"));
    Ok(())
}
#[test]
fn target_failure_runtime_failure_missing_and_ambiguous_are_distinct() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, mut obs) = observations(&f)?;
    for (outcome, exit, verdict, reason, eligibility) in [
        (
            ExecutionOutcome::Completed,
            Some(0),
            V::Proven,
            ReasonCode::EvidenceEstablished,
            CertificationEligibility::EligibleForCertification,
        ),
        (
            ExecutionOutcome::Completed,
            Some(1),
            V::Failed,
            ReasonCode::TargetExitNonzero,
            CertificationEligibility::NotEligible,
        ),
        (
            ExecutionOutcome::SandboxFailure,
            None,
            V::Inconclusive,
            ReasonCode::InfrastructureFailure,
            CertificationEligibility::Inconclusive,
        ),
        (
            ExecutionOutcome::StartFailure,
            None,
            V::Inconclusive,
            ReasonCode::InfrastructureFailure,
            CertificationEligibility::Inconclusive,
        ),
        (
            ExecutionOutcome::Completed,
            None,
            V::Inconclusive,
            ReasonCode::AmbiguousExecution,
            CertificationEligibility::Inconclusive,
        ),
        (
            ExecutionOutcome::Completed,
            Some(-1),
            V::Inconclusive,
            ReasonCode::AmbiguousExecution,
            CertificationEligibility::Inconclusive,
        ),
        (
            ExecutionOutcome::TimedOut,
            None,
            V::Failed,
            ReasonCode::ExecutionLimit,
            CertificationEligibility::NotEligible,
        ),
        (
            ExecutionOutcome::ResourceLimit,
            None,
            V::Failed,
            ReasonCode::ExecutionLimit,
            CertificationEligibility::NotEligible,
        ),
    ] {
        test_fact(&mut obs, outcome, exit);
        let e = run(&f, &b, &ids, &obs, 1)?;
        let p = property(&e, PropertyId::TestSuiteCompletes)?;
        assert_eq!(
            (p.verdict, p.reason, e.eligibility),
            (verdict, reason, eligibility)
        );
    }
    obs.retain(|o| !(o.id.step == "test" && o.id.kind == ObservationKind::ExecutionFinished));
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.verdict,
        V::NotProven
    );
    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    Ok(())
}
#[test]
fn every_missing_mandatory_fact_never_passes() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, obs) = observations(&f)?;
    for i in 0..obs.len() {
        let mut subset = obs.clone();
        subset.remove(i);
        let e = run(&f, &b, &ids, &subset, 1)?;
        assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
        assert!(e.properties.iter().any(|p| p.verdict == V::NotProven));
    }
    let e = run(&f, &b, &[], &[], 1)?;
    assert!(
        e.properties
            .iter()
            .filter(|p| p.property != PropertyId::SourceComplete)
            .all(|p| p.verdict == V::NotProven)
    );
    Ok(())
}
#[test]
fn substitution_of_source_commit_plan_profile_step_job_category_or_kind_never_satisfies() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, obs) = observations(&f)?;
    for attack in 0..10 {
        let mut forged = obs.clone();
        for o in &mut forged {
            match attack {
                0 => o.source.snapshot_sha256 = digest_bytes(b"other-source"),
                1 => o.source.commit = GitObjectId::parse("c".repeat(40))?,
                2 => o.source.tree = GitObjectId::parse("c".repeat(40))?,
                3 => o.plan_sha256 = digest_bytes(b"another-plan"),
                4 => o.profile = "node".into(),
                5 => o.id.step = "wrong-step".into(),
                6 => o.id.execution = ExecutionId::new(),
                7 => {
                    if let ObservationFact::ExecutionFinished { category, .. } = &mut o.fact {
                        *category = EvidenceCategory::Execution;
                    }
                }
                8 => o.id.kind = ObservationKind::SourceIdentityMatched,
                _ => o.producer = "LLM-says-PASS/v1".into(),
            }
        }
        let e = run(&f, &b, &ids, &forged, 1)?;
        assert_ne!(
            property(&e, PropertyId::TestSuiteCompletes)?.verdict,
            V::Proven,
            "attack {attack}"
        );
        assert_ne!(
            e.eligibility,
            CertificationEligibility::EligibleForCertification
        );
    }
    Ok(())
}
#[test]
fn unknown_schema_or_producer_is_inconclusive_and_never_reinterpreted() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, obs) = observations(&f)?;
    for unknown in [true, false] {
        let mut changed = obs.clone();
        for o in &mut changed {
            if unknown {
                o.schema = 2;
            } else {
                o.producer = "archcert-docker-cli-v2/9.9".into();
            }
        }
        let e = run(&f, &b, &ids, &changed, 1)?;
        assert_eq!(
            property(&e, PropertyId::TestSuiteCompletes)?.verdict,
            V::Inconclusive
        );
        assert_eq!(e.eligibility, CertificationEligibility::Inconclusive);
    }
    Ok(())
}
#[test]
fn identical_duplicates_are_idempotent_and_contradictions_are_inconclusive() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, mut obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    obs.extend(obs.clone());
    assert_eq!(
        serde_json::to_value(&e)?,
        serde_json::to_value(run(&f, &b, &ids, &obs, 1)?)?
    );
    let mut contrary = obs
        .iter()
        .find(|o| o.id.step == "test" && o.id.kind == ObservationKind::ExecutionFinished)
        .ok_or("missing")?
        .clone();
    contrary.fact = ObservationFact::ExecutionFinished {
        outcome: ExecutionOutcome::Completed,
        exit_code: Some(1),
        category: EvidenceCategory::Test,
    };
    obs.push(contrary);
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.reason,
        ReasonCode::ContradictoryEvidence
    );
    assert_eq!(e.eligibility, CertificationEligibility::Inconclusive);
    obs.reverse();
    assert_eq!(
        serde_json::to_value(&e)?,
        serde_json::to_value(run(&f, &b, &ids, &obs, 1)?)?
    );
    Ok(())
}
fn permute<T: Clone>(items: &mut [T], start: usize, apply: &mut impl FnMut(&[T]) -> R) -> R {
    if start == items.len() {
        return apply(items);
    }
    for i in start..items.len() {
        items.swap(start, i);
        permute(items, start + 1, apply)?;
        items.swap(start, i);
    }
    Ok(())
}
#[test]
fn exhaustive_fact_permutations_and_audit_time_leave_results_and_finding_ids_unchanged() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, mut obs) = observations(&f)?;
    test_fact(&mut obs, ExecutionOutcome::Completed, Some(1));
    let mut baseline = serde_json::to_value(run(&f, &b, &ids, &obs, 1)?)?;
    baseline
        .as_object_mut()
        .ok_or("object")?
        .remove("evaluated_at");
    let mut chunk = obs[..4].to_vec();
    permute(&mut chunk, 0, &mut |chunk| {
        let mut changed = chunk.to_vec();
        changed.extend_from_slice(&obs[4..]);
        for rotation in 0..changed.len() {
            changed.rotate_left(rotation);
            let mut e = serde_json::to_value(run(&f, &b, &ids, &changed, 123456)?)?;
            e.as_object_mut().ok_or("object")?.remove("evaluated_at");
            assert_eq!(baseline, e);
        }
        Ok(())
    })?;
    Ok(())
}
#[test]
fn property_permutations_and_toml_whitespace_have_identical_canonical_identity() -> R {
    let b = bundle()?;
    let f = fixture()?;
    let (ids, obs) = observations(&f)?;
    let expected = serde_json::to_value(run(&f, &b, &ids, &obs, 1)?)?;
    let mut parts = DEVELOPMENT_POLICY.split("[[properties]]");
    let header = parts.next().ok_or("header")?;
    let mut properties: Vec<_> = parts.collect();
    // Exhaust all 7! permutations; evaluate representative rotations too.
    permute(&mut properties, 0, &mut |properties| {
        let text = format!(
            "# whitespace and order are not identity\n{}\n[[properties]]{}",
            header,
            properties.join("\n[[properties]]")
        );
        let other = PolicyBundle::read(text.as_bytes())?;
        assert_eq!(b.canonical_bytes(), other.canonical_bytes());
        assert_eq!(b.identity(), other.identity());
        Ok(())
    })?;
    properties.reverse();
    let text = format!(
        "{}[[properties]]{}",
        header,
        properties.join("[[properties]]")
    );
    let other = PolicyBundle::read(text.as_bytes())?;
    assert_eq!(
        expected,
        serde_json::to_value(run(&f, &other, &ids, &obs, 1)?)?
    );
    Ok(())
}
#[test]
fn strict_parser_bounds_unknown_fields_duplicates_and_rule_confusion_reject() -> R {
    for text in [
        format!("{}\nunknown=true",DEVELOPMENT_POLICY),
        DEVELOPMENT_POLICY.replace("schema = 1","schema = 2"),
        DEVELOPMENT_POLICY.replace("kind = \"ALWAYS\"", "kind = \"ALWAYS\", script = \"true\""),
        DEVELOPMENT_POLICY.replace("kind = \"SOURCE_COMPLETE\"", "kind = \"SOURCE_COMPLETE\", override = true"),
        DEVELOPMENT_POLICY.replace("category = \"TEST\"", "category = \"EXECUTION\""),
        DEVELOPMENT_POLICY.replace("steps = [\"test\"]", "steps = [\"test\", \"test\"]"),
        DEVELOPMENT_POLICY.replace("id = \"BUILD_COMPLETES\"", "id = \"TEST_SUITE_COMPLETES\""),
        DEVELOPMENT_POLICY.replace("archcert-development-v1", &"x".repeat(129)),
        DEVELOPMENT_POLICY.replace("The authority-selected build command completed with exit zero; no build artifact security claim.",&"x".repeat(2049)),
        "x".repeat(MAX_POLICY_BYTES+1),
        DEVELOPMENT_POLICY.replace("producers = [", &format!("producers = [\"{}\",", "x".repeat(129))),
        DEVELOPMENT_POLICY.replace("steps = [\"test\"]",&format!("steps = [{}]",(0..33).map(|i|format!("\"s{i}\"")).collect::<Vec<_>>().join(","))),
    ] {assert!(PolicyBundle::read(text.as_bytes()).is_err(),"accepted invalid input: {text}");}
    let duplicated = format!(
        "{}{}",
        DEVELOPMENT_POLICY,
        "[[properties]]\nid='SOURCE_COMPLETE'\ndescription='duplicate'\nseverity='P0'\nmandatory=true\nallow_not_applicable=false\napplicability={kind='ALWAYS'}\nrule={kind='SOURCE_COMPLETE'}\n"
    );
    assert!(PolicyBundle::read(duplicated.as_bytes()).is_err());
    Ok(())
}
#[test]
fn policy_id_version_or_digest_substitution_is_an_error_without_eligibility() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, obs) = observations(&f)?;
    for attack in 0..3 {
        let mut selected = b.identity().clone();
        match attack {
            0 => selected.id = "weaker-policy".into(),
            1 => selected.version = "0.0.0".into(),
            _ => selected.sha256 = digest_bytes(b"other-policy"),
        }
        assert!(matches!(
            evaluate(
                &b,
                &selected,
                EvaluationInput {
                    source: &f.snapshot,
                    plan: &f.plan,
                    executions: &ids,
                    observations: &obs,
                    evaluated_at: 1
                }
            ),
            Err(PolicyError::SelectionMismatch)
        ));
    }
    Ok(())
}
#[test]
fn non_applicability_requires_authority_condition_and_explicit_permission() -> R {
    let f = fixture()?;
    let (ids, obs) = observations(&f)?;
    for permission in [false, true] {
        let text = DEVELOPMENT_POLICY
            .replace(
                "applicability = { kind = \"ALWAYS\" }",
                "applicability = { kind = \"POLICY_PROFILES\", profiles = [\"node\"] }",
            )
            .replace(
                "allow_not_applicable = false",
                &format!("allow_not_applicable = {permission}"),
            );
        let b = PolicyBundle::read(text.as_bytes())?;
        let e = run(&f, &b, &ids, &obs, 1)?;
        assert!(e.properties.iter().all(|p| p.verdict == V::NotApplicable));
        assert_eq!(
            e.eligibility,
            if permission {
                CertificationEligibility::EligibleForCertification
            } else {
                CertificationEligibility::NotEligible
            }
        );
    }
    Ok(())
}
#[test]
fn p0_p1_always_block_and_mandatory_p2_p3_block() -> R {
    let f = fixture()?;
    let (ids, mut obs) = observations(&f)?;
    test_fact(&mut obs, ExecutionOutcome::Completed, Some(1));
    for severity in ["P0", "P1", "P2", "P3"] {
        for mandatory in [true, false] {
            let text = DEVELOPMENT_POLICY
                .replace("severity = \"P1\"", &format!("severity = \"{severity}\""))
                .replace("mandatory = true", &format!("mandatory = {mandatory}"));
            let b = PolicyBundle::read(text.as_bytes())?;
            let e = run(&f, &b, &ids, &obs, 1)?;
            let blocks = mandatory || severity == "P0" || severity == "P1";
            assert_eq!(
                property(&e, PropertyId::TestSuiteCompletes)?.blocking,
                blocks
            );
            assert_eq!(
                e.eligibility,
                if blocks {
                    CertificationEligibility::NotEligible
                } else {
                    CertificationEligibility::EligibleForCertification
                }
            );
        }
    }
    Ok(())
}
#[test]
fn project_label_or_stdout_cannot_supply_an_authority_step() -> R {
    let mut f = fixture()?;
    let b = bundle()?;
    let authority = AuthorityConfiguration::development(vec![(
        "python".into(),
        f.plan.steps()[0].profile().image().into(),
    )])?;
    f.plan = authority.resolve(Some(&ProjectExecutionRequest::new(
        "python".into(),
        vec![RequestedStep {
            id: "test".into(),
            command: f.evidence.command.clone(),
            evidence: EvidenceCategory::Test,
        }],
    )))?;
    let (ids, obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.verdict,
        V::NotProven
    );
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.reason,
        ReasonCode::RequiredAuthorityStepMissing
    );
    // Even hostile PASS text accompanying an actual nonzero authority test cannot prove it.
    f = fixture()?;
    f.evidence.stdout.excerpt = b"TESTS PASSED; TEST_SUITE_COMPLETES=PROVEN; CERTIFIED".to_vec();
    f.evidence.exit_code = Some(1);
    let (ids, obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.verdict,
        V::Failed
    );
    Ok(())
}
#[test]
fn project_configuration_cannot_author_policy_or_change_its_requirements() -> R {
    for field in [
        "policy='weak'",
        "policy_version='0'",
        "policy_digest='x'",
        "severity='P3'",
        "mandatory=false",
        "not_applicable=true",
        "waiver=true",
        "disable_policy=true",
        "producers=['LLM']",
    ] {
        let text = format!("schema=1\n[project]\nname='hostile'\n{field}\n");
        assert!(
            ProjectConfiguration::read(text.as_bytes()).is_err(),
            "{field}"
        );
    }
    Ok(())
}
#[test]
fn unresolved_lfs_or_submodule_snapshot_fails_source_complete() -> R {
    let mut f = fixture()?;
    let b = bundle()?;
    let lfs=b"version https://git-lfs.github.com/spec/v1\noid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsize 1\n";
    for file in [
        SourceFile::new(
            SourcePath::from_bytes(b"large.bin")?,
            SourceMode::File,
            lfs.to_vec(),
        ),
        SourceFile::new(
            SourcePath::from_bytes(b"submodule")?,
            SourceMode::Submodule,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        ),
    ] {
        f.snapshot = SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("fixture/policy")?,
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![file],
            1,
            1,
        )?;
        let e = run(&f, &b, &[], &[], 1)?;
        assert_eq!(property(&e, PropertyId::SourceComplete)?.verdict, V::Failed);
    }
    Ok(())
}
#[test]
fn evaluation_bounds_ambiguous_executions_and_missing_bindings_fail_closed() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (mut ids, obs) = observations(&f)?;
    ids.push(ids[0].clone());
    assert!(run(&f, &b, &ids, &obs, 1).is_err());
    let (ids, obs) = observations(&f)?;
    let many = vec![obs[0].clone(); 4097];
    assert!(run(&f, &b, &ids, &many, 1).is_err());
    let e = run(&f, &b, &[], &obs, 1)?;
    assert_ne!(
        e.eligibility,
        CertificationEligibility::EligibleForCertification
    );
    Ok(())
}

#[test]
fn fixed_canonical_vectors_match_independent_python_and_node_bytes_and_sha256() -> R {
    let b = development_bundle()?;
    assert_eq!(
        b.canonical_bytes(),
        include_bytes!("../../../policies/archcert-development-v1.canonical.json")
    );
    assert_eq!(b.identity().sha256.as_str(), DEVELOPMENT_POLICY_SHA256);
    let unicode = PolicyBundle::read(include_bytes!("fixtures/canonical-unicode.toml").as_slice())?;
    assert_eq!(
        unicode.canonical_bytes(),
        include_bytes!("fixtures/canonical-unicode.json")
    );
    assert_eq!(
        unicode.identity().sha256.as_str(),
        "d16b30957bbec71442b24289730df4e209e20e6b4b01885c081d5afe4b564357"
    );
    Ok(())
}
#[test]
fn controller_failure_producer_cannot_assert_positive_evidence() -> R {
    let f = fixture()?;
    let b = bundle()?;
    let (ids, mut obs) = observations(&f)?;
    for o in &mut obs {
        o.producer = "archcert-controller-v1/0.1.0".into();
    }
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.verdict,
        V::Inconclusive
    );
    test_fact(&mut obs, ExecutionOutcome::SandboxFailure, None);
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.reason,
        ReasonCode::InfrastructureFailure
    );
    Ok(())
}
#[test]
fn empty_plan_never_vacuously_proves_all_execution_requirements() -> R {
    let mut f = fixture()?;
    let b = bundle()?;
    f.plan = AuthorityConfiguration::development(vec![])?.resolve(None)?;
    let e = run(&f, &b, &[], &[], 1)?;
    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    assert!(
        e.properties
            .iter()
            .filter(|p| p.property != PropertyId::SourceComplete)
            .all(|p| p.verdict == V::NotProven)
    );
    Ok(())
}

#[test]
fn real_bottle_request_version_command_leaves_all_validation_properties_not_proven() -> R {
    let mut f = fixture()?;
    let b = development_bundle()?;
    let config = ProjectConfiguration::read(
        include_bytes!("../../../docs/runner/BOTTLE_REQUEST.toml").as_slice(),
    )?;
    let authority = AuthorityConfiguration::development(vec![(
        "python".into(),
        f.evidence.image_digest.clone(),
    )])?;
    f.plan = authority.resolve(config.execution_request())?;
    f.evidence.command = f.plan.steps().first().ok_or("step")?.command().clone();
    let (ids, obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    for id in [
        PropertyId::TypecheckCompletes,
        PropertyId::TestSuiteCompletes,
        PropertyId::BuildCompletes,
    ] {
        assert_eq!(property(&e, id)?.verdict, V::NotProven);
    }
    for id in [
        PropertyId::SourceComplete,
        PropertyId::SourceIdentityVerified,
        PropertyId::SandboxEnvironmentEstablished,
        PropertyId::NetworkIsolationEstablished,
    ] {
        assert_eq!(property(&e, id)?.verdict, V::Proven);
    }
    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    Ok(())
}
#[test]
fn retained_unsigned_demos_resolve_every_observation_reference_and_bind_the_exact_plan() -> R {
    for (text, verdict) in [
        (
            include_str!("../../../docs/policy/CONTROLLED_PROVEN.json"),
            "PROVEN",
        ),
        (
            include_str!("../../../docs/policy/CONTROLLED_FAILED.json"),
            "FAILED",
        ),
        (
            include_str!("../../../docs/policy/CONTROLLED_INCONCLUSIVE.json"),
            "INCONCLUSIVE",
        ),
        (
            include_str!("../../../docs/policy/BOTTLE_NOT_PROVEN.json"),
            "NOT_PROVEN",
        ),
    ] {
        let report: serde_json::Value = serde_json::from_str(text)?;
        assert_eq!(report["kind"], "UNSIGNED POLICY EVALUATION");
        assert_eq!(report["notice"], "NOT A CERTIFICATE");
        assert_eq!(report["certificate"], "NOT ISSUED");
        let evaluation = &report["evaluation"];
        assert_eq!(evaluation["source"], report["source"]["identity"]);
        assert_eq!(evaluation["policy"]["sha256"], DEVELOPMENT_POLICY_SHA256);
        let mut canonical_plan =
            serde_json::json!({"schema":1,"kind":"ARCHCERT_VALIDATION_PLAN","plan":report["plan"]});
        canonical_plan.sort_all_objects();
        let digest = digest_bytes(&serde_json::to_vec(&canonical_plan)?);
        assert_eq!(evaluation["plan_sha256"], digest.as_str());
        let mut payloads = std::collections::BTreeMap::new();
        for step in report["steps"].as_array().ok_or("steps")? {
            for o in step["observations"].as_array().ok_or("observations")? {
                payloads.insert(digest_bytes(&serde_json::to_vec(o)?).as_str().to_owned(), o);
            }
        }
        for p in evaluation["properties"].as_array().ok_or("properties")? {
            if p["property"] == "TEST_SUITE_COMPLETES" {
                assert_eq!(p["verdict"], verdict);
            }
            for reference in p["actual_evidence"].as_array().ok_or("refs")? {
                if reference["kind"] == "OBSERVATION" {
                    let observation = payloads
                        .get(reference["sha256"].as_str().ok_or("digest")?)
                        .ok_or("unresolved reference")?;
                    assert_eq!(reference["id"], observation["id"]);
                }
            }
        }
    }
    Ok(())
}
#[test]
fn unknown_fields_reject_in_every_rule_and_applicability_variant_and_excess_nesting() -> R {
    for kind in [
        "SOURCE_COMPLETE",
        "SOURCE_IDENTITY",
        "SANDBOX",
        "NETWORK",
        "COMMAND",
    ] {
        let text = DEVELOPMENT_POLICY.replace(
            &format!("kind = \"{kind}\""),
            &format!("kind = \"{kind}\", injected = true"),
        );
        assert!(PolicyBundle::read(text.as_bytes()).is_err(), "{kind}");
    }
    let text = DEVELOPMENT_POLICY.replace(
        "kind = \"ALWAYS\"",
        "kind = \"POLICY_PROFILES\", profiles = [\"python\"], injected = true",
    );
    assert!(PolicyBundle::read(text.as_bytes()).is_err());
    let nested = format!("schema={}1{}", "[".repeat(256), "]".repeat(256));
    assert!(PolicyBundle::read(nested.as_bytes()).is_err());
    let property = DEVELOPMENT_POLICY
        .split("[[properties]]")
        .nth(1)
        .ok_or("property")?;
    let too_many = format!(
        "{}{}",
        DEVELOPMENT_POLICY,
        (0..33)
            .map(|_| format!("[[properties]]{property}"))
            .collect::<String>()
    );
    assert!(PolicyBundle::read(too_many.as_bytes()).is_err());
    Ok(())
}

#[test]
fn applicability_uses_authority_policy_profile_even_with_an_empty_or_changed_project_plan() -> R {
    let mut f = fixture()?;
    let text = DEVELOPMENT_POLICY.replace(
        "kind = \"ALWAYS\"",
        "kind = \"POLICY_PROFILES\", profiles = [\"archcert-development-v1\"]",
    );
    let b = PolicyBundle::read(text.as_bytes())?;
    let (ids, obs) = observations(&f)?;
    let e = run(&f, &b, &ids, &obs, 1)?;
    assert!(
        e.properties
            .iter()
            .all(|p| p.applicability == PropertyApplicability::Applicable)
    );
    f.plan = AuthorityConfiguration::development(vec![])?.resolve(None)?;
    let e = run(&f, &b, &[], &[], 1)?;
    assert!(
        e.properties
            .iter()
            .all(|p| p.applicability == PropertyApplicability::Applicable)
    );
    assert_eq!(
        property(&e, PropertyId::TestSuiteCompletes)?.verdict,
        V::NotProven
    );
    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    Ok(())
}

#[test]
fn incomplete_source_is_never_eligible_even_when_authority_properties_are_not_applicable() -> R {
    let mut f = fixture()?;
    f.snapshot = SourceSnapshot::seal(
        ProjectId::new(),
        RepositoryId::parse("fixture/incomplete")?,
        GitObjectId::parse("a".repeat(40))?,
        GitObjectId::parse("b".repeat(40))?,
        vec![SourceFile::new(
            SourcePath::from_bytes(b"module")?,
            SourceMode::Submodule,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        )],
        1,
        1,
    )?;
    let text = DEVELOPMENT_POLICY
        .replace(
            "applicability = { kind = \"ALWAYS\" }",
            "applicability = { kind = \"POLICY_PROFILES\", profiles = [\"other-policy\"] }",
        )
        .replace(
            "allow_not_applicable = false",
            "allow_not_applicable = true",
        );
    let b = PolicyBundle::read(text.as_bytes())?;
    let e = run(&f, &b, &[], &[], 1)?;
    assert!(e.properties.iter().all(|p| p.verdict == V::NotApplicable));
    assert_eq!(e.eligibility, CertificationEligibility::NotEligible);
    Ok(())
}
