//! Project requests never deserialize into authority or runtime configuration.
use archcert_application::{
    configuration::{ConfigurationError, ProjectConfiguration},
    validation::{
        AuthorityConfiguration, AuthorityExecutionProfile, AuthorityRequiredStep, EvidenceCategory,
        PlanError, ProjectExecutionRequest, RequestedStep, StepOrigin, check_development_request,
    },
};
use archcert_domain::execution::{ExecutionCommand, ExecutionLimits, ExecutionProfile};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const CONFIG: &str = "schema=1\n[project]\nname='fixture'\n[execution]\nprofile='node'\n[[execution.commands]]\nname='tests'\nprogram='node'\nargs=['tests.js']\n";
fn command(program: &str) -> Result<ExecutionCommand, archcert_domain::execution::ExecutionError> {
    ExecutionCommand::new(program.into(), vec![], "/source".into())
}
fn profile() -> Result<AuthorityExecutionProfile, PlanError> {
    AuthorityExecutionProfile::new(
        ExecutionProfile::new(
            "node".into(),
            format!("approved@sha256:{}", "a".repeat(64)),
            vec!["node".into()],
            ExecutionLimits::default(),
        )?,
        ExecutionLimits::default(),
    )
}
#[test]
fn production_example_parses_through_the_production_parser() -> TestResult {
    let config = ProjectConfiguration::read(
        include_bytes!("../../../config/archcert.toml.example").as_slice(),
    )?;
    check_development_request(config.execution_request().ok_or("execution missing")?)?;
    assert_eq!(config.name(), "example-project");
    Ok(())
}
#[test]
fn unknown_schema_is_an_explicit_rejection() {
    for version in [0, 2, u32::MAX] {
        assert!(
            matches!(ProjectConfiguration::parse(&CONFIG.replace("schema=1", &format!("schema={version}"))), Err(ConfigurationError::UnknownSchema(v)) if v == version)
        );
    }
}
#[test]
fn unknown_fields_reject_at_every_table_boundary() {
    for invalid in [
        format!("unknown=true\n{CONFIG}"),
        CONFIG.replace("name='fixture'", "name='fixture'\nunknown=true"),
        CONFIG.replace("profile='node'", "profile='node'\nunknown=true"),
        format!("{CONFIG}unknown=true\n"),
    ] {
        assert!(ProjectConfiguration::parse(&invalid).is_err());
    }
}
#[test]
fn project_cannot_enable_network_choose_image_endpoint_or_raise_limits() {
    for setting in [
        "network='host'",
        "network={enabled=true}",
        "image='evil:latest'",
        "runner_image='evil:latest'",
        "endpoint='unix:///var/run/docker.sock'",
        "runtime={endpoint='unix:///evil'}",
        "docker='/evil'",
        "workspace_root='/host'",
        "limits={memory_bytes=999999999}",
        "maximum_limits={pids=1024}",
        "environment={HOME='/host'}",
        "mounts=['/:/host']",
        "privileged=true",
        "mandatory_steps=[]",
    ] {
        for invalid in [
            format!("{setting}\n{CONFIG}"),
            CONFIG.replace("profile='node'", &format!("profile='node'\n{setting}")),
            format!("{CONFIG}{setting}\n"),
        ] {
            assert!(
                ProjectConfiguration::parse(&invalid).is_err(),
                "accepted {setting}"
            );
        }
    }
}
#[test]
fn duplicate_commands_and_invalid_commands_cwd_categories_reject() {
    for invalid in [
        format!("{CONFIG}[[execution.commands]]\nname='tests'\nprogram='node'\nargs=[]\n"),
        CONFIG.replace("program='node'", "program='sh -c test'"),
        CONFIG.replace("name='tests'", "name='../tests'"),
        format!("{CONFIG}working_directory='/source/../host'\n"),
        format!("{CONFIG}evidence='PASS'\n"),
        format!("{CONFIG}origin='AUTHORITY_REQUIRED'\n"),
    ] {
        assert!(ProjectConfiguration::parse(&invalid).is_err());
    }
}
#[test]
fn config_read_is_bounded_before_decoding() {
    let bytes = std::io::repeat(b' ').take(300_000);
    assert!(matches!(
        ProjectConfiguration::read(bytes),
        Err(ConfigurationError::TooLarge)
    ));
}
#[test]
fn unknown_profile_and_unapproved_program_reject_at_authority_resolution() -> TestResult {
    let authority = AuthorityConfiguration::new(vec![profile()?], vec![])?;
    for invalid in [
        CONFIG.replace("profile='node'", "profile='unregistered'"),
        CONFIG.replace("program='node'", "program='sh'"),
    ] {
        let config = ProjectConfiguration::parse(&invalid)?;
        let request = config.execution_request().ok_or("request missing")?;
        assert!(authority.resolve(Some(request)).is_err());
        assert!(check_development_request(request).is_err());
    }
    Ok(())
}
#[test]
fn mandatory_steps_survive_omission_and_project_requests_cannot_replace_them() -> TestResult {
    let authority = AuthorityConfiguration::new(
        vec![profile()?],
        vec![AuthorityRequiredStep {
            id: "mandatory-test".into(),
            profile: "node".into(),
            command: command("node")?,
            evidence: EvidenceCategory::Test,
        }],
    )?;
    let mandatory_only = authority.resolve(None)?;
    assert_eq!(mandatory_only.steps().len(), 1);
    assert_eq!(
        mandatory_only.steps()[0].origin(),
        StepOrigin::AuthorityRequired
    );
    let config = ProjectConfiguration::parse(CONFIG)?;
    let composed = authority.resolve(config.execution_request())?;
    assert_eq!(composed.steps().len(), 2);
    assert_eq!(composed.steps()[0].id(), "mandatory-test");
    assert_eq!(composed.steps()[0].origin(), StepOrigin::AuthorityRequired);
    assert_eq!(composed.steps()[1].origin(), StepOrigin::ProjectRequested);
    let collision =
        ProjectConfiguration::parse(&CONFIG.replace("name='tests'", "name='mandatory-test'"))?;
    assert!(authority.resolve(collision.execution_request()).is_err());
    // Programmatic callers cannot bypass IDs/counts either.
    let duplicate = ProjectExecutionRequest::new(
        "node".into(),
        vec![RequestedStep {
            id: "mandatory-test".into(),
            command: command("node")?,
            evidence: EvidenceCategory::Build,
        }],
    );
    assert!(authority.resolve(Some(&duplicate)).is_err());
    assert_eq!(
        authority.resolve(None)?.steps()[0].command(),
        &command("node")?
    );
    Ok(())
}
#[test]
fn authority_registry_controls_image_executables_and_every_limit_ceiling() -> TestResult {
    let profile = profile()?;
    for n in 0..9 {
        let mut limits = profile.default_limits();
        match n {
            0 => limits.timeout_ms += 1,
            1 => limits.cpu_millis += 1,
            2 => limits.memory_bytes += 1,
            3 => limits.pids += 1,
            4 => limits.stdout_bytes += 1,
            5 => limits.stderr_bytes += 1,
            6 => limits.excerpt_bytes += 1,
            7 => limits.scratch_bytes += 1,
            _ => limits.output_bytes += 1,
        }
        assert!(matches!(
            profile.with_limits(limits),
            Err(PlanError::MaximumExceeded)
        ));
    }
    let authority = AuthorityConfiguration::new(vec![profile], vec![])?;
    let config = ProjectConfiguration::parse(CONFIG)?;
    let plan = authority.resolve(config.execution_request())?;
    let resolved = plan.steps().first().ok_or("empty plan")?;
    assert_eq!(
        resolved.profile().image(),
        format!("approved@sha256:{}", "a".repeat(64))
    );
    assert_eq!(resolved.profile().limits(), ExecutionLimits::default());
    assert!(
        AuthorityConfiguration::development(vec![(
            "node22".into(),
            format!("node@sha256:{}", "a".repeat(64))
        )])
        .is_err()
    );
    Ok(())
}
#[test]
fn duplicate_authority_profiles_and_invalid_mandatory_steps_reject() -> TestResult {
    assert!(AuthorityConfiguration::new(vec![profile()?, profile()?], vec![]).is_err());
    assert!(
        AuthorityConfiguration::new(
            vec![profile()?],
            vec![AuthorityRequiredStep {
                id: "mandatory".into(),
                profile: "unknown".into(),
                command: command("node")?,
                evidence: EvidenceCategory::Execution,
            }]
        )
        .is_err()
    );
    Ok(())
}
use std::io::Read;
