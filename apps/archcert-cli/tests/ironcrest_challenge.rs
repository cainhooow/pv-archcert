//! Opt-in real OCI challenge composition. Synthetic source identities are controlled
//! test fixtures, not authenticated admission or independent certification.

use archcert_application::{
    challenges::*,
    execution::SandboxRunner,
    knowledge::*,
    materialization::{CleanupStatus, MaterializationRequest, SourceMaterializer},
    semantic::*,
    validation::*,
};
use archcert_domain::{
    GitObjectId, ProjectId,
    execution::*,
    jobs::{JobId, PolicyPin},
    materialization::*,
    source::*,
};
use archcert_materialization::{AuthorityWorkspaceRoot, UnixSourceMaterializer};
use archcert_runner::{DockerRootlessRunner, DockerRuntime};
use archcert_semantic::ReplayReviewer;
use std::{fs, os::unix::fs::PermissionsExt};
type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GOOD:&[u8]=br#"import sqlite3
def settle(path, key, amount):
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO ledger (key, amount) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM ledger WHERE key = ?)", (key, amount, key))
"#;

const BAD: &[u8] = br#"import sqlite3
def settle(path, key, amount):
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO ledger (key, amount) VALUES (?, ?)", (key, amount))
"#;

#[tokio::test]
#[ignore = "requires explicit provisioned rootless OCI and pinned Python image"]
async fn approved_authority_replay_challenge_passes_good_fixture_and_rejects_duplicate_ledger() -> R
{
    let image = std::env::var("ARCHCERT_TEST_IMAGE")?;
    let runner = DockerRootlessRunner::new(DockerRuntime::new(
        std::env::var("ARCHCERT_TEST_DOCKER")?.into(),
        std::env::var("ARCHCERT_TEST_ENDPOINT")?,
    )?);
    runner.verify_environment()?;

    for (bytes, exit) in [(GOOD, 0), (BAD, 1)] {
        let s = SourceSnapshot::seal(
            ProjectId::new(),
            RepositoryId::parse("ironcrest/controlled-ledger")?,
            GitObjectId::parse("a".repeat(40))?,
            GitObjectId::parse("b".repeat(40))?,
            vec![SourceFile::new(
                SourcePath::from_bytes(b"settlement.py")?,
                SourceMode::File,
                bytes.to_vec(),
            )],
            1,
            1700000000,
        )?;
        let engine = KnowledgeEngine::new(vec![], KnowledgeLimits::default())?;

        let k = engine.extract(&s, &[], None)?;

        let impact = analyze_impact(&k, None)?;
        let policy_bytes = br#"{"kind":"CONTROLLED_CHALLENGE_TEST_ONLY"}"#;
        let policy = PolicyPin {
            id: "controlled-challenge-test-only".into(),
            version: "1".into(),
            sha256: digest_bytes(policy_bytes),
        };
        let request = SemanticReviewRequest::prepare(
            ReviewContext {
                job: JobId::new(),
                source: &s,
                knowledge: &k,
                impact: &impact,
                bundles: &[],
                policy: &policy,
                policy_bytes,
                authority_profile_sha256: digest_bytes(b"controlled-authority-test"),
                authority_profile_bytes: None,
                observations: &[],
                claims: &[],
            },
            ReviewerSelection::replay(),
            SemanticLimits::default(),
        )?;
        let response = SemanticReviewResponse {
            schema: 1,
            request_sha256: request.artifact().digest().clone(),
            complete: true,
            items: vec![],
            proposed_challenges: vec![ChallengeProposal {
                id: "idempotency-hypothesis".into(),
                challenge_template_id: IDEMPOTENCY_TEMPLATE.into(),
                parameters: ChallengeParameters { repetitions: 5 },
                reason: "Exercise final ledger cardinality after repeated identical keys".into(),
                related_authority_id: policy.id.clone(),
            }],
        };
        let reviewer = ReplayReviewer::new(
            request.artifact().digest().clone(),
            serde_json::to_vec(&response)?,
        )?;

        let review =
            SemanticReviewArtifact::accept(&request, reviewer.review(&request).await, 1700000001)?;

        assert_eq!(
            semantic_gate(&request, Some(&review)),
            SemanticGateDecision::Continue
        );

        let authority =
            AuthorityConfiguration::development(vec![("python".into(), image.clone())])?;
        let challenges = AuthorityChallengeRegistry::controlled()?.plan(
            &request,
            &review,
            authority.profile("python")?,
        )?;
        let authority = authority.with_required_steps(
            challenges
                .challenges()
                .iter()
                .map(|c| c.required_step())
                .collect(),
        )?;

        let plan = authority.resolve(None)?;
        let step = plan.steps().first().ok_or("challenge missing")?;
        let root = tempfile::tempdir()?;
        let path = root.path().canonicalize()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let materializer = UnixSourceMaterializer::new(AuthorityWorkspaceRoot::open(&path)?);

        let prepared = materializer.prepare(
            &s,
            &MaterializationRequest {
                snapshot: SnapshotReference {
                    project: s.project(),
                    repository: s.repository().clone(),
                    identity: s.identity().clone(),
                },
                limits: MaterializationLimits::default(),
            },
        )?;

        let execution = runner.execute(step.execution_request(prepared.runner_input)?);
        prepared.cleanup.destroy()?;
        let execution = execution?;

        assert_eq!(execution.cleanup, CleanupStatus::Destroyed);
        assert_eq!(execution.evidence.outcome, ExecutionOutcome::Completed);
        assert_eq!(execution.evidence.exit_code, Some(exit));
        assert_eq!(execution.evidence.source, *s.identity());

        let observations = ValidationObservation::from_execution(&plan, step, &execution.evidence)?;

        assert!(observations.iter().any(|o| matches!(
            o.fact,
            ObservationFact::ExecutionFinished { exit_code: Some(code), .. } if code == exit
        )));
        // The same replayed semantic CLEAR precedes both outcomes. Only actual
        // isolated command/final-state evidence distinguishes the controlled cases.
    }

    Ok(())
}
