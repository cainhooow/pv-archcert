//! Worker protocol rejection and compatibility across the real process contract.

use archcert_application::worker::*;
use archcert_domain::{
    GitObjectId, ProjectId, SourceIdentity,
    ingress::*,
    jobs::*,
    source::{RepositoryId, digest_bytes},
};
use archcert_protocol::protobuf::{execution::v1 as p, worker::*};
use prost::Message;
#[test]
fn pinned_assignments_roundtrip_and_reject_mutable_or_missing_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let toml = include_str!("../../../docs/policy/CONTROLLED_AUTHORITY.toml").to_owned();
    let image = format!("python@sha256:{}", "a".repeat(64));
    let plan = resolve_authority_plan("python", &image, &toml)?;
    let inputs = JobInputs {
        project: ProjectId::new(),
        repository: RepositoryId::parse("fixture/repo")?,
        submission: SourceSubmissionId::new(),
        source: SourceIdentity {
            commit: GitObjectId::parse("a".repeat(40))?,
            tree: GitObjectId::parse("b".repeat(40))?,
            snapshot_sha256: digest_bytes(b"source"),
        },
        actor: GitActorId::parse(JobId::new().to_string())?,
        policy: PolicyPin {
            id: "development".into(),
            version: "1.0.0".into(),
            sha256: digest_bytes(b"policy"),
        },
        profile: "python".into(),
        image,
        plan_sha256: plan.digest()?,
        authority_toml: toml,
        maximum_attempts: 2,
    };
    let assignment = WorkerAssignment {
        job: JobId::new(),
        attempt: AttemptId::new(),
        inputs,
        source_artifact: b"snapshot codec is independently verified by the worker".to_vec(),
    };
    let bytes = encode_assignment(&assignment)?;

    let decoded = decode_assignment(&bytes)?;

    assert_eq!(decoded.inputs, assignment.inputs);
    assert_eq!(decoded.attempt, assignment.attempt);

    let original = p::WorkerAssignment::decode(bytes.as_slice())?;

    for variant in 0..5 {
        let mut w = original.clone();

        match variant {
            0 => w.contract_version = 0,
            1 => w.image = "python:latest".into(),
            2 => w.source = None,
            3 => w.plan_sha256 = None,
            _ => w.maximum_attempts = 999,
        };

        assert!(decode_assignment(&w.encode_to_vec()).is_err());
    }

    let mut additive = bytes;
    additive.extend([0xa0, 0x06, 1]);

    assert_eq!(decode_assignment(&additive)?.inputs, assignment.inputs);
    assert!(decode_assignment(&[]).is_err());
    assert!(decode_result(&[]).is_err());
    assert!(decode_result(&[255]).is_err());

    let result = WorkerResult {
        schema: 1,
        job: assignment.job,
        attempt: assignment.attempt,
        source: assignment.inputs.source.clone(),
        plan_sha256: assignment.inputs.plan_sha256.clone(),
        producer: "archcert-worker-v1/0.1.0".into(),
        steps: vec![],
    };

    assert!(
        result
            .validate(assignment.job, assignment.attempt, &assignment.inputs)
            .is_err()
    );

    let roundtrip = decode_result(&encode_result(&result)?)?;

    assert_eq!(roundtrip.job, result.job);

    let mut w = p::WorkerResult::decode(encode_result(&result)?.as_slice())?;
    w.contract_version = 2;

    assert!(decode_result(&w.encode_to_vec()).is_err());

    Ok(())
}

#[test]
fn operational_command_deserialization_cannot_bypass_constructor() {
    let malformed = serde_json::json!({
        "program": "python",
        "args": [],
        "working_directory": "/etc"
    });

    assert!(
        serde_json::from_value::<archcert_domain::execution::ExecutionCommand>(malformed).is_err()
    );
    assert!(
        serde_json::from_str::<archcert_domain::execution::ExecutionId>(
            "\"00000000-0000-0000-0000-000000000000\""
        )
        .is_err()
    );
}
