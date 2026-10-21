//! Wire compatibility and semantic round trips, never cryptographic canonicality.

use archcert_application::ingress as app;
use archcert_domain::{
    GitObjectId, Sha256Digest, SourceIdentity,
    ingress::{DeviceKeyId, GitActorId, SourceSubmissionId},
    source::{RepositoryId, SourceFile, SourceMode, SourcePath, SourceSnapshot, SourceStatus},
};
use archcert_protocol::protobuf::{
    COMMON_PACKAGE, CONTRACT_VERSION, FILE_DESCRIPTOR_SET, SOURCE_PACKAGE, common::v1 as c,
    decode_submission, encode_submission, source::v1 as p,
};
use prost::Message;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const GOLDEN: &[u8] = include_bytes!("fixtures/source-v1/submission.pb");

const COMMIT: &str = "67085b42fe02ff0832641629a31634338214be00";

const TREE: &str = "c6365ec31116a8e66e83f91b058c472fe0064df7";

const SOURCE: &str = "5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af";

fn expected() -> Result<app::SourceSubmissionState> {
    Ok(app::SourceSubmissionState {
        submission: SourceSubmissionId::parse("00000000-0000-4000-8000-000000000006")?,
        project: "00000000-0000-4000-8000-000000000004".parse()?,
        repository: RepositoryId::parse("archcert/northgate-fixture")?,
        actor: GitActorId::parse("00000000-0000-4000-8000-000000000005".into())?,
        device: DeviceKeyId::parse("22".repeat(32))?,
        transport: app::SourceTransport::SshPublicKey,
        submitted_refs: vec!["refs/heads/fixture".into()],
        requested_commit: Some(GitObjectId::parse(COMMIT)?),
        object_algorithm: app::GitObjectAlgorithm::Sha1,
        source: Some(app::SourceState {
            identity: SourceIdentity {
                commit: GitObjectId::parse(COMMIT)?,
                tree: GitObjectId::parse(TREE)?,
                snapshot_sha256: Sha256Digest::parse(SOURCE)?,
            },
            schema_version: 1,
            completeness: SourceStatus::Complete,
            lfs_unresolved: 0,
            submodules_unresolved: 0,
            resolution: None,
        }),
        status: app::SubmissionStatus::Accepted,
        received_at: 1_760_000_000,
        accepted_at: Some(1_760_000_001),
    })
}

fn wire<T: Message + Default>(message: T) -> Result<T> {
    Ok(T::decode(message.encode_to_vec().as_slice())?)
}

#[test]
fn fixed_protoc_artifact_decodes_to_recorded_semantics() -> Result {
    assert_eq!(CONTRACT_VERSION, 1);
    assert_eq!(SOURCE_PACKAGE, "archcert.source.v1");
    assert_eq!(COMMON_PACKAGE, "archcert.common.v1");
    assert_eq!(decode_submission(GOLDEN)?, expected()?);

    // Generated descriptor inspection verifies both real versioned packages.
    let descriptors = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET)?;

    for package in [SOURCE_PACKAGE, COMMON_PACKAGE] {
        assert!(
            descriptors
                .file
                .iter()
                .any(|f| f.package.as_deref() == Some(package))
        );
    }

    Ok(())
}

#[test]
fn common_identities_round_trip_through_generated_binary_dtos() -> Result {
    let state = expected()?;

    assert_eq!(
        state.project,
        wire(c::ProjectId::from(&state.project))?.try_into()?
    );
    assert_eq!(
        state.repository,
        wire(c::RepositoryId::from(&state.repository))?.try_into()?
    );
    assert_eq!(
        state.submission,
        wire(c::SourceSubmissionId::from(&state.submission))?.try_into()?
    );
    assert_eq!(
        state.actor,
        wire(c::GitActorId::from(&state.actor))?.try_into()?
    );
    assert_eq!(
        state.device,
        wire(c::DeviceKeyId::try_from(&state.device)?)?.try_into()?
    );

    let identity = state.source.ok_or("source missing")?.identity;

    assert_eq!(
        identity.snapshot_sha256,
        wire(c::Sha256Digest::try_from(&identity.snapshot_sha256)?)?.try_into()?
    );

    for width in [40, 64] {
        let oid = GitObjectId::parse("a".repeat(width))?;

        assert_eq!(oid, wire(c::GitObjectId::try_from(&oid)?)?.try_into()?);
    }

    assert_eq!(
        identity,
        wire(c::SourceIdentity::try_from(&identity)?)?.try_into()?
    );

    Ok(())
}

#[test]
fn actual_snapshot_identity_survives_all_source_state_round_trips() -> Result {
    for width in [40, 64] {
        let mut state = expected()?;
        let snapshot = SourceSnapshot::seal(
            state.project,
            state.repository.clone(),
            GitObjectId::parse("a".repeat(width))?,
            GitObjectId::parse("b".repeat(width))?,
            vec![SourceFile::new(
                SourcePath::from_bytes(b"file")?,
                SourceMode::File,
                b"content".to_vec(),
            )],
            3,
            state.received_at,
        )?;
        state.requested_commit = Some(snapshot.identity().commit.clone());
        state.object_algorithm = if width == 40 {
            app::GitObjectAlgorithm::Sha1
        } else {
            app::GitObjectAlgorithm::Sha256
        };
        let source = state.source.as_mut().ok_or("source missing")?;
        source.identity = snapshot.identity().clone();
        let decoded = decode_submission(&encode_submission(&state)?)?;

        assert_eq!(decoded, state);
        assert_eq!(
            decoded.source.ok_or("source missing")?.identity,
            *snapshot.identity()
        );

        state.status = app::SubmissionStatus::IncompleteExternalSource;
        let source = state.source.as_mut().ok_or("source missing")?;
        source.completeness = SourceStatus::IncompleteExternalSource;
        source.lfs_unresolved = 1;
        source.submodules_unresolved = 2;

        assert_eq!(decode_submission(&encode_submission(&state)?)?, state);

        let source = state.source.as_mut().ok_or("source missing")?;
        let original = source.identity.clone();
        source.schema_version = 2;
        source.completeness = SourceStatus::Complete;
        source.lfs_unresolved = 0;
        source.submodules_unresolved = 0;
        source.identity.snapshot_sha256 = Sha256Digest::parse("cc".repeat(32))?;
        source.resolution = Some(app::SourceResolutionSummary {
            parent_submission: SourceSubmissionId::parse("00000000-0000-4000-8000-000000000007")?,
            original,
            resolver_actor: state.actor.clone(),
            lfs_resolved: 1,
            submodules_resolved: 2,
        });
        state.status = app::SubmissionStatus::Accepted;
        state.transport = app::SourceTransport::AuthorityPrivateSourceResolution;

        assert_eq!(decode_submission(&encode_submission(&state)?)?, state);
    }

    Ok(())
}

#[test]
fn early_and_rejected_states_round_trip_without_implying_accepted_source() -> Result {
    for status in [
        app::SubmissionStatus::Received,
        app::SubmissionStatus::Quarantined,
        app::SubmissionStatus::Validating,
        app::SubmissionStatus::Rejected,
    ] {
        let mut state = expected()?;
        state.status = status;
        state.source = None;
        state.accepted_at = None;
        state.submitted_refs.clear();
        state.requested_commit = None;

        assert_eq!(decode_submission(&encode_submission(&state)?)?, state);
    }

    Ok(())
}

type Mutation = fn(&mut p::SourceSubmission) -> Result;

fn reject_mutations(cases: &[(&str, Mutation)]) -> Result {
    for (name, mutate) in cases {
        let mut dto = p::SourceSubmission::decode(GOLDEN)?;
        mutate(&mut dto)?;

        assert!(
            app::SourceSubmissionState::try_from(dto.clone()).is_err(),
            "DTO: {name}"
        );
        assert!(
            decode_submission(&dto.encode_to_vec()).is_err(),
            "wire: {name}"
        );
    }

    Ok(())
}

fn source(dto: &mut p::SourceSubmission) -> Result<&mut p::SourceState> {
    dto.source.as_mut().ok_or_else(|| "source missing".into())
}

fn identity(dto: &mut p::SourceSubmission) -> Result<&mut c::SourceIdentity> {
    source(dto)?
        .identity
        .as_mut()
        .ok_or_else(|| "identity missing".into())
}

fn git(dto: &mut p::SourceSubmission) -> Result<&mut p::GitSubmission> {
    dto.git
        .as_mut()
        .ok_or_else(|| "Git provenance missing".into())
}

#[test]
fn malformed_ids_and_missing_semantic_values_fail_closed() -> Result {
    reject_mutations(&[
        ("malformed submission", |d| {
            d.submission.as_mut().ok_or("submission")?.value = "../submission".into();

            Ok(())
        }),
        ("noncanonical submission", |d| {
            d.submission.as_mut().ok_or("submission")?.value =
                "00000000000040008000000000000006".into();

            Ok(())
        }),
        ("invalid repository", |d| {
            d.repository.as_mut().ok_or("repository")?.value =
                "https://user:secret@example.invalid/target".into();

            Ok(())
        }),
        ("empty repository", |d| {
            d.repository.as_mut().ok_or("repository")?.value.clear();

            Ok(())
        }),
        ("malformed project", |d| {
            d.project.as_mut().ok_or("project")?.value = "project".into();

            Ok(())
        }),
        ("malformed actor", |d| {
            d.actor
                .as_mut()
                .ok_or("actor")?
                .actor
                .as_mut()
                .ok_or("actor ID")?
                .value = "actor".into();

            Ok(())
        }),
        ("missing actor identity", |d| {
            d.actor = None;

            Ok(())
        }),
        ("missing actor ID", |d| {
            d.actor.as_mut().ok_or("actor")?.actor = None;

            Ok(())
        }),
        ("missing device", |d| {
            d.actor.as_mut().ok_or("actor")?.device = None;

            Ok(())
        }),
        ("missing submission", |d| {
            d.submission = None;

            Ok(())
        }),
        ("missing project", |d| {
            d.project = None;

            Ok(())
        }),
        ("missing repository", |d| {
            d.repository = None;

            Ok(())
        }),
        ("missing Git provenance", |d| {
            d.git = None;

            Ok(())
        }),
        ("missing source", |d| {
            d.source = None;

            Ok(())
        }),
        ("missing source identity", |d| {
            source(d)?.identity = None;

            Ok(())
        }),
        ("missing commit", |d| {
            identity(d)?.commit = None;

            Ok(())
        }),
        ("missing tree", |d| {
            identity(d)?.tree = None;

            Ok(())
        }),
        ("missing source SHA-256", |d| {
            identity(d)?.snapshot = None;

            Ok(())
        }),
        ("missing requested commit", |d| {
            git(d)?.requested_commit = None;

            Ok(())
        }),
        ("missing received time", |d| {
            d.received_at = None;

            Ok(())
        }),
        ("missing accepted time", |d| {
            d.accepted_at = None;

            Ok(())
        }),
    ])
}

#[test]
fn digest_lengths_and_required_enums_fail_closed() -> Result {
    for length in [0, 1, 19, 20, 21, 31, 33, 64] {
        let mut dto = p::SourceSubmission::decode(GOLDEN)?;
        identity(&mut dto)?
            .snapshot
            .as_mut()
            .ok_or("snapshot")?
            .sha256 = vec![0; length];

        assert!(
            decode_submission(&dto.encode_to_vec()).is_err(),
            "source digest length {length}"
        );

        let mut dto = p::SourceSubmission::decode(GOLDEN)?;
        dto.actor
            .as_mut()
            .ok_or("actor")?
            .device
            .as_mut()
            .ok_or("device")?
            .sha256 = vec![0; length];

        assert!(
            decode_submission(&dto.encode_to_vec()).is_err(),
            "device digest length {length}"
        );
    }

    for algorithm in [c::GitObjectAlgorithm::Sha1, c::GitObjectAlgorithm::Sha256] {
        for length in [0, 1, 19, 20, 21, 31, 32, 33, 64] {
            let valid = length
                == if algorithm == c::GitObjectAlgorithm::Sha1 {
                    20
                } else {
                    32
                };

            assert_eq!(
                GitObjectId::try_from(c::GitObjectId {
                    algorithm: algorithm as i32,
                    digest: vec![0xaa; length]
                })
                .is_ok(),
                valid
            );
        }
    }

    for unknown in [0, -1, 999] {
        for field in 0..5 {
            let mut dto = p::SourceSubmission::decode(GOLDEN)?;

            match field {
                0 => dto.status = unknown,
                1 => source(&mut dto)?.completeness = unknown,
                2 => git(&mut dto)?.transport = unknown,
                3 => git(&mut dto)?.object_algorithm = unknown,
                _ => {
                    identity(&mut dto)?
                        .commit
                        .as_mut()
                        .ok_or("commit")?
                        .algorithm = unknown
                }
            }

            assert!(
                decode_submission(&dto.encode_to_vec()).is_err(),
                "enum {field}: {unknown}"
            );
        }
    }

    Ok(())
}

#[test]
fn unsupported_schemas_timestamps_and_contradictory_states_fail_closed() -> Result {
    reject_mutations(&[
        ("default contract", |d| {
            d.contract_version = 0;

            Ok(())
        }),
        ("future contract", |d| {
            d.contract_version = 2;

            Ok(())
        }),
        ("default source schema", |d| {
            source(d)?.schema_version = 0;

            Ok(())
        }),
        ("future source schema", |d| {
            source(d)?.schema_version = 3;

            Ok(())
        }),
        ("resolved schema without binding summary", |d| {
            source(d)?.schema_version = 2;

            Ok(())
        }),
        ("mixed object algorithms", |d| {
            identity(d)?.tree = Some(c::GitObjectId {
                algorithm: c::GitObjectAlgorithm::Sha256 as i32,
                digest: vec![0xbb; 32],
            });

            Ok(())
        }),
        ("mismatched requested commit", |d| {
            git(d)?.requested_commit.as_mut().ok_or("commit")?.digest = vec![0xcc; 20];

            Ok(())
        }),
        ("mismatched object format", |d| {
            git(d)?.object_algorithm = c::GitObjectAlgorithm::Sha256 as i32;

            Ok(())
        }),
        ("accepted incomplete source", |d| {
            source(d)?.completeness = p::SourceCompleteness::IncompleteExternalSource as i32;
            source(d)?.lfs_unresolved = 1;

            Ok(())
        }),
        ("incomplete without requirements", |d| {
            d.status = p::SubmissionStatus::IncompleteExternalSource as i32;
            source(d)?.completeness = p::SourceCompleteness::IncompleteExternalSource as i32;

            Ok(())
        }),
        ("complete with unresolved source", |d| {
            source(d)?.lfs_unresolved = 1;

            Ok(())
        }),
        ("rejected with source", |d| {
            d.status = p::SubmissionStatus::Rejected as i32;

            Ok(())
        }),
        ("missing ref provenance", |d| {
            git(d)?.submitted_refs.clear();

            Ok(())
        }),
        ("invalid ref", |d| {
            git(d)?.submitted_refs = vec!["refs/heads/../private".into()];

            Ok(())
        }),
        ("negative timestamp", |d| {
            d.received_at.as_mut().ok_or("time")?.seconds = -1;

            Ok(())
        }),
        ("timestamp beyond year 9999", |d| {
            d.received_at.as_mut().ok_or("time")?.seconds = 253_402_300_800;

            Ok(())
        }),
        ("fractional timestamp", |d| {
            d.received_at.as_mut().ok_or("time")?.nanos = 1;

            Ok(())
        }),
        ("invalid timestamp nanos", |d| {
            d.received_at.as_mut().ok_or("time")?.nanos = -1;

            Ok(())
        }),
        ("acceptance before reception", |d| {
            d.accepted_at.as_mut().ok_or("time")?.seconds = 0;

            Ok(())
        }),
    ])
}

/// Hypothetical additive fields in a newer schema, encoded at unused tags. This
/// test-only type is not an ArchCert authority contract or a future API promise.
#[derive(Clone, PartialEq, Message)]
struct FutureClaims {
    #[prost(bool, tag = "100")]
    source_verified: bool,
    #[prost(bool, tag = "101")]
    certified: bool,
    #[prost(bool, tag = "102")]
    network_allowed: bool,
}

#[test]
fn additive_unknown_fields_decode_but_cannot_create_positive_authority() -> Result {
    let claims = FutureClaims {
        source_verified: true,
        certified: true,
        network_allowed: true,
    }
    .encode_to_vec();

    for status in [
        app::SubmissionStatus::Rejected,
        app::SubmissionStatus::IncompleteExternalSource,
    ] {
        let mut state = expected()?;
        state.status = status;

        if status == app::SubmissionStatus::Rejected {
            state.source = None;
            state.accepted_at = None;
        } else {
            let source = state.source.as_mut().ok_or("source")?;
            source.completeness = SourceStatus::IncompleteExternalSource;
            source.lfs_unresolved = 1;
        }

        let mut bytes = encode_submission(&state)?;
        bytes.extend_from_slice(&claims);

        assert_eq!(decode_submission(&bytes)?, state);
    }

    let mut dto = p::SourceSubmission::decode(GOLDEN)?;
    dto.status = 0;
    let mut bytes = dto.encode_to_vec();
    bytes.extend_from_slice(&claims);

    assert!(decode_submission(&bytes).is_err());

    Ok(())
}

#[test]
fn distinct_valid_field_orders_preserve_semantics_without_canonical_bytes() -> Result {
    let mut dto = p::SourceSubmission::decode(GOLDEN)?;
    let actor = dto.actor.take();
    let mut reordered = dto.encode_to_vec();
    // A second partial message places field 5 after field 10. Protobuf permits
    // this order; the same logical observation now has different wire bytes.
    reordered.extend_from_slice(
        &p::SourceSubmission {
            actor,
            ..Default::default()
        }
        .encode_to_vec(),
    );

    assert_ne!(reordered, GOLDEN);
    assert_eq!(decode_submission(&reordered)?, expected()?);

    let mut later = expected()?;
    later.received_at += 100;
    later.accepted_at = later.accepted_at.map(|t| t + 100);
    later.submitted_refs = vec!["refs/heads/another".into()];

    assert_eq!(
        decode_submission(&encode_submission(&later)?)?.source,
        expected()?.source
    );

    Ok(())
}

#[test]
fn malformed_or_oversized_wire_input_is_rejected() {
    assert!(decode_submission(&vec![0; 65_537]).is_err());
    assert!(decode_submission(&[0xff]).is_err());
    assert!(decode_submission(&GOLDEN[..GOLDEN.len() - 1]).is_err());
    assert!(decode_submission(&[]).is_err());
}
