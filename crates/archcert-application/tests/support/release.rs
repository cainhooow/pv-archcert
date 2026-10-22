use archcert_application::release::*;
use archcert_domain::{
    GitObjectId, ProjectId, execution::*, materialization::WorkspaceId, release::*, source::*,
};
use std::collections::BTreeMap;

pub type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub fn recipe() -> R<RustReleaseRecipe> {
    Ok(RustReleaseRecipe::new(
        BuildEnvironment {
            image: format!("authority/rust@sha256:{}", "a".repeat(64)),
            dependency_bundle_sha256: digest_bytes(b"authority public dependencies"),
            toolchain_sha256: digest_bytes(b"authority rustc inventory"),
        },
        "archcert",
    )?)
}

pub fn input() -> R<BuildInputManifest> {
    let recipe = recipe()?;

    Ok(BuildInputManifest {
        schema: 1,
        kind: "ARCHCERT_BUILD_INPUT".into(),
        certified_source: CertifiedSourceIdentity {
            project: ProjectId::new(),
            repository: RepositoryId::parse("test/release")?,
            source: archcert_domain::SourceIdentity {
                commit: GitObjectId::parse("b".repeat(40))?,
                tree: GitObjectId::parse("c".repeat(40))?,
                snapshot_sha256: digest_bytes(b"exact source"),
            },
            certificate_sha256: digest_bytes(b"source certificate payload"),
        },
        recipe: recipe.description().clone(),
        recipe_identity: recipe.identity()?,
        environment_identity: recipe.environment_identity()?,
        source_policy_sha256: digest_bytes(b"source policy"),
        source_authority_key_sha256: digest_bytes(b"source public key"),
        release_authority_key_sha256: digest_bytes(b"release public key"),
        release_policy: RELEASE_POLICY.into(),
        release_policy_sha256: release_policy_digest(),
    })
}

pub fn result(input: &BuildInputManifest, ordinal: BuildOrdinal, bytes: &[u8]) -> R<BuildResult> {
    let marker = b"ARCHCERT_BUILD_READY_V1\n";
    let stream = |bytes: &[u8]| CapturedStream {
        sha256: digest_bytes(bytes),
        observed_bytes: bytes.len() as u64,
        excerpt: bytes.into(),
        truncated: false,
        complete: true,
    };
    let evidence = ExecutionEvidence {
        execution: ExecutionId::new(),
        source: input.certified_source.source.clone(),
        workspace: WorkspaceId::new(),
        backend: "DockerRootlessRunner".into(),
        backend_version: "archcert-docker-release-v1".into(),
        producer_version: "0.1.0".into(),
        observed_runtime: ObservedRuntimeIdentity {
            client_path: "/authority/docker".into(),
            client_version: "synthetic".into(),
            server_version: "synthetic".into(),
            runtime_information: BTreeMap::from([(
                "authority/control-profile".into(),
                "large-offline-image-v1/60s".into(),
            )]),
        },
        toolchain: ToolchainObservation::NotObserved,
        image_digest: input.recipe.environment.image.clone(),
        base_image_id: format!("sha256:{}", "d".repeat(64)),
        execution_image_id: format!("sha256:{}", "e".repeat(64)),
        profile: input.recipe.profile.clone(),
        command: input.recipe.command.clone(),
        network: NetworkPolicy::Denied,
        limits: input.recipe.limits,
        environment_keys: sandbox_environment().into_keys().collect(),
        container_user: "10001:10001".into(),
        started_at_ms: 1,
        ended_at_ms: 2,
        duration_ms: 1,
        exit_code: Some(0),
        termination: TerminationReason::Exit,
        stdout: stream(marker),
        stderr: stream(b""),
        outcome: ExecutionOutcome::Completed,
    };

    Ok(BuildResult {
        schema: 1,
        kind: "ARCHCERT_BUILD_RESULT".into(),
        invocation: input.identity()?,
        ordinal,
        source: input.certified_source.clone(),
        recipe: input.recipe_identity.clone(),
        environment: input.environment_identity.clone(),
        completion: BuildCompletion::Complete,
        execution: Some(evidence),
        cleanup_complete: true,
        artifact: Some(artifact_identity(bytes)?),
    })
}
