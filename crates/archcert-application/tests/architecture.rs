//! Small Cargo metadata dependency guard, also run by the default workspace tests.

use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

fn allowed_inward_dependency(package: &str, dependency: &str) -> bool {
    if [
        "archcert-domain",
        "archcert-application",
        "archcert-knowledge",
    ]
    .contains(&package)
        && (is_protobuf_dependency(dependency)
            || is_persistence_dependency(dependency)
            || is_semantic_provider_dependency(dependency)
            || is_provider_http_dependency(dependency)
            || is_runtime_dependency(dependency))
    {
        return false;
    }

    if package == "archcert-glassmere" && dependency.starts_with("archcert-") {
        return ["archcert-domain", "archcert-application"].contains(&dependency);
    }

    if package == "archcert-runner"
        && (dependency == "archcert-semantic" || is_semantic_provider_dependency(dependency))
    {
        return false;
    }

    if package != "archcert-crypto"
        && package != "archcert-certificate"
        && package != "archcert-cli"
        && package != "archcert-controller"
        && [
            "ed25519-dalek",
            "ring",
            "openssl",
            "cryptoki",
            "aws-sdk-kms",
        ]
        .contains(&dependency)
    {
        return false;
    }

    match package {
        "archcert-domain" => {
            !dependency.starts_with("archcert-")
                && ![
                    "axum", "tokio", "rustix", "sqlx", "diesel", "bollard", "git2", "gix",
                    "reqwest", "tar", "flate2",
                ]
                .contains(&dependency)
        }
        "archcert-application" => {
            !dependency.starts_with("archcert-") || dependency == "archcert-domain"
        }
        "archcert-observation" => [
            "archcert-domain",
            "archcert-application",
            "archcert-storage",
            "archcert-certificate",
            "archcert-crypto",
            "async-trait",
            "rustix",
            "serde",
            "serde_json",
            "tokio",
        ]
        .contains(&dependency),
        "archcert-knowledge" => {
            (!dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application"].contains(&dependency))
                && !["reqwest", "tokio", "rustix", "sqlx"].contains(&dependency)
                && !is_semantic_provider_dependency(dependency)
        }
        "archcert-semantic" => {
            (!dependency.starts_with("archcert-")
                || [
                    "archcert-domain",
                    "archcert-application",
                    "archcert-knowledge",
                ]
                .contains(&dependency))
                && !["reqwest", "rustix", "sqlx"].contains(&dependency)
        }
        "archcert-policy" => {
            (!dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application"].contains(&dependency))
                && ![
                    "axum", "tokio", "rustix", "sqlx", "diesel", "bollard", "git2", "gix",
                    "reqwest", "tar", "flate2",
                ]
                .contains(&dependency)
        }
        "archcert-runner" => ![
            "archcert-materialization",
            "archcert-crypto",
            "archcert-certificate",
            "archcert-evidence",
            "ed25519-dalek",
        ]
        .contains(&dependency),
        "archcert-gateway" => {
            (!dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application", "archcert-source"]
                    .contains(&dependency))
                && !["bollard", "docker-api", "ed25519-dalek", "archcert-crypto"]
                    .contains(&dependency)
        }
        "archcert-gateway-cli" => {
            !dependency.starts_with("archcert-")
                || [
                    "archcert-gateway",
                    "archcert-domain",
                    "archcert-source",
                    "archcert-protocol",
                ]
                .contains(&dependency)
        }
        "archcert-protocol" => {
            !dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application"].contains(&dependency)
        }
        "archcert-source" | "archcert-materialization" => ![
            "archcert-crypto",
            "archcert-certificate",
            "archcert-evidence",
            "ed25519-dalek",
        ]
        .contains(&dependency),
        "archcert-worker" => ![
            "archcert-storage",
            "archcert-crypto",
            "archcert-certificate",
            "sqlx",
            "postgres",
            "tokio-postgres",
        ]
        .contains(&dependency),
        "archcert-crypto" => !dependency.starts_with("archcert-"),
        "archcert-evidence" => {
            !dependency.starts_with("archcert-")
                || ["archcert-domain", "archcert-application", "archcert-policy"]
                    .contains(&dependency)
        }
        "archcert-certificate" => {
            !dependency.starts_with("archcert-")
                || [
                    "archcert-domain",
                    "archcert-application",
                    "archcert-policy",
                    "archcert-evidence",
                    "archcert-crypto",
                ]
                .contains(&dependency)
        }
        _ => true,
    }
}

fn is_semantic_provider_dependency(name: &str) -> bool {
    [
        "async-openai",
        "openai",
        "anthropic",
        "rig-core",
        "genai",
        "llm",
        "ollama-rs",
    ]
    .iter()
    .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}-")))
}

fn is_provider_http_dependency(name: &str) -> bool {
    ["reqwest", "ureq", "isahc"].contains(&name)
}

fn semantic_forbidden_capability(name: &str) -> bool {
    is_runtime_dependency(name)
        || is_persistence_dependency(name)
        || [
            "archcert-source",
            "archcert-materialization",
            "archcert-gateway",
            "archcert-crypto",
            "archcert-certificate",
            "archcert-evidence",
            "ed25519-dalek",
            "ring",
            "openssl",
            "cryptoki",
            "aws-sdk-kms",
        ]
        .contains(&name)
}

fn dependency_closure(graph: &BTreeMap<String, Vec<String>>, root: &str) -> BTreeSet<String> {
    let mut pending = vec![root.to_owned()];
    let mut seen = BTreeSet::new();

    while let Some(name) = pending.pop() {
        if seen.insert(name.clone()) {
            pending.extend(graph.get(&name).into_iter().flatten().cloned());
        }
    }

    seen
}

fn is_persistence_dependency(name: &str) -> bool {
    name == "sqlx"
        || name.starts_with("sqlx-")
        || name == "postgres"
        || name == "tokio-postgres"
        || name == "diesel"
        || name.starts_with("aws-sdk-s3")
        || name == "rust-s3"
        || name == "object_store"
        || name == "axum"
        || name == "archcert-storage"
}

fn is_protobuf_dependency(name: &str) -> bool {
    name == "prost"
        || name.starts_with("prost-")
        || name == "tonic"
        || name.starts_with("tonic-")
        || name.starts_with("protoc-")
        || name == "archcert-protocol"
        || name.starts_with("archcert-proto")
}

fn is_runtime_dependency(name: &str) -> bool {
    name == "archcert-runner"
        || name == "bollard"
        || name.starts_with("bollard-")
        || name == "docker-api"
        || name.starts_with("docker-api-")
}

#[test]
fn workspace_dependencies_point_inward_and_scaffolds_stay_outside_active_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let metadata = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()?;

    assert!(metadata.status.success(), "cargo metadata failed");

    let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
    let mut graph = BTreeMap::<String, Vec<String>>::new();

    for package in metadata["packages"].as_array().ok_or("packages missing")? {
        let name = package["name"].as_str().ok_or("package name missing")?;

        for dependency in package["dependencies"]
            .as_array()
            .ok_or("dependencies missing")?
        {
            let dep = dependency["name"]
                .as_str()
                .ok_or("dependency name missing")?;
            // Runner test fixtures may compose materialization; inward layers
            // must stay independent even through dev dependencies.
            let runner_fixture = name == "archcert-runner"
                && dep == "archcert-materialization"
                && dependency["kind"] == "dev";

            assert!(
                runner_fixture || allowed_inward_dependency(name, dep),
                "forbidden architecture edge: {name} -> {dep}"
            );

            if dependency["kind"] != "dev" {
                graph.entry(name.into()).or_default().push(dep.into());
            }
        }
    }

    // External normal/build dependencies are included so an intermediary cannot
    // bring transport, persistence, providers or runtime authority into the core.
    for root in [
        "archcert-domain",
        "archcert-application",
        "archcert-knowledge",
    ] {
        let mut pending = vec![root.to_owned()];
        let mut seen = BTreeSet::new();

        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }

            assert!(
                !(is_protobuf_dependency(&name)
                    || is_persistence_dependency(&name)
                    || is_semantic_provider_dependency(&name)
                    || is_provider_http_dependency(&name)
                    || is_runtime_dependency(&name)),
                "transport, persistence, provider or runtime enters inward graph {root}: {name}"
            );

            pending.extend(graph.get(&name).into_iter().flatten().cloned());
        }
    }

    for name in dependency_closure(&graph, "archcert-semantic") {
        assert!(
            !semantic_forbidden_capability(&name),
            "runtime, acquisition, persistence or signing capability enters semantic adapter: {name}"
        );
    }

    // The CLI deliberately composes issuance. Execution and transport graphs do
    // not acquire signing authority, directly or through an intermediate crate.
    for root in [
        "archcertd",
        "archcert-glassmere",
        "archcert-control-plane",
        "archcert-worker",
        "archcert-gateway",
        "archcert-gateway-cli",
        "archcert-runner",
        "archcert-source",
        "archcert-materialization",
        "archcert-application",
        "archcert-policy",
        "archcert-knowledge",
        "archcert-semantic",
    ] {
        let mut pending = vec![root.to_owned()];
        let mut seen = BTreeSet::new();

        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }

            assert!(
                ![
                    "archcert-evidence",
                    "archcert-crypto",
                    "archcert-certificate",
                    "ed25519-dalek"
                ]
                .contains(&name.as_str()),
                "signing authority enters forbidden graph {root}: {name}"
            );

            if ["archcert-worker", "archcert-semantic"].contains(&root) {
                assert!(
                    !is_persistence_dependency(&name),
                    "database/object-store authority enters worker: {name}"
                );
            }

            if root == "archcert-runner" {
                assert!(
                    name != "archcert-semantic" && !is_semantic_provider_dependency(&name),
                    "semantic provider enters execution graph: {name}"
                );
            }

            pending.extend(graph.get(&name).into_iter().flatten().cloned());
        }
    }

    for root in [
        "archcert-glassmere",
        "archcert-panel",
        "archcert-observation",
    ] {
        for name in dependency_closure(&graph, root) {
            assert!(
                !is_runtime_dependency(&name)
                    && !is_semantic_provider_dependency(&name)
                    && ![
                        "archcert-source",
                        "archcert-gateway",
                        "archcert-materialization",
                        "archcert-semantic"
                    ]
                    .contains(&name.as_str()),
                "runtime, provider or acquisition enters Glassmere graph {root}: {name}"
            );
        }
    }

    assert!(
        !graph.contains_key("archcert-local-api"),
        "product onboarding belongs in archcertd"
    );

    for name in dependency_closure(&graph, "archcertd") {
        assert!(
            !is_runtime_dependency(&name) && !is_semantic_provider_dependency(&name),
            "runtime/provider enters the API boundary: {name}"
        );
    }

    for root in ["archcert-gateway", "archcert-gateway-cli"] {
        let mut pending = vec![root.to_owned()];
        let mut seen = BTreeSet::new();

        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }

            assert!(
                ![
                    "archcert-runner",
                    "archcert-materialization",
                    "archcert-policy",
                    "bollard",
                    "docker-api"
                ]
                .contains(&name.as_str()),
                "execution/policy authority enters gateway graph: {name}"
            );

            pending.extend(graph.get(&name).into_iter().flatten().cloned());
        }
    }

    Ok(())
}

#[test]
fn guard_rejects_forbidden_dependencies_including_renamed_package_names() {
    for (owner, dep) in [
        ("archcert-glassmere", "archcert-certificate"),
        ("archcert-glassmere", "archcert-storage"),
        ("archcert-glassmere", "archcert-runner"),
        ("archcert-glassmere", "archcert-source"),
        ("archcert-glassmere", "archcert-semantic"),
        ("archcert-glassmere", "archcert-observation"),
        ("archcert-application", "archcert-observation"),
        ("archcert-observation", "archcert-control-plane"),
        ("archcert-observation", "archcert-runner"),
        ("archcert-observation", "archcert-gateway"),
        ("archcert-observation", "archcert-semantic"),
        ("archcert-observation", "ed25519-dalek"),
        ("archcert-observation", "axum"),
        ("archcert-observation", "hyper"),
        ("archcert-domain", "archcert-application"),
        ("archcert-domain", "archcert-source"),
        ("archcert-domain", "axum"),
        ("archcert-domain", "sqlx-postgres"),
        ("archcert-domain", "postgres"),
        ("archcert-domain", "aws-sdk-s3"),
        ("archcert-application", "sqlx"),
        ("archcert-application", "archcert-storage"),
        ("archcert-domain", "tokio"),
        ("archcert-domain", "async-openai"),
        ("archcert-application", "anthropic"),
        ("archcert-application", "openai-api"),
        ("archcert-application", "reqwest"),
        ("archcert-domain", "ureq"),
        ("archcert-knowledge", "archcert-crypto"),
        ("archcert-knowledge", "archcert-storage"),
        ("archcert-knowledge", "archcert-runner"),
        ("archcert-knowledge", "async-openai"),
        ("archcert-knowledge", "prost-types"),
        ("archcert-knowledge", "tonic"),
        ("archcert-knowledge", "bollard-stubs"),
        ("archcert-application", "bollard"),
        ("archcert-application", "docker-api"),
        ("archcert-semantic", "archcert-crypto"),
        ("archcert-semantic", "archcert-storage"),
        ("archcert-semantic", "archcert-runner"),
        ("archcert-runner", "archcert-semantic"),
        ("archcert-runner", "async-openai"),
        ("archcert-runner", "anthropic"),
        ("archcert-application", "archcert-protocol"),
        ("archcert-domain", "archcert-proto"),
        ("archcert-domain", "prost"),
        ("archcert-domain", "prost-types"),
        ("archcert-domain", "tonic"),
        ("archcert-application", "prost"),
        ("archcert-application", "prost-build"),
        ("archcert-application", "prost-types"),
        ("archcert-application", "tonic"),
        ("archcert-application", "archcert-protocol-protobuf"),
        ("archcert-protocol", "archcert-gateway"),
        ("archcert-protocol", "archcert-certificate"),
        ("archcert-application", "archcert-runner"),
        ("archcert-runner", "archcert-materialization"),
        ("archcert-domain", "archcert-policy"),
        ("archcert-application", "archcert-policy"),
        ("archcert-policy", "archcert-runner"),
        ("archcert-policy", "archcert-materialization"),
        ("archcert-policy", "archcert-protocol"),
        ("archcert-policy", "axum"),
        ("archcert-policy", "rustix"),
        ("archcert-runner", "archcert-crypto"),
        ("archcert-runner", "archcert-certificate"),
        ("archcert-materialization", "archcert-crypto"),
        ("archcert-source", "archcert-crypto"),
        ("archcert-gateway", "archcert-certificate"),
        ("archcert-gateway", "archcert-crypto"),
        ("archcert-gateway", "archcert-runner"),
        ("archcert-gateway", "archcert-materialization"),
        ("archcert-gateway", "archcert-policy"),
        ("archcert-gateway-cli", "archcert-certificate"),
        ("archcert-evidence", "archcert-crypto"),
        ("archcert-crypto", "archcert-runner"),
    ] {
        assert!(!allowed_inward_dependency(owner, dep));
    }

    assert!(allowed_inward_dependency(
        "archcert-application",
        "archcert-domain"
    ));
}

#[test]
fn semantic_capability_guard_rejects_transitive_and_cyclic_intermediaries() {
    for forbidden in [
        "archcert-runner",
        "bollard",
        "docker-api",
        "archcert-storage",
        "archcert-source",
        "archcert-gateway",
        "archcert-crypto",
        "archcert-certificate",
        "ed25519-dalek",
        "aws-sdk-kms",
    ] {
        let graph = BTreeMap::from([
            ("archcert-semantic".into(), vec!["intermediary".into()]),
            ("intermediary".into(), vec!["cycle".into()]),
            (
                "cycle".into(),
                vec!["intermediary".into(), forbidden.into()],
            ),
        ]);

        let closure = dependency_closure(&graph, "archcert-semantic");

        assert!(
            closure
                .iter()
                .any(|name| semantic_forbidden_capability(name))
        );
    }
}

#[test]
fn runner_and_source_interfaces_contain_no_signing_capability() {
    for source in [
        include_str!("../src/materialization.rs"),
        include_str!("../src/execution.rs"),
        include_str!("../src/release.rs"),
        include_str!("../src/release/workflow.rs"),
        include_str!("../src/source.rs"),
        include_str!("../src/configuration.rs"),
        include_str!("../src/semantic.rs"),
        include_str!("../src/semantic/greywatch.rs"),
        include_str!("../../archcert-semantic/src/lib.rs"),
        include_str!("../src/knowledge.rs"),
        include_str!("../src/ironcrest.rs"),
        include_str!("../src/ironcrest/workflow.rs"),
        include_str!("../../archcert-domain/src/source.rs"),
        include_str!("../../archcert-domain/src/materialization.rs"),
    ] {
        for forbidden in [
            "CertificateSigner",
            "SigningKey",
            "LocalDevelopmentSigner",
            "DetachedSignature",
        ] {
            assert!(
                !source.contains(forbidden),
                "signing capability in execution interface: {forbidden}"
            );
        }
    }
}

#[test]
fn source_and_runner_capabilities_cannot_carry_acquisition_authority() {
    let source = include_str!("../src/materialization.rs");
    let fields = source
        .split("pub struct RunnerInput")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap_or("");

    assert!(!fields.is_empty());

    for forbidden in [
        "RepositoryId",
        "GitActorId",
        "DeviceKeyId",
        "Credential",
        "Token",
        "Url",
        "SourceStore",
        "ExternalSourceAuthority",
        "GitGateway",
    ] {
        assert!(!fields.contains(forbidden));
    }

    let source = include_str!("../../archcert-domain/src/source.rs");
    let fields = source
        .split("pub struct SourceSnapshot")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap_or("");

    assert!(!fields.is_empty());

    for forbidden in [
        "GitActorId",
        "DeviceKeyId",
        "Credential",
        "Token",
        "Url",
        "SourceStore",
        "GitGateway",
        "ExternalSourceAuthority",
    ] {
        assert!(!fields.contains(forbidden));
    }

    let binding = include_str!("../../archcert-domain/src/source/binding.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in [
        "GitActorId",
        "DeviceKeyId",
        "Credential",
        "Token",
        "Url",
        "SourceStore",
        "GitGateway",
        "ExternalSourceAuthority",
    ] {
        assert!(
            !binding.contains(forbidden),
            "acquisition type in source binding: {forbidden}"
        );
    }

    let gateway = concat!(
        include_str!("../../archcert-gateway/src/lib.rs"),
        include_str!("../../archcert-gateway/src/git.rs"),
        include_str!("../../archcert-gateway/src/protocol.rs"),
        include_str!("../../archcert-gateway/src/store.rs"),
        include_str!("../../archcert-gateway/src/resolution.rs")
    );

    for forbidden in [
        "SandboxRunner",
        "RunnerInput",
        "CertificateSigner",
        "DockerRootlessRunner",
        "archcert_policy",
        "archcert_certificate",
    ] {
        assert!(!gateway.contains(forbidden));
    }
}
